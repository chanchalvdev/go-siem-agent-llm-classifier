package ioc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chverma/siemagent/internal/logsafe"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// Source says where a watchlist's indicators come from.
type Source string

const (
	// SourceManual lists are edited by analysts and stored in the database.
	SourceManual Source = "manual"
	// SourceFeed lists are downloaded from a URL and refreshed periodically.
	SourceFeed Source = "feed"
	// SourceFile lists are read from IOC_WATCHLIST_DIR at start (read-only).
	SourceFile Source = "file"
)

const (
	// MaxIndicatorsPerList bounds one feed or file.
	MaxIndicatorsPerList = 1_000_000
	// MaxManualIndicators bounds a hand-maintained list.
	MaxManualIndicators = 100_000
	// MaxAddPerRequest bounds one AddIndicators call.
	MaxAddPerRequest = 10_000
	maxFeedBytes     = 64 << 20
	minRefresh       = 15 * time.Minute
	defaultRefresh   = 6 * time.Hour
)

var (
	// ErrNotFound means no watchlist has the ID.
	ErrNotFound = errors.New("watchlist not found")
	// ErrReadOnly means the watchlist's indicators cannot be edited here.
	ErrReadOnly = errors.New("watchlist is read-only")
)

// Watchlist is a named set of indicators. A match raises the event to
// Severity (if it is lower) and adds a detection.
type Watchlist struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Source      Source          `json:"source"`
	URL         string          `json:"url,omitempty"` // feeds only
	Severity    models.Severity `json:"severity"`
	Enabled     bool            `json:"enabled"`
	// RefreshSeconds is how often a feed is downloaded again.
	RefreshSeconds int       `json:"refresh_seconds,omitempty"`
	CreatedBy      string    `json:"created_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`

	// Runtime state, not persisted.
	Count       int        `json:"count"`
	Skipped     int        `json:"skipped,omitempty"` // feed/file lines that were not indicators
	LastFetched *time.Time `json:"last_fetched,omitempty"`
	Error       string     `json:"error,omitempty"`
	Hits        int64      `json:"hits"`
	LastHit     *time.Time `json:"last_hit,omitempty"`
}

// NewWatchlist is a request to create a manual list or a feed.
type NewWatchlist struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Source         Source          `json:"source"`
	URL            string          `json:"url"`
	Severity       models.Severity `json:"severity"`
	RefreshSeconds int             `json:"refresh_seconds"`
}

// Update changes a watchlist; nil fields are left alone.
type Update struct {
	Name     *string          `json:"name"`
	Enabled  *bool            `json:"enabled"`
	Severity *models.Severity `json:"severity"`
}

// Store persists manual and feed watchlists and manual indicators. File
// lists live only in memory.
type Store interface {
	ListWatchlists(ctx context.Context) ([]Watchlist, error)
	SaveWatchlist(ctx context.Context, w Watchlist) error
	DeleteWatchlist(ctx context.Context, id string) error
	Indicators(ctx context.Context, watchlistID string) ([]Indicator, error)
	AddIndicators(ctx context.Context, watchlistID string, inds []Indicator) error
	RemoveIndicator(ctx context.Context, watchlistID, value string) error
}

// Fetcher downloads a feed; tests replace it.
type Fetcher func(ctx context.Context, url string) (io.ReadCloser, error)

// Service owns the watchlists and the index events are matched against.
type Service struct {
	store Store
	fetch Fetcher
	now   func() time.Time

	mu    sync.Mutex
	lists map[string]*Watchlist
	inds  map[string][]Indicator // by watchlist ID
	idx   atomic.Pointer[index]
	// rebuildMu keeps concurrent rebuilds from storing an older snapshot
	// over a newer one.
	rebuildMu sync.Mutex
}

// NewService loads the stored watchlists and their manual indicators. Feeds
// are downloaded by Start.
func NewService(ctx context.Context, st Store) (*Service, error) {
	s := &Service{store: st, fetch: httpFetch, now: time.Now, lists: map[string]*Watchlist{}, inds: map[string][]Indicator{}}
	lists, err := st.ListWatchlists(ctx)
	if err != nil {
		return nil, err
	}
	for i := range lists {
		w := lists[i]
		if w.Source == SourceManual {
			inds, err := st.Indicators(ctx, w.ID)
			if err != nil {
				return nil, err
			}
			s.inds[w.ID] = inds
			w.Count = len(inds)
		}
		s.lists[w.ID] = &w
	}
	s.rebuild()
	return s, nil
}

// LoadDir adds every *.txt, *.csv and *.list file in dir as a read-only
// watchlist named after the file. The severity is P2 unless the file name
// starts with "p1-" … "p4-" (e.g. p1-ransomware-c2.txt).
func (s *Service) LoadDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("IOC_WATCHLIST_DIR: %w", err)
	}
	n := 0
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".txt" && ext != ".csv" && ext != ".list") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path) //nolint:gosec // operator-configured directory
		if err != nil {
			return n, err
		}
		inds, skipped, perr := ParseList(f, MaxIndicatorsPerList)
		_ = f.Close()
		base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		sev := models.SeverityP2
		if len(base) > 3 && base[0] == 'p' && base[1] >= '1' && base[1] <= '4' && base[2] == '-' {
			sev = models.Severity("P" + string(base[1]))
			base = base[3:]
		}
		now := s.now().UTC()
		w := &Watchlist{
			ID: "file:" + e.Name(), Name: base, Source: SourceFile, Severity: sev, Enabled: true,
			Description: "Loaded from " + e.Name(), CreatedAt: now, LastFetched: &now,
			Count: len(inds), Skipped: skipped,
		}
		if perr != nil {
			w.Error = perr.Error()
		}
		s.mu.Lock()
		s.lists[w.ID] = w
		s.inds[w.ID] = inds
		s.mu.Unlock()
		n++
	}
	s.rebuild()
	return n, nil
}

// Start downloads feeds now and whenever they are due, until ctx ends.
func (s *Service) Start(ctx context.Context) {
	s.refreshDue(ctx, true)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshDue(ctx, false)
		}
	}
}

func (s *Service) refreshDue(ctx context.Context, all bool) {
	now := s.now()
	var due []string
	s.mu.Lock()
	for id, w := range s.lists {
		if w.Source != SourceFeed || !w.Enabled {
			continue
		}
		every := time.Duration(w.RefreshSeconds) * time.Second
		if all || w.LastFetched == nil || now.Sub(*w.LastFetched) >= every {
			due = append(due, id)
		}
	}
	s.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		_ = s.Refresh(ctx, id)
	}
}

// Refresh downloads a feed again. The previous indicators stay in use when
// the download fails.
func (s *Service) Refresh(ctx context.Context, id string) error {
	s.mu.Lock()
	w, ok := s.lists[id]
	var url string
	if ok {
		url = w.URL
	}
	s.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if w.Source != SourceFeed {
		return fmt.Errorf("%w: only feeds can be refreshed", ErrReadOnly)
	}

	fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inds, skipped, err := s.download(fctx, url)
	now := s.now().UTC()

	s.mu.Lock()
	w, ok = s.lists[id]
	if !ok { // deleted while downloading
		s.mu.Unlock()
		return ErrNotFound
	}
	w.LastFetched = &now
	if err != nil {
		w.Error = err.Error()
		s.mu.Unlock()
		metrics.IOCFeedErrorsTotal.Inc()
		slog.Warn("watchlist feed refresh failed", "component", "ioc", "watchlist", logsafe.String(w.Name), "error", logsafe.Err(err))
		return err
	}
	w.Error, w.Count, w.Skipped = "", len(inds), skipped
	s.inds[id] = inds
	s.mu.Unlock()
	s.rebuild()
	slog.Info("watchlist feed refreshed", "component", "ioc", "watchlist", logsafe.String(w.Name), "indicators", len(inds), "skipped", skipped)
	return nil
}

func (s *Service) download(ctx context.Context, url string) ([]Indicator, int, error) {
	body, err := s.fetch(ctx, url)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = body.Close() }()
	return ParseList(io.LimitReader(body, maxFeedBytes), MaxIndicatorsPerList)
}

var feedClient = &http.Client{Timeout: 2 * time.Minute}

func httpFetch(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "siemagent-watchlist/1")
	resp, err := feedClient.Do(req) //nolint:gosec // admins configure feed URLs
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("feed answered HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// rebuild indexes the indicators of every enabled list and swaps the index in.
func (s *Service) rebuild() {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	x := newIndex()
	s.mu.Lock()
	for id, w := range s.lists {
		if !w.Enabled {
			continue
		}
		for _, ind := range s.inds[id] {
			x.add(id, ind)
		}
	}
	s.mu.Unlock()
	s.idx.Store(x)
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "WL-" + strings.ToUpper(hex.EncodeToString(b))
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func validSeverity(s models.Severity) bool {
	switch s {
	case models.SeverityP1, models.SeverityP2, models.SeverityP3, models.SeverityP4:
		return true
	}
	return false
}

// Create adds a manual list or a feed. Start's loop downloads a new feed
// within a minute (it has never been fetched); Refresh does it at once.
func (s *Service) Create(ctx context.Context, actor string, n NewWatchlist) (Watchlist, error) {
	w := Watchlist{
		ID: newID(), Name: strings.TrimSpace(n.Name), Description: strings.TrimSpace(n.Description),
		Source: n.Source, URL: strings.TrimSpace(n.URL), Severity: n.Severity, Enabled: true,
		CreatedBy: actor, CreatedAt: s.now().UTC(),
	}
	if w.Name == "" || len(w.Name) > 100 {
		return Watchlist{}, invalid("name is required (up to 100 characters)")
	}
	if len(w.Description) > 500 {
		return Watchlist{}, invalid("description is too long")
	}
	if w.Severity == "" {
		w.Severity = models.SeverityP2
	}
	if !validSeverity(w.Severity) {
		return Watchlist{}, invalid("severity must be P1–P4")
	}
	switch w.Source {
	case SourceManual:
		w.URL = ""
	case SourceFeed:
		if !strings.HasPrefix(w.URL, "https://") && !strings.HasPrefix(w.URL, "http://") {
			return Watchlist{}, invalid("a feed needs an http(s) URL")
		}
		w.RefreshSeconds = n.RefreshSeconds
		if w.RefreshSeconds == 0 {
			w.RefreshSeconds = int(defaultRefresh / time.Second)
		}
		if time.Duration(w.RefreshSeconds)*time.Second < minRefresh {
			return Watchlist{}, invalid("refresh must be at least 15 minutes (900 seconds)")
		}
	default:
		return Watchlist{}, invalid("source must be manual or feed")
	}
	s.mu.Lock()
	for _, x := range s.lists {
		if strings.EqualFold(x.Name, w.Name) {
			s.mu.Unlock()
			return Watchlist{}, invalid("a watchlist named %q already exists", w.Name)
		}
	}
	s.mu.Unlock()
	if err := s.store.SaveWatchlist(ctx, w); err != nil {
		return Watchlist{}, err
	}
	s.mu.Lock()
	s.lists[w.ID] = &w
	s.mu.Unlock()
	return w, nil
}

// Get returns one watchlist.
func (s *Service) Get(id string) (Watchlist, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.lists[id]
	if !ok {
		return Watchlist{}, ErrNotFound
	}
	return *w, nil
}

// List returns every watchlist, by name.
func (s *Service) List() []Watchlist {
	s.mu.Lock()
	out := make([]Watchlist, 0, len(s.lists))
	for _, w := range s.lists {
		out = append(out, *w)
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b Watchlist) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

// Update renames, enables/disables or re-grades a watchlist.
func (s *Service) Update(ctx context.Context, id string, u Update) (Watchlist, error) {
	s.mu.Lock()
	w, ok := s.lists[id]
	if !ok {
		s.mu.Unlock()
		return Watchlist{}, ErrNotFound
	}
	next := *w
	s.mu.Unlock()
	if u.Name != nil {
		next.Name = strings.TrimSpace(*u.Name)
		if next.Name == "" || len(next.Name) > 100 {
			return Watchlist{}, invalid("name is required (up to 100 characters)")
		}
	}
	if u.Severity != nil {
		if !validSeverity(*u.Severity) {
			return Watchlist{}, invalid("severity must be P1–P4")
		}
		next.Severity = *u.Severity
	}
	if u.Enabled != nil {
		next.Enabled = *u.Enabled
	}
	if next.Source != SourceFile { // file lists are configured on disk
		if err := s.store.SaveWatchlist(ctx, next); err != nil {
			return Watchlist{}, err
		}
	}
	s.mu.Lock()
	if cur, ok := s.lists[id]; ok {
		cur.Name, cur.Severity, cur.Enabled = next.Name, next.Severity, next.Enabled
		next = *cur
	}
	s.mu.Unlock()
	s.rebuild()
	return next, nil
}

// Delete removes a manual list or feed.
func (s *Service) Delete(ctx context.Context, id string) error {
	w, err := s.Get(id)
	if err != nil {
		return err
	}
	if w.Source == SourceFile {
		return fmt.Errorf("%w: remove the file from IOC_WATCHLIST_DIR instead", ErrReadOnly)
	}
	if err := s.store.DeleteWatchlist(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.lists, id)
	delete(s.inds, id)
	s.mu.Unlock()
	s.rebuild()
	return nil
}

// Indicators returns up to limit indicators of a list, in list order.
func (s *Service) Indicators(id string, limit int) ([]Indicator, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.lists[id]; !ok {
		return nil, 0, ErrNotFound
	}
	all := s.inds[id]
	return slices.Clone(all[:min(limit, len(all))]), len(all), nil
}

// AddIndicators adds values to a manual list. Invalid values are reported
// back; valid ones are added (existing ones are left as they are).
func (s *Service) AddIndicators(ctx context.Context, id, actor, note string, values []string) (added []Indicator, rejected []string, err error) {
	w, err := s.Get(id)
	if err != nil {
		return nil, nil, err
	}
	if w.Source != SourceManual {
		return nil, nil, fmt.Errorf("%w: only manual lists take indicators by hand", ErrReadOnly)
	}
	if len(values) == 0 || len(values) > MaxAddPerRequest {
		return nil, nil, invalid("send 1 to %d indicators", MaxAddPerRequest)
	}
	note = strings.TrimSpace(note)
	if len(note) > 200 {
		return nil, nil, invalid("note is too long (200 characters)")
	}

	s.mu.Lock()
	have := map[string]bool{}
	for _, ind := range s.inds[id] {
		have[ind.Value] = true
	}
	existing := len(s.inds[id])
	s.mu.Unlock()

	for _, v := range values {
		ind, perr := Parse(v)
		if perr != nil {
			rejected = append(rejected, v)
			continue
		}
		if have[ind.Value] {
			continue
		}
		have[ind.Value] = true
		ind.Note, ind.AddedBy = note, actor
		added = append(added, ind)
	}
	if existing+len(added) > MaxManualIndicators {
		return nil, nil, invalid("a manual list holds at most %d indicators", MaxManualIndicators)
	}
	if len(added) == 0 {
		return nil, rejected, nil
	}
	if err := s.store.AddIndicators(ctx, id, added); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	s.inds[id] = append(s.inds[id], added...)
	if cur, ok := s.lists[id]; ok {
		cur.Count = len(s.inds[id])
	}
	s.mu.Unlock()
	s.rebuild()
	return added, rejected, nil
}

// RemoveIndicator deletes one value from a manual list.
func (s *Service) RemoveIndicator(ctx context.Context, id, value string) error {
	w, err := s.Get(id)
	if err != nil {
		return err
	}
	if w.Source != SourceManual {
		return fmt.Errorf("%w: only manual lists can be edited", ErrReadOnly)
	}
	if ind, perr := Parse(value); perr == nil {
		value = ind.Value
	}
	if err := s.store.RemoveIndicator(ctx, id, value); err != nil {
		return err
	}
	s.mu.Lock()
	s.inds[id] = slices.DeleteFunc(s.inds[id], func(ind Indicator) bool { return ind.Value == value })
	if cur, ok := s.lists[id]; ok {
		cur.Count = len(s.inds[id])
	}
	s.mu.Unlock()
	s.rebuild()
	return nil
}

// LookupResult is one watchlist containing a looked-up value.
type LookupResult struct {
	WatchlistID string          `json:"watchlist_id"`
	Watchlist   string          `json:"watchlist"`
	Indicator   string          `json:"indicator"`
	Severity    models.Severity `json:"severity"`
}

// Lookup checks one value (an IP, domain, hash or URL) against the enabled lists.
func (s *Service) Lookup(value string) []LookupResult {
	var out []LookupResult
	for _, h := range s.idx.Load().match(strings.TrimSpace(value)) {
		for _, id := range h.Lists {
			if w, err := s.Get(id); err == nil {
				out = append(out, LookupResult{WatchlistID: id, Watchlist: w.Name, Indicator: h.Indicator, Severity: w.Severity})
			}
		}
	}
	return out
}

// Enrich checks an event against the watchlists. Each hit adds a detection
// ("ioc:<watchlist>"), the matched value joins the event's IOCs, and the
// severity rises to the most severe matching list. Returns the event and
// whether anything matched.
func (s *Service) Enrich(ev models.ClassifiedEvent) (models.ClassifiedEvent, bool) {
	hits := s.idx.Load().match(ev.Event.Raw, ev.Event.Message)
	if len(hits) == 0 {
		return ev, false
	}
	now := s.now().UTC()
	worst := models.Severity("")
	var titles []string
	s.mu.Lock()
	for _, h := range hits {
		for _, id := range h.Lists {
			w, ok := s.lists[id]
			if !ok || !w.Enabled {
				continue
			}
			w.Hits++
			w.LastHit = &now
			title := fmt.Sprintf("%s on watchlist %s", h.Value, w.Name)
			if h.Indicator != h.Value {
				title = fmt.Sprintf("%s (%s) on watchlist %s", h.Value, h.Indicator, w.Name)
			}
			titles = append(titles, title)
			ev.Detections = append(ev.Detections, models.Detection{
				RuleID: "ioc:" + id,
				Title:  "Threat intel match: " + title,
				Level:  levelFor(w.Severity),
				Tags:   []string{"ioc", "ioc." + string(h.Type)},
			})
			if !slices.Contains(ev.IOCs, h.Value) {
				ev.IOCs = append(ev.IOCs, h.Value)
			}
			if worst == "" || rank(w.Severity) < rank(worst) {
				worst = w.Severity
			}
			metrics.IOCMatchesTotal.WithLabelValues(string(h.Type)).Inc()
		}
	}
	s.mu.Unlock()
	if worst == "" {
		return ev, false
	}
	// Keep the most severe detection first, as the rules engine does.
	slices.SortStableFunc(ev.Detections, func(a, b models.Detection) int { return levelRank(a.Level) - levelRank(b.Level) })
	if ev.Severity == "" || rank(worst) < rank(ev.Severity) {
		ev.Severity = worst
		// The watchlist is now the main reason for the alert.
		ev.AttackType = "Known Malicious Indicator"
		ev.Summary = "Threat intel match: " + strings.Join(titles, "; ") + ". " + ev.Summary
		ev.Summary = strings.TrimSpace(ev.Summary)
	}
	return ev, true
}

func levelFor(s models.Severity) string {
	switch s {
	case models.SeverityP1:
		return "critical"
	case models.SeverityP2:
		return "high"
	case models.SeverityP3:
		return "medium"
	}
	return "low"
}

func levelRank(l string) int {
	return slices.Index([]string{"critical", "high", "medium", "low", "informational"}, l)
}

func rank(s models.Severity) int {
	switch s {
	case models.SeverityP1:
		return 1
	case models.SeverityP2:
		return 2
	case models.SeverityP3:
		return 3
	case models.SeverityP4:
		return 4
	case models.SeverityP5:
		return 5
	}
	return 6
}

// Memory is the in-memory Store used without a database.
type Memory struct {
	mu    sync.Mutex
	lists map[string]Watchlist
	inds  map[string][]Indicator
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{lists: map[string]Watchlist{}, inds: map[string][]Indicator{}}
}

func (m *Memory) ListWatchlists(context.Context) ([]Watchlist, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Watchlist, 0, len(m.lists))
	for _, w := range m.lists {
		out = append(out, w)
	}
	return out, nil
}

func (m *Memory) SaveWatchlist(_ context.Context, w Watchlist) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists[w.ID] = persisted(w)
	return nil
}

func (m *Memory) DeleteWatchlist(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.lists[id]; !ok {
		return ErrNotFound
	}
	delete(m.lists, id)
	delete(m.inds, id)
	return nil
}

func (m *Memory) Indicators(_ context.Context, id string) ([]Indicator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.inds[id]), nil
}

func (m *Memory) AddIndicators(_ context.Context, id string, inds []Indicator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inds[id] = append(m.inds[id], inds...)
	return nil
}

func (m *Memory) RemoveIndicator(_ context.Context, id, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	before := len(m.inds[id])
	m.inds[id] = slices.DeleteFunc(m.inds[id], func(ind Indicator) bool { return ind.Value == value })
	if len(m.inds[id]) == before {
		return fmt.Errorf("%w: %s is not on the list", ErrNotFound, value)
	}
	return nil
}

// persisted drops the runtime-only fields before a watchlist is stored.
func persisted(w Watchlist) Watchlist {
	w.Count, w.Skipped, w.LastFetched, w.Error, w.Hits, w.LastHit = 0, 0, nil, "", 0, nil
	return w
}
