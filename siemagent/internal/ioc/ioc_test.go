package ioc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/models"
)

func TestParse(t *testing.T) {
	ok := map[string]Indicator{
		"203.0.113.9":                      {Value: "203.0.113.9", Type: TypeIP},
		" 2001:db8::1 ":                    {Value: "2001:db8::1", Type: TypeIP},
		"::ffff:203.0.113.9":               {Value: "203.0.113.9", Type: TypeIP},
		"198.51.100.17/24":                 {Value: "198.51.100.0/24", Type: TypeCIDR},
		"203.0.113.9/32":                   {Value: "203.0.113.9", Type: TypeIP},
		"Evil.Example.":                    {Value: "evil.example", Type: TypeDomain},
		"hxxp://bad[.]example/x":           {Value: "bad.example", Type: TypeDomain},
		"https://203.0.113.5:8443/payload": {Value: "203.0.113.5", Type: TypeIP},
		"D41D8CD98F00B204E9800998ECF8427E": {Value: "d41d8cd98f00b204e9800998ecf8427e", Type: TypeHash},
		strings.Repeat("a", 64):            {Value: strings.Repeat("a", 64), Type: TypeHash},
	}
	for in, want := range ok {
		got, err := Parse(in)
		if err != nil || got.Value != want.Value || got.Type != want.Type {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0.0.0.0", "127.0.0.1", "10.0.0.0/4", "2001::/16", "not an ioc", "abc", "1.2.3.4/33", strings.Repeat("a", 33)} {
		if _, err := Parse(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) should fail, got %v", bad, err)
		}
	}
}

func TestParseListFormats(t *testing.T) {
	list := `# Feodo Tracker style
203.0.113.9
203.0.113.9
; comment
0.0.0.0 evil.example
"198.51.100.0/24","botnet",2026-10-01
ip_address,first_seen
d41d8cd98f00b204e9800998ecf8427e  # trailing comment
nonsense here
`
	inds, skipped, err := ParseList(strings.NewReader(list), 100)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, i := range inds {
		vals = append(vals, i.Value)
	}
	if strings.Join(vals, " ") != "203.0.113.9 evil.example 198.51.100.0/24 d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("parsed %v", vals)
	}
	if skipped != 2 {
		t.Errorf("skipped %d, want 2 (CSV header and nonsense)", skipped)
	}
	if _, _, err := ParseList(strings.NewReader("1.1.1.1\n2.2.2.2\n3.3.3.3\n"), 2); err == nil {
		t.Error("over the limit must fail")
	}
}

func event(raw string, sev models.Severity) models.ClassifiedEvent {
	return models.ClassifiedEvent{
		Event:      models.LogEvent{Raw: raw, Message: raw},
		AttackType: "Normal Activity", Severity: sev, IOCs: []string{}, Summary: "Looks routine.",
	}
}

func manualService(t *testing.T, sev models.Severity, values ...string) (*Service, Watchlist) {
	t.Helper()
	ctx := context.Background()
	svc, err := NewService(ctx, NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	w, err := svc.Create(ctx, "ana", NewWatchlist{Name: "Known bad", Source: SourceManual, Severity: sev})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) > 0 {
		if _, rejected, err := svc.AddIndicators(ctx, w.ID, "ana", "case 42", values); err != nil || len(rejected) > 0 {
			t.Fatalf("add: %v rejected %v", err, rejected)
		}
	}
	return svc, w
}

func TestEnrichMatchesEveryType(t *testing.T) {
	svc, w := manualService(t, models.SeverityP2,
		"203.0.113.9", "198.51.100.0/24", "evil.example", "2001:db8::/48",
		"d41d8cd98f00b204e9800998ecf8427e")
	cases := map[string]string{
		"sshd: Failed password for root from 203.0.113.9 port 22": "203.0.113.9",
		"nginx: GET / from 198.51.100.77":                         "198.51.100.77",
		"dns query cdn.www.evil.example A":                        "cdn.www.evil.example",
		"conn from 2001:db8::42 accepted":                         "2001:db8::42",
		"edr: hash D41D8CD98F00B204E9800998ECF8427E quarantined":  "d41d8cd98f00b204e9800998ecf8427e",
	}
	for raw, value := range cases {
		out, ok := svc.Enrich(event(raw, models.SeverityP5))
		if !ok {
			t.Errorf("%q: no match", raw)
			continue
		}
		if out.Severity != models.SeverityP2 || out.AttackType != "Known Malicious Indicator" ||
			!strings.HasPrefix(out.Summary, "Threat intel match: ") {
			t.Errorf("%q: verdict %+v", raw, out)
		}
		if len(out.Detections) != 1 || out.Detections[0].RuleID != "ioc:"+w.ID || out.Detections[0].Level != "high" {
			t.Errorf("%q: detections %+v", raw, out.Detections)
		}
		found := false
		for _, v := range out.IOCs {
			found = found || v == value
		}
		if !found {
			t.Errorf("%q: IOCs %v missing %s", raw, out.IOCs, value)
		}
	}

	for _, raw := range []string{
		"cron[1]: job at 10:30:00 ran for 203.0.113.10",
		"user visited notevil.example",
		"service sshd.service restarted",
	} {
		if _, ok := svc.Enrich(event(raw, models.SeverityP5)); ok {
			t.Errorf("%q must not match", raw)
		}
	}
	if got, _ := svc.Get(w.ID); got.Hits != 5 || got.LastHit == nil {
		t.Errorf("hits %d", got.Hits)
	}
}

func TestEnrichKeepsMoreSevereVerdict(t *testing.T) {
	svc, _ := manualService(t, models.SeverityP3, "203.0.113.9")
	ev := event("Shadow copies deleted by 203.0.113.9", models.SeverityP1)
	ev.AttackType = "Ransomware"
	ev.Detections = []models.Detection{{RuleID: "shadow", Title: "Shadow Copies Deleted", Level: "critical"}}
	out, ok := svc.Enrich(ev)
	if !ok || out.Severity != models.SeverityP1 || out.AttackType != "Ransomware" || out.Summary != "Looks routine." {
		t.Fatalf("a P3 watchlist must not downgrade or relabel a P1: %+v", out)
	}
	if len(out.Detections) != 2 || out.Detections[0].RuleID != "shadow" {
		t.Fatalf("most severe detection first: %+v", out.Detections)
	}
}

func TestDisableEditAndDelete(t *testing.T) {
	ctx := context.Background()
	svc, w := manualService(t, models.SeverityP2, "203.0.113.9")
	raw := "from 203.0.113.9"

	off := false
	if _, err := svc.Update(ctx, w.ID, Update{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.Enrich(event(raw, models.SeverityP5)); ok {
		t.Fatal("disabled list still matches")
	}
	on, p1 := true, models.SeverityP1
	if _, err := svc.Update(ctx, w.ID, Update{Enabled: &on, Severity: &p1}); err != nil {
		t.Fatal(err)
	}
	if out, ok := svc.Enrich(event(raw, models.SeverityP5)); !ok || out.Severity != models.SeverityP1 {
		t.Fatalf("re-enabled as P1: %+v", out)
	}
	bad := models.Severity("P5")
	if _, err := svc.Update(ctx, w.ID, Update{Severity: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("P5 severity: %v", err)
	}

	added, rejected, err := svc.AddIndicators(ctx, w.ID, "ana", "", []string{"203.0.113.9", "evil.example", "junk!"})
	if err != nil || len(added) != 1 || len(rejected) != 1 {
		t.Fatalf("add: %v %v %v", added, rejected, err)
	}
	if err := svc.RemoveIndicator(ctx, w.ID, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.Enrich(event(raw, models.SeverityP5)); ok {
		t.Fatal("removed indicator still matches")
	}
	if err := svc.RemoveIndicator(ctx, w.ID, "203.0.113.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}
	if res := svc.Lookup("www.evil.example"); len(res) != 1 || res[0].Indicator != "evil.example" {
		t.Fatalf("lookup: %+v", res)
	}
	if err := svc.Delete(ctx, w.ID); err != nil {
		t.Fatal(err)
	}
	if res := svc.Lookup("evil.example"); len(res) != 0 {
		t.Fatal("deleted list still matches")
	}
	if err := svc.Delete(ctx, w.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	svc, _ := manualService(t, models.SeverityP2)
	for name, n := range map[string]NewWatchlist{
		"no name":      {Source: SourceManual},
		"duplicate":    {Name: "known BAD", Source: SourceManual},
		"bad source":   {Name: "x", Source: "magic"},
		"feed no url":  {Name: "x", Source: SourceFeed},
		"feed ftp":     {Name: "x", Source: SourceFeed, URL: "ftp://feeds.example/list"},
		"fast refresh": {Name: "x", Source: SourceFeed, URL: "https://feeds.example/list", RefreshSeconds: 60},
		"severity P5":  {Name: "x", Source: SourceManual, Severity: models.SeverityP5},
	} {
		if _, err := svc.Create(ctx, "ada", n); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFeedRefresh(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(ctx, NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	body, fail := "203.0.113.9\nnot-an-ioc\n", false
	svc.fetch = func(context.Context, string) (io.ReadCloser, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("feed down")
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }

	w, err := svc.Create(ctx, "ada", NewWatchlist{Name: "Feodo", Source: SourceFeed, URL: "https://feeds.example/ip.txt", Severity: models.SeverityP1})
	if err != nil {
		t.Fatal(err)
	}
	if w.RefreshSeconds != 6*3600 {
		t.Errorf("default refresh %d", w.RefreshSeconds)
	}
	svc.refreshDue(ctx, true)
	got, _ := svc.Get(w.ID)
	if got.Count != 1 || got.Skipped != 1 || got.Error != "" || got.LastFetched == nil {
		t.Fatalf("after refresh: %+v", got)
	}
	if out, ok := svc.Enrich(event("from 203.0.113.9", models.SeverityP4)); !ok || out.Severity != models.SeverityP1 {
		t.Fatal("feed indicator not matched")
	}

	// Not due yet: no fetch. Then the feed fails: the old indicators stay.
	mu.Lock()
	body, fail = "198.51.100.1\n", true
	mu.Unlock()
	now = now.Add(time.Hour)
	svc.refreshDue(ctx, false)
	if got, _ := svc.Get(w.ID); got.Error != "" {
		t.Fatal("refreshed before it was due")
	}
	now = now.Add(6 * time.Hour)
	svc.refreshDue(ctx, false)
	got, _ = svc.Get(w.ID)
	if got.Error != "feed down" || got.Count != 1 {
		t.Fatalf("failed refresh: %+v", got)
	}
	if _, ok := svc.Enrich(event("from 203.0.113.9", models.SeverityP4)); !ok {
		t.Fatal("a failed refresh must keep the previous indicators")
	}
	if _, _, err := svc.AddIndicators(ctx, w.ID, "ana", "", []string{"1.2.3.4"}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("feeds are read-only: %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("p1-ransomware-c2.txt", "evil.example\n")
	write("tor-exits.list", "185.220.101.77\n")
	write("README.md", "203.0.113.9\n") // ignored
	svc, err := NewService(context.Background(), NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	n, err := svc.LoadDir(dir)
	if err != nil || n != 2 {
		t.Fatalf("loaded %d, %v", n, err)
	}
	lists := svc.List()
	if len(lists) != 2 || lists[0].Name != "ransomware-c2" || lists[0].Severity != models.SeverityP1 ||
		lists[1].Name != "tor-exits" || lists[1].Severity != models.SeverityP2 || lists[1].Source != SourceFile {
		t.Fatalf("lists: %+v", lists)
	}
	if _, ok := svc.Enrich(event("Accepted password for root from 185.220.101.77", models.SeverityP4)); !ok {
		t.Fatal("file indicator not matched")
	}
	if err := svc.Delete(context.Background(), lists[1].ID); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("file lists are read-only: %v", err)
	}
	if _, err := svc.LoadDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory must fail")
	}
}

func TestMatchBudget(t *testing.T) {
	svc, _ := manualService(t, models.SeverityP2, "203.0.113.250")
	var b strings.Builder
	for i := range 200 {
		b.WriteString("10.0.0.")
		b.WriteString(string(rune('0' + i%10)))
		b.WriteString(" ")
	}
	b.WriteString("203.0.113.250")
	// Distinct candidates beyond the budget are not inspected; this bounds
	// the cost of hostile log lines. Repeated values do not use it up.
	if _, ok := svc.Enrich(event(b.String(), models.SeverityP5)); !ok {
		t.Fatal("ten distinct values stay within the budget")
	}
}

func TestReloadManualListFromStore(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	svc, err := NewService(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := svc.Create(ctx, "ana", NewWatchlist{Name: "Case 42", Source: SourceManual})
	if _, _, err := svc.AddIndicators(ctx, w.ID, "ana", "phishing", []string{"evil.example"}); err != nil {
		t.Fatal(err)
	}
	again, err := NewService(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if res := again.Lookup("evil.example"); len(res) != 1 {
		t.Fatal("manual list not reloaded")
	}
	inds, total, _ := again.Indicators(w.ID, 10)
	if total != 1 || inds[0].Note != "phishing" || inds[0].AddedBy != "ana" {
		t.Fatalf("indicators: %+v", inds)
	}
}

func TestMatchBudgetBoundsHostileLines(t *testing.T) {
	svc, _ := manualService(t, models.SeverityP2, "203.0.113.250")
	var b strings.Builder
	for i := range maxCandidates + 10 {
		b.WriteString("10.0.")
		b.WriteString(strings.Repeat("1", 1+i/100))
		b.WriteString(".")
		b.WriteString(itoa(i % 100))
		b.WriteString(" ")
	}
	b.WriteString("203.0.113.250")
	if _, ok := svc.Enrich(event(b.String(), models.SeverityP5)); ok {
		t.Fatal("values past the per-event budget must not be inspected")
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
