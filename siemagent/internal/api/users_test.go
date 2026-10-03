package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/chverma/siemagent/internal/auth"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/incident"
)

const testPW = "correct horse battery"

// usersServer starts a server with accounts: one per role.
func usersServer(t *testing.T, keys ...string) (*httptest.Server, *auth.Service) {
	t.Helper()
	ctx := context.Background()
	users, err := auth.NewService(ctx, auth.NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	users.SetHashCost(bcrypt.MinCost)
	for name, role := range map[string]auth.Role{"ada": auth.RoleAdmin, "ana": auth.RoleAnalyst, "vic": auth.RoleViewer} {
		if _, err := users.CreateUser(ctx, "test", auth.NewUser{Username: name, Password: testPW, Role: role}); err != nil {
			t.Fatal(err)
		}
	}
	inc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	srv := New(config.Config{Port: "0", APIKeys: keys}, &mockClassifier{result: p2Result()}, WithUsers(users), WithIncidents(inc))
	ts := httptest.NewServer(srv.router)
	t.Cleanup(ts.Close)
	return ts, users
}

// client is a browser-like client with a cookie jar.
type client struct {
	t    *testing.T
	ts   *httptest.Server
	hc   *http.Client
	csrf bool
}

func newClient(t *testing.T, ts *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, ts: ts, hc: &http.Client{Jar: jar}, csrf: true}
}

func (c *client) do(method, path, body string, out any) int {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.csrf {
		req.Header.Set("X-Requested-With", "siemagent")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (c *client) login(user string) {
	c.t.Helper()
	if code := c.do(http.MethodPost, "/api/auth/login", `{"username":"`+user+`","password":"`+testPW+`"}`, nil); code != http.StatusOK {
		c.t.Fatalf("login %s: %d", user, code)
	}
}

func TestLoginRequiredOnceUsersExist(t *testing.T) {
	ts, _ := usersServer(t)
	c := newClient(t, ts)
	var e map[string]any
	if code := c.do(http.MethodGet, "/api/events", "", &e); code != http.StatusUnauthorized || e["login_required"] != true {
		t.Fatalf("anonymous: %d %v", code, e)
	}
	if code := c.do(http.MethodPost, "/api/auth/login", `{"username":"ana","password":"wrong password!!"}`, nil); code != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", code)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login", strings.NewReader(`{"username":"ana","password":"`+testPW+`"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || len(cookie.Value) != 64 {
		t.Fatalf("session cookie = %+v", cookie)
	}

	c.login("ana")
	var me map[string]any
	c.do(http.MethodGet, "/api/auth/me", "", &me)
	perms, _ := me["permissions"].(map[string]any)
	if me["username"] != "ana" || me["role"] != "analyst" || me["auth"] != "session" || perms["write"] != true || perms["admin"] != false {
		t.Fatalf("me = %v", me)
	}
	if code := c.do(http.MethodGet, "/api/events", "", nil); code != http.StatusOK {
		t.Fatalf("logged in: %d", code)
	}
	if code := c.do(http.MethodPost, "/api/auth/logout", "", nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	if code := c.do(http.MethodGet, "/api/events", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", code)
	}
}

func TestRolesEnforced(t *testing.T) {
	ts, _ := usersServer(t)
	type check struct {
		method, path, body string
	}
	read := check{http.MethodGet, "/api/incidents", ""}
	write := check{http.MethodPost, "/api/classify", `{"log":"sshd: Failed password for root from 203.0.113.7"}`}
	admin := check{http.MethodGet, "/api/users", ""}
	want := map[string][3]int{
		"vic": {http.StatusOK, http.StatusForbidden, http.StatusForbidden},
		"ana": {http.StatusOK, http.StatusOK, http.StatusForbidden},
		"ada": {http.StatusOK, http.StatusOK, http.StatusOK},
	}
	for user, codes := range want {
		c := newClient(t, ts)
		c.login(user)
		for i, ch := range []check{read, write, admin} {
			if got := c.do(ch.method, ch.path, ch.body, nil); got != codes[i] {
				t.Errorf("%s %s %s: got %d want %d", user, ch.method, ch.path, got, codes[i])
			}
		}
	}
}

func TestCSRFHeaderRequiredForCookieWrites(t *testing.T) {
	ts, _ := usersServer(t)
	c := newClient(t, ts)
	c.login("ana")
	c.csrf = false
	if code := c.do(http.MethodPost, "/api/classify", `{"log":"x"}`, nil); code != http.StatusForbidden {
		t.Fatalf("cookie write without header: %d", code)
	}
	if code := c.do(http.MethodGet, "/api/events", "", nil); code != http.StatusOK {
		t.Fatalf("reads don't need the header: %d", code)
	}
}

func TestAPIKeysStillWorkAlongsideUsers(t *testing.T) {
	ts, _ := usersServer(t, "svc-key")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/users", nil)
	req.Header.Set("X-API-Key", "svc-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API keys act as admin service accounts: %d", resp.StatusCode)
	}
}

func TestUserAdministrationAndAudit(t *testing.T) {
	ts, _ := usersServer(t)
	admin := newClient(t, ts)
	admin.login("ada")

	var created auth.User
	if code := admin.do(http.MethodPost, "/api/users", `{"username":"Neo","password":"`+testPW+`","role":"analyst"}`, &created); code != http.StatusCreated || created.Username != "neo" {
		t.Fatalf("create: %d %+v", code, created)
	}
	var e map[string]string
	if code := admin.do(http.MethodPost, "/api/users", `{"username":"xy","password":"short","role":"viewer"}`, &e); code != http.StatusBadRequest || !strings.Contains(e["error"], "at least 12") {
		t.Fatalf("weak password: %d %v", code, e)
	}

	neo := newClient(t, ts)
	neo.login("neo")
	if code := admin.do(http.MethodPatch, "/api/users/"+created.ID, `{"role":"viewer"}`, nil); code != http.StatusOK {
		t.Fatalf("demote: %d", code)
	}
	// Role changes apply to existing sessions immediately.
	if code := neo.do(http.MethodPost, "/api/classify", `{"log":"x"}`, nil); code != http.StatusForbidden {
		t.Fatalf("demoted user can still write: %d", code)
	}
	if code := admin.do(http.MethodPatch, "/api/users/"+created.ID, `{"disabled":true}`, nil); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if code := neo.do(http.MethodGet, "/api/events", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("disabled user still has a session: %d", code)
	}

	var users []map[string]any
	admin.do(http.MethodGet, "/api/users", "", &users)
	for _, u := range users {
		if _, leaked := u["password_hash"]; leaked {
			t.Fatal("password hash in API response")
		}
	}

	var log []auth.AuditEntry
	admin.do(http.MethodGet, "/api/audit?limit=50", "", &log)
	var actions []string
	for _, a := range log {
		actions = append(actions, a.Actor+" "+a.Action)
	}
	joined := strings.Join(actions, "|")
	for _, want := range []string{
		"ada PATCH /api/users/{id}", "ada user.update", "ada POST /api/users", "neo login", "ada login",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit missing %q in %v", want, actions)
		}
	}
}

func TestPasswordChangeOverHTTP(t *testing.T) {
	ts, _ := usersServer(t)
	c := newClient(t, ts)
	c.login("vic")
	body := `{"current_password":"` + testPW + `","new_password":"viewer's new passphrase"}`
	if code := c.do(http.MethodPost, "/api/auth/password", body, nil); code != http.StatusNoContent {
		t.Fatalf("change password: %d", code)
	}
	c2 := newClient(t, ts)
	if code := c2.do(http.MethodPost, "/api/auth/login", `{"username":"vic","password":"viewer's new passphrase"}`, nil); code != http.StatusOK {
		t.Fatalf("login with new password: %d", code)
	}
}

func TestOpenModeWithoutUsersOrKeys(t *testing.T) {
	users, _ := auth.NewService(context.Background(), auth.NewMemory(), 0)
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult}, WithUsers(users))
	ts := httptest.NewServer(srv.router)
	defer ts.Close()
	var me map[string]any
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/auth/me", "", &me); code != http.StatusOK || me["auth"] != "open" || me["role"] != "admin" {
		t.Fatalf("open mode: %d %v", code, me)
	}
}
