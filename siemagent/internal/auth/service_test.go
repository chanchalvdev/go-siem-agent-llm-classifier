package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const pw = "correct horse battery"

// testService returns a fast (low bcrypt cost) service with a test clock.
func testService(t *testing.T, st Store) (*Service, *time.Time) {
	t.Helper()
	svc, err := NewService(context.Background(), st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc.cost = bcrypt.MinCost
	now := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	return svc, &now
}

func mustCreate(t *testing.T, svc *Service, name string, role Role) User {
	t.Helper()
	u, err := svc.CreateUser(context.Background(), "admin", NewUser{Username: name, Password: pw, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRolePermissions(t *testing.T) {
	cases := map[Role][3]bool{
		RoleViewer:  {true, false, false},
		RoleAnalyst: {true, true, false},
		RoleAdmin:   {true, true, true},
		Role("x"):   {false, false, false},
	}
	for role, want := range cases {
		got := [3]bool{role.Can(PermRead), role.Can(PermWrite), role.Can(PermAdmin)}
		if got != want {
			t.Errorf("%s: got %v want %v", role, got, want)
		}
	}
}

func TestBootstrapOnlyOnce(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	if svc.UsersEnabled() {
		t.Fatal("no users yet")
	}
	if created, err := svc.Bootstrap(ctx, "", ""); created || err != nil {
		t.Fatal("empty bootstrap must be a no-op")
	}
	if created, err := svc.Bootstrap(ctx, "Admin", pw); !created || err != nil {
		t.Fatalf("bootstrap: %v %v", created, err)
	}
	if !svc.UsersEnabled() {
		t.Fatal("users should now be enabled")
	}
	if created, _ := svc.Bootstrap(ctx, "other", pw); created {
		t.Fatal("bootstrap must not run once users exist")
	}
	u, err := svc.store.UserByName(ctx, "admin")
	if err != nil || u.Role != RoleAdmin {
		t.Fatalf("bootstrap admin: %+v %v", u, err)
	}
	if _, err := svc.Bootstrap(context.Background(), "x", "short"); err != nil {
		t.Fatal("bootstrap after users exist is a no-op even with a bad password")
	}
}

func TestCreateUserValidation(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	mustCreate(t, svc, "alice", RoleAnalyst)
	for name, in := range map[string]NewUser{
		"short password": {Username: "bob", Password: "short", Role: RoleViewer},
		"long password":  {Username: "bob", Password: strings.Repeat("x", 73), Role: RoleViewer},
		"bad role":       {Username: "bob", Password: pw, Role: "root"},
		"bad username":   {Username: "b ob", Password: pw, Role: RoleViewer},
		"taken":          {Username: "ALICE", Password: pw, Role: RoleViewer},
	} {
		if _, err := svc.CreateUser(ctx, "admin", in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestLoginAndSessions(t *testing.T) {
	svc, now := testService(t, NewMemory())
	ctx := context.Background()
	alice := mustCreate(t, svc, "alice", RoleAnalyst)

	if _, _, err := svc.Login(ctx, "alice", "wrong password!", "1.2.3.4"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := svc.Login(ctx, "nobody", pw, "1.2.3.4"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user must look the same as a wrong password: %v", err)
	}
	token, u, err := svc.Login(ctx, " Alice ", pw, "1.2.3.4")
	if err != nil || u.ID != alice.ID || len(token) != 64 {
		t.Fatalf("login: %v %+v", err, u)
	}
	got, err := svc.Authenticate(ctx, token)
	if err != nil || got.Username != "alice" || got.LastLoginAt == nil {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	if _, err := svc.Authenticate(ctx, token+"x"); err == nil {
		t.Fatal("tampered token accepted")
	}

	*now = now.Add(2 * time.Hour) // past the 1h TTL
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatal("expired session accepted")
	}

	token, _, _ = svc.Login(ctx, "alice", pw, "")
	if err := svc.Logout(ctx, token, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatal("session survived logout")
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	svc, now := testService(t, NewMemory())
	ctx := context.Background()
	mustCreate(t, svc, "alice", RoleAnalyst)
	for range maxFailures {
		_, _, _ = svc.Login(ctx, "alice", "wrong password!", "")
	}
	if _, _, err := svc.Login(ctx, "alice", pw, ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("even the right password is refused while locked: %v", err)
	}
	*now = now.Add(failureWindow + time.Second)
	if _, _, err := svc.Login(ctx, "alice", pw, ""); err != nil {
		t.Fatalf("lock should expire: %v", err)
	}
}

func TestDisableAndPasswordResetEndSessions(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	mustCreate(t, svc, "root-admin", RoleAdmin)
	bob := mustCreate(t, svc, "bob", RoleAnalyst)

	token, _, _ := svc.Login(ctx, "bob", pw, "")
	yes := true
	if _, err := svc.UpdateUser(ctx, "root-admin", bob.ID, UserUpdate{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatal("disabled user's session still valid")
	}
	if _, _, err := svc.Login(ctx, "bob", pw, ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("disabled user logged in: %v", err)
	}

	no := false
	newPW := "a brand new passphrase"
	if _, err := svc.UpdateUser(ctx, "root-admin", bob.ID, UserUpdate{Disabled: &no, Password: &newPW}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login(ctx, "bob", pw, ""); err == nil {
		t.Fatal("old password still works after reset")
	}
	if _, _, err := svc.Login(ctx, "bob", newPW, ""); err != nil {
		t.Fatalf("new password: %v", err)
	}
}

func TestLastAdminIsProtected(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	admin := mustCreate(t, svc, "admin", RoleAdmin)
	viewer := RoleViewer
	yes := true
	if _, err := svc.UpdateUser(ctx, "admin", admin.ID, UserUpdate{Role: &viewer}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("demoting the last admin: %v", err)
	}
	if _, err := svc.UpdateUser(ctx, "admin", admin.ID, UserUpdate{Disabled: &yes}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("disabling the last admin: %v", err)
	}
	second := mustCreate(t, svc, "second", RoleAdmin)
	if _, err := svc.UpdateUser(ctx, "second", admin.ID, UserUpdate{Role: &viewer}); err != nil {
		t.Fatalf("with another admin it is allowed: %v", err)
	}
	if _, err := svc.UpdateUser(ctx, "second", second.ID, UserUpdate{Disabled: &yes}); !errors.Is(err, ErrInvalid) {
		t.Fatal("second is now the last admin")
	}
	if _, err := svc.UpdateUser(ctx, "x", "usr_missing", UserUpdate{Role: &viewer}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	u := mustCreate(t, svc, "alice", RoleViewer)
	if err := svc.ChangePassword(ctx, u.ID, "wrong password!", "another long one"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, pw, "short"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("weak new password: %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, pw, "another long one"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login(ctx, "alice", "another long one", ""); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}

func TestAuditTrail(t *testing.T) {
	svc, _ := testService(t, NewMemory())
	ctx := context.Background()
	mustCreate(t, svc, "alice", RoleAnalyst)
	_, _, _ = svc.Login(ctx, "alice", "nope nope nope", "9.9.9.9")
	_, _, _ = svc.Login(ctx, "alice", pw, "9.9.9.9")

	all, _ := svc.ListAudit(ctx, AuditFilter{})
	var actions []string
	for _, e := range all {
		actions = append(actions, e.Actor+":"+e.Action)
	}
	if strings.Join(actions, ",") != "alice:login,alice:login.failed,admin:user.create" {
		t.Fatalf("audit (newest first) = %v", actions)
	}
	if mine, _ := svc.ListAudit(ctx, AuditFilter{Actor: "admin", Limit: 5}); len(mine) != 1 {
		t.Fatalf("actor filter: %+v", mine)
	}
}

func TestPasswordHashNeverSerialised(t *testing.T) {
	u := User{Username: "a", PasswordHash: []byte("secret-hash")}
	if strings.Contains(mustJSON(t, u), "secret-hash") {
		t.Fatal("password hash leaked into JSON")
	}
}

func TestMemoryStoreContract(t *testing.T) { testStoreContract(t, NewMemory()) }

// testStoreContract checks behaviour every Store shares. st must be empty.
func testStoreContract(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	u := User{ID: "usr_1", Username: "alice", Role: RoleAnalyst, CreatedAt: base, PasswordHash: []byte("h")}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	dup := u
	dup.ID = "usr_2"
	if err := st.CreateUser(ctx, dup); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate username: %v", err)
	}
	if n, _ := st.CountUsers(ctx); n != 1 {
		t.Fatalf("count = %d", n)
	}
	u.Role, u.Disabled, u.DisplayName = RoleAdmin, true, "Alice"
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchLogin(ctx, u.ID, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := st.UserByName(ctx, "alice")
	if err != nil || got.Role != RoleAdmin || !got.Disabled || got.DisplayName != "Alice" ||
		string(got.PasswordHash) != "h" || got.LastLoginAt == nil || !got.LastLoginAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("user = %+v %v", got, err)
	}
	if _, err := st.UserByID(ctx, "usr_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := st.UpdateUser(ctx, User{ID: "usr_nope"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if list, _ := st.ListUsers(ctx); len(list) != 1 {
		t.Fatalf("list = %+v", list)
	}

	for _, s := range []Session{
		{TokenHash: "t1", UserID: u.ID, CreatedAt: base, ExpiresAt: base.Add(time.Hour)},
		{TokenHash: "t2", UserID: u.ID, CreatedAt: base, ExpiresAt: base.Add(time.Hour)},
	} {
		if err := st.CreateSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := st.SessionUser(ctx, "t1", base.Add(time.Minute)); err != nil || got.ID != u.ID {
		t.Fatalf("session user: %+v %v", got, err)
	}
	if _, err := st.SessionUser(ctx, "t1", base.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
	if err := st.DeleteSession(ctx, "t2"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionUser(ctx, "t2", base); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted session still valid")
	}
	_ = st.CreateSession(ctx, Session{TokenHash: "t3", UserID: u.ID, CreatedAt: base, ExpiresAt: base.Add(time.Hour)})
	if err := st.DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionUser(ctx, "t3", base); !errors.Is(err, ErrNotFound) {
		t.Fatal("user sessions not deleted")
	}

	for i, a := range []string{"login", "user.update", "logout"} {
		if err := st.AddAudit(ctx, AuditEntry{At: base.Add(time.Duration(i) * time.Second), Actor: "alice", Action: a, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.AddAudit(ctx, AuditEntry{At: base.Add(time.Minute), Actor: "bob", Action: "login"})
	all, _ := st.ListAudit(ctx, AuditFilter{})
	if len(all) != 4 || all[0].Actor != "bob" || all[1].Action != "logout" || all[1].ID == 0 {
		t.Fatalf("audit newest first: %+v", all)
	}
	if mine, _ := st.ListAudit(ctx, AuditFilter{Actor: "alice", Limit: 2}); len(mine) != 2 || mine[0].Action != "logout" {
		t.Fatalf("filtered audit: %+v", mine)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
