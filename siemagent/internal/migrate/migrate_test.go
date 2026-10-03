package migrate

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 || all[0].Version != 1 || all[0].Name != "baseline" {
		t.Fatalf("first migration must be 0001_baseline, got %+v", all)
	}
	for i, m := range all {
		if i > 0 && m.Version <= all[i-1].Version {
			t.Errorf("migrations out of order: %d after %d", m.Version, all[i-1].Version)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("%04d_%s is empty", m.Version, m.Name)
		}
		if len(m.Checksum) != 64 {
			t.Errorf("%04d_%s checksum %q", m.Version, m.Name, m.Checksum)
		}
	}
}

// The baseline must apply cleanly to databases created by the old start-up
// schema files, so every statement in it has to be idempotent.
func TestBaselineIsIdempotent(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(all[0].SQL, "\n") {
		l := strings.TrimSpace(strings.ToUpper(line))
		if strings.HasPrefix(l, "CREATE ") && !strings.Contains(l, "IF NOT EXISTS") {
			t.Errorf("baseline statement is not idempotent: %s", line)
		}
	}
}

func TestLoadSortsAndValidatesNames(t *testing.T) {
	fsys := fstest.MapFS{
		"m/0002_second.sql": {Data: []byte("SELECT 2;")},
		"m/0001_first.sql":  {Data: []byte("SELECT 1;")},
	}
	got, err := load(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "first" || got[1].Name != "second" {
		t.Fatalf("got %+v", got)
	}

	for name, file := range map[string]string{
		"bad name":      "m/add_users.sql",
		"version zero":  "m/0000_zero.sql",
		"upper case":    "m/0003_AddUsers.sql",
		"short version": "m/12_short.sql",
		"wrong suffix":  "m/0003_users.txt",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(fstest.MapFS{file: {Data: []byte("SELECT 1;")}}, "m"); err == nil {
				t.Errorf("%s: want error", file)
			}
		})
	}

	dup := fstest.MapFS{
		"m/0001_a.sql": {Data: []byte("SELECT 1;")},
		"m/0001_b.sql": {Data: []byte("SELECT 1;")},
	}
	if _, err := load(dup, "m"); err == nil || !strings.Contains(err.Error(), "share version") {
		t.Errorf("duplicate versions: got %v", err)
	}
}

func TestPending(t *testing.T) {
	all := []Migration{
		{Version: 1, Name: "baseline", Checksum: "aaa"},
		{Version: 2, Name: "retention", Checksum: "bbb"},
		{Version: 3, Name: "suppression", Checksum: "ccc"},
	}

	t.Run("fresh database runs everything", func(t *testing.T) {
		got, err := Pending(all, nil)
		if err != nil || len(got) != 3 {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("only the missing ones, in order", func(t *testing.T) {
		got, err := Pending(all, []Applied{{Version: 1, Name: "baseline", Checksum: "aaa"}})
		if err != nil || len(got) != 2 || got[0].Version != 2 || got[1].Version != 3 {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("up to date", func(t *testing.T) {
		got, err := Pending(all, []Applied{
			{Version: 1, Checksum: "aaa"}, {Version: 2, Checksum: "bbb"}, {Version: 3, Checksum: "ccc"},
		})
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("edited migration is refused", func(t *testing.T) {
		_, err := Pending(all, []Applied{{Version: 1, Name: "baseline", Checksum: "changed"}})
		if err == nil || !strings.Contains(err.Error(), "changed after it was applied") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("newer database is refused", func(t *testing.T) {
		_, err := Pending(all, []Applied{{Version: 9, Name: "future", Checksum: "zzz"}})
		if !errors.Is(err, ErrNewerDatabase) {
			t.Fatalf("got %v", err)
		}
	})
}
