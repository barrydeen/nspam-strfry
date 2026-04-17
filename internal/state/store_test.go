package state

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pub := strings.Repeat("ab", 32) // 64 hex chars

	// Unknown pubkey -> pending/zero, found=false.
	a, found, err := s.Get(pub)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected not found for fresh pubkey")
	}
	if a.State != Pending {
		t.Fatalf("zero-value state = %v, want Pending", a.State)
	}

	// Append two notes as pending.
	a.Notes = append(a.Notes, StoredNote{ID: "n1", Content: "hello"})
	a.Notes = append(a.Notes, StoredNote{ID: "n2", Content: "world"})
	if err := s.Put(pub, a); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !found || len(got.Notes) != 2 {
		t.Fatalf("roundtrip failed: found=%v notes=%d", found, len(got.Notes))
	}

	// Promote to whitelist.
	if err := s.SetWhitelist(pub); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.Get(pub)
	if got.State != Whitelisted || len(got.Notes) != 0 {
		t.Fatalf("after whitelist: state=%v notes=%d", got.State, len(got.Notes))
	}

	// Iterate.
	var seen int
	s.ForEach(func(r ListRecord) error {
		if r.Pubkey == pub && r.Author.State == Whitelisted {
			seen++
		}
		return nil
	})
	if seen != 1 {
		t.Fatalf("ForEach saw %d matches, want 1", seen)
	}
}

func TestInvalidPubkeyRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, _, err := s.Get("zz"); err == nil {
		t.Fatal("expected error for short pubkey")
	}
	if err := s.Put("zz", Author{}); err == nil {
		t.Fatal("expected error for short pubkey")
	}
}
