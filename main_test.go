package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barrydeen/nspam-strfry/internal/policy"
	"github.com/barrydeen/nspam-strfry/internal/state"
	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

// stubScorer is a minimal Scorer that returns a fixed probability.
type stubScorer struct{ prob float64 }

func (s *stubScorer) Score(_ []*strfry.Event) float64 { return s.prob }

// TestRunLoop exercises the JSONL stdin/stdout loop end-to-end without the
// embedded model: a stub scorer is wired through a real state store, and
// multi-line input is piped through run().
func TestRunLoop(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	p := policy.New(policy.Config{}, st, &stubScorer{prob: 0.95}, nil)

	pubA := strings.Repeat("aa", 32) // will be blacklisted after first kind:1 write
	pubB := strings.Repeat("bb", 32) // kind:0 — passthrough

	in := strings.NewReader(strings.Join([]string{
		// bot on pubA
		`{"type":"new","sourceType":"IP4","event":{"id":"ev1","pubkey":"` + pubA + `","kind":1,"created_at":1,"tags":[],"content":"buy crypto now"}}`,
		// follow-up from pubA after blacklist → reject
		`{"type":"new","sourceType":"IP4","event":{"id":"ev2","pubkey":"` + pubA + `","kind":1,"created_at":2,"tags":[],"content":"still spam"}}`,
		// metadata from pubB — passthrough
		`{"type":"new","sourceType":"IP4","event":{"id":"ev3","pubkey":"` + pubB + `","kind":0,"created_at":3,"tags":[],"content":"{}"}}`,
		// stream replication of pubA — always accept regardless of blacklist
		`{"type":"new","sourceType":"Stream","event":{"id":"ev4","pubkey":"` + pubA + `","kind":1,"created_at":4,"tags":[],"content":"replicated"}}`,
		"",
	}, "\n"))

	var out bytes.Buffer
	if err := run(context.Background(), in, &out, p); err != nil && err.Error() != "EOF" {
		t.Fatalf("run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 response lines, got %d: %q", len(lines), out.String())
	}

	var resp strfry.Response
	for i, want := range []struct {
		id     string
		action strfry.Action
	}{
		{"ev1", strfry.ActionReject},
		{"ev2", strfry.ActionReject},
		{"ev3", strfry.ActionAccept},
		{"ev4", strfry.ActionAccept},
	} {
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatalf("line %d: decode %v (%q)", i, err, lines[i])
		}
		if resp.ID != want.id || resp.Action != want.action {
			t.Fatalf("line %d: want {id=%s action=%s} got %+v", i, want.id, want.action, resp)
		}
	}
}
