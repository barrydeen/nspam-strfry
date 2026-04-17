package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/barrydeen/nspam-strfry/internal/state"
	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

type stubScorer struct {
	prob float64
}

func (s *stubScorer) Score([]*strfry.Event) float64 { return s.prob }

func newTestPolicy(t *testing.T, scoreProb float64) (*Policy, *state.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Config{}, st, &stubScorer{prob: scoreProb}, nil), st
}

func evt(content string) *strfry.Event {
	return &strfry.Event{
		ID:      "deadbeef",
		Pubkey:  strings.Repeat("aa", 32),
		Kind:    1,
		Content: content,
	}
}

func msg(src strfry.SourceType, ev *strfry.Event) *strfry.Message {
	return &strfry.Message{Type: "new", SourceType: src, Event: ev}
}

func TestNonKind1Accepts(t *testing.T) {
	p, _ := newTestPolicy(t, 0.99) // would-be blacklist score
	e := evt("hi")
	e.Kind = 0 // metadata
	r := p.Decide(msg(strfry.SourceIP4, e))
	if r.Action != strfry.ActionAccept {
		t.Fatalf("kind:0 should pass through, got %v", r)
	}
}

func TestNonLiveSourceAccepts(t *testing.T) {
	p, _ := newTestPolicy(t, 0.99)
	for _, src := range []strfry.SourceType{strfry.SourceStream, strfry.SourceSync, strfry.SourceImport, strfry.SourceStored} {
		r := p.Decide(msg(src, evt("hi")))
		if r.Action != strfry.ActionAccept {
			t.Fatalf("source %s should pass through, got %v", src, r)
		}
	}
}

func TestFirstNoteConfidentReal(t *testing.T) {
	p, st := newTestPolicy(t, 0.10) // confident real
	r := p.Decide(msg(strfry.SourceIP4, evt("hello world")))
	if r.Action != strfry.ActionAccept {
		t.Fatalf("want accept, got %v", r)
	}
	a, _, _ := st.Get(strings.Repeat("aa", 32))
	if a.State != state.Whitelisted {
		t.Fatalf("want whitelisted, got %v", a.State)
	}
}

func TestFirstNoteConfidentBot(t *testing.T) {
	p, st := newTestPolicy(t, 0.95)
	r := p.Decide(msg(strfry.SourceIP4, evt("buy crypto now")))
	if r.Action != strfry.ActionReject || r.Msg == "" {
		t.Fatalf("want reject with msg, got %v", r)
	}
	a, _, _ := st.Get(strings.Repeat("aa", 32))
	if a.State != state.Blacklisted {
		t.Fatalf("want blacklisted, got %v", a.State)
	}
}

func TestUncertainAccumulates(t *testing.T) {
	p, st := newTestPolicy(t, 0.50) // ambiguous
	for i := 0; i < 5; i++ {
		r := p.Decide(msg(strfry.SourceIP4, evt("meh")))
		if r.Action != strfry.ActionAccept {
			t.Fatalf("iter %d: want accept, got %v", i, r)
		}
	}
	a, _, _ := st.Get(strings.Repeat("aa", 32))
	if a.State != state.Pending || len(a.Notes) != 5 {
		t.Fatalf("after 5 pending: state=%v notes=%d", a.State, len(a.Notes))
	}
}

func TestCapReachedWhitelist(t *testing.T) {
	p, st := newTestPolicy(t, 0.50)
	for i := 0; i < DefaultCap-1; i++ {
		p.Decide(msg(strfry.SourceIP4, evt("meh")))
	}
	// 10th event: should flip to whitelist.
	r := p.Decide(msg(strfry.SourceIP4, evt("meh")))
	if r.Action != strfry.ActionAccept {
		t.Fatalf("want accept at cap, got %v", r)
	}
	a, _, _ := st.Get(strings.Repeat("aa", 32))
	if a.State != state.Whitelisted {
		t.Fatalf("want whitelisted at cap, got %v", a.State)
	}
}

func TestBlacklistedAutoRejects(t *testing.T) {
	p, st := newTestPolicy(t, 0.01) // even a confident-real score shouldn't matter
	st.SetBlacklist(strings.Repeat("aa", 32))
	r := p.Decide(msg(strfry.SourceIP4, evt("whatever")))
	if r.Action != strfry.ActionReject {
		t.Fatalf("blacklisted should reject, got %v", r)
	}
}

func TestWhitelistedAutoAccepts(t *testing.T) {
	p, st := newTestPolicy(t, 0.99) // even a confident-bot score shouldn't matter
	st.SetWhitelist(strings.Repeat("aa", 32))
	r := p.Decide(msg(strfry.SourceIP4, evt("whatever")))
	if r.Action != strfry.ActionAccept {
		t.Fatalf("whitelisted should accept, got %v", r)
	}
}

func TestPendingToBotAfterSeveralNotes(t *testing.T) {
	// First 3 notes ambiguous, 4th pushes confidence over threshold.
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	score := &stubScorer{prob: 0.5}
	p := New(Config{}, st, score, nil)

	for i := 0; i < 3; i++ {
		p.Decide(msg(strfry.SourceIP4, evt("whatever")))
	}
	score.prob = 0.95
	r := p.Decide(msg(strfry.SourceIP4, evt("buy crypto now")))
	if r.Action != strfry.ActionReject {
		t.Fatalf("want reject on late bot detection, got %v", r)
	}
	a, _, _ := st.Get(strings.Repeat("aa", 32))
	if a.State != state.Blacklisted {
		t.Fatalf("want blacklisted, got %v", a.State)
	}
}
