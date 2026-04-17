// Package policy orchestrates the model and state store to produce a verdict
// for each incoming strfry event.
package policy

import (
	"github.com/barrydeen/nspam-strfry/internal/model"
	"github.com/barrydeen/nspam-strfry/internal/state"
	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

// Defaults match the user's decision rules.
const (
	DefaultBotThreshold  = 0.90 // bot_prob ≥ -> blacklist
	DefaultRealThreshold = 0.25 // bot_prob ≤ -> whitelist (i.e. real confidence ≥ 0.75)
	DefaultCap           = 10   // max pending notes before forced decision
)

// Config lets operators tune thresholds via CLI flags.
type Config struct {
	BotThreshold  float64
	RealThreshold float64
	Cap           int
}

func (c Config) withDefaults() Config {
	if c.BotThreshold == 0 {
		c.BotThreshold = DefaultBotThreshold
	}
	if c.RealThreshold == 0 {
		c.RealThreshold = DefaultRealThreshold
	}
	if c.Cap == 0 {
		c.Cap = DefaultCap
	}
	return c
}

// Scorer is the subset of *model.Model that policy needs. Lets tests swap in
// a stub scorer without pulling the embedded weights.
type Scorer interface {
	Score(bundle []*strfry.Event) float64
}

// Policy is the decision engine.
type Policy struct {
	cfg    Config
	store  *state.Store
	scorer Scorer
	// logFn receives one line per non-passthrough decision, written to stderr.
	logFn func(format string, args ...any)
}

// New constructs a Policy. logFn may be nil (in which case logging is dropped).
func New(cfg Config, store *state.Store, scorer Scorer, logFn func(string, ...any)) *Policy {
	if logFn == nil {
		logFn = func(string, ...any) {}
	}
	return &Policy{
		cfg:    cfg.withDefaults(),
		store:  store,
		scorer: scorer,
		logFn:  logFn,
	}
}

// Decide returns the strfry response for the given message.
func (p *Policy) Decide(msg *strfry.Message) strfry.Response {
	if msg == nil || msg.Event == nil {
		return strfry.Response{Action: strfry.ActionReject, Msg: "internal: empty event"}
	}
	ev := msg.Event
	resp := strfry.Response{ID: ev.ID}

	// Only gate kind:1. Everything else passes through untouched — the model
	// is trained only on text notes (see export/v0.9/model_card.md).
	if ev.Kind != 1 {
		resp.Action = strfry.ActionAccept
		return resp
	}

	// Replication / backfill traffic bypasses scoring — we only want to
	// evaluate live client writes. Matches the example plugin's pattern.
	if !msg.SourceType.IsLiveClient() {
		resp.Action = strfry.ActionAccept
		return resp
	}

	author, _, err := p.store.Get(ev.Pubkey)
	if err != nil {
		// Invalid pubkey or DB error — safer to accept than to reject: a
		// broken plugin should not break the relay. Log loudly.
		p.logFn("store.Get(%s): %v — accepting", ev.Pubkey, err)
		resp.Action = strfry.ActionAccept
		return resp
	}

	switch author.State {
	case state.Whitelisted:
		resp.Action = strfry.ActionAccept
		return resp
	case state.Blacklisted:
		resp.Action = strfry.ActionReject
		resp.Msg = "author blacklisted by nspam"
		return resp
	}

	// Pending path: build the scoring bundle (existing notes + this event),
	// capped to the last cfg.Cap notes.
	bundle := make([]*strfry.Event, 0, len(author.Notes)+1)
	for i := range author.Notes {
		n := &author.Notes[i]
		bundle = append(bundle, &strfry.Event{
			ID:        n.ID,
			Pubkey:    ev.Pubkey,
			Content:   n.Content,
			Tags:      n.Tags,
			CreatedAt: n.CreatedAt,
			Kind:      1,
		})
	}
	bundle = append(bundle, ev)
	if len(bundle) > p.cfg.Cap {
		bundle = bundle[len(bundle)-p.cfg.Cap:]
	}

	prob := p.scorer.Score(bundle)

	switch {
	case prob >= p.cfg.BotThreshold:
		if err := p.store.SetBlacklist(ev.Pubkey); err != nil {
			p.logFn("SetBlacklist(%s): %v", ev.Pubkey, err)
		}
		p.logFn("blacklist pubkey=%s notes=%d prob=%.4f", ev.Pubkey, len(bundle), prob)
		resp.Action = strfry.ActionReject
		resp.Msg = "author flagged as bot by nspam"
		return resp

	case prob <= p.cfg.RealThreshold:
		if err := p.store.SetWhitelist(ev.Pubkey); err != nil {
			p.logFn("SetWhitelist(%s): %v", ev.Pubkey, err)
		}
		p.logFn("whitelist pubkey=%s notes=%d prob=%.4f reason=confident-real", ev.Pubkey, len(bundle), prob)
		resp.Action = strfry.ActionAccept
		return resp

	case len(bundle) >= p.cfg.Cap:
		// Cap reached while still uncertain — lean permissive, whitelist.
		if err := p.store.SetWhitelist(ev.Pubkey); err != nil {
			p.logFn("SetWhitelist(%s): %v", ev.Pubkey, err)
		}
		p.logFn("whitelist pubkey=%s notes=%d prob=%.4f reason=cap-reached", ev.Pubkey, len(bundle), prob)
		resp.Action = strfry.ActionAccept
		return resp

	default:
		// Still pending — stash the note, accept it.
		newAuthor := state.Author{
			State: state.Pending,
			Notes: append(author.Notes, state.NewStoredNote(ev)),
		}
		if len(newAuthor.Notes) > p.cfg.Cap {
			newAuthor.Notes = newAuthor.Notes[len(newAuthor.Notes)-p.cfg.Cap:]
		}
		if err := p.store.Put(ev.Pubkey, newAuthor); err != nil {
			p.logFn("Put(%s): %v", ev.Pubkey, err)
		}
		p.logFn("pending pubkey=%s notes=%d prob=%.4f", ev.Pubkey, len(newAuthor.Notes), prob)
		resp.Action = strfry.ActionAccept
		return resp
	}
}

// Compile-time check that *model.Model implements Scorer.
var _ Scorer = (*model.Model)(nil)
