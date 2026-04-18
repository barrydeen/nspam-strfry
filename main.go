// Command nspam-strfry is a strfry write-policy plugin that classifies Nostr
// kind:1 notes using the embedded nspam model and maintains per-pubkey state.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/barrydeen/nspam-strfry/internal/model"
	"github.com/barrydeen/nspam-strfry/internal/policy"
	"github.com/barrydeen/nspam-strfry/internal/state"
	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

func main() {
	var (
		dbPath        = flag.String("db", "/var/lib/nspam-strfry/state.db", "path to bbolt state file")
		botThreshold  = flag.Float64("threshold-bot", policy.DefaultBotThreshold, "bot_prob ≥ this → blacklist")
		realThreshold = flag.Float64("threshold-real", policy.DefaultRealThreshold, "bot_prob ≤ this → whitelist")
		cap_              = flag.Int("cap", policy.DefaultCap, "max pending notes per pubkey before forced decision")
		minNotesBlacklist = flag.Int("min-notes-blacklist", policy.DefaultMinNotesBlacklist, "minimum notes before blacklisting")
		verbose           = flag.Bool("v", false, "log every decision (otherwise only state transitions)")
	)
	flag.Parse()

	log.SetOutput(os.Stderr)
	log.SetPrefix("[nspam-strfry] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	m, err := model.Load()
	if err != nil {
		log.Fatalf("load model: %v", err)
	}
	log.Printf("model loaded (total_features=%d)", m.Config.TotalFeatures)

	st, err := state.Open(*dbPath)
	if err != nil {
		log.Fatalf("open state db %q: %v", *dbPath, err)
	}
	defer st.Close()
	log.Printf("state db opened: %s", *dbPath)

	// Install a signal handler so we flush the bbolt DB on SIGTERM / SIGINT.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %s — closing", sig)
		cancel()
		// best-effort close, then exit.
		_ = st.Close()
		os.Exit(0)
	}()

	logFn := log.Printf
	_ = verbose // wired through below — we currently always log transitions.

	p := policy.New(policy.Config{
		BotThreshold:      *botThreshold,
		RealThreshold:     *realThreshold,
		Cap:               *cap_,
		MinNotesBlacklist: *minNotesBlacklist,
	}, st, m, logFn)

	if err := run(ctx, os.Stdin, os.Stdout, p); err != nil && err != io.EOF {
		log.Printf("loop exited: %v", err)
	}
}

// run reads one JSON message per line from in and writes one JSON response
// per line to out. It never returns success — strfry keeps the plugin alive
// for the lifetime of the relay.
func run(ctx context.Context, in io.Reader, out io.Writer, p Decider) error {
	// bufio.Scanner with a generous buffer: nostr events can include large
	// base64-encoded content (images, long text). 4 MB is well above any
	// realistic event size.
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 256*1024), 4*1024*1024)

	enc := json.NewEncoder(out)
	// json.Encoder writes a trailing newline after each Encode call, which
	// is exactly what strfry expects.

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var msg strfry.Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("decode: %v (line=%q)", err, truncate(line, 200))
			// Can't echo the event ID if decode failed. Skip — strfry will
			// time-out the pending request and reject on its own side.
			continue
		}
		resp := p.Decide(&msg)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

// Decider is the minimal interface the plugin loop needs; keeps main.go
// decoupled from the concrete policy.Policy type.
type Decider interface {
	Decide(*strfry.Message) strfry.Response
}

// compile-time assertion — keeps the above interface aligned with policy.Policy.
var _ Decider = (*policy.Policy)(nil)

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
