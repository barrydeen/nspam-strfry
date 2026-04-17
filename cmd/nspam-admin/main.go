// Command nspam-admin inspects and manually edits the nspam-strfry state DB.
//
// Usage:
//
//	nspam-admin --db PATH <subcommand> [args]
//
// Subcommands:
//
//	list [pending|whitelisted|blacklisted]   list pubkeys (optionally filtered)
//	show <pubkey>                            show full record (including pending notes)
//	set whitelist <pubkey>                   force-whitelist
//	set blacklist <pubkey>                   force-blacklist
//	clear <pubkey>                           remove from store (resets to pending-unseen)
//	stats                                    counts by state
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/barrydeen/nspam-strfry/internal/state"
)

func main() {
	dbPath := flag.String("db", "/var/lib/nspam-strfry/state.db", "path to bbolt state file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: nspam-admin --db PATH <subcommand> [args]")
		fmt.Fprintln(os.Stderr, "subcommands: list, show, set, clear, stats")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// Read-only commands use a shared lock so they work while the plugin is running.
	// Write commands (set, clear) need an exclusive lock.
	needsWrite := args[0] == "set" || args[0] == "clear"

	var st *state.Store
	var err error
	if needsWrite {
		st, err = state.Open(*dbPath)
	} else {
		st, err = state.OpenReadOnly(*dbPath)
	}
	if err != nil {
		fatalf("open %s: %v", *dbPath, err)
	}
	defer st.Close()

	switch args[0] {
	case "list":
		var filter string
		if len(args) > 1 {
			filter = args[1]
		}
		cmdList(st, filter)
	case "show":
		if len(args) < 2 {
			fatalf("show requires a pubkey")
		}
		cmdShow(st, args[1])
	case "set":
		if len(args) < 3 {
			fatalf("set requires: set <whitelist|blacklist> <pubkey>")
		}
		cmdSet(st, args[1], args[2])
	case "clear":
		if len(args) < 2 {
			fatalf("clear requires a pubkey")
		}
		if err := st.Delete(args[1]); err != nil {
			fatalf("clear: %v", err)
		}
		fmt.Println("ok")
	case "stats":
		cmdStats(st)
	default:
		fatalf("unknown subcommand %q", args[0])
	}
}

func cmdList(st *state.Store, filter string) {
	want := state.State(255)
	switch filter {
	case "":
	case "pending":
		want = state.Pending
	case "whitelisted":
		want = state.Whitelisted
	case "blacklisted":
		want = state.Blacklisted
	default:
		fatalf("unknown filter %q", filter)
	}
	err := st.ForEach(func(r state.ListRecord) error {
		if want != 255 && r.Author.State != want {
			return nil
		}
		fmt.Printf("%s\t%s\tnotes=%d\tupdated=%d\n",
			r.Pubkey, r.Author.State, len(r.Author.Notes), r.Author.UpdatedAt)
		return nil
	})
	if err != nil {
		fatalf("list: %v", err)
	}
}

func cmdShow(st *state.Store, pub string) {
	a, found, err := st.Get(pub)
	if err != nil {
		fatalf("show: %v", err)
	}
	if !found {
		fmt.Println("(not found — effectively pending with no notes seen yet)")
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(struct {
		Pubkey string       `json:"pubkey"`
		State  string       `json:"state"`
		NNotes int          `json:"n_notes"`
		Author state.Author `json:"author"`
	}{pub, a.State.String(), len(a.Notes), a})
}

func cmdSet(st *state.Store, which, pub string) {
	switch which {
	case "whitelist":
		if err := st.SetWhitelist(pub); err != nil {
			fatalf("set whitelist: %v", err)
		}
	case "blacklist":
		if err := st.SetBlacklist(pub); err != nil {
			fatalf("set blacklist: %v", err)
		}
	default:
		fatalf("set: expected whitelist|blacklist, got %q", which)
	}
	fmt.Println("ok")
}

func cmdStats(st *state.Store) {
	counts := map[state.State]int{}
	totalNotes := 0
	err := st.ForEach(func(r state.ListRecord) error {
		counts[r.Author.State]++
		totalNotes += len(r.Author.Notes)
		return nil
	})
	if err != nil {
		fatalf("stats: %v", err)
	}
	total := counts[state.Pending] + counts[state.Whitelisted] + counts[state.Blacklisted]
	fmt.Printf("authors total=%d  whitelisted=%d  blacklisted=%d  pending=%d  pending_notes=%d\n",
		total, counts[state.Whitelisted], counts[state.Blacklisted], counts[state.Pending], totalNotes)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
