# nspam-strfry

A [strfry](https://github.com/hoytech/strfry) write-policy plugin that gates
incoming Nostr `kind:1` notes using the
[nspam classifier](https://github.com/YOUR_USERNAME/nspam-classifier). Each
pubkey moves through three states:

- **whitelisted** — auto-accept, skip the model forever
- **blacklisted** — auto-reject, skip the model forever
- **pending** — score every new note against the classifier; promote to
  whitelist or blacklist once confidence crosses a threshold, else keep the
  note and keep scoring

The classifier is compiled into the binary (pure Go port of the exported
nspam v0.9 model, bit-exact against the sklearn training pipeline via the
`parity_fixtures.jsonl` and `hash_fixtures.jsonl` test suites).

## Decision rules

Per kind:1 note from a live client (`sourceType ∈ {IP4,IP6}`):

| condition | action |
|---|---|
| `bot_prob ≥ 0.90` | blacklist the pubkey, reject this event |
| `bot_prob ≤ 0.25` | whitelist the pubkey, accept this event |
| pending pubkey has hit the 10-note cap (still uncertain) | whitelist, accept |
| otherwise | accept this event, remain pending, keep the note for later scoring |

Non-`kind:1` events and non-live sources (`Stream`, `Sync`, `Import`,
`Stored`) bypass the plugin unconditionally.

Thresholds and cap are tunable at runtime via flags.

## Build

```sh
go build -o nspam-strfry .
go build -o nspam-admin ./cmd/nspam-admin
```

The binary is fully self-contained — the model weights (~960 KB) and config
are embedded via `//go:embed`.

## Run under strfry

In your `strfry.conf`:

```conf
relay {
    writePolicy {
        plugin = "/usr/local/bin/nspam-strfry --db /var/lib/nspam-strfry/state.db"
    }
}
```

All log output goes to stderr (which ends up in strfry's log). Stdout is
reserved for the JSONL response protocol.

## Flags

```
--db               path to bbolt state file (default /var/lib/nspam-strfry/state.db)
--threshold-bot    bot_prob ≥ this → blacklist (default 0.90)
--threshold-real   bot_prob ≤ this → whitelist (default 0.25)
--cap              max pending notes per pubkey before forced decision (default 10)
```

## Admin CLI

`nspam-admin` opens the same bbolt file and lets you inspect or edit state:

```sh
nspam-admin --db /var/lib/nspam-strfry/state.db stats
nspam-admin --db /var/lib/nspam-strfry/state.db list blacklisted
nspam-admin --db /var/lib/nspam-strfry/state.db show <hexpubkey>
nspam-admin --db /var/lib/nspam-strfry/state.db set whitelist <hexpubkey>
nspam-admin --db /var/lib/nspam-strfry/state.db set blacklist <hexpubkey>
nspam-admin --db /var/lib/nspam-strfry/state.db clear <hexpubkey>
```

Only one process can hold the bbolt file open at a time, so stop the plugin
(or use a read-only inspection workflow) before running admin commands.

## Tests

```sh
go test ./...
```

- `internal/model` — hash parity (10 tokens) and full-pipeline parity (50
  bundles) against the exported fixtures. The parity test is the critical
  gate that proves the Go port matches sklearn.
- `internal/state` — bbolt roundtrip.
- `internal/policy` — all state-machine transitions.
- `./` (main) — full JSONL stdin/stdout loop with a stub scorer.

## Upgrading the model

When nspam ships a new model version:

1. Replace `internal/model/assets/weights.npz` and `internal/model/assets/config.json`.
2. Replace `internal/model/testdata/parity_fixtures.jsonl` and
   `internal/model/testdata/hash_fixtures.jsonl`.
3. Re-run `go test ./internal/model` — must pass before shipping.
4. If feature layout changes (`total_features`, `n_features_*`,
   `structural_names`, `group_feature_names`), re-review the port in
   `internal/model/ngram.go` and `internal/model/structural.go`.
5. Rebuild the binary; existing bbolt state is forward-compatible (state is
   pubkey-level, not model-version-level).
