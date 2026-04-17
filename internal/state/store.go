// Package state persists per-pubkey plugin state in a SQLite database.
package state

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/barrydeen/nspam-strfry/internal/strfry"
	_ "github.com/mattn/go-sqlite3"
)

type State uint8

const (
	Pending     State = 0
	Whitelisted State = 1
	Blacklisted State = 2
)

func (s State) String() string {
	switch s {
	case Whitelisted:
		return "whitelisted"
	case Blacklisted:
		return "blacklisted"
	default:
		return "pending"
	}
}

// StoredNote is the per-note data we keep for scoring a pending author. We
// only need content, tags, and created_at for the featurizer. ID is kept
// purely for debugging via nspam-admin.
type StoredNote struct {
	ID        string     `json:"id"`
	Content   string     `json:"content"`
	Tags      [][]string `json:"tags"`
	CreatedAt int64      `json:"created_at"`
}

func NewStoredNote(ev *strfry.Event) StoredNote {
	return StoredNote{
		ID:        ev.ID,
		Content:   ev.Content,
		Tags:      ev.Tags,
		CreatedAt: ev.CreatedAt,
	}
}

// Author is the per-pubkey record stored in the authors table.
type Author struct {
	State     State        `json:"state"`
	UpdatedAt int64        `json:"updated_at"` // unix seconds
	Notes     []StoredNote `json:"notes,omitempty"`
}

// Store wraps a SQLite database.
type Store struct {
	db *sql.DB
}

func openDB(path string, params string) (*Store, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000"
	if params != "" {
		dsn += "&" + params
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS authors (
		pubkey TEXT PRIMARY KEY,
		state  INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0,
		notes  TEXT NOT NULL DEFAULT '[]'
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Open opens (or creates) the SQLite database at path with WAL mode.
func Open(path string) (*Store, error) {
	return openDB(path, "")
}

// OpenReadOnly opens the SQLite database in read-only mode.
func OpenReadOnly(path string) (*Store, error) {
	return openDB(path, "mode=ro")
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// validatePubkey checks that a hex pubkey is 64 hex characters.
func validatePubkey(hexPub string) error {
	if len(hexPub) != 64 {
		return fmt.Errorf("invalid pubkey %q", hexPub)
	}
	for _, c := range hexPub {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("invalid pubkey %q", hexPub)
		}
	}
	return nil
}

// Get returns the stored author record. When the pubkey is unknown it
// returns a zero-value Author (state=Pending, no notes) and found=false.
func (s *Store) Get(hexPub string) (Author, bool, error) {
	if err := validatePubkey(hexPub); err != nil {
		return Author{}, false, err
	}
	var a Author
	var notesJSON string
	err := s.db.QueryRow(
		`SELECT state, updated_at, notes FROM authors WHERE pubkey = ?`, hexPub,
	).Scan(&a.State, &a.UpdatedAt, &notesJSON)
	if err == sql.ErrNoRows {
		return Author{}, false, nil
	}
	if err != nil {
		return Author{}, false, err
	}
	if err := json.Unmarshal([]byte(notesJSON), &a.Notes); err != nil {
		return Author{}, false, fmt.Errorf("unmarshal notes: %w", err)
	}
	return a, true, nil
}

// Put writes the full author record for a pubkey. Used by policy after it
// decides on the next state, and by the admin CLI.
func (s *Store) Put(hexPub string, a Author) error {
	if err := validatePubkey(hexPub); err != nil {
		return err
	}
	a.UpdatedAt = time.Now().Unix()
	notesJSON, err := json.Marshal(a.Notes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO authors (pubkey, state, updated_at, notes) VALUES (?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at, notes=excluded.notes`,
		hexPub, a.State, a.UpdatedAt, string(notesJSON),
	)
	return err
}

// Delete removes the pubkey from the store.
func (s *Store) Delete(hexPub string) error {
	if err := validatePubkey(hexPub); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM authors WHERE pubkey = ?`, hexPub)
	return err
}

// SetWhitelist marks the pubkey whitelisted and clears any pending notes.
func (s *Store) SetWhitelist(hexPub string) error {
	return s.Put(hexPub, Author{State: Whitelisted})
}

// SetBlacklist marks the pubkey blacklisted and clears any pending notes.
func (s *Store) SetBlacklist(hexPub string) error {
	return s.Put(hexPub, Author{State: Blacklisted})
}

// ListRecord pairs a pubkey with its author record for iteration.
type ListRecord struct {
	Pubkey string
	Author Author
}

// ForEach invokes fn for every stored author.
func (s *Store) ForEach(fn func(ListRecord) error) error {
	rows, err := s.db.Query(`SELECT pubkey, state, updated_at, notes FROM authors`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rec ListRecord
		var notesJSON string
		if err := rows.Scan(&rec.Pubkey, &rec.Author.State, &rec.Author.UpdatedAt, &notesJSON); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(notesJSON), &rec.Author.Notes); err != nil {
			return fmt.Errorf("unmarshal notes for %s: %w", rec.Pubkey, err)
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}
