// Package state persists per-pubkey plugin state in a bbolt file.
package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/barrydeen/nspam-strfry/internal/strfry"
	bolt "go.etcd.io/bbolt"
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

// Author is the per-pubkey record stored in the authors bucket.
type Author struct {
	State     State        `json:"state"`
	UpdatedAt int64        `json:"updated_at"` // unix seconds
	Notes     []StoredNote `json:"notes,omitempty"`
}

var authorsBucket = []byte("authors")

// Store wraps a bbolt database.
type Store struct {
	db *bolt.DB
}

// Open opens (or creates) the bbolt database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(authorsBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// pubkeyKey decodes the hex pubkey to 32 raw bytes. An invalid input returns
// nil so callers can short-circuit to a safe default (reject).
func pubkeyKey(hexPub string) []byte {
	if len(hexPub) != 64 {
		return nil
	}
	b, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil
	}
	return b
}

// Get returns the stored author record. When the pubkey is unknown it
// returns a zero-value Author (state=Pending, no notes) and found=false.
func (s *Store) Get(hexPub string) (Author, bool, error) {
	key := pubkeyKey(hexPub)
	if key == nil {
		return Author{}, false, fmt.Errorf("invalid pubkey %q", hexPub)
	}
	var a Author
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(authorsBucket)
		v := b.Get(key)
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &a)
	})
	return a, found, err
}

// Put writes the full author record for a pubkey. Used by policy after it
// decides on the next state, and by the admin CLI.
func (s *Store) Put(hexPub string, a Author) error {
	key := pubkeyKey(hexPub)
	if key == nil {
		return fmt.Errorf("invalid pubkey %q", hexPub)
	}
	a.UpdatedAt = time.Now().Unix()
	val, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(authorsBucket).Put(key, val)
	})
}

// Delete removes the pubkey from the store.
func (s *Store) Delete(hexPub string) error {
	key := pubkeyKey(hexPub)
	if key == nil {
		return fmt.Errorf("invalid pubkey %q", hexPub)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(authorsBucket).Delete(key)
	})
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

// ForEach invokes fn for every stored author. Pubkeys are re-encoded to hex.
func (s *Store) ForEach(fn func(ListRecord) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(authorsBucket)
		return b.ForEach(func(k, v []byte) error {
			var a Author
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			return fn(ListRecord{Pubkey: hex.EncodeToString(k), Author: a})
		})
	})
}
