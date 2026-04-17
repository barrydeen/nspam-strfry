package model

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

type parityNote struct {
	ID        string     `json:"id"`
	Content   string     `json:"content"`
	Tags      [][]string `json:"tags"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Pubkey    string     `json:"pubkey"`
	Sig       string     `json:"sig"`
}

type parityFixture struct {
	Label                   int          `json:"label"`
	Pubkey                  string       `json:"pubkey"`
	Notes                   []parityNote `json:"notes"`
	ExpectedRawScore        float64      `json:"expected_raw_score"`
	ExpectedCalibratedScore float64      `json:"expected_calibrated_score"`
}

func TestScoreParity(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	path := filepath.Join("testdata", "parity_fixtures.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<22), 1<<22)

	var maxErr float64
	var meanErr float64
	var count int
	var failures int
	const tol = 1e-5

	for s.Scan() {
		var fx parityFixture
		if err := json.Unmarshal(s.Bytes(), &fx); err != nil {
			t.Fatalf("decode: %v", err)
		}
		bundle := make([]*strfry.Event, len(fx.Notes))
		for i, n := range fx.Notes {
			bundle[i] = &strfry.Event{
				ID:        n.ID,
				Pubkey:    n.Pubkey,
				Kind:      n.Kind,
				Content:   n.Content,
				Tags:      n.Tags,
				CreatedAt: n.CreatedAt,
				Sig:       n.Sig,
			}
		}
		got := m.Score(bundle)
		errAbs := math.Abs(got - fx.ExpectedCalibratedScore)
		if errAbs > maxErr {
			maxErr = errAbs
		}
		meanErr += errAbs
		count++
		if errAbs > tol {
			failures++
			if failures <= 5 {
				t.Logf("bundle %d (pubkey=%s...): want=%.6f got=%.6f err=%.2e",
					count, fx.Pubkey[:16], fx.ExpectedCalibratedScore, got, errAbs)
			}
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count == 0 {
		t.Fatal("no fixtures loaded")
	}

	t.Logf("fixtures=%d  max_err=%.3e  mean_err=%.3e  failures(>%.0e)=%d",
		count, maxErr, meanErr/float64(count), tol, failures)

	if maxErr > tol {
		t.Fatalf("max calibrated-score error %.3e exceeds tolerance %.0e", maxErr, tol)
	}
}
