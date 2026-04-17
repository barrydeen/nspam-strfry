package model

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type hashFixtureBucket struct {
	Index int     `json:"index"`
	Value float32 `json:"value"`
}

type hashFixture struct {
	Token         string              `json:"token"`
	WordBuckets   []hashFixtureBucket `json:"word_buckets"`
	CharWBBuckets []hashFixtureBucket `json:"char_wb_buckets"`
}

func loadHashFixtures(t *testing.T) []hashFixture {
	t.Helper()
	path := filepath.Join("testdata", "hash_fixtures.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var fixtures []hashFixture
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		var fx hashFixture
		if err := json.Unmarshal(s.Bytes(), &fx); err != nil {
			t.Fatalf("decode: %v", err)
		}
		fixtures = append(fixtures, fx)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return fixtures
}

// bucketSum hashes each n-gram into a sparse map, accumulating signed counts.
func bucketSum(ngrams []string, nFeatures uint32) map[int]float32 {
	m := make(map[int]float32, len(ngrams))
	for _, g := range ngrams {
		idx, sign := bucketAndSign(g, nFeatures)
		m[int(idx)] += sign
	}
	return m
}

func bucketsToSortedFixture(m map[int]float32) []hashFixtureBucket {
	out := make([]hashFixtureBucket, 0, len(m))
	for k, v := range m {
		if v == 0 {
			continue
		}
		out = append(out, hashFixtureBucket{Index: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	// The export-side fixtures are truncated to the first 32 sorted buckets
	// (see src/export.py `_token_fixtures` — `[:32]`). Match that here.
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func TestHashParity(t *testing.T) {
	fixtures := loadHashFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no fixtures loaded")
	}

	for _, fx := range fixtures {
		t.Run(fx.Token, func(t *testing.T) {
			// Word buckets: analyzer "word" with default sklearn regex on the
			// single token as the full document. sklearn's tokenizer filters
			// single-char tokens (\w\w+) — hash_fixtures only includes tokens
			// that survive this filter, but we still run the full analyzer.
			wordGrams := wordAnalyze(fx.Token)
			// For a single-token input, 1-grams=[token] if it matches ≥2 word
			// chars, else empty; there are no 2-grams.
			gotWord := bucketsToSortedFixture(bucketSum(wordGrams, nFeaturesWord))
			if !bucketsEqual(gotWord, fx.WordBuckets) {
				t.Errorf("word buckets mismatch\nwant: %v\ngot:  %v", fx.WordBuckets, gotWord)
			}

			// Char_wb buckets: the fixture is emitted from sklearn using the
			// token as raw_text — so our char_wb analyzer should see the exact
			// string, not a preprocessed one.
			charGrams := charWBAnalyze(fx.Token)
			gotChar := bucketsToSortedFixture(bucketSum(charGrams, nFeaturesChar))
			if !bucketsEqual(gotChar, fx.CharWBBuckets) {
				t.Errorf("char_wb buckets mismatch\nwant: %v\ngot:  %v", fx.CharWBBuckets, gotChar)
			}
		})
	}
}

func bucketsEqual(a, b []hashFixtureBucket) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Index != b[i].Index || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}
