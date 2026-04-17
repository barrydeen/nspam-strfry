package model

import (
	"regexp"
	"strings"
)

const (
	nFeaturesChar uint32 = 131072 // 2^17
	nFeaturesWord uint32 = 131072 // 2^17
	charNMin             = 3
	charNMax             = 5
	wordNMin             = 1
	wordNMax             = 2
)

// sklearnWordTokenRegex is the default token pattern used by sklearn's
// CountVectorizer / HashingVectorizer: `(?u)\b\w\w+\b`. In Python with
// re.UNICODE this matches runs of 2+ word characters.
//
// Go's regexp supports \w only as `[0-9A-Za-z_]` (ASCII). To match Python's
// Unicode \w we need an explicit class. Python's UNICODE \w =
//
//	[\p{L}\p{N}\p{M}_]  (letters, numbers, marks, underscore)
//
// sklearn's word tokens therefore match: [\p{L}\p{N}\p{M}_]{2,} with word
// boundaries. RE2 doesn't support \b with non-ASCII word chars reliably, but
// since our class already requires two consecutive word chars, matching
// greedily and then iterating finds the same tokens (the "boundary" is
// whatever lies between consecutive matches).
var sklearnWordTokenRegex = regexp.MustCompile(`[\p{L}\p{N}\p{M}_][\p{L}\p{N}\p{M}_]+`)

// wordAnalyze extracts sklearn-compatible word tokens from the preprocessed
// text, then emits 1-grams and 2-grams (space-joined) in document order.
func wordAnalyze(text string) []string {
	tokens := sklearnWordTokenRegex.FindAllString(text, -1)
	out := make([]string, 0, len(tokens)*2)
	// 1-grams
	for _, t := range tokens {
		out = append(out, t)
	}
	// 2-grams (only if wordNMax >= 2)
	if wordNMax >= 2 {
		for i := 0; i+1 < len(tokens); i++ {
			out = append(out, tokens[i]+" "+tokens[i+1])
		}
	}
	return out
}

// charWBAnalyze replicates sklearn's char_wb analyzer for ngram_range=(3,5).
//
// sklearn behavior (sklearn/feature_extraction/text.py VectorizerMixin._char_wb_ngrams):
//
//	for each whitespace-separated word w in the text:
//	    padded = " " + w + " "
//	    for n in range(3, 6):
//	        if len(padded) < n: continue
//	        for i in range(0, len(padded) - n + 1):
//	            yield padded[i:i+n]
//
// Important: the split is on Python `str.split()` (default), which splits on
// runs of any Unicode whitespace and discards empty tokens. The n-grams are
// emitted in the raw_text (NFKC but invisibles preserved) — there is no
// further lowercasing because HashingVectorizer(lowercase=False) is used.
func charWBAnalyze(text string) []string {
	// Python `str.split()` with no args splits on any whitespace including
	// Unicode; we approximate with a regex split.
	words := pythonSplit(text)
	var ngrams []string
	for _, w := range words {
		padded := " " + w + " "
		runes := []rune(padded)
		for n := charNMin; n <= charNMax; n++ {
			if len(runes) < n {
				continue
			}
			for i := 0; i+n <= len(runes); i++ {
				ngrams = append(ngrams, string(runes[i:i+n]))
			}
		}
	}
	return ngrams
}

// whitespaceSplitRegex matches runs of Unicode whitespace for Python-style split.
var whitespaceSplitRegex = regexp.MustCompile(`[\s\p{Z}]+`)

func pythonSplit(s string) []string {
	if s == "" {
		return nil
	}
	parts := whitespaceSplitRegex.Split(strings.TrimSpace(s), -1)
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// accumulateNGrams hashes each n-gram into its bucket and accumulates signed
// counts into the feature vector segment. The segment is indexed from 0.
func accumulateNGrams(ngrams []string, nFeatures uint32, into []float32) {
	for _, g := range ngrams {
		idx, sign := bucketAndSign(g, nFeatures)
		into[idx] += sign
	}
}
