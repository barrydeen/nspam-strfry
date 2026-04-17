package model

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

// invisibleSet mirrors INVISIBLE in nspam-classifier/src/preprocess.py
// (ZERO_WIDTH ∪ BIDI). These are stripped from the "text" view and counted
// into the zero_width structural feature.
var invisibleSet = map[rune]struct{}{
	'\u200b': {}, // zero-width space
	'\u200c': {}, // zero-width non-joiner
	'\u200d': {}, // zero-width joiner
	'\u2060': {}, // word joiner
	'\ufeff': {}, // zero-width no-break space / BOM
	'\u180e': {}, // mongolian vowel separator
	'\u2061': {},
	'\u2062': {},
	'\u2063': {},
	'\u2064': {},
	'\u202a': {}, '\u202b': {}, '\u202c': {}, '\u202d': {}, '\u202e': {},
	'\u2066': {}, '\u2067': {}, '\u2068': {}, '\u2069': {},
	'\u200e': {}, '\u200f': {},
}

func isInvisible(r rune) bool {
	_, ok := invisibleSet[r]
	return ok
}

func countInvisible(s string) int {
	n := 0
	for _, r := range s {
		if isInvisible(r) {
			n++
		}
	}
	return n
}

func stripInvisible(s string) string {
	hasAny := false
	for _, r := range s {
		if isInvisible(r) {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isInvisible(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// _URL_RE: r"https?://([^\s/]+)(/\S*)?" case-insensitive.
// Replace with http://<host-lower>. Drops path/query.
var urlRegex = regexp.MustCompile(`(?i)https?://([^\s/]+)(/\S*)?`)

func normalizeURLs(s string) string {
	return urlRegex.ReplaceAllStringFunc(s, func(match string) string {
		m := urlRegex.FindStringSubmatch(match)
		host := strings.ToLower(m[1])
		return "http://" + host
	})
}

// caser applies Unicode case folding. Go's golang.org/x/text/cases.Fold
// implements the Unicode CaseFolding.txt algorithm — the same mapping Python's
// str.casefold() uses.
var caser = cases.Fold()

func casefold(s string) string {
	return caser.String(s)
}

// whitespaceRegex matches runs of any Unicode whitespace (\s in Python re).
var whitespaceRegex = regexp.MustCompile(`\s+`)

// language.Und is acceptable for cases.Fold because case folding is
// language-invariant. Kept here for documentation only.
var _ = language.Und

// Prepared mirrors the Python Prepared dataclass.
type Prepared struct {
	Text        string // normalized, stripped, casefolded, whitespace-collapsed (word-analyzer input)
	RawText     string // NFKC-normalized but with invisibles preserved (char_wb input)
	ZeroWidthN  int
}

// Preprocess mirrors nspam-classifier/src/preprocess.py:preprocess().
func Preprocess(text string) Prepared {
	nfkc := norm.NFKC.String(text)
	zw := countInvisible(nfkc)

	stripped := stripInvisible(nfkc)
	stripped = normalizeURLs(stripped)
	stripped = casefold(stripped)
	stripped = whitespaceRegex.ReplaceAllString(stripped, " ")
	stripped = strings.TrimSpace(stripped)

	return Prepared{
		Text:       stripped,
		RawText:    nfkc,
		ZeroWidthN: zw,
	}
}

// tokenize mirrors src/preprocess.py:tokenize() — used only for group features.
// Pattern: \p{L}[\p{L}\p{M}\p{N}_]*|\p{N}+|https?://\S+|[#@][\w]+
// Returns tokens found in the (already casefolded) text. No further lowercasing.
func tokenize(text string) []string {
	return tokenizeRegex.FindAllString(text, -1)
}

var tokenizeRegex = regexp.MustCompile(`\p{L}[\p{L}\p{M}\p{N}_]*|\p{N}+|https?://\S+|[#@]\w+`)

// isLetter / isUpper mirror Python's str.isalpha() and str.isupper() for a
// single character — both are Unicode-aware.
func isLetter(r rune) bool { return unicode.IsLetter(r) }
func isUpper(r rune) bool  { return unicode.IsUpper(r) }
