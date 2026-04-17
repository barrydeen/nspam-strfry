package model

import (
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/barrydeen/nspam-strfry/internal/strfry"
)

// Structural feature indices (within the 17-element per-note block), matching
// STRUCTURAL_FEATURES in nspam-classifier/src/features.py.
const (
	idxLenChars          = 0
	idxLenTokens         = 1
	idxURLCount          = 2
	idxUniqueDomainCount = 3
	idxMentionCount      = 4
	idxHashtagCount      = 5
	idxTagPCount         = 6
	idxTagECount         = 7
	idxTagTCount         = 8
	idxTagOtherCount     = 9
	idxEmojiCount        = 10
	idxEmojiRatio        = 11
	idxZeroWidthCount    = 12
	idxCapsRatio         = 13
	idxDigitRatio        = 14
	idxPunctRatio        = 15
	idxDupBodyBucket     = 16

	nStructural    = 17
	nGroupFeatures = 6
	nStructTotal   = nStructural + nGroupFeatures // 23
)

// structuralURLRegex mirrors _URL_RE in features.py (note: features.py uses a
// slightly different pattern than preprocess.py — here it only captures the
// host, and there's no optional path group).
var structuralURLRegex = regexp.MustCompile(`(?i)https?://([^\s/]+)`)

// nostrMentionRegex matches `nostr:` or bare NIP-19 entity prefixes followed
// by bech32 chars. Mirrors _MENTION_RE in features.py.
var nostrMentionRegex = regexp.MustCompile(`(?i)\b(?:nostr:)?(?:npub1|note1|nprofile1|nevent1|naddr1)[0-9a-z]+`)

// hashtagRegex mirrors _HASHTAG_RE in features.py.
var hashtagRegex = regexp.MustCompile(`#\w+`)

// digitRegex mirrors \p{N}.
var digitRegex = regexp.MustCompile(`\p{N}`)

// punctRegex mirrors \p{P}.
var punctRegex = regexp.MustCompile(`\p{P}`)

// wsTokenRegex mirrors _TOKEN_RE in features.py — splits on whitespace.
var wsTokenRegex = regexp.MustCompile(`\S+`)

// extractStructural computes the 17 per-note structural features for one
// record, leaving dup_body_bucket at dupBucket (always 0 at inference).
func extractStructural(rec *strfry.Event, dupBucket int) [nStructural]float64 {
	var out [nStructural]float64

	content := ""
	if rec != nil {
		content = rec.Content
	}
	tags := [][]string(nil)
	if rec != nil {
		tags = rec.Tags
	}

	zw := countInvisible(content)
	lenChars := len([]rune(content)) // Python `len(str)` counts code points
	tokens := wsTokenRegex.FindAllString(content, -1)
	lenTokens := len(tokens)

	urls := structuralURLRegex.FindAllStringSubmatch(content, -1)
	urlCount := len(urls)
	domainSet := make(map[string]struct{}, urlCount)
	for _, m := range urls {
		domainSet[strings.ToLower(m[1])] = struct{}{}
	}

	mentionCount := len(nostrMentionRegex.FindAllString(content, -1))
	hashtagCount := len(hashtagRegex.FindAllString(content, -1))

	var tagP, tagE, tagT, tagOther int
	for _, t := range tags {
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "p":
			tagP++
		case "e":
			tagE++
		case "t":
			tagT++
		default:
			tagOther++
		}
	}

	emojiCount := countEmoji(content)
	digitCount := len(digitRegex.FindAllString(content, -1))
	punctCount := len(punctRegex.FindAllString(content, -1))

	var alphaChars, capsChars int
	for _, r := range content {
		if unicode.IsLetter(r) {
			alphaChars++
			if unicode.IsUpper(r) {
				capsChars++
			}
		}
	}

	out[idxLenChars] = float64(lenChars)
	out[idxLenTokens] = float64(lenTokens)
	out[idxURLCount] = float64(urlCount)
	out[idxUniqueDomainCount] = float64(len(domainSet))
	out[idxMentionCount] = float64(mentionCount)
	out[idxHashtagCount] = float64(hashtagCount)
	out[idxTagPCount] = float64(tagP)
	out[idxTagECount] = float64(tagE)
	out[idxTagTCount] = float64(tagT)
	out[idxTagOtherCount] = float64(tagOther)
	out[idxEmojiCount] = float64(emojiCount)
	out[idxEmojiRatio] = ratio(emojiCount, lenChars)
	out[idxZeroWidthCount] = float64(zw)
	out[idxCapsRatio] = ratio(capsChars, alphaChars)
	out[idxDigitRatio] = ratio(digitCount, lenChars)
	out[idxPunctRatio] = ratio(punctCount, lenChars)
	out[idxDupBodyBucket] = float64(dupBucket)
	return out
}

func ratio(n, d int) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// bundleStructural aggregates per-note structural features by mean across the
// bundle, then appends the 6 group-level features.
//
// Returns a slice of length 23 (17 + 6) in sklearn feature ordering.
func bundleStructural(bundle []*strfry.Event) []float64 {
	if len(bundle) == 0 {
		return make([]float64, nStructTotal)
	}
	perNote := make([][nStructural]float64, 0, len(bundle))
	for _, rec := range bundle {
		perNote = append(perNote, extractStructural(rec, 0))
	}
	// mean across notes
	agg := make([]float64, nStructural)
	for _, row := range perNote {
		for j := 0; j < nStructural; j++ {
			agg[j] += row[j]
		}
	}
	inv := 1.0 / float64(len(bundle))
	for j := range agg {
		agg[j] *= inv
	}

	// group features (same ordering as GROUP_FEATURES in features.py)
	var timeSpanHours, lenStd, sameFirstRatio, meanJaccard float64
	var nUniqueBodies float64

	bodyKeys := make(map[string]struct{}, len(bundle))
	for _, rec := range bundle {
		k := bodyKey(rec.Content)
		if k == "" {
			continue
		}
		bodyKeys[k] = struct{}{}
	}
	nUniqueBodies = float64(len(bodyKeys))

	// time span across created_at
	if len(bundle) >= 2 {
		minC := bundle[0].CreatedAt
		maxC := bundle[0].CreatedAt
		count := 0
		for _, rec := range bundle {
			if rec.CreatedAt == 0 {
				continue
			}
			if count == 0 || rec.CreatedAt < minC {
				minC = rec.CreatedAt
			}
			if count == 0 || rec.CreatedAt > maxC {
				maxC = rec.CreatedAt
			}
			count++
		}
		if count >= 2 {
			timeSpanHours = float64(maxC-minC) / 3600.0
		}

		texts := make([]string, len(bundle))
		for i, rec := range bundle {
			texts[i] = rec.Content
		}
		// len std (population std, np.std default ddof=0)
		charLens := make([]float64, len(texts))
		for i, t := range texts {
			charLens[i] = float64(len([]rune(t)))
		}
		lenStd = popStd(charLens)

		tokenSets := make([]map[string]struct{}, len(texts))
		firstTokens := make([]string, 0, len(texts))
		for i, t := range texts {
			toks := tokenize(casefold(t))
			set := make(map[string]struct{}, len(toks))
			for _, tk := range toks {
				set[tk] = struct{}{}
			}
			tokenSets[i] = set
			if len(toks) > 0 {
				firstTokens = append(firstTokens, toks[0])
			}
		}
		if len(firstTokens) > 0 {
			counts := map[string]int{}
			top := 0
			for _, t := range firstTokens {
				counts[t]++
				if counts[t] > top {
					top = counts[t]
				}
			}
			sameFirstRatio = float64(top) / float64(len(bundle))
		}

		var sims []float64
		for i := 0; i < len(tokenSets); i++ {
			for j := i + 1; j < len(tokenSets); j++ {
				a, b := tokenSets[i], tokenSets[j]
				unionN := len(a)
				for k := range b {
					if _, ok := a[k]; !ok {
						unionN++
					}
				}
				if unionN == 0 {
					continue
				}
				interN := 0
				for k := range a {
					if _, ok := b[k]; ok {
						interN++
					}
				}
				sims = append(sims, float64(interN)/float64(unionN))
			}
		}
		if len(sims) > 0 {
			var s float64
			for _, v := range sims {
				s += v
			}
			meanJaccard = s / float64(len(sims))
		}
	}

	out := make([]float64, nStructTotal)
	copy(out, agg)
	out[nStructural+0] = float64(len(bundle)) // group_size
	out[nStructural+1] = timeSpanHours
	out[nStructural+2] = nUniqueBodies
	out[nStructural+3] = lenStd
	out[nStructural+4] = sameFirstRatio
	out[nStructural+5] = meanJaccard
	return out
}

// bodyKey mirrors NspamFeaturizer._body_key: strip invisibles, casefold,
// trim, and truncate to first 200 *code points* (Python slicing semantics).
func bodyKey(text string) string {
	stripped := stripInvisible(text)
	stripped = strings.TrimSpace(casefold(stripped))
	runes := []rune(stripped)
	if len(runes) > 200 {
		runes = runes[:200]
	}
	return string(runes)
}

// popStd computes the population standard deviation (np.std default, ddof=0).
func popStd(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, v := range xs {
		sum += v
	}
	mean := sum / float64(len(xs))
	var sqsum float64
	for _, v := range xs {
		d := v - mean
		sqsum += d * d
	}
	return math.Sqrt(sqsum / float64(len(xs)))
}
