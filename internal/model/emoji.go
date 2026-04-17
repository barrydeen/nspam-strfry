package model

import "unicode"

// countEmoji mirrors `len(_EMOJI_RE.findall(content))` in features.py where
//
//	_EMOJI_RE = re2.compile(r"[\p{Emoji_Presentation}\p{Extended_Pictographic}]")
//
// One match per code point whose property set includes either of those two
// Unicode properties. See emoji_ranges.go for the table — generated from the
// same Python `regex` module as the training pipeline.
func countEmoji(s string) int {
	n := 0
	for _, r := range s {
		if unicode.Is(emojiRangeTable, r) {
			n++
		}
	}
	return n
}
