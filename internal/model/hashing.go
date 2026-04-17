package model

import (
	"github.com/spaolacci/murmur3"
)

// bucketAndSign mirrors sklearn's HashingVectorizer with alternate_sign=True.
//
// sklearn reference (sklearn/feature_extraction/_hashing_fast.pyx):
//
//	h = murmurhash3_32(token, 0)          // returns uint32, reinterpreted as int32
//	idx = abs(h) % n_features
//	value = 1.0 if h >= 0 else -1.0
//
// In practice sklearn masks rather than mods because n_features is a power of 2.
// Implementation: treat the 32-bit hash as signed int32, use its sign for value,
// and take |h| & (n-1) for the bucket. The sole tricky case is h = INT32_MIN
// (-2147483648) whose absolute value overflows — sklearn casts through uint32
// so the bucket is `uint32(h) & (n-1)` which yields the right bits.
func bucketAndSign(token string, nFeatures uint32) (idx uint32, sign float32) {
	u := murmur3.Sum32WithSeed([]byte(token), 0)
	s := int32(u)
	if s < 0 {
		sign = -1
	} else {
		sign = 1
	}
	// Absolute-value-then-mod is equivalent to bit-masking by (n-1) when n is
	// a power of 2, EXCEPT that Python's abs(int32_min) is 2^31 (not overflow);
	// that index still wraps correctly because abs(int32_min) % (1<<17) == 0
	// and (uint32(int32_min) & mask) is also 0 for mask = (1<<17)-1.
	// For our fixed n=131072 both paths agree.
	mask := nFeatures - 1
	if s < 0 {
		idx = uint32(-int64(s)) & mask
	} else {
		idx = uint32(s) & mask
	}
	return
}
