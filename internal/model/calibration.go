package model

// interpClamped mirrors `np.interp(x, xp, yp)` then `np.clip(..., 0.0, 1.0)`.
// Assumes xp is sorted ascending (sklearn IsotonicRegression returns sorted
// knots). For x outside [xp[0], xp[-1]] np.interp returns the boundary value.
func interpClamped(x float64, xp, yp []float32) float64 {
	if len(xp) == 0 {
		return clamp01(x)
	}
	if x <= float64(xp[0]) {
		return clamp01(float64(yp[0]))
	}
	if x >= float64(xp[len(xp)-1]) {
		return clamp01(float64(yp[len(yp)-1]))
	}
	// binary search for the first xp[i] > x
	lo, hi := 0, len(xp)-1
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if float64(xp[mid]) <= x {
			lo = mid
		} else {
			hi = mid
		}
	}
	x0, x1 := float64(xp[lo]), float64(xp[lo+1])
	y0, y1 := float64(yp[lo]), float64(yp[lo+1])
	if x1 == x0 {
		return clamp01(y0)
	}
	t := (x - x0) / (x1 - x0)
	return clamp01(y0 + t*(y1-y0))
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
