// Package model is a pure-Go port of the nspam-classifier inference pipeline.
//
// It is validated against the export/v0.9 parity_fixtures.jsonl and
// hash_fixtures.jsonl so scores match sklearn's output within float32
// precision.
package model

import (
	"archive/zip"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math"

	"github.com/barrydeen/nspam-strfry/internal/strfry"
	"github.com/sbinet/npyio"
)

//go:embed assets/weights.npz assets/config.json
var assetsFS embed.FS

// Config is a (loosely-typed) subset of the exported config.json — we only
// read fields the port currently consumes.
type Config struct {
	NFeaturesChar  int `json:"n_features_char"`
	NFeaturesWord  int `json:"n_features_word"`
	TotalFeatures  int `json:"total_features"`
}

// Model holds the loaded weights and calibration table.
type Model struct {
	EffectiveCoef []float32 // shape [TotalFeatures]
	Intercept     float32
	CalibX        []float32
	CalibY        []float32
	Config        Config
}

// Load reads the embedded assets and returns a ready-to-score Model.
func Load() (*Model, error) {
	cfgBytes, err := assetsFS.ReadFile("assets/config.json")
	if err != nil {
		return nil, fmt.Errorf("read config.json: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("parse config.json: %w", err)
	}
	if cfg.NFeaturesChar != int(nFeaturesChar) || cfg.NFeaturesWord != int(nFeaturesWord) {
		return nil, fmt.Errorf("config feature dims (%d,%d) != build constants (%d,%d)",
			cfg.NFeaturesChar, cfg.NFeaturesWord, nFeaturesChar, nFeaturesWord)
	}

	npzBytes, err := assetsFS.ReadFile("assets/weights.npz")
	if err != nil {
		return nil, fmt.Errorf("read weights.npz: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(npzBytes), int64(len(npzBytes)))
	if err != nil {
		return nil, fmt.Errorf("open npz: %w", err)
	}

	arrays := map[string][]float32{}
	intercept := float32(0)
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", zf.Name, err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", zf.Name, err)
		}
		// Use npyio.Read high-level helper on a fresh reader.
		var tmp []float32
		switch zf.Name {
		case "intercept.npy":
			// scalar stored as a 0-d or 1-element array
			if err := npyio.Read(bytes.NewReader(raw), &tmp); err == nil {
				if len(tmp) != 1 {
					return nil, fmt.Errorf("intercept expected 1 element, got %d", len(tmp))
				}
				intercept = tmp[0]
				continue
			}
			// fall back to float64
			var tmp64 []float64
			if err := npyio.Read(bytes.NewReader(raw), &tmp64); err != nil {
				return nil, fmt.Errorf("read intercept: %w", err)
			}
			if len(tmp64) != 1 {
				return nil, fmt.Errorf("intercept expected 1 element, got %d", len(tmp64))
			}
			intercept = float32(tmp64[0])
		default:
			if err := npyio.Read(bytes.NewReader(raw), &tmp); err != nil {
				// some arrays might be stored as float64 — coerce
				var tmp64 []float64
				if err2 := npyio.Read(bytes.NewReader(raw), &tmp64); err2 != nil {
					return nil, fmt.Errorf("read %s: %w", zf.Name, err)
				}
				tmp = make([]float32, len(tmp64))
				for i, v := range tmp64 {
					tmp[i] = float32(v)
				}
			}
			arrays[zf.Name] = tmp
		}
	}

	coef, ok := arrays["effective_coef.npy"]
	if !ok {
		return nil, fmt.Errorf("effective_coef.npy missing from npz")
	}
	if len(coef) != cfg.TotalFeatures {
		return nil, fmt.Errorf("effective_coef length %d != total_features %d", len(coef), cfg.TotalFeatures)
	}
	calibX, ok := arrays["calib_x.npy"]
	if !ok {
		return nil, fmt.Errorf("calib_x.npy missing from npz")
	}
	calibY, ok := arrays["calib_y.npy"]
	if !ok {
		return nil, fmt.Errorf("calib_y.npy missing from npz")
	}

	return &Model{
		EffectiveCoef: coef,
		Intercept:     intercept,
		CalibX:        calibX,
		CalibY:        calibY,
		Config:        cfg,
	}, nil
}

// Score returns the calibrated bot probability in [0,1] for a bundle of up to
// 10 Nostr events. Mirrors verify_export.py: compute raw_score = sigmoid(
// features · coef + intercept), then isotonic-interpolate via (calib_x,
// calib_y), clamped to [0,1].
func (m *Model) Score(bundle []*strfry.Event) float64 {
	if len(bundle) == 0 {
		return 0
	}

	// Preprocess every note; accumulate text blocks for hash analyzers.
	var normChunks, rawChunks []string
	for _, rec := range bundle {
		p := Preprocess(rec.Content)
		normChunks = append(normChunks, p.Text)
		rawChunks = append(rawChunks, p.RawText)
	}
	normJoined := joinWithSpace(normChunks)
	rawJoined := joinWithSpace(rawChunks)

	// Char and word n-gram hash buckets -> sparse accumulations.
	charGrams := charWBAnalyze(rawJoined)
	wordGrams := wordAnalyze(normJoined)

	// Dot product directly: for each n-gram, bucket & sign, then add
	// sign * coef[offset + bucket] to the running total.
	charOffset := 0
	wordOffset := int(nFeaturesChar)
	structOffset := int(nFeaturesChar) + int(nFeaturesWord)

	var logit float64 = float64(m.Intercept)
	for _, g := range charGrams {
		idx, sign := bucketAndSign(g, nFeaturesChar)
		logit += float64(sign) * float64(m.EffectiveCoef[charOffset+int(idx)])
	}
	for _, g := range wordGrams {
		idx, sign := bucketAndSign(g, nFeaturesWord)
		logit += float64(sign) * float64(m.EffectiveCoef[wordOffset+int(idx)])
	}

	// Structural + group features (dense).
	struct23 := bundleStructural(bundle)
	for i, v := range struct23 {
		// sklearn internally cast to float32 before the dot product (the
		// transform output is float32 CSR). Match that here.
		logit += float64(float32(v)) * float64(m.EffectiveCoef[structOffset+i])
	}

	// Sigmoid -> raw probability.
	raw := 1.0 / (1.0 + math.Exp(-logit))
	// Isotonic calibration -> final bot probability.
	return interpClamped(raw, m.CalibX, m.CalibY)
}

func joinWithSpace(parts []string) string {
	n := 0
	for _, p := range parts {
		n += len(p) + 1
	}
	if n == 0 {
		return ""
	}
	buf := make([]byte, 0, n)
	for i, p := range parts {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, p...)
	}
	return string(buf)
}
