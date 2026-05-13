// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pq

import (
	"errors"
	"testing"
)

func TestMode_StringAndPredicates(t *testing.T) {
	for _, tc := range []struct {
		mode            Mode
		wantString      string
		wantPostQuantum bool
		wantPQAware     bool
	}{
		{ModeClassical, "classical", false, false},
		{ModeHybrid, "hybrid", false, true},
		{ModeStrictPQ, "strict-pq", true, true},
		{Mode(99), "unknown", false, false},
	} {
		if tc.mode.String() != tc.wantString {
			t.Errorf("Mode(%d).String() = %q, want %q",
				tc.mode, tc.mode.String(), tc.wantString)
		}
		if tc.mode.IsPostQuantum() != tc.wantPostQuantum {
			t.Errorf("%s.IsPostQuantum() = %t, want %t",
				tc.mode, tc.mode.IsPostQuantum(), tc.wantPostQuantum)
		}
		if tc.mode.IsPQAware() != tc.wantPQAware {
			t.Errorf("%s.IsPQAware() = %t, want %t",
				tc.mode, tc.mode.IsPQAware(), tc.wantPQAware)
		}
	}
}

// TestMode_ProfileLink pins the bridge between the higher-level
// named mode and the lower-level precompile forbid-bits. The
// invariant: strict-PQ mode installs Strict() at the EVM
// precompile layer; classical and hybrid install Permissive().
func TestMode_ProfileLink(t *testing.T) {
	if p := ModeStrictPQ.Profile(); !p.ForbidEcrecover || !p.ForbidBLS12381 {
		t.Error("ModeStrictPQ.Profile() did not return Strict()")
	}
	for _, m := range []Mode{ModeClassical, ModeHybrid} {
		p := m.Profile()
		if p.ForbidEcrecover || p.ForbidBLS12381 {
			t.Errorf("%s.Profile() returned Strict() (want Permissive())", m)
		}
	}
}

func TestModeFromPQFlag(t *testing.T) {
	if got := ModeFromPQFlag(true); got != ModeStrictPQ {
		t.Errorf("ModeFromPQFlag(true) = %s, want strict-pq", got)
	}
	if got := ModeFromPQFlag(false); got != ModeClassical {
		t.Errorf("ModeFromPQFlag(false) = %s, want classical", got)
	}
}

func TestModeFromString(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"classical", ModeClassical, false},
		{"hybrid", ModeHybrid, false},
		{"strict-pq", ModeStrictPQ, false},
		{"", 0, true},
		{"PQ", 0, true},
		{"strict_pq", 0, true},
		{"Strict-PQ", 0, true}, // case sensitive
	} {
		got, err := ModeFromString(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ModeFromString(%q) err=%v, wantErr=%t",
				tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ModeFromString(%q) = %s, want %s",
				tc.input, got, tc.want)
		}
	}
}

func TestErrClassicalAuthForbidden_IsCheckable(t *testing.T) {
	wrapped := errors.New("envelope rejected: " + ErrClassicalAuthForbidden.Error())
	// Direct sentinel comparison via errors.Is works because the
	// sentinel is a package-level var. Downstream packages wrap
	// it with fmt.Errorf("...: %w", pq.ErrClassicalAuthForbidden);
	// errors.Is unwraps and matches.
	if errors.Is(wrapped, ErrClassicalAuthForbidden) {
		t.Error("errors.Is matched on string-wrapped (not %w-wrapped) error — that's wrong, this test pins the negative case")
	}
	// Positive: %w-wrapped errors should unwrap correctly.
	formatted := errors.Join(ErrClassicalAuthForbidden, errors.New("at gate X"))
	if !errors.Is(formatted, ErrClassicalAuthForbidden) {
		t.Error("errors.Is failed to match a Join-wrapped sentinel")
	}
}
