// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pq

import (
	"errors"
	"testing"
)

// stubEvidence implements PQEvidencer with a configurable bool.
type stubEvidence struct{ has bool }

func (s *stubEvidence) HasPQEvidence() bool { return s.has }

// TestValidateMode_Classical_ignoresEverything pins that classical
// mode never refuses, never calls the verifier. Both with and
// without evidence; the gate is a no-op.
func TestValidateMode_Classical_ignoresEverything(t *testing.T) {
	called := false
	verify := func() error { called = true; return errors.New("would have refused") }
	for _, ev := range []PQEvidencer{nil, &stubEvidence{has: false}, &stubEvidence{has: true}} {
		if err := ValidateMode(ModeClassical, ev, verify); err != nil {
			t.Errorf("ModeClassical refused: %v (ev=%v)", err, ev)
		}
	}
	if called {
		t.Error("ModeClassical called the verifier (should never)")
	}
}

// TestValidateMode_StrictPQ_refusesMissingEvidence pins the
// canonical refusal: strict-PQ + nil evidence + non-nil verifier
// must return ErrClassicalAuthForbidden WITHOUT calling verify
// (the evidence-absent fast path).
func TestValidateMode_StrictPQ_refusesMissingEvidence(t *testing.T) {
	verifyCalled := false
	verify := func() error { verifyCalled = true; return nil }
	for _, ev := range []PQEvidencer{nil, &stubEvidence{has: false}} {
		err := ValidateMode(ModeStrictPQ, ev, verify)
		if !errors.Is(err, ErrClassicalAuthForbidden) {
			t.Errorf("StrictPQ accepted missing evidence: err=%v (ev=%v)", err, ev)
		}
	}
	if verifyCalled {
		t.Error("Verify called even though evidence was absent")
	}
}

// TestValidateMode_StrictPQ_evidencePresent_callsVerify pins the
// happy path: strict-PQ + evidence-bearing input → call verifier.
func TestValidateMode_StrictPQ_evidencePresent_callsVerify(t *testing.T) {
	called := false
	verify := func() error { called = true; return nil }
	if err := ValidateMode(ModeStrictPQ, &stubEvidence{has: true}, verify); err != nil {
		t.Fatalf("StrictPQ refused valid evidence: %v", err)
	}
	if !called {
		t.Error("Verify not called even though evidence was present")
	}
}

// TestValidateMode_StrictPQ_verifyErrorPropagates pins that
// verifier errors flow through verbatim (the gate does NOT
// rewrap them) so consumers can errors.Is against their own
// granular failure types.
func TestValidateMode_StrictPQ_verifyErrorPropagates(t *testing.T) {
	want := errors.New("validator-set: pubkey not registered")
	verify := func() error { return want }
	err := ValidateMode(ModeStrictPQ, &stubEvidence{has: true}, verify)
	if !errors.Is(err, want) {
		t.Errorf("verify error not propagated: %v", err)
	}
	// ErrClassicalAuthForbidden should NOT fire here — the
	// refusal cause is the verifier, not the gate.
	if errors.Is(err, ErrClassicalAuthForbidden) {
		t.Error("verify-error path incorrectly mapped to ErrClassicalAuthForbidden")
	}
}

// TestValidateMode_Hybrid_acceptsMissingEvidence pins the hybrid
// fallback: missing evidence is NOT refused. The caller is
// expected to log a stale-PQ warning and validate the classical
// lane separately.
func TestValidateMode_Hybrid_acceptsMissingEvidence(t *testing.T) {
	called := false
	verify := func() error { called = true; return nil }
	for _, ev := range []PQEvidencer{nil, &stubEvidence{has: false}} {
		if err := ValidateMode(ModeHybrid, ev, verify); err != nil {
			t.Errorf("Hybrid refused missing evidence: %v (ev=%v)", err, ev)
		}
	}
	if called {
		t.Error("Hybrid called verify when evidence was absent")
	}
}

// TestValidateMode_Hybrid_evidencePresent_validates pins that
// hybrid + present evidence still calls the verifier — the
// fallback is to classical only when evidence is ABSENT.
func TestValidateMode_Hybrid_evidencePresent_validates(t *testing.T) {
	called := false
	verify := func() error { called = true; return nil }
	if err := ValidateMode(ModeHybrid, &stubEvidence{has: true}, verify); err != nil {
		t.Fatalf("Hybrid refused valid evidence: %v", err)
	}
	if !called {
		t.Error("Hybrid did not call verify on present evidence")
	}
}

// TestValidateMode_nilVerify pins that a nil verify is treated
// as "gate-only, skip verification" — useful for fast-path
// rejection at the receive boundary BEFORE expensive crypto.
func TestValidateMode_nilVerify(t *testing.T) {
	// StrictPQ + evidence present + nil verify → accept (gate
	// invariant satisfied, verification deferred).
	if err := ValidateMode(ModeStrictPQ, &stubEvidence{has: true}, nil); err != nil {
		t.Errorf("nil verify with evidence present refused: %v", err)
	}
	// StrictPQ + evidence absent + nil verify → REFUSE (gate
	// invariant violated, verifier irrelevant).
	if err := ValidateMode(ModeStrictPQ, nil, nil); !errors.Is(err, ErrClassicalAuthForbidden) {
		t.Errorf("nil verify with evidence absent did not refuse: %v", err)
	}
}

// TestRequireMode_strictPQOnly pins the dedicated entry point:
// callers that mean "strict-PQ only, no hybrid fallback" use
// RequireMode and the gate enforces accordingly without taking
// a mode parameter.
func TestRequireMode_strictPQOnly(t *testing.T) {
	if err := RequireMode(nil, nil); !errors.Is(err, ErrClassicalAuthForbidden) {
		t.Errorf("RequireMode accepted nil evidence: %v", err)
	}
	if err := RequireMode(&stubEvidence{has: true}, nil); err != nil {
		t.Errorf("RequireMode refused present evidence: %v", err)
	}
}
