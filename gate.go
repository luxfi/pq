// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// gate.go — the strict-PQ admission gate, decomplected.
//
// Before this file lived, each consumer (warp.RequireMLDSACertSetForProfile,
// zap.RequireAttestationForProfile, dex.VerifyOrderForProfile, …)
// reimplemented the same three-step shape:
//
//   1. if mode doesn't require PQ → accept
//   2. if mode requires PQ and no PQ evidence present → refuse
//   3. if PQ evidence present → call the consumer's verifier
//
// Each copy was a place where a future Mode could grow a fourth
// arm and silently miss one of the gates. Five copies = five
// places to update; one gate = one place.
//
// Decomplection:
//
//   • Mode (mode.go)         — the value
//   • PQEvidencer + Verify   — the per-input contract a consumer
//                              fulfills to plug into the gate
//   • ValidateMode + RequireMode — the gates (this file)
//
// Each consumer:
//
//   • Makes its input implement HasPQEvidence() bool
//   • Passes a Verify (func() error) that does the consumer-
//     specific verification work
//   • Calls pq.ValidateMode(mode, evidence, verify) — one line.
//
// Concerns separated:
//
//   verification logic = caller's `verify` closure
//   policy enforcement = pq.ValidateMode
//   evidence shape     = caller's HasPQEvidence()
//   error vocabulary   = pq.ErrClassicalAuthForbidden (single sentinel)
//
// One concept, one function, one error, one mode. No copies.

package pq

// PQEvidencer is the per-input contract: does the input carry
// the post-quantum authentication material the gate needs?
//
//   - warp.EnvelopeV2          → HasPQEvidence = HasMLDSACertSet()
//   - zap.Attestation          → HasPQEvidence = att != nil && len(Sig) > 0
//   - dex.SignedOrderPQ        → HasPQEvidence = true   (the type itself is the evidence)
//   - dex.SignedOrder          → HasPQEvidence = false  (classical, no PQ evidence)
//   - lqd tx (MLDSATxType)     → HasPQEvidence = tx.Type() == MLDSATxType
//
// Nil-safe: the gate checks for a nil PQEvidencer before calling
// HasPQEvidence, so consumers can pass nil to mean "no evidence
// attached at all".
type PQEvidencer interface {
	HasPQEvidence() bool
}

// Verify is the per-consumer verification closure. The gate
// invokes it ONLY after confirming the evidence is present. Each
// consumer captures whatever inputs the verification needs
// (transcript hash, pubkey, validator-set membership check) in
// the closure — the gate doesn't know or care about the shape.
//
// Returning nil = evidence verified.
// Returning non-nil = the gate propagates the error verbatim.
type Verify func() error

// ValidateMode is the canonical strict-PQ admission gate. One
// function dispatches the entire mode policy:
//
//   - ModeClassical:
//     returns nil (PQ evidence ignored).
//
//   - ModeHybrid:
//     evidence present → validate via the supplied Verify;
//     evidence absent  → return nil (caller logs stale-PQ
//     warning; classical verification path
//     remains the trust root).
//
//   - ModeStrictPQ:
//     evidence absent  → ErrClassicalAuthForbidden;
//     evidence present → validate via the supplied Verify.
//
// verify may be nil — the gate still enforces the
// "evidence present under strict-PQ" invariant but skips the
// verification call. Useful for callers that want the gate to
// run BEFORE the expensive verification work (e.g. a quick
// reject of envelopes missing MLDSACertSet at the receive
// boundary; full verification happens later).
//
// evidence may be nil — equivalent to "no PQ material attached"
// (HasPQEvidence returns false implicitly).
func ValidateMode(mode Mode, evidence PQEvidencer, verify Verify) error {
	if !mode.IsPQAware() {
		// Classical: no PQ enforcement, no validation called.
		return nil
	}
	hasEvidence := evidence != nil && evidence.HasPQEvidence()
	if !hasEvidence {
		if mode.IsPostQuantum() {
			return ErrClassicalAuthForbidden
		}
		// Hybrid + no evidence: accept, classical fallback.
		return nil
	}
	// Evidence present: verify if the caller asked us to.
	if verify == nil {
		return nil
	}
	return verify()
}

// RequireMode is the strict-PQ-only variant: refuses if no PQ
// evidence is attached regardless of mode. Use this when the
// CALLER has already decided "I am a strict-PQ consumer, refuse
// without evidence." Equivalent to:
//
//	ValidateMode(ModeStrictPQ, evidence, verify)
//
// Exists as a separate name so call sites that mean "strict-PQ
// only, no hybrid fallback" are grep-able.
func RequireMode(evidence PQEvidencer, verify Verify) error {
	return ValidateMode(ModeStrictPQ, evidence, verify)
}
