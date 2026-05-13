// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// mode.go — canonical strict-PQ chain security mode.
//
// Decomplected from the per-package SecurityProfile types that
// previously lived in luxfi/warp, luxfi/zap, lux/dex, luxfi/fhe.
// One place defines the named profile (classical / hybrid /
// strict-pq); every consumer imports it. Each consumer keeps its
// own Require*ForMode function because the INPUTS differ
// (envelope vs order vs precompile-op vs FHE-params) but the
// MODE dispatch is identical.
//
// The relationship to Profile (in profile.go) is "named modes →
// concrete forbid-bits". Strict-PQ mode installs Strict() at the
// EVM precompile layer; classical and hybrid install Permissive().
// The mode also carries an envelope / order / handshake-level
// stance that the EVM precompile layer doesn't see — those
// dispatch off the Mode directly inside each consumer.

package pq

import (
	"errors"
	"fmt"
)

// Mode is the chain-wide strict-PQ posture. A chain pins exactly
// one Mode at genesis and never flips it at runtime without a
// hard fork.
//
//   - ModeClassical: BLS Beam / ECDSA tx sigs / secp256k1
//     SignedOrder trusted as auth root. MLDSACertSet / SignedOrderPQ
//     ignored even if present.
//
//   - ModeHybrid: validates MLDSACertSet / SignedOrderPQ when
//     present, falls back to classical with a stale-PQ warning
//     when absent. Safe migration middle — operator turns ON PQ
//     validation today and turns OFF classical trust later.
//
//   - ModeStrictPQ: REFUSES every classical authentication root.
//     MLDSACertSet REQUIRED on Warp envelopes; SignedOrderPQ
//     REQUIRED on DEX orders; MLDSATxType REQUIRED on EVM
//     tx-pool admission; ML-DSA-65 channel binding REQUIRED on
//     ZAP connections; PN9QP27_STD128Q params REQUIRED on FHE.
//     Canonical Liquid default; strict Lux + Zoo profile.
type Mode int

const (
	// ModeClassical is the default for legacy chains with no
	// ML-DSA validator material yet generated.
	ModeClassical Mode = iota

	// ModeHybrid validates PQ material when present, accepts
	// classical-only with a stale-PQ warning.
	ModeHybrid

	// ModeStrictPQ refuses every classical authentication root.
	ModeStrictPQ
)

// String returns the canonical wire name. Audit pipelines match
// on these strings; renaming here breaks every downstream consumer.
func (m Mode) String() string {
	switch m {
	case ModeClassical:
		return "classical"
	case ModeHybrid:
		return "hybrid"
	case ModeStrictPQ:
		return "strict-pq"
	default:
		return "unknown"
	}
}

// IsPostQuantum reports whether this mode REFUSES classical-only
// authentication. Only ModeStrictPQ returns true; hybrid is PQ-
// AWARE (validates PQ when present) but not PQ-only.
func (m Mode) IsPostQuantum() bool {
	return m == ModeStrictPQ
}

// IsPQAware reports whether this mode VALIDATES PQ material when
// the peer presents it. Both ModeHybrid and ModeStrictPQ return
// true; ModeClassical ignores PQ material even when present.
func (m Mode) IsPQAware() bool {
	return m == ModeHybrid || m == ModeStrictPQ
}

// Profile returns the EVM-precompile-level Profile that this Mode
// installs. ModeStrictPQ → Strict() (every classical primitive
// refused at the precompile boundary); ModeClassical + ModeHybrid
// → Permissive() (every primitive admitted). Hybrid validates PQ
// authentication at higher layers (envelope / order / handshake)
// but doesn't refuse classical primitives inside contracts.
func (m Mode) Profile() *Profile {
	if m == ModeStrictPQ {
		return Strict()
	}
	return Permissive()
}

// ModeFromPQFlag lifts a chain-config "pq" boolean (the same flag
// liquidity/operator writes into /data/configs/chains/<id>/config.json)
// to a Mode. true → ModeStrictPQ; false → ModeClassical.
//
// Intentionally binary: a chain that wants strict-PQ shouldn't
// have a fallback path opened by a future operator turning the
// same flag from true → "hybrid". Strict-PQ is a one-way door.
// Operators that want hybrid pin the profile via ModeFromString
// using the explicit "hybrid" string.
func ModeFromPQFlag(pq bool) Mode {
	if pq {
		return ModeStrictPQ
	}
	return ModeClassical
}

// ModeFromString parses an operator-supplied profile string.
// Refuses unknown values rather than defaulting; the gate at
// every layer assumes the mode is well-known.
func ModeFromString(s string) (Mode, error) {
	switch s {
	case "classical":
		return ModeClassical, nil
	case "hybrid":
		return ModeHybrid, nil
	case "strict-pq":
		return ModeStrictPQ, nil
	default:
		return ModeClassical, fmt.Errorf("pq: unknown mode %q (want classical|hybrid|strict-pq)", s)
	}
}

// ErrClassicalAuthForbidden is the umbrella sentinel returned by
// every consumer-layer gate when a strict-PQ chain is presented
// classical authentication material. errors.Is(err, pq.ErrClassicalAuthForbidden)
// works across luxfi/warp, luxfi/zap, lux/dex, luxfi/evm, lux/fhe
// — audit pipelines grep ONE identifier across every refusal
// site in the system.
//
// Per-family precompile errors (ErrEcrecoverForbidden, etc.) live
// alongside this sentinel in refuse.go; they fire INSIDE a
// contract execution, this one fires at the chain-level
// authentication boundary (envelope / order / handshake / tx pool).
var ErrClassicalAuthForbidden = errors.New(
	"pq: classical authentication forbidden under strict-PQ mode")
