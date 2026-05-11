// Package pq defines the strict post-quantum profile that constrains
// which cryptographic operations a Quasar node accepts.
//
// The package contains no cryptographic primitives. It expresses a
// policy:
//
//   - [Profile] is the value. Eight Forbid* flags, one per cryptographic
//     primitive family. nil and the zero value both mean classical
//     semantics; [Strict] sets every flag true.
//
//   - [Op] is the operation a precompile reports. Sixteen stable
//     identifiers cover the EVM precompile families plus polynomial
//     commitments.
//
//   - [Refuse] is the gate. Every constrained operation calls it once
//     at the top of its entry point and otherwise proceeds in its own
//     lane. The profile does not know how the operations compute; the
//     operations do not know how the profile is selected.
//
// One way only: one variable holds the active profile, one function
// installs it, one function reads it, one function gates each call.
//
//	pq.SetActive(pq.Strict())                          // chain bootstrap
//	if err := pq.Refuse(pq.OpEcrecover); err != nil    // every precompile
//
// Profile values are immutable. Two helpers construct the canonical
// presets:
//
//   - [Strict]      forbids every classical primitive family
//   - [Permissive]  admits every operation
//
// [Profile.Hash] is the SHA3-256 of the canonical encoding. Consensus
// emits this hash into block headers so any observer can verify which
// profile a block was produced under.
//
// Environment override: when QUASAR_STRICT_PQ is set to a truthy
// value, [FromEnv] returns [Strict]; otherwise it returns [Permissive].
// Mainnet binaries set this in their entrypoint.
package pq
