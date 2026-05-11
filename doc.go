// Package pq defines the strict post-quantum profile that
// constrains which cryptographic operations a Quasar node accepts.
//
// The package contains no cryptographic primitives. It expresses a
// policy: a [Profile] value enumerates which classical operations
// are forbidden, and [Refuse] reports whether a given [Op] is
// admissible under the profile currently bound to a [context.Context].
//
// Policy and enforcement are decomplected. Each implementation of a
// constrained operation (an ECDSA precompile, a pairing precompile, a
// classical SNARK verifier) calls [Refuse] once at the top of its
// entry point and otherwise proceeds independently. The profile does
// not know how those operations compute; the operations do not know
// how the profile selects them.
//
// Profile values are immutable. Two helpers construct the canonical
// preset profiles:
//
//   - [Strict]      enforces the strict-PQ boundary: forbids classical
//                   asymmetric primitives (ECDSA, X25519, Ed25519),
//                   pairing-based curves, KZG point evaluation,
//                   classical SNARKs, and non-SHA3 hash functions.
//   - [Permissive]  permits all operations; the default for unbound
//                   contexts and for testnets that admit legacy
//                   contracts.
//
// A profile's [Profile.Hash] is the SHA3-256 of its canonical byte
// encoding. Consensus emits this hash into block headers so any
// observer can verify which profile a block was produced under.
//
// The active profile is bound to a context via [WithProfile] and
// retrieved via [FromContext]. Tests and isolated subsystems may
// pass an explicit profile to [Refuse] without involving a context.
//
// Environment override: when QUASAR_STRICT_PQ is set to a truthy
// value, [ProfileFromEnv] returns [Strict]; otherwise it returns
// [Permissive]. Mainnet binaries set this in their startup path.
package pq
