# pq

`pq` defines the strict post-quantum profile that constrains
which cryptographic operations a Quasar node accepts.

The package contains no cryptographic primitives. It expresses a
policy.

## Model

A `Profile` is a small immutable value whose flags enumerate which
classical operations are forbidden. `Refuse(ctx, op)` reports whether
a given operation is admissible under the profile bound to `ctx`.
Profiles serialise to eight canonical bytes; `Profile.Hash` is the
SHA3-256 of that encoding. Consensus emits the hash into block
headers so any observer can determine which profile produced a block.

Policy and enforcement are decomplected. Each constrained operation
(an ECDSA precompile, a pairing precompile, a Groth16 verifier) calls
`Refuse` once at the top of its entry point and otherwise proceeds in
its own lane. The profile does not know how the operations compute;
the operations do not know how the profile is selected.

## Profiles

| Profile | Construction | Effect |
|---|---|---|
| Strict | `pq.Strict()` | Forbids every classical category. |
| Permissive | `pq.Permissive()` | Admits every operation. |

A profile that sets `StrictPQ` but omits any individual `Forbid*` flag
is ill-formed. `Profile.Canonical` rewrites such a profile into the
canonical Strict form; `Profile.Valid` reports whether a profile is
already in canonical form.

## Categories

The `Category` type groups operations the same Forbid* flag governs:

| Category | Members |
|---|---|
| `CatECDSAContractAuth` | `ECDSARecover`, `ECDSAVerify`, `Schnorr` |
| `CatClassicalSig` | `Ed25519`, `X25519` |
| `CatPairingPrecompile` | `BN254Pairing`, `BLS12381Pair`, `BLSSignature` |
| `CatKZGPrecompile` | `KZGEval` |
| `CatClassicalSNARK` | `Groth16`, `Plonk`, `Marlin` |
| `CatNonSHA3Hash` | `SHA256`, `RIPEMD160`, `Blake2b`, `Blake2s`, `Keccak256` |

## Use

```go
import "github.com/luxfi/pq"

// Bind the active profile once at startup.
ctx := pq.WithProfile(context.Background(), pq.ProfileFromEnv())

// Each constrained primitive calls Refuse at the top of its Run.
func (p *kzgPointEval) Run(ctx context.Context, in []byte) ([]byte, error) {
    if err := pq.Refuse(ctx, pq.KZGEval); err != nil {
        return nil, err
    }
    // ... evaluation
}
```

## Environment

`QUASAR_STRICT_PQ=1` selects Strict at startup via `ProfileFromEnv`.
Mainnet binaries set this in their entrypoint. Any other value
(including absent) selects Permissive.

## Versioning

The canonical encoding is versioned. The current version is 1.
Adding new fields uses the reserved tail; changing the meaning of an
existing bit requires a version bump and a consensus-level upgrade.

## Tests

```
go test ./... -count=1
```

The strict and permissive profile hashes are pinned in
`profile_test.go`. A change to either is a consensus-breaking change.
