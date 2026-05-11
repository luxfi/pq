package annulus

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Profile selects which classical operations the strict-PQ boundary
// admits. A profile is a small immutable value; it is safe to copy
// freely and to publish in block headers via [Profile.Hash].
//
// Each Forbid* flag corresponds to a [Category]. When a flag is true,
// [Refuse] rejects every [Op] whose [CategoryOf] is that category.
type Profile struct {
	// StrictPQ records whether this profile claims to be a strict
	// post-quantum profile. Setting it forces all Forbid* flags to true
	// via [Profile.Canonical]; observers verify both invariants.
	StrictPQ bool

	// ForbidECDSAContractAuth blocks ECDSA-based signature verification
	// in contract execution and direct precompile calls. Includes
	// secp256k1 recovery, generic ECDSA verify, and Schnorr.
	ForbidECDSAContractAuth bool

	// ForbidClassicalSignatures blocks Ed25519 and X25519 — classical
	// asymmetric primitives outside the ECDSA family.
	ForbidClassicalSignatures bool

	// ForbidPairingPrecompiles blocks alt_bn128 and BLS12-381 pairing
	// operations, including BLS aggregate signatures that rely on them.
	ForbidPairingPrecompiles bool

	// ForbidKZGPrecompiles blocks EIP-4844-style point evaluation.
	ForbidKZGPrecompiles bool

	// ForbidClassicalSNARKs blocks pairing-based proof verifiers
	// (Groth16, Plonk, Marlin). STARK and FRI verifiers are not
	// constrained by this flag.
	ForbidClassicalSNARKs bool

	// ForbidNonSHA3Hashes blocks SHA-256, RIPEMD-160, BLAKE2, and
	// Keccak-256 precompiles. The strict profile permits only the
	// NIST-standard SHA3 family.
	ForbidNonSHA3Hashes bool
}

// Strict returns the canonical strict-PQ profile. All Forbid* flags
// are set; StrictPQ is true. Mainnet builds use this profile.
func Strict() Profile {
	return Profile{
		StrictPQ:                  true,
		ForbidECDSAContractAuth:   true,
		ForbidClassicalSignatures: true,
		ForbidPairingPrecompiles:  true,
		ForbidKZGPrecompiles:      true,
		ForbidClassicalSNARKs:     true,
		ForbidNonSHA3Hashes:       true,
	}
}

// Permissive returns a profile that admits every operation. Test
// networks that retain legacy contracts use this profile.
func Permissive() Profile { return Profile{} }

// Canonical normalises a profile: when StrictPQ is true, every Forbid*
// flag is forced to true. A profile that claims strict-PQ but omits a
// forbidden category is not well-formed; consensus rejects it via
// [Profile.Valid].
func (p Profile) Canonical() Profile {
	if !p.StrictPQ {
		return p
	}
	return Strict()
}

// Valid reports whether a profile is internally consistent. A strict
// profile must forbid every category; a non-strict profile is always
// valid.
func (p Profile) Valid() bool {
	if !p.StrictPQ {
		return true
	}
	return p == Strict()
}

// Forbids reports whether the profile rejects the given category.
func (p Profile) Forbids(cat Category) bool {
	switch cat {
	case CatECDSAContractAuth:
		return p.ForbidECDSAContractAuth
	case CatClassicalSig:
		return p.ForbidClassicalSignatures
	case CatPairingPrecompile:
		return p.ForbidPairingPrecompiles
	case CatKZGPrecompile:
		return p.ForbidKZGPrecompiles
	case CatClassicalSNARK:
		return p.ForbidClassicalSNARKs
	case CatNonSHA3Hash:
		return p.ForbidNonSHA3Hashes
	default:
		return false
	}
}

// Encode returns the canonical 8-byte encoding of a profile. Layout:
//
//	byte 0  bitfield: bit0 StrictPQ, bit1..6 Forbid* in declaration order.
//	byte 1  version (currently 1).
//	bytes 2..7 reserved, must be zero.
//
// Encoding is stable across releases; new fields extend the reserved
// tail and bump the version.
func (p Profile) Encode() [8]byte {
	var b [8]byte
	if p.StrictPQ {
		b[0] |= 1 << 0
	}
	if p.ForbidECDSAContractAuth {
		b[0] |= 1 << 1
	}
	if p.ForbidClassicalSignatures {
		b[0] |= 1 << 2
	}
	if p.ForbidPairingPrecompiles {
		b[0] |= 1 << 3
	}
	if p.ForbidKZGPrecompiles {
		b[0] |= 1 << 4
	}
	if p.ForbidClassicalSNARKs {
		b[0] |= 1 << 5
	}
	if p.ForbidNonSHA3Hashes {
		b[0] |= 1 << 6
	}
	b[1] = profileVersion
	return b
}

// Hash returns the SHA3-256 of the canonical encoding. Block producers
// publish this hash so observers can confirm which profile the block
// was produced under.
func (p Profile) Hash() [32]byte {
	enc := p.Encode()
	return sha3.Sum256(enc[:])
}

// DecodeProfile reconstructs a profile from its canonical encoding.
// It returns the zero profile and false when the version is unknown
// or reserved bits are set.
func DecodeProfile(b [8]byte) (Profile, bool) {
	if b[1] != profileVersion {
		return Profile{}, false
	}
	for i := 2; i < 8; i++ {
		if b[i] != 0 {
			return Profile{}, false
		}
	}
	p := Profile{
		StrictPQ:                  b[0]&(1<<0) != 0,
		ForbidECDSAContractAuth:   b[0]&(1<<1) != 0,
		ForbidClassicalSignatures: b[0]&(1<<2) != 0,
		ForbidPairingPrecompiles:  b[0]&(1<<3) != 0,
		ForbidKZGPrecompiles:      b[0]&(1<<4) != 0,
		ForbidClassicalSNARKs:     b[0]&(1<<5) != 0,
		ForbidNonSHA3Hashes:       b[0]&(1<<6) != 0,
	}
	return p, true
}

const profileVersion = 1

// HashUint returns the first 8 bytes of [Profile.Hash] as a uint64.
// Convenience for log lines and short comparisons; never for security
// decisions.
func (p Profile) HashUint() uint64 {
	h := p.Hash()
	return binary.BigEndian.Uint64(h[:8])
}
