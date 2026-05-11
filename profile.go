package pq

import "golang.org/x/crypto/sha3"

// Profile selects which classical operations the strict-PQ boundary
// admits. A small immutable value; safe to copy and to publish in
// block headers via [Profile.Hash].
//
// Each Forbid* field names a cryptographic primitive family — not an
// abstract category. A chain operator typically sets every field at
// once via [Strict]; a nil profile means "admit every operation".
//
// Flag layout matches the EVM precompile addresses one-to-one so a
// node binary can install a profile, the EVM can refuse a precompile,
// and an observer can read [Profile.Hash] from a block header — all
// describing the same eight booleans.
type Profile struct {
	// Asymmetric signatures.
	ForbidEcrecover  bool // ecrecover at 0x01 (secp256k1 recovery)
	ForbidP256Verify bool // p256Verify at 0x100 (RIP-7212, secp256r1)

	// Non-SHA3 hash / compression precompiles.
	ForbidSHA256    bool // 0x02
	ForbidRIPEMD160 bool // 0x03
	ForbidBlake2F   bool // 0x09 (Blake2b compression — not BLAKE3)

	// Pairing-friendly curves, per family.
	ForbidBn256    bool // alt_bn128 at 0x06–0x08 (BN254)
	ForbidBLS12381 bool // EIP-2537 at 0x0b–0x11

	// Polynomial commitment.
	ForbidKZG bool // kzgPointEvaluation at 0x0a (Cancun)
}

// Strict returns the canonical strict-PQ profile: every Forbid* flag
// is true. Mainnet PQ chains install this.
func Strict() *Profile {
	return &Profile{
		ForbidEcrecover:  true,
		ForbidP256Verify: true,
		ForbidSHA256:     true,
		ForbidRIPEMD160:  true,
		ForbidBlake2F:    true,
		ForbidBn256:      true,
		ForbidBLS12381:   true,
		ForbidKZG:        true,
	}
}

// Permissive returns a profile with every Forbid* flag false. The zero
// value Profile{} is observationally equivalent and a nil *Profile is
// the canonical "no profile installed" state — all three admit every
// operation.
func Permissive() *Profile { return &Profile{} }

// Forbids reports whether the profile refuses op. A nil profile
// returns false (classical semantics).
func (p *Profile) Forbids(op Op) bool {
	if p == nil {
		return false
	}
	switch op {
	case OpEcrecover:
		return p.ForbidEcrecover
	case OpP256Verify:
		return p.ForbidP256Verify
	case OpSHA256:
		return p.ForbidSHA256
	case OpRIPEMD160:
		return p.ForbidRIPEMD160
	case OpBlake2F:
		return p.ForbidBlake2F
	case OpBn256Add, OpBn256ScalarMul, OpBn256Pairing:
		return p.ForbidBn256
	case OpBLS12381G1Add, OpBLS12381G1MSM,
		OpBLS12381G2Add, OpBLS12381G2MSM,
		OpBLS12381Pairing, OpBLS12381MapG1, OpBLS12381MapG2:
		return p.ForbidBLS12381
	case OpKZGPointEval:
		return p.ForbidKZG
	}
	return false
}

// Encode returns the canonical 16-byte encoding of a profile.
//
//	byte 0   version (currently 2)
//	byte 1   flags: bit i = the i'th Forbid* field
//	bytes 2..15  reserved, must be zero
//
// New primitive families extend the flags region; renaming or
// reordering fields requires a version bump.
func (p *Profile) Encode() [16]byte {
	var b [16]byte
	b[0] = profileVersion
	if p == nil {
		return b
	}
	var flags byte
	if p.ForbidEcrecover {
		flags |= 1 << 0
	}
	if p.ForbidP256Verify {
		flags |= 1 << 1
	}
	if p.ForbidSHA256 {
		flags |= 1 << 2
	}
	if p.ForbidRIPEMD160 {
		flags |= 1 << 3
	}
	if p.ForbidBlake2F {
		flags |= 1 << 4
	}
	if p.ForbidBn256 {
		flags |= 1 << 5
	}
	if p.ForbidBLS12381 {
		flags |= 1 << 6
	}
	if p.ForbidKZG {
		flags |= 1 << 7
	}
	b[1] = flags
	return b
}

// Hash returns the SHA3-256 of the canonical encoding. Block producers
// publish this hash so observers can confirm which profile a block
// was produced under.
func (p *Profile) Hash() [32]byte {
	enc := p.Encode()
	return sha3.Sum256(enc[:])
}

// DecodeProfile reconstructs a profile from its canonical encoding.
// Returns (nil, false) on unknown version or non-zero reserved bytes.
func DecodeProfile(b [16]byte) (*Profile, bool) {
	if b[0] != profileVersion {
		return nil, false
	}
	for i := 2; i < 16; i++ {
		if b[i] != 0 {
			return nil, false
		}
	}
	flags := b[1]
	p := &Profile{
		ForbidEcrecover:  flags&(1<<0) != 0,
		ForbidP256Verify: flags&(1<<1) != 0,
		ForbidSHA256:     flags&(1<<2) != 0,
		ForbidRIPEMD160:  flags&(1<<3) != 0,
		ForbidBlake2F:    flags&(1<<4) != 0,
		ForbidBn256:      flags&(1<<5) != 0,
		ForbidBLS12381:   flags&(1<<6) != 0,
		ForbidKZG:        flags&(1<<7) != 0,
	}
	return p, true
}

const profileVersion = 2
