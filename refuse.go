package pq

import (
	"errors"
	"sync/atomic"
)

// Family errors. Each names the specific primitive family it refuses;
// dashboards and replay tools attribute violations to the right family.
var (
	ErrEcrecoverForbidden  = errors.New("ecrecover forbidden by chain security profile (PQ)")
	ErrP256VerifyForbidden = errors.New("p256Verify forbidden by chain security profile (PQ)")
	ErrSHA256Forbidden     = errors.New("sha256 forbidden by chain security profile (PQ)")
	ErrRIPEMD160Forbidden  = errors.New("ripemd160 forbidden by chain security profile (PQ)")
	ErrBlake2FForbidden    = errors.New("blake2F forbidden by chain security profile (PQ)")
	ErrBn256Forbidden      = errors.New("alt_bn128 (BN254) family forbidden by chain security profile (PQ)")
	ErrBLS12381Forbidden   = errors.New("BLS12-381 family forbidden by chain security profile (PQ)")
	ErrKZGForbidden        = errors.New("KZG point evaluation forbidden by chain security profile (PQ)")
)

// errorFor returns the family-specific error for op, or nil if op is
// admissible or unknown.
func errorFor(op Op) error {
	switch op {
	case OpEcrecover:
		return ErrEcrecoverForbidden
	case OpP256Verify:
		return ErrP256VerifyForbidden
	case OpSHA256:
		return ErrSHA256Forbidden
	case OpRIPEMD160:
		return ErrRIPEMD160Forbidden
	case OpBlake2F:
		return ErrBlake2FForbidden
	case OpBn256Add, OpBn256ScalarMul, OpBn256Pairing:
		return ErrBn256Forbidden
	case OpBLS12381G1Add, OpBLS12381G1MSM,
		OpBLS12381G2Add, OpBLS12381G2MSM,
		OpBLS12381Pairing, OpBLS12381MapG1, OpBLS12381MapG2:
		return ErrBLS12381Forbidden
	case OpKZGPointEval:
		return ErrKZGForbidden
	}
	return nil
}

// active holds the package-level profile. nil = classical semantics.
var active atomic.Pointer[Profile]

// SetActive installs the package-level profile. Callers without
// context (EVM precompiles whose Run signature lacks ctx) read this.
// Call once at chain bootstrap.
func SetActive(p *Profile) { active.Store(p) }

// Active returns the package-level profile, or nil if none has been
// installed (classical semantics).
func Active() *Profile { return active.Load() }

// Refuse reports whether the active package-level profile admits op.
// Returns nil when admissible; family-specific error otherwise.
// Refuse(OpUnknown) always returns nil.
func Refuse(op Op) error { return RefuseUnder(active.Load(), op) }

// RefuseUnder is the context-free variant of [Refuse]: it consults the
// supplied profile directly. Suitable for tests and for subsystems
// that resolve the active profile through their own indirection.
func RefuseUnder(p *Profile, op Op) error {
	if p == nil || !p.Forbids(op) {
		return nil
	}
	return errorFor(op)
}
