package pq

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
)

// stderr is the destination for the deprecation warning emitted by the
// package-level shims. It is unexported; tests that call the shims
// will receive one stderr line per process.
var stderr = os.Stderr

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

// RefuseUnder reports whether p admits op. Returns nil when admissible
// (including when p is nil — classical semantics) or family-specific
// error otherwise. RefuseUnder(OpUnknown) always returns nil.
//
// This is the canonical, per-profile gate. Callers should hold a
// *Profile (typically from chain config) and call this method directly.
func (p *Profile) RefuseUnder(op Op) error {
	if p == nil || !p.Forbids(op) {
		return nil
	}
	return errorFor(op)
}

// active holds a deprecated, package-level profile.
//
// Deprecated: a process-global profile is wrong for multi-chain hosts
// (last-writer-wins). Hold a *Profile per chain (e.g. on ChainConfig)
// and call (*Profile).RefuseUnder directly. The package-level state is
// retained as a compatibility shim only.
var active atomic.Pointer[Profile]

// warnOnce guards the one-shot deprecation warning emitted from each
// shim. We do not import a logger here (pq has no log dep); the message
// is written to standard error so misuse is loud but harmless.
var warnOnce sync.Once

func warnDeprecated() {
	warnOnce.Do(func() {
		// stderr write avoids a logger dependency; one line per process.
		const msg = "pq: package-global active profile is deprecated; use per-chain ChainConfig.PQ and (*Profile).RefuseUnder instead\n"
		// stderr write is best-effort.
		_, _ = stderr.Write([]byte(msg))
	})
}

// SetActive installs the package-level profile.
//
// Deprecated: store the profile per chain (e.g. ChainConfig.PQ) and use
// (*Profile).RefuseUnder. The package-global path has last-writer-wins
// semantics across chains hosted in one process.
func SetActive(p *Profile) {
	warnDeprecated()
	active.Store(p)
}

// Active returns the package-level profile, or nil if none has been
// installed (classical semantics).
//
// Deprecated: see [SetActive].
func Active() *Profile {
	warnDeprecated()
	return active.Load()
}

// Refuse reports whether the package-level profile admits op.
//
// Deprecated: call (*Profile).RefuseUnder on the per-chain profile.
// Retained as a shim that reads the deprecated package-level state.
func Refuse(op Op) error {
	warnDeprecated()
	return active.Load().RefuseUnder(op)
}
