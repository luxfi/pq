package pq

import (
	"errors"
	"reflect"
	"testing"
)

// ── Presets ────────────────────────────────────────────────────────

func TestStrictForbidsAllFamilies(t *testing.T) {
	p := Strict()
	flags := map[string]bool{
		"Ecrecover":  p.ForbidEcrecover,
		"P256Verify": p.ForbidP256Verify,
		"SHA256":     p.ForbidSHA256,
		"RIPEMD160":  p.ForbidRIPEMD160,
		"Blake2F":    p.ForbidBlake2F,
		"Bn256":      p.ForbidBn256,
		"BLS12381":   p.ForbidBLS12381,
		"KZG":        p.ForbidKZG,
	}
	for name, v := range flags {
		if !v {
			t.Errorf("Strict().Forbid%s must be true", name)
		}
	}
}

func TestPermissiveForbidsNothing(t *testing.T) {
	p := Permissive()
	for op := range opName {
		if op == OpUnknown {
			continue
		}
		if p.Forbids(op) {
			t.Errorf("Permissive must not forbid %v", op)
		}
	}
}

// ── Forbids ────────────────────────────────────────────────────────

func TestNilProfileNeverForbids(t *testing.T) {
	var p *Profile
	for op := range opName {
		if p.Forbids(op) {
			t.Errorf("nil profile must not forbid %v", op)
		}
	}
}

func TestForbidsCoversAllOps(t *testing.T) {
	p := Strict()
	for op := range opName {
		if op == OpUnknown {
			continue
		}
		if !p.Forbids(op) {
			t.Errorf("Strict must forbid %v", op)
		}
	}
}

// ── Refuse + RefuseUnder ───────────────────────────────────────────

func TestRefuseUnderStrict(t *testing.T) {
	p := Strict()
	cases := []struct {
		op      Op
		wantErr error
	}{
		{OpEcrecover, ErrEcrecoverForbidden},
		{OpP256Verify, ErrP256VerifyForbidden},
		{OpSHA256, ErrSHA256Forbidden},
		{OpRIPEMD160, ErrRIPEMD160Forbidden},
		{OpBlake2F, ErrBlake2FForbidden},
		{OpBn256Add, ErrBn256Forbidden},
		{OpBn256ScalarMul, ErrBn256Forbidden},
		{OpBn256Pairing, ErrBn256Forbidden},
		{OpBLS12381G1Add, ErrBLS12381Forbidden},
		{OpBLS12381G1MSM, ErrBLS12381Forbidden},
		{OpBLS12381G2Add, ErrBLS12381Forbidden},
		{OpBLS12381G2MSM, ErrBLS12381Forbidden},
		{OpBLS12381Pairing, ErrBLS12381Forbidden},
		{OpBLS12381MapG1, ErrBLS12381Forbidden},
		{OpBLS12381MapG2, ErrBLS12381Forbidden},
		{OpKZGPointEval, ErrKZGForbidden},
	}
	for _, c := range cases {
		if err := p.RefuseUnder(c.op); !errors.Is(err, c.wantErr) {
			t.Errorf("Strict.RefuseUnder(%v) want %v, got %v", c.op, c.wantErr, err)
		}
	}
}

func TestRefuseUnderPermissive(t *testing.T) {
	p := Permissive()
	for op := range opName {
		if op == OpUnknown {
			continue
		}
		if err := p.RefuseUnder(op); err != nil {
			t.Errorf("Permissive.RefuseUnder(%v) want nil, got %v", op, err)
		}
	}
}

func TestRefuseUnderNilIsPermissive(t *testing.T) {
	var p *Profile
	for op := range opName {
		if err := p.RefuseUnder(op); err != nil {
			t.Errorf("nil.RefuseUnder(%v) want nil, got %v", op, err)
		}
	}
}

func TestRefuseUnknownOp(t *testing.T) {
	if err := Strict().RefuseUnder(OpUnknown); err != nil {
		t.Errorf("Strict.RefuseUnder(OpUnknown) want nil, got %v", err)
	}
	if err := Strict().RefuseUnder(Op(0xff)); err != nil {
		t.Errorf("Strict.RefuseUnder(Op(0xff)) want nil, got %v", err)
	}
}

// ── Active package-level profile ────────────────────────────────────

func resetActive(t *testing.T) {
	t.Helper()
	prev := Active()
	t.Cleanup(func() { SetActive(prev) })
}

func TestActiveRoundTrip(t *testing.T) {
	resetActive(t)
	p := &Profile{ForbidBn256: true}
	SetActive(p)
	if got := Active(); got != p {
		t.Fatalf("Active must return installed pointer")
	}
}

func TestRefuseReadsActive(t *testing.T) {
	resetActive(t)
	SetActive(Strict())
	if err := Refuse(OpEcrecover); !errors.Is(err, ErrEcrecoverForbidden) {
		t.Fatalf("Refuse must read Active; got %v", err)
	}
	SetActive(nil)
	if err := Refuse(OpEcrecover); err != nil {
		t.Fatalf("Refuse(nil active) want nil, got %v", err)
	}
}

// ── Encode / Decode / Hash ─────────────────────────────────────────

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []*Profile{
		Permissive(),
		Strict(),
		{ForbidEcrecover: true},
		{ForbidBn256: true, ForbidKZG: true},
		{ForbidSHA256: true, ForbidRIPEMD160: true, ForbidBlake2F: true},
	}
	for _, p := range cases {
		enc := p.Encode()
		dec, ok := DecodeProfile(enc)
		if !ok {
			t.Fatalf("decode failed for %+v", p)
		}
		if !reflect.DeepEqual(p, dec) {
			t.Errorf("round-trip mismatch\n got %+v\nwant %+v", dec, p)
		}
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	enc := Strict().Encode()
	enc[0] = 99
	if _, ok := DecodeProfile(enc); ok {
		t.Error("decode must reject unknown version")
	}
}

func TestDecodeRejectsReservedBytes(t *testing.T) {
	enc := Strict().Encode()
	enc[5] = 1
	if _, ok := DecodeProfile(enc); ok {
		t.Error("decode must reject non-zero reserved byte")
	}
}

func TestHashStable(t *testing.T) {
	if Strict().Hash() != Strict().Hash() {
		t.Error("Strict hash not stable")
	}
	if Strict().Hash() == Permissive().Hash() {
		t.Error("Strict and Permissive must hash differently")
	}
}

// The strict and permissive hashes are the consensus contract. A
// change to either is consensus-breaking and requires a
// canonical-encoding version bump.
func TestStrictHashLocked(t *testing.T) {
	got := Strict().Hash()
	want := [32]byte{
		// Version 2, flags 0xff, reserved zero — SHA3-256.
		0x9e, 0xfd, 0xbf, 0x42, 0x40, 0x85, 0xb0, 0x55,
		0x78, 0x66, 0xc2, 0x2b, 0x0a, 0x4e, 0x0c, 0x48,
		0xe2, 0xed, 0x90, 0xc8, 0xc9, 0xe3, 0xf6, 0x99,
		0xd1, 0x7a, 0x3e, 0x07, 0x83, 0xcb, 0x21, 0x28,
	}
	if got != want {
		t.Errorf("strict profile hash drift\n got %x\nwant %x", got, want)
	}
}

func TestPermissiveHashLocked(t *testing.T) {
	got := Permissive().Hash()
	want := [32]byte{
		// Version 2, flags 0x00, reserved zero — SHA3-256.
		0x25, 0x6f, 0x4d, 0xaa, 0x37, 0x54, 0x35, 0x49,
		0xe0, 0x6b, 0xd1, 0x01, 0xaa, 0xb7, 0xf2, 0x1a,
		0x9b, 0x9d, 0xff, 0x46, 0xd3, 0x22, 0xa9, 0x39,
		0x2e, 0x6b, 0x03, 0x5c, 0xf4, 0xf0, 0xf6, 0x38,
	}
	if got != want {
		t.Errorf("permissive profile hash drift\n got %x\nwant %x", got, want)
	}
}

// ── Op naming ──────────────────────────────────────────────────────

func TestStringStable(t *testing.T) {
	for op, want := range opName {
		if got := op.String(); got != want {
			t.Errorf("Op(%d).String() = %q, want %q", op, got, want)
		}
	}
}

func TestStringUnknown(t *testing.T) {
	if got := Op(0xff).String(); got != "Op(0xff)" {
		t.Errorf("got %q", got)
	}
}

// ── Env ────────────────────────────────────────────────────────────

func TestFromEnvTruthy(t *testing.T) {
	cases := []string{"1", "true", "TRUE", "yes", "Y", "on", "ON", " 1 "}
	for _, v := range cases {
		t.Setenv(EnvVar, v)
		if got := FromEnv(); !reflect.DeepEqual(got, Strict()) {
			t.Errorf("env=%q want Strict, got %+v", v, got)
		}
	}
}

func TestFromEnvFalsy(t *testing.T) {
	cases := []string{"", "0", "false", "no", "off", "anything"}
	for _, v := range cases {
		t.Setenv(EnvVar, v)
		if got := FromEnv(); !reflect.DeepEqual(got, Permissive()) {
			t.Errorf("env=%q want Permissive, got %+v", v, got)
		}
	}
}
