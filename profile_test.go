package pq

import (
	"reflect"
	"testing"
)

func TestStrictForbidsAllCategories(t *testing.T) {
	p := Strict()
	cats := []Category{
		CatECDSAContractAuth,
		CatClassicalSig,
		CatPairingPrecompile,
		CatKZGPrecompile,
		CatClassicalSNARK,
		CatNonSHA3Hash,
	}
	for _, c := range cats {
		if !p.Forbids(c) {
			t.Errorf("strict profile should forbid category %d", c)
		}
	}
	if !p.StrictPQ {
		t.Error("Strict() must have StrictPQ=true")
	}
}

func TestPermissiveForbidsNothing(t *testing.T) {
	p := Permissive()
	cats := []Category{
		CatECDSAContractAuth, CatClassicalSig, CatPairingPrecompile,
		CatKZGPrecompile, CatClassicalSNARK, CatNonSHA3Hash,
	}
	for _, c := range cats {
		if p.Forbids(c) {
			t.Errorf("permissive profile must not forbid category %d", c)
		}
	}
	if p.StrictPQ {
		t.Error("Permissive() must have StrictPQ=false")
	}
}

func TestCanonicalStrictForcesAllFlags(t *testing.T) {
	p := Profile{StrictPQ: true} // missing all Forbid* flags
	got := p.Canonical()
	want := Strict()
	if got != want {
		t.Errorf("Canonical of bare strict\n got %+v\nwant %+v", got, want)
	}
}

func TestValid(t *testing.T) {
	if !Strict().Valid() {
		t.Error("Strict must be valid")
	}
	if !Permissive().Valid() {
		t.Error("Permissive must be valid")
	}
	// StrictPQ without all Forbid* flags is invalid.
	bad := Profile{StrictPQ: true, ForbidECDSAContractAuth: true}
	if bad.Valid() {
		t.Error("strict-but-not-canonical profile must be invalid")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []Profile{
		Permissive(),
		Strict(),
		{ForbidECDSAContractAuth: true},
		{ForbidPairingPrecompiles: true, ForbidKZGPrecompiles: true},
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
	enc[1] = 99
	if _, ok := DecodeProfile(enc); ok {
		t.Error("decode must reject unknown version")
	}
}

func TestDecodeRejectsReservedBytes(t *testing.T) {
	enc := Strict().Encode()
	enc[4] = 1 // reserved byte set
	if _, ok := DecodeProfile(enc); ok {
		t.Error("decode must reject non-zero reserved byte")
	}
}

func TestHashStableAcrossProfile(t *testing.T) {
	// Strict and Permissive must hash differently and stably.
	h1 := Strict().Hash()
	h2 := Permissive().Hash()
	if h1 == h2 {
		t.Fatal("Strict and Permissive must hash differently")
	}
	if h1 != Strict().Hash() {
		t.Error("Strict hash is not stable across calls")
	}
}

// The strict profile hash is part of the consensus contract; pin it.
// If this assertion changes, every consensus implementation that
// validates strict-PQ blocks must be updated in lockstep — and the
// canonical encoding must bump its version byte.
func TestStrictHashLocked(t *testing.T) {
	got := Strict().Hash()
	want := [32]byte{
		0x9d, 0x70, 0xa6, 0x92, 0x10, 0x3d, 0x09, 0x41,
		0x4f, 0xfb, 0x25, 0x77, 0xca, 0x53, 0x85, 0x2c,
		0x99, 0xb2, 0xd1, 0x3b, 0x98, 0x7c, 0x49, 0xf2,
		0x08, 0x52, 0x89, 0x9f, 0x9a, 0x0b, 0xe3, 0x48,
	}
	if got != want {
		t.Errorf("strict profile hash drift\n got %x\nwant %x", got, want)
	}
}

func TestPermissiveHashLocked(t *testing.T) {
	got := Permissive().Hash()
	want := [32]byte{
		0xcf, 0x7b, 0x7f, 0x49, 0xed, 0xca, 0xd4, 0x72,
		0x28, 0x38, 0x27, 0x7d, 0xd3, 0x10, 0xdc, 0xf6,
		0xa6, 0x1d, 0x05, 0x52, 0xce, 0x0f, 0x21, 0x16,
		0xad, 0x39, 0xc3, 0xdc, 0xd2, 0x3b, 0xd9, 0x16,
	}
	if got != want {
		t.Errorf("permissive profile hash drift\n got %x\nwant %x", got, want)
	}
}

func TestHashUintNonZero(t *testing.T) {
	if Strict().HashUint() == 0 {
		t.Error("strict hash uint must be non-zero")
	}
}
