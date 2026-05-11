package pq

import (
	"context"
	"errors"
	"testing"
)

func TestRefuseUnderStrict(t *testing.T) {
	p := Strict()
	forbidden := []Op{
		ECDSARecover, ECDSAVerify, Ed25519, X25519, Schnorr,
		BN254Pairing, BLS12381Pair, BLSSignature,
		KZGEval, Groth16, Plonk, Marlin,
		SHA256, RIPEMD160, Blake2b, Blake2s, Keccak256,
	}
	for _, op := range forbidden {
		err := RefuseUnder(p, op)
		if err == nil {
			t.Errorf("strict profile must refuse %s", op)
			continue
		}
		var v *Violation
		if !errors.As(err, &v) {
			t.Errorf("refuse of %s did not wrap *Violation: %v", op, err)
		}
	}
}

func TestRefuseUnderPermissive(t *testing.T) {
	p := Permissive()
	for op := range opName {
		if op == OpUnknown {
			continue
		}
		if err := RefuseUnder(p, op); err != nil {
			t.Errorf("permissive profile must allow %s; got %v", op, err)
		}
	}
}

func TestRefuseUnknownOpFails(t *testing.T) {
	err := RefuseUnder(Permissive(), Op(0xffff))
	if !errors.Is(err, ErrUnknownOp) {
		t.Errorf("expected ErrUnknownOp, got %v", err)
	}
}

func TestRefuseUsesContextProfile(t *testing.T) {
	ctx := WithProfile(context.Background(), Strict())
	if err := Refuse(ctx, KZGEval); err == nil {
		t.Error("strict context should refuse KZGEval")
	}
}

func TestRefuseDefaultsToPermissive(t *testing.T) {
	if err := Refuse(context.Background(), KZGEval); err != nil {
		t.Errorf("bare context defaults to permissive; got %v", err)
	}
}

func TestRefuseNilContextPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil context should panic")
		}
	}()
	_ = Refuse(nil, KZGEval) //nolint:staticcheck // intentional
}

func TestViolationCarriesProfileHash(t *testing.T) {
	p := Strict()
	err := RefuseUnder(p, KZGEval)
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("expected *Violation, got %v", err)
	}
	if v.Op != KZGEval {
		t.Errorf("violation op got %s want KZGEval", v.Op)
	}
	if v.Profile != p.Hash() {
		t.Errorf("violation profile hash mismatch")
	}
}

func TestMustRefusePanicsOnStrict(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustRefuse should panic on violation")
		}
	}()
	ctx := WithProfile(context.Background(), Strict())
	MustRefuse(ctx, KZGEval)
}

func TestMustRefuseSilentOnPermissive(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustRefuse should not panic under permissive; recovered %v", r)
		}
	}()
	MustRefuse(context.Background(), KZGEval)
}
