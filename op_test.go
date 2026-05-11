package annulus

import "testing"

// Every recognised op must belong to a known category. A new op that
// arrives without a category falls through to OpUnknown and silently
// bypasses every profile — this test refuses that drift.
func TestEveryOpHasCategory(t *testing.T) {
	for op := range opName {
		if op == OpUnknown {
			continue
		}
		if CategoryOf(op) == CatUnknown {
			t.Errorf("op %s has no category", op)
		}
	}
}

func TestStringRoundTrip(t *testing.T) {
	cases := []Op{
		ECDSARecover, ECDSAVerify, Ed25519, X25519,
		BN254Pairing, BLS12381Pair, BLSSignature,
		KZGEval, Groth16, Plonk, Marlin,
		SHA256, RIPEMD160, Blake2b, Blake2s, Keccak256,
	}
	for _, op := range cases {
		if s := op.String(); s == "" || s == "unknown" {
			t.Errorf("op %d rendered as %q", op, s)
		}
	}
}

func TestUnknownOpRenders(t *testing.T) {
	op := Op(0xffff)
	if got := op.String(); got != "Op(0xffff)" {
		t.Errorf("got %q want Op(0xffff)", got)
	}
}

func TestCategoryOfClosed(t *testing.T) {
	if CategoryOf(Op(0xffff)) != CatUnknown {
		t.Error("unknown op should be CatUnknown")
	}
	if CategoryOf(OpUnknown) != CatUnknown {
		t.Error("OpUnknown should be CatUnknown")
	}
}
