package pq

import "fmt"

// Op names a classical cryptographic primitive a profile may refuse.
// Op values are categorical at the precompile level: Byzantium and
// Istanbul variants of the same operation report the same Op.
//
// Stable identifiers. Append-only.
type Op uint8

// The complete set of recognised operations.
const (
	OpUnknown Op = iota

	// Asymmetric signatures.
	OpEcrecover  // ecrecover (0x01)
	OpP256Verify // p256Verify (0x100, RIP-7212)

	// Hash / compression.
	OpSHA256    // 0x02
	OpRIPEMD160 // 0x03
	OpBlake2F   // 0x09 (Blake2b compression — not BLAKE3)

	// alt_bn128 (BN254).
	OpBn256Add       // 0x06
	OpBn256ScalarMul // 0x07
	OpBn256Pairing   // 0x08

	// BLS12-381 (EIP-2537).
	OpBLS12381G1Add   // 0x0b
	OpBLS12381G1MSM   // 0x0c
	OpBLS12381G2Add   // 0x0d
	OpBLS12381G2MSM   // 0x0e
	OpBLS12381Pairing // 0x0f
	OpBLS12381MapG1   // 0x10
	OpBLS12381MapG2   // 0x11

	// Polynomial commitment.
	OpKZGPointEval // 0x0a (Cancun)
)

var opName = map[Op]string{
	OpUnknown:         "unknown",
	OpEcrecover:       "ecrecover",
	OpP256Verify:      "p256Verify",
	OpSHA256:          "sha256",
	OpRIPEMD160:       "ripemd160",
	OpBlake2F:         "blake2F",
	OpBn256Add:        "bn256Add",
	OpBn256ScalarMul:  "bn256ScalarMul",
	OpBn256Pairing:    "bn256Pairing",
	OpBLS12381G1Add:   "bls12381G1Add",
	OpBLS12381G1MSM:   "bls12381G1MSM",
	OpBLS12381G2Add:   "bls12381G2Add",
	OpBLS12381G2MSM:   "bls12381G2MSM",
	OpBLS12381Pairing: "bls12381Pairing",
	OpBLS12381MapG1:   "bls12381MapG1",
	OpBLS12381MapG2:   "bls12381MapG2",
	OpKZGPointEval:    "kzgPointEvaluation",
}

// String returns the canonical name of an op. Unknown values render
// as "Op(0xNN)" so failures in unfamiliar callers stay identifiable.
func (o Op) String() string {
	if s, ok := opName[o]; ok {
		return s
	}
	return fmt.Sprintf("Op(0x%02x)", uint8(o))
}
