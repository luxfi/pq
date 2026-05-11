package annulus

import "fmt"

// Op enumerates the classical cryptographic operations a profile may
// forbid. Values are stable identifiers; their numeric ordering carries
// no semantic meaning and is part of the canonical profile encoding.
//
// Op values are categorical rather than per-precompile: a verifier for
// any ECDSA-over-secp256k1 signature, regardless of how it is invoked,
// reports the same [ECDSAVerify] op.
type Op uint16

// The complete set of recognized operations. Values are append-only;
// adding a new variant is a backward-compatible change to the wire
// format, removing one is not.
const (
	OpUnknown Op = 0

	// Asymmetric primitives over classical (non-PQ) groups.
	ECDSARecover Op = 0x0010 // EVM precompile 0x01 family.
	ECDSAVerify  Op = 0x0011 // Generic ECDSA signature verification.
	Ed25519      Op = 0x0012 // EdDSA over Curve25519.
	Schnorr      Op = 0x0013 // Schnorr signatures over a non-PQ group.
	X25519       Op = 0x0014 // ECDH on Curve25519.

	// Pairing-friendly curve operations.
	BN254Pairing  Op = 0x0020 // alt_bn128 pairing (EVM 0x08).
	BLS12381Pair  Op = 0x0021 // BLS12-381 pairing.
	BLSSignature  Op = 0x0022 // BLS aggregate / threshold signatures.

	// Polynomial commitment schemes that rely on pairings.
	KZGEval Op = 0x0030 // EIP-4844 point evaluation.

	// Classical SNARK verifiers.
	Groth16 Op = 0x0040
	Plonk   Op = 0x0041
	Marlin  Op = 0x0042

	// Non-SHA3 hash and compression functions. SHA256 itself is not
	// quantum-broken, but a strict-PQ profile demands a single
	// NIST-recommended primitive family (SHA3) for hash-of-everything
	// composability with the rest of the stack.
	SHA256     Op = 0x0050
	RIPEMD160  Op = 0x0051
	Blake2b    Op = 0x0052
	Blake2s    Op = 0x0053
	Keccak256  Op = 0x0054 // legacy Keccak (Ethereum) distinct from SHA3-256.
)

var opName = map[Op]string{
	OpUnknown:    "unknown",
	ECDSARecover: "ECDSARecover",
	ECDSAVerify:  "ECDSAVerify",
	Ed25519:      "Ed25519",
	Schnorr:      "Schnorr",
	X25519:       "X25519",
	BN254Pairing: "BN254Pairing",
	BLS12381Pair: "BLS12381Pair",
	BLSSignature: "BLSSignature",
	KZGEval:      "KZGEval",
	Groth16:      "Groth16",
	Plonk:        "Plonk",
	Marlin:       "Marlin",
	SHA256:       "SHA256",
	RIPEMD160:    "RIPEMD160",
	Blake2b:      "Blake2b",
	Blake2s:      "Blake2s",
	Keccak256:    "Keccak256",
}

// String returns the canonical name of an [Op]. Unknown values render
// as "Op(0x….)" so failures in unfamiliar callers remain identifiable.
func (o Op) String() string {
	if s, ok := opName[o]; ok {
		return s
	}
	return fmt.Sprintf("Op(0x%04x)", uint16(o))
}

// Category groups [Op] values into the boundary categories a [Profile]
// can forbid wholesale. A profile that forbids a category implicitly
// forbids every operation belonging to it.
type Category uint8

const (
	CatUnknown            Category = 0
	CatECDSAContractAuth  Category = 1 // ECDSARecover, ECDSAVerify, Schnorr.
	CatClassicalSig       Category = 2 // Ed25519, X25519 — non-ECDSA classical asymmetric.
	CatPairingPrecompile  Category = 3 // BN254Pairing, BLS12381Pair, BLSSignature.
	CatKZGPrecompile      Category = 4 // KZGEval.
	CatClassicalSNARK     Category = 5 // Groth16, Plonk, Marlin.
	CatNonSHA3Hash        Category = 6 // SHA256, RIPEMD160, Blake2*, Keccak256.
)

// category maps each op to its category. The mapping is closed: every
// known op belongs to exactly one category.
var category = map[Op]Category{
	ECDSARecover: CatECDSAContractAuth,
	ECDSAVerify:  CatECDSAContractAuth,
	Schnorr:      CatECDSAContractAuth,
	Ed25519:      CatClassicalSig,
	X25519:       CatClassicalSig,
	BN254Pairing: CatPairingPrecompile,
	BLS12381Pair: CatPairingPrecompile,
	BLSSignature: CatPairingPrecompile,
	KZGEval:      CatKZGPrecompile,
	Groth16:      CatClassicalSNARK,
	Plonk:        CatClassicalSNARK,
	Marlin:       CatClassicalSNARK,
	SHA256:       CatNonSHA3Hash,
	RIPEMD160:    CatNonSHA3Hash,
	Blake2b:      CatNonSHA3Hash,
	Blake2s:      CatNonSHA3Hash,
	Keccak256:    CatNonSHA3Hash,
}

// CategoryOf returns the category of an [Op]. [OpUnknown] and any
// unrecognized op return [CatUnknown].
func CategoryOf(op Op) Category { return category[op] }
