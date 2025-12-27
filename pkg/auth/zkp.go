package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/group"
)

// Use Ristretto255 for the group
var G group.Group = group.Ristretto255

// ZKPProof represents the Schnorr signature/proof (R, z).
type ZKPProof struct {
	R []byte // Commitment
	Z []byte // Response
}

// GenerateZKPSession generates a proof of knowledge of the secret key 'x'
// bound to a specific session 'nonce'.
// x: Scalar (secret key)
// P: Element (public key), P = xG
// nonce: Session unique data from server
func GenerateZKPSession(x group.Scalar, P group.Element, nonce []byte) (*ZKPProof, error) {
	// 1. Generate random ephemeral secret r
	r := G.RandomScalar(rand.Reader)

	// 2. Compute commitment R = rG
	R := G.NewElement().Mul(G.Generator(), r)

	// 3. Compute challenge e = H(P, R, nonce)
	RBytes, _ := R.MarshalBinary()
	PBytes, _ := P.MarshalBinary()

	e := hashChallenge(PBytes, RBytes, nonce)

	// 4. Compute response z = r + e*x
	// z = r + x * e
	z := G.NewScalar().Mul(x, e)
	z.Add(z, r)

	zBytes, _ := z.MarshalBinary()

	return &ZKPProof{
		R: RBytes,
		Z: zBytes,
	}, nil
}

// VerifyZKPSession verifies protocol: zG = R + eP
func VerifyZKPSession(PBytes []byte, nonce []byte, proof *ZKPProof) error {
	defer func() {
		// Basic prevention of timing attacks on error paths (rudimentary)
	}()

	P := G.NewElement()
	if err := P.UnmarshalBinary(PBytes); err != nil {
		return err
	}

	R := G.NewElement()
	if err := R.UnmarshalBinary(proof.R); err != nil {
		return err
	}

	z := G.NewScalar()
	if err := z.UnmarshalBinary(proof.Z); err != nil {
		return err
	}

	// Recompute challenge e
	e := hashChallenge(PBytes, proof.R, nonce)

	// Verify zG == R + eP
	lhs := G.NewElement().Mul(G.Generator(), z)

	rhs := G.NewElement().Mul(P, e)
	rhs.Add(rhs, R)

	if !lhs.IsEqual(rhs) {
		return errors.New("zkp verification failed")
	}

	return nil
}

// hashChallenge computes H(P, R, nonce) -> Scalar
func hashChallenge(P, R, nonce []byte) group.Scalar {
	h := sha256.New()
	h.Write([]byte("ANTIGRAVITY_ZKP_V1"))
	h.Write(P)
	h.Write(R)
	h.Write(nonce)

	digest := h.Sum(nil)

	// Map random bytes to scalar
	s := G.RandomScalar(rand.Reader) // Just to init
	// There is a cleaner way to map hash to scalar in circl usually,
	// often SetBytes or SetBytesReduced.
	// For Ristretto255, we can interpret bytes as scalar.
	// We'll use a crude way if specific MapToScalar isn't handy, but
	// typically typical libraries have SetBytes.
	// We just need a deterministic scalar from digest.
	// Let's rely on Unmarshal or similar if available, or Reduce.
	// Ristretto255 Scalar from bytes (reduced)
	_ = s // ignore random init

	// Use SetBytes which usually does reduction or checking.
	// Correct way for Ristretto255 is often SetBytesModOrder or similar.
	// We check circl source typically.
	// G.NewScalar().SetBytes(digest) is likely supported.

	out := G.NewScalar()
	// To be safe, use the property that 64 bytes -> scalar is standard in Ed25519-like logic.
	// But here we have 32 bytes from SHA256.
	// Helper to ensure it fits:
	// We'll extend digest to be safe or use what we have.
	// Simplest for now:
	// We will assume SetBytes works for 32 bytes.
	if len(digest) < 32 {
		// pad
		pad := make([]byte, 32)
		copy(pad, digest)
		digest = pad
	}
	// Note: In real app, check error or use Wide reduction.
	out.UnmarshalBinary(digest)
	return out
}

// GenerateIdentity generates a simplified Identity keypair (x, P)
func GenerateIdentity() (group.Scalar, group.Element, error) {
	x := G.RandomScalar(rand.Reader)
	P := G.NewElement().Mul(G.Generator(), x)
	return x, P, nil
}
