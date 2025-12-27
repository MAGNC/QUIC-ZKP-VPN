package crypto

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Ensure MLDSASigner implements crypto.Signer
var _ crypto.Signer = (*MLDSASigner)(nil)

// MLDSASigner wraps an ML-DSA private key to implement crypto.Signer.
type MLDSASigner struct {
	priv *mldsa65.PrivateKey
	pub  *mldsa65.PublicKey
}

// NewMLDSASigner creates a new signer from a given private key.
func NewMLDSASigner(priv *mldsa65.PrivateKey) *MLDSASigner {
	return &MLDSASigner{
		priv: priv,
		pub:  priv.Public().(*mldsa65.PublicKey),
	}
}

// GenerateKey generates a new ML-DSA-65 key pair and returns the signer.
func GenerateKey() (*MLDSASigner, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MLDSASigner{
		priv: priv,
		pub:  pub,
	}, nil
}

// Public returns the public key.
func (s *MLDSASigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest.
// Note: ML-DSA signs the message directly in common usage, but crypto.Signer
// expects integration with TLS which might pass digests.
// For pure ML-DSA in TLS 1.3, the content to look at depends on integration.
// Here we assume 'digest' is the content to sign.
func (s *MLDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Delegate to the underlying implementation which satisfies crypto.Signer
	return s.priv.Sign(rand, digest, opts)
}

// Byte encoding helpers if needed
func (s *MLDSASigner) MarshalBinary() ([]byte, error) {
	return s.priv.MarshalBinary()
}

// PublicBytes returns the binary representation of the public key.
func (s *MLDSASigner) PublicBytes() ([]byte, error) {
	return s.pub.MarshalBinary()
}

// VerifyMLDSA verifies a signature given the public key bytes.
func VerifyMLDSA(pubBytes, msg, sig []byte) error {
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if !mldsa65.Verify(pk, msg, nil, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
