package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func Verify(cert *x509.Certificate, algorithm string, content, value []byte) error {
	digest := sha256.Sum256(content)
	switch algorithm {
	case "ed25519":
		key, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, content, value) {
			return fmt.Errorf("Ed25519 signature is invalid")
		}
	case "rsa_pss_sha256":
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 1<<11 {
			return fmt.Errorf("RSA signing key must contain at least 2^11 bits")
		}
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("RSA-PSS signature is invalid")
		}
	case "ecdsa_sha256":
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve.Params().BitSize < 256 || !ecdsa.VerifyASN1(key, digest[:], value) {
			return fmt.Errorf("ECDSA signature is invalid")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %q", algorithm)
	}
	return nil
}
