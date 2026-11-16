package codec

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sealpath/internal/model"
)

func Digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 || len(data) > 65536 {
		return nil, model.Invalid("certificate must contain 1-65536 bytes")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, model.Invalid("expected exactly one CERTIFICATE PEM block")
		}
		data = block.Bytes
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, model.Invalid("invalid X.509 certificate: %v", err)
	}
	if cert.SerialNumber.Sign() < 0 {
		return nil, model.Invalid("negative serial number")
	}
	return cert, nil
}
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	if len(data) == 0 || len(data) > 1048576 {
		return nil, model.Invalid("CRL must contain 1-1048576 bytes")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, model.Invalid("expected one X509 CRL PEM block")
		}
		data = block.Bytes
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, model.Invalid("invalid CRL: %v", err)
	}
	if crl.Number == nil || crl.Number.Sign() < 0 {
		return nil, model.Invalid("CRL number is required and nonnegative")
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		return nil, model.Invalid("CRL next_update must follow this_update")
	}
	return crl, nil
}
func DecodeCertificates(values map[string]model.Certificate) (map[string]*x509.Certificate, error) {
	result := map[string]*x509.Certificate{}
	for id, value := range values {
		cert, err := ParseCertificate(value.DER)
		if err != nil || Digest(value.DER) != id {
			return nil, fmt.Errorf("certificate material %s is inconsistent", id)
		}
		result[id] = cert
	}
	return result, nil
}
