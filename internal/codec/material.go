package codec

import (
	"fmt"
	"sealpath/internal/model"
)

// ValidateRevocations checks the unsigned index fields against signed DER before
// any selection by issuer, sequence or time can depend on those fields.
func ValidateRevocations(values map[string]model.RevocationList, certificates map[string]model.Certificate) error {
	for id, value := range values {
		list, err := ParseCRL(value.DER)
		if err != nil || value.ID != id || Digest(value.DER) != id {
			return fmt.Errorf("CRL content identity is inconsistent: %s", id)
		}
		if value.Number != list.Number.String() || !value.ThisUpdate.Equal(list.ThisUpdate) || !value.NextUpdate.Equal(list.NextUpdate) {
			return fmt.Errorf("CRL index does not match signed content: %s", id)
		}
		issuer, ok := certificates[value.IssuerID]
		if !ok {
			return fmt.Errorf("CRL issuer is absent: %s", id)
		}
		cert, err := ParseCertificate(issuer.DER)
		if err != nil || !cert.IsCA || Digest(issuer.DER) != value.IssuerID || list.CheckSignatureFrom(cert) != nil {
			return fmt.Errorf("CRL issuer binding is invalid: %s", id)
		}
	}
	return nil
}
