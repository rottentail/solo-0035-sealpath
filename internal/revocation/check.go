package revocation

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"time"
)

func Check(cert, issuer *x509.Certificate, lists map[string]model.RevocationList, at time.Time) (model.Check, string) {
	issuerID := codec.Digest(issuer.Raw)
	var chosen *model.RevocationList
	for _, item := range lists {
		if item.IssuerID != issuerID || item.ThisUpdate.After(at) {
			continue
		}
		number, ok := new(big.Int).SetString(item.Number, 10)
		if !ok {
			continue
		}
		if chosen == nil {
			copy := item
			chosen = &copy
			continue
		}
		old, _ := new(big.Int).SetString(chosen.Number, 10)
		if number.Cmp(old) > 0 {
			copy := item
			chosen = &copy
		}
	}
	if chosen == nil {
		return model.Check{Code: "revocation", Status: "unknown", Detail: "no issuer CRL exists at the requested time"}, ""
	}
	list, err := codec.ParseCRL(chosen.DER)
	if err != nil || codec.Digest(chosen.DER) != chosen.ID || list.CheckSignatureFrom(issuer) != nil {
		return model.Check{Code: "revocation", Status: "fail", Detail: "CRL material signature or identity is invalid"}, chosen.ID
	}
	if !at.Before(list.NextUpdate) {
		return model.Check{Code: "revocation", Status: "unknown", Detail: "issuer CRL has expired"}, chosen.ID
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 && !entry.RevocationTime.After(at) {
			return model.Check{Code: "revocation", Status: "fail", Detail: fmt.Sprintf("certificate %s was revoked at %s", cert.SerialNumber, entry.RevocationTime.UTC().Format(time.RFC3339))}, chosen.ID
		}
	}
	return model.Check{Code: "revocation", Status: "pass", Detail: "serial is absent from the valid issuer CRL"}, chosen.ID
}
