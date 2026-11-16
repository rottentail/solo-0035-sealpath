package revocation

import (
	"math/big"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"time"
)

type Service struct{ Store *repository.Store }

func (s Service) Import(issuerID string, data []byte) (model.RevocationList, error) {
	var out model.RevocationList
	list, err := codec.ParseCRL(data)
	if err != nil {
		return out, err
	}
	out = model.RevocationList{ID: codec.Digest(list.Raw), IssuerID: issuerID, DER: list.Raw, Number: list.Number.String(), ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate, ReceivedAt: time.Now().UTC()}
	err = s.Store.Update("revocation.accepted", out.ID, func(st *model.State) error {
		issuer, ok := st.Certificates[issuerID]
		if !ok {
			return model.Missing("CRL issuer", issuerID)
		}
		cert, err := codec.ParseCertificate(issuer.DER)
		if err != nil {
			return err
		}
		if !cert.IsCA || list.CheckSignatureFrom(cert) != nil {
			return model.Invalid("CRL issuer signature is invalid")
		}
		if existing, ok := st.Revocations[out.ID]; ok {
			out = existing
			return nil
		}
		for _, previous := range st.Revocations {
			if previous.IssuerID != issuerID {
				continue
			}
			n, _ := new(big.Int).SetString(previous.Number, 10)
			if n != nil && n.Cmp(list.Number) >= 0 {
				return model.Conflict("new CRL number must advance the issuer's sequence")
			}
			if list.ThisUpdate.Before(previous.ThisUpdate) {
				return model.Conflict("new CRL cannot move this_update backwards")
			}
		}
		st.Revocations[out.ID] = out
		return nil
	})
	return out, err
}
