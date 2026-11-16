package authority

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"time"
)

type Service struct{ Store *repository.Store }

func (s Service) ImportCertificate(data []byte) (model.Certificate, error) {
	c, err := codec.ParseCertificate(data)
	if err != nil {
		return model.Certificate{}, err
	}
	id := codec.Digest(c.Raw)
	value := model.Certificate{ID: id, DER: c.Raw, Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: c.SerialNumber.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter, IsCA: c.IsCA, ReceivedAt: time.Now().UTC()}
	err = s.Store.Update("certificate.accepted", id, func(st *model.State) error {
		if existing, ok := st.Certificates[id]; ok {
			value = existing
			return nil
		}
		if len(st.Certificates) >= 4096 {
			return model.Conflict("certificate capacity exhausted")
		}
		st.Certificates[id] = value
		return nil
	})
	return value, err
}
