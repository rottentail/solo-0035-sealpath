package signature

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"time"
)

type Service struct{ Store *repository.Store }
type Request struct {
	ArtifactID    string `json:"artifact_id"`
	CertificateID string `json:"certificate_id"`
	Algorithm     string `json:"algorithm"`
	Value         []byte `json:"value"`
}

func (s Service) Import(input Request) (model.Signature, error) {
	var out model.Signature
	if len(input.Value) == 0 || len(input.Value) > 16384 {
		return out, model.Invalid("signature must contain 1-16384 bytes")
	}
	id, err := codec.JSONDigest(input)
	if err != nil {
		return out, err
	}
	err = s.Store.Update("signature.accepted", id, func(st *model.State) error {
		a, ok := st.Artifacts[input.ArtifactID]
		if !ok {
			return model.Missing("artifact", input.ArtifactID)
		}
		c, ok := st.Certificates[input.CertificateID]
		if !ok {
			return model.Missing("certificate", input.CertificateID)
		}
		cert, err := codec.ParseCertificate(c.DER)
		if err != nil {
			return err
		}
		if cert.IsCA {
			return model.Invalid("signer must be an end-entity certificate")
		}
		if err = Verify(cert, input.Algorithm, a.Content, input.Value); err != nil {
			return model.Invalid("%v", err)
		}
		if old, ok := st.Signatures[id]; ok {
			out = old
			return nil
		}
		out = model.Signature{ID: id, ArtifactID: input.ArtifactID, CertificateID: input.CertificateID, Algorithm: input.Algorithm, Value: input.Value, ReceivedAt: time.Now().UTC()}
		st.Signatures[id] = out
		return nil
	})
	return out, err
}
