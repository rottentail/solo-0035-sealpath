package authority

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sort"
	"time"
)

type TrustRequest struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Roots            []string `json:"roots"`
	ExpectedRevision int      `json:"expected_revision"`
}

func (s Service) PutTrust(input TrustRequest) (model.TrustSet, error) {
	var out model.TrustSet
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	if input.Name == "" || len(input.Name) > 200 || len(input.Roots) == 0 || len(input.Roots) > 32 {
		return out, model.Invalid("name and 1-32 trust roots are required")
	}
	roots := append([]string(nil), input.Roots...)
	sort.Strings(roots)
	for i := 1; i < len(roots); i++ {
		if roots[i] == roots[i-1] {
			return out, model.Invalid("duplicate trust root")
		}
	}
	err := s.Store.Update("trust.revised", input.ID, func(st *model.State) error {
		current, exists := st.TrustSets[input.ID]
		if current.Revision != input.ExpectedRevision {
			return model.Conflict("trust set revision changed")
		}
		if exists && current.Status == "retired" {
			return model.Conflict("retired trust set cannot be edited")
		}
		for _, id := range roots {
			value, ok := st.Certificates[id]
			if !ok {
				return model.Missing("root certificate", id)
			}
			cert, err := codec.ParseCertificate(value.DER)
			if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
				return model.Invalid("trust root must be a self-signed CA")
			}
		}
		created := current.CreatedAt
		if !exists {
			created = time.Now().UTC()
		}
		out = model.TrustSet{ID: input.ID, Name: input.Name, Roots: roots, Revision: current.Revision + 1, Status: "active", CreatedAt: created}
		st.TrustSets[out.ID] = out
		return nil
	})
	return out, err
}
func (s Service) Retire(id string, revision int) (model.TrustSet, error) {
	var out model.TrustSet
	err := s.Store.Update("trust.retired", id, func(st *model.State) error {
		current, ok := st.TrustSets[id]
		if !ok {
			return model.Missing("trust set", id)
		}
		if current.Revision != revision {
			return model.Conflict("trust set revision changed")
		}
		if current.Status == "retired" {
			return model.Conflict("trust set is already retired")
		}
		current.Status = "retired"
		current.Revision++
		out = current
		st.TrustSets[id] = current
		return nil
	})
	return out, err
}
