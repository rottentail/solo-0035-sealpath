package verification

import (
	"sealpath/internal/model"
	"sealpath/internal/repository"
)

type Service struct{ Store *repository.Store }

func (s Service) Verify(request model.VerifyRequest) (model.Decision, error) {
	var out model.Decision
	// Capture and persist under one repository revision so no policy or root edit can intervene.
	err := s.Store.Update("decision.recorded", request.SignatureID, func(st *model.State) error {
		material, pinned, err := Capture(*st, request)
		if err != nil {
			return err
		}
		out, err = Evaluate(material, pinned)
		if err != nil {
			return err
		}
		if old, ok := st.Decisions[out.ID]; ok {
			out = old
			return nil
		}
		st.Decisions[out.ID] = out
		st.Materials[out.ID] = material
		return nil
	})
	return out, err
}
