package policy

import (
	"sealpath/internal/artifact"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"sort"
	"strings"
	"time"
)

type Service struct{ Store *repository.Store }
type Request struct {
	ID               string   `json:"id"`
	ExpectedVersion  int      `json:"expected_version"`
	Algorithms       []string `json:"algorithms"`
	Revocation       string   `json:"revocation"`
	MaxArtifactBytes int      `json:"max_artifact_bytes"`
	SubjectContains  string   `json:"subject_contains"`
}

func (s Service) Create(input Request) (model.Policy, error) {
	var out model.Policy
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	if input.Revocation != "required" && input.Revocation != "best_effort" {
		return out, model.Invalid("revocation must be required or best_effort")
	}
	if input.MaxArtifactBytes < 1 || input.MaxArtifactBytes > artifact.MaxBytes {
		return out, model.Invalid("invalid artifact byte limit")
	}
	if len(input.Algorithms) == 0 || len(input.Algorithms) > 3 {
		return out, model.Invalid("one to three algorithms are required")
	}
	algorithms := append([]string(nil), input.Algorithms...)
	sort.Strings(algorithms)
	for i, a := range algorithms {
		if a != "ed25519" && a != "rsa_pss_sha256" && a != "ecdsa_sha256" {
			return out, model.Invalid("unsupported algorithm %s", a)
		}
		if i > 0 && a == algorithms[i-1] {
			return out, model.Invalid("duplicate algorithm")
		}
	}
	if len(input.SubjectContains) > 200 || strings.ContainsAny(input.SubjectContains, "\r\n") {
		return out, model.Invalid("invalid subject constraint")
	}
	err := s.Store.Update("policy.versioned", input.ID, func(st *model.State) error {
		versions := st.Policies[input.ID]
		if len(versions) != input.ExpectedVersion {
			return model.Conflict("policy version changed")
		}
		out = model.Policy{ID: input.ID, Version: len(versions) + 1, Status: "active", Algorithms: algorithms, Revocation: input.Revocation, MaxArtifactBytes: input.MaxArtifactBytes, SubjectContains: input.SubjectContains, CreatedAt: time.Now().UTC()}
		st.Policies[input.ID] = append(versions, out)
		return nil
	})
	return out, err
}
func Select(st model.State, id string, version int) (model.Policy, error) {
	values := st.Policies[id]
	if len(values) == 0 {
		return model.Policy{}, model.Missing("policy", id)
	}
	if version == 0 {
		version = len(values)
	}
	if version < 1 || version > len(values) {
		return model.Policy{}, model.Missing("policy version", id)
	}
	return values[version-1], nil
}
