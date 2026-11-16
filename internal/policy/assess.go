package policy

import (
	"sealpath/internal/model"
	"strings"
)

func Assess(p model.Policy, a model.Artifact, s model.Signature, cert model.Certificate) []model.Check {
	checks := []model.Check{}
	add := func(code string, passed bool, detail string) {
		status := "fail"
		if passed {
			status = "pass"
		}
		checks = append(checks, model.Check{Code: code, Status: status, Detail: detail})
	}
	allowed := false
	for _, algorithm := range p.Algorithms {
		if s.Algorithm == algorithm {
			allowed = true
		}
	}
	add("algorithm", allowed, "signature algorithm compared with the selected policy")
	add("artifact_size", a.Size <= p.MaxArtifactBytes, "artifact size compared with the selected policy")
	add("subject", p.SubjectContains == "" || strings.Contains(cert.Subject, p.SubjectContains), "signer subject compared with the selected policy")
	return checks
}
