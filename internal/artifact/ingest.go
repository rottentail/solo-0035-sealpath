package artifact

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"strings"
	"time"
)

const MaxBytes = 4 * 1024 * 1024

type Service struct{ Store *repository.Store }
type Request struct {
	Name           string `json:"name"`
	MediaType      string `json:"media_type"`
	Content        []byte `json:"content"`
	ExpectedDigest string `json:"expected_digest"`
}

func (s Service) Import(input Request) (model.Artifact, error) {
	var out model.Artifact
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 200 {
		return out, model.Invalid("artifact name must contain 1-200 characters")
	}
	if len(input.Content) == 0 || len(input.Content) > MaxBytes {
		return out, model.Invalid("artifact content must contain 1-4194304 bytes")
	}
	id := codec.Digest(input.Content)
	if input.ExpectedDigest != "" && input.ExpectedDigest != id {
		return out, model.Invalid("artifact digest does not match content")
	}
	if input.MediaType == "" {
		input.MediaType = "application/octet-stream"
	}
	out = model.Artifact{ID: id, Name: input.Name, MediaType: input.MediaType, Content: input.Content, Size: len(input.Content), ReceivedAt: time.Now().UTC()}
	err := s.Store.Update("artifact.accepted", id, func(st *model.State) error {
		if existing, ok := st.Artifacts[id]; ok {
			out = existing
			return nil
		}
		var used int
		for _, a := range st.Artifacts {
			used += a.Size
		}
		if used+out.Size > 64*1024*1024 {
			return model.Conflict("artifact capacity exhausted")
		}
		st.Artifacts[id] = out
		return nil
	})
	return out, err
}
