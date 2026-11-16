package transport

import (
	"net/http"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sort"
)

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var input model.VerifyRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Verifier.Verify(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) listDecisions(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, after, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	ids := []string{}
	for id := range state.Decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if after > len(ids) {
		after = len(ids)
	}
	end := after + limit
	if end > len(ids) {
		end = len(ids)
	}
	values := []model.Decision{}
	for _, id := range ids[after:end] {
		values = append(values, state.Decisions[id])
	}
	writeJSON(w, 200, values)
}
func (s *Server) getDecision(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.Decisions[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("decision", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}
func (s *Server) exportBundle(w http.ResponseWriter, r *http.Request) {
	out, err := s.Evidence.Export(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	var input model.Bundle
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := evidence.Replay(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	out, err := s.Evidence.Compare(r.URL.Query().Get("left"), r.URL.Query().Get("right"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
