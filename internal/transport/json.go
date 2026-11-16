package transport

import (
	"encoding/json"
	"net/http"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"strconv"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func readJSON(r *http.Request, value any) error {
	if content := r.Header.Get("Content-Type"); content != "application/json" && content != "application/json; charset=utf-8" {
		return model.Invalid("Content-Type must be application/json")
	}
	if err := codec.DecodeStrict(r.Body, value); err != nil {
		return model.Invalid("%v", err)
	}
	return nil
}
func page(r *http.Request) (int, int, error) {
	limit, after := 100, 0
	var err error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 500 {
			return 0, 0, model.Invalid("limit must be in 1-500")
		}
	}
	if value := r.URL.Query().Get("after"); value != "" {
		after, err = strconv.Atoi(value)
		if err != nil || after < 0 {
			return 0, 0, model.Invalid("after must be nonnegative")
		}
	}
	return limit, after, nil
}
