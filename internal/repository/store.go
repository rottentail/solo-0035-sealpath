package repository

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sealpath/internal/model"
	"sync"
	"time"
)

type Store struct {
	mu    sync.RWMutex
	path  string
	state model.State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: model.NewState()}
	if path == "" {
		return nil, fmt.Errorf("state path is required")
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("invalid persisted state: %w", err)
	}
	if err = ValidateState(s.state); err != nil {
		return nil, err
	}
	return s, nil
}
func clone(value model.State) (model.State, error) {
	var out model.State
	data, err := json.Marshal(value)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(data, &out)
	return out, err
}
func (s *Store) Snapshot() (model.State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.state)
}
func (s *Store) Update(kind, id string, fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := clone(s.state)
	if err != nil {
		return err
	}
	if err = fn(&next); err != nil {
		return err
	}
	next.Sequence++
	next.Events = append(next.Events, model.Event{Sequence: next.Sequence, Kind: kind, ObjectID: id, At: time.Now().UTC()})
	if err = ValidateState(next); err != nil {
		return fmt.Errorf("state invariant: %w", err)
	}
	if err = s.persist(next); err != nil {
		return err
	}
	s.state = next
	return nil
}
func (s *Store) persist(value model.State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	pending, err := os.CreateTemp(filepath.Dir(s.path), ".sealpath-*.tmp")
	if err != nil {
		return err
	}
	name := pending.Name()
	defer os.Remove(name)
	if err = pending.Chmod(0600); err == nil {
		_, err = pending.Write(data)
	}
	if err == nil {
		err = pending.Sync()
	}
	closeErr := pending.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}
