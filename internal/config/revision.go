package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var ErrRevisionConflict = errors.New("configuration revision does not match")

// Revision identifies the complete persisted configuration snapshot. It is
// an opaque concurrency token, not a promise that the data plane is healthy.
func Revision(cfg Config) string {
	data, _ := json.Marshal(cfg) // Config contains only JSON-encodable fields.
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (s *Store) GetWithRevision() (Config, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.cfg), Revision(s.cfg)
}

// UpdateIfRevision checks and writes under one lock. An empty expected value
// preserves compatibility with clients that do not send If-Match.
func (s *Store) UpdateIfRevision(expected string, fn func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != "" && expected != Revision(s.cfg) {
		return Config{}, ErrRevisionConflict
	}
	return s.updateLocked(fn)
}
