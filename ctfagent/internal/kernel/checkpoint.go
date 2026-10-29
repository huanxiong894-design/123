package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ctfagent/internal/core"
)

const checkpointVersion = 1

// ChallengeCheckpoint 是一题的可恢复状态。Board 只含结构化事实、假设、产物和尝试，
// 不保存 cookie jar 或运行中 socket；恢复时重新获取目标连接并重建会话。
type ChallengeCheckpoint struct {
	Version     int           `json:"version"`
	Scope       string        `json:"scope,omitempty"`
	ChallengeID string        `json:"challenge_id"`
	Status      string        `json:"status"` // running | paused | solved
	Round       int           `json:"round"`
	NextRound   int           `json:"next_round"`
	Spent       time.Duration `json:"spent_ns,omitempty"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Summary     string        `json:"summary,omitempty"`
	Unverified  bool          `json:"unverified,omitempty"`
	Board       *core.Board   `json:"board,omitempty"`
}

// CheckpointStore writes one private, atomically-replaced JSON file per challenge.
type CheckpointStore struct {
	dir   string
	scope string
	mu    sync.Mutex
}

func NewCheckpointStore(dir string) (*CheckpointStore, error) {
	return NewScopedCheckpointStore(dir, "")
}

// NewScopedCheckpointStore keeps checkpoints from different platforms/campaigns from colliding.
func NewScopedCheckpointStore(dir, scope string) (*CheckpointStore, error) {
	dir = strings.TrimSpace(dir)
	scope = strings.TrimSpace(scope)
	if dir == "" {
		return nil, fmt.Errorf("checkpoint directory is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, err
	}
	return &CheckpointStore{dir: abs, scope: scope}, nil
}

func (s *CheckpointStore) Save(cp ChallengeCheckpoint) error {
	if strings.TrimSpace(cp.ChallengeID) == "" {
		return fmt.Errorf("checkpoint challenge id is empty")
	}
	if cp.Scope == "" {
		cp.Scope = s.scope
	}
	if cp.Scope != s.scope {
		return fmt.Errorf("checkpoint scope %q does not match store scope %q", cp.Scope, s.scope)
	}
	if cp.Round < 1 || cp.NextRound < 1 {
		return fmt.Errorf("checkpoint round numbers must be positive")
	}
	if cp.Spent < 0 {
		return fmt.Errorf("checkpoint spent time cannot be negative")
	}
	if cp.Status != "running" && cp.Status != "paused" && cp.Status != "solved" {
		return fmt.Errorf("invalid checkpoint status %q", cp.Status)
	}
	if cp.Version == 0 {
		cp.Version = checkpointVersion
	}
	if cp.Version != checkpointVersion {
		return fmt.Errorf("unsupported checkpoint version %d", cp.Version)
	}
	cp.UpdatedAt = time.Now().UTC()
	if cp.Board != nil {
		cp.Board = cp.Board.Clone()
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	name := s.fileName(cp.ChallengeID)
	tmp, err := os.CreateTemp(s.dir, ".checkpoint-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(s.dir, name)); err != nil {
		return err
	}
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s *CheckpointStore) LoadAll() (map[string]ChallengeCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	out := make(map[string]ChallengeCheckpoint)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "challenge-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var cp ChallengeCheckpoint
		if err := json.Unmarshal(b, &cp); err != nil {
			return nil, fmt.Errorf("read checkpoint %s: %w", e.Name(), err)
		}
		if cp.Version != checkpointVersion || cp.ChallengeID == "" || cp.Round < 1 || cp.NextRound < 1 || cp.Spent < 0 || (cp.Status != "running" && cp.Status != "paused" && cp.Status != "solved") {
			return nil, fmt.Errorf("invalid checkpoint metadata in %s", e.Name())
		}
		if e.Name() != s.fileNameFor(cp.Scope, cp.ChallengeID) {
			return nil, fmt.Errorf("checkpoint filename/id mismatch in %s", e.Name())
		}
		if cp.Scope != s.scope {
			continue
		}
		out[cp.ChallengeID] = cp
	}
	return out, nil
}

func (s *CheckpointStore) fileName(id string) string {
	return s.fileNameFor(s.scope, id)
}

func (s *CheckpointStore) fileNameFor(scope, id string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + id))
	return "challenge-" + hex.EncodeToString(sum[:12]) + ".json"
}

// Remove deletes a challenge checkpoint after an operator explicitly abandons it.
func (s *CheckpointStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, s.fileName(id)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
