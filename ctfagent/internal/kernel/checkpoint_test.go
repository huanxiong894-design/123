package kernel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ctfagent/internal/core"
)

func TestCheckpointStoreScopesSameChallengeID(t *testing.T) {
	dir := t.TempDir()
	local, err := NewScopedCheckpointStore(dir, "local")
	if err != nil {
		t.Fatal(err)
	}
	tsec, err := NewScopedCheckpointStore(dir, "tsec")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		store *CheckpointStore
		scope string
	}{
		{local, "local"}, {tsec, "tsec"},
	} {
		if err := item.store.Save(ChallengeCheckpoint{
			ChallengeID: "same-id", Status: "paused", Round: 1, NextRound: 2,
		}); err != nil {
			t.Fatal(err)
		}
		loaded, err := item.store.LoadAll()
		if err != nil {
			t.Fatal(err)
		}
		if got := loaded["same-id"].Scope; got != item.scope {
			t.Fatalf("scope=%q, want %q", got, item.scope)
		}
	}
}

func TestCheckpointStoreAtomicRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-checkpoints")
	store, err := NewCheckpointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	board := core.NewBoard(&core.Challenge{ID: "round-trip"})
	board.AddFact("service is reachable", "HTTP 200")
	cp := ChallengeCheckpoint{
		ChallengeID: "round-trip", Status: "paused", Round: 1, NextRound: 2,
		Spent: 7 * time.Minute, Summary: "continue in later round", Board: board,
	}
	if err := store.Save(cp); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".json" {
		t.Fatalf("expected one checkpoint file, got %v", entries)
	}
	info, err := os.Stat(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint permissions=%o, want 600", info.Mode().Perm())
	}
	loaded, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := loaded["round-trip"]
	if !ok || got.NextRound != 2 || got.Spent != 7*time.Minute || len(got.Board.Facts) != 1 {
		t.Fatalf("checkpoint round trip mismatch: %+v", got)
	}
}
