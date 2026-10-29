package core

import (
	"strings"
	"testing"
)

func TestBoardTracksCandidateProvenanceAndFlagProgress(t *testing.T) {
	board := NewBoard(&Challenge{ID: "multi", FlagCount: 2})
	if board.Phase != "scope" || board.FlagCount != 2 {
		t.Fatalf("initial workflow state=%+v", board)
	}
	board.AddCandidate("flag{one}", "r1-s2-c1", "http", "url=/api", "flag{one}")
	if !board.SetCandidateStatus("flag{one}", "submitted") || board.Candidates[0].Status != "submitted" {
		t.Fatalf("candidate did not enter submitted state: %+v", board.Candidates[0])
	}
	board.SetPhase("proof")
	board.RecordFlag("flag{one}", true)
	if board.Candidates[0].Status != "accepted" || board.SolvedFlags() != 1 || board.Phase != "flag_progress" {
		t.Fatalf("first accepted candidate state=%+v", board)
	}
	board.AddCandidate("flag{two}", "r1-s4-c1", "read", "path=flag.txt", "flag{two}")
	board.RecordFlag("flag{two}", true)
	if board.SolvedFlags() != 2 || board.Phase != "complete" {
		t.Fatalf("multi-flag completion state=%+v", board)
	}
	if !strings.Contains(board.Situation(2000), "2/2") || !strings.Contains(board.Situation(2000), "r1-s4-c1") {
		t.Fatal("Situation omitted flag count or provenance")
	}
}

func TestBoardCloneDoesNotShareHints(t *testing.T) {
	board := NewBoard(&Challenge{ID: "clone", Meta: map[string]string{"platform_hint": "declared"}})
	copy := board.Clone()
	copy.Hints["platform_hint"] = "changed"
	if board.Hints["platform_hint"] != "declared" {
		t.Fatalf("clone mutation changed source Board hint: %q", board.Hints["platform_hint"])
	}
}
