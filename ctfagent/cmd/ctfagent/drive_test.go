package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ctfagent/internal/core"
)

func TestSafeMailboxID(t *testing.T) {
	a := safeMailboxID("../task/one")
	b := safeMailboxID("task_one")
	if strings.ContainsAny(a, "/\\") || strings.Contains(a, "..") {
		t.Fatalf("mailbox ID escaped path syntax: %q", a)
	}
	if a == b {
		t.Fatalf("distinct challenge IDs collided: %q", a)
	}
}

func TestSelectDriveChallengesPreservesExplicitFIFOOrder(t *testing.T) {
	input := []core.Challenge{{ID: "d-03"}, {ID: "d-01"}, {ID: "d-02"}}
	got, err := selectDriveChallenges(input, "d-01, d-02,d-03")
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{got[0].ID, got[1].ID, got[2].ID}
	if strings.Join(ids, ",") != "d-01,d-02,d-03" {
		t.Fatalf("explicit order lost: %v", ids)
	}
	if _, err := selectDriveChallenges(input, "d-01,d-01"); err == nil {
		t.Fatal("duplicate --only ID should fail")
	}
	if _, err := selectDriveChallenges(input, "d-99"); err == nil {
		t.Fatal("unknown --only ID should fail rather than silently skip")
	}
}

func TestBuildDriveAdapterAcceptsGenericPromptSpecs(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "practice.json")
	body := `{"id":"practice-web","title":"Synthetic web task","category":"web","prompt":"Inspect only the provided practice target.","targets":["http://127.0.0.1:8080"]}`
	if err := os.WriteFile(spec, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ad, err := buildDriveAdapter(context.Background(), &commonFlags{platform: "prompt", suite: filepath.Join(dir, "work")}, multiFlag{spec})
	if err != nil {
		t.Fatal(err)
	}
	if ad.Name() != "prompt" {
		t.Fatalf("expected generic prompt adapter, got %q", ad.Name())
	}
	challenges, err := ad.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(challenges) != 1 || challenges[0].ID != "practice-web" || len(challenges[0].Targets) != 1 {
		t.Fatalf("unexpected prompt challenges: %+v", challenges)
	}
}

func TestBuildDriveAdapterRejectsSpecsForOtherPlatforms(t *testing.T) {
	_, err := buildDriveAdapter(context.Background(), &commonFlags{platform: "local"}, multiFlag{"unused.json"})
	if err == nil || !strings.Contains(err.Error(), "仅适用于") {
		t.Fatalf("expected clear platform/spec error, got %v", err)
	}
}
