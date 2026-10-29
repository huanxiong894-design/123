package llm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileChanMailboxWaitRedactAndValidatedReply(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-mailbox")
	fc, err := NewFileChan(root)
	if err != nil {
		t.Fatal(err)
	}
	fc.Timeout = 3 * time.Second
	fc.PollInterval = 5 * time.Millisecond
	tools := []Tool{{Name: "fact", Description: "record fact"}}
	result := make(chan Reply, 1)
	errCh := make(chan error, 1)
	go func() {
		reply, err := fc.Chat(context.Background(), Request{
			System: "safe system",
			Messages: []Message{
				{Role: "tool", Name: "http", Content: `{"password":"secret-value","flag":"flag{abcdef}"}`},
			},
			Tools: tools,
		})
		result <- reply
		errCh <- err
	}()

	summary, err := WaitPending(context.Background(), root, 2*time.Second, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Turn != 0 || len(summary.Tools) != 1 || summary.Tools[0] != "fact" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	preview, _ := json.Marshal(summary.Preview)
	for _, leaked := range []string{"secret-value", "flag{"} {
		if strings.Contains(string(preview), leaked) {
			t.Fatalf("preview leaked %q: %s", leaked, preview)
		}
	}
	reqInfo, err := os.Stat(summary.Path)
	if err != nil {
		t.Fatal(err)
	}
	if reqInfo.Mode().Perm() != 0o600 {
		t.Fatalf("request file mode = %o, want 600", reqInfo.Mode().Perm())
	}

	response := []byte(`{"content":"recorded","calls":[{"name":"fact","args":{"text":"verified"}}]}`)
	replyPath, calls, err := WriteMailboxReply(summary.Path, response)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || replyPath != summary.ReplyPath {
		t.Fatalf("reply path/calls = %q/%d", replyPath, calls)
	}
	replyInfo, err := os.Stat(replyPath)
	if err != nil {
		t.Fatal(err)
	}
	if replyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("reply file mode = %o, want 600", replyInfo.Mode().Perm())
	}
	select {
	case got := <-result:
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if got.Message.Content != "recorded" || len(got.Message.ToolCalls) != 1 || got.Message.ToolCalls[0].Name != "fact" {
			t.Fatalf("unexpected parsed reply: %+v", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("FileChan did not consume the atomic reply")
	}
}

func TestWriteMailboxReplyRejectsUnknownToolAndMalformedArgs(t *testing.T) {
	root := t.TempDir()
	req := requestFile{Turn: 0, Tools: []ToolBrief{{Name: "http"}}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "req-000.json")
	if err := os.WriteFile(requestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`{"content":"x","calls":[{"name":"sh","args":{}}]}`,
		`{"content":"x","calls":[{"name":"http","args":"not-object"}]}`,
		`{"content":"x","calls":[]} trailing`,
	} {
		if _, _, err := WriteMailboxReply(requestPath, []byte(invalid)); err == nil {
			t.Fatalf("expected invalid reply to be rejected: %s", invalid)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "reply-000.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid reply should not be written, stat error=%v", err)
	}
}
