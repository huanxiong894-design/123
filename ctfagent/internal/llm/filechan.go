package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ctfagent/internal/safety"
)

// FileChan is an external decision client: each solver turn is written to a
// private request file, then the solver waits for a validated reply file.
type FileChan struct {
	Dir            string
	Timeout        time.Duration // per-turn wait limit; zero relies on ctx
	PollInterval   time.Duration
	MalformedGrace time.Duration
	turn           int
}

func NewFileChan(dir string) (*FileChan, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &FileChan{Dir: abs, Timeout: 30 * time.Minute, PollInterval: 100 * time.Millisecond, MalformedGrace: 2 * time.Second}, nil
}

func (f *FileChan) Name() string { return "filechan" }

type requestFile struct {
	Turn     int         `json:"turn"`
	System   string      `json:"system"`
	Messages []Message   `json:"messages"`
	Tools    []ToolBrief `json:"tools"`
	Hint     string      `json:"hint"`
}

type ToolBrief struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type replyFile struct {
	Content string     `json:"content"`
	Calls   []callSpec `json:"calls"`
}

type callSpec struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// MailboxSummary is safe to print in a terminal: message text and tool arguments
// are redacted, while the raw request remains available in its owner-only file.
type MailboxSummary struct {
	Path      string    `json:"path"`
	Turn      int       `json:"turn"`
	Tools     []string  `json:"tools"`
	Preview   []Message `json:"preview"`
	ReplyPath string    `json:"reply_path"`
}

// WaitPending waits for the oldest unanswered req-*.json beneath root.
func WaitPending(ctx context.Context, root string, timeout, poll time.Duration) (MailboxSummary, error) {
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	var timer *time.Timer
	var timeoutC <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutC = timer.C
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if info, ok, err := findPending(root); err != nil {
			return MailboxSummary{}, err
		} else if ok {
			return summarizeRequest(info)
		}
		select {
		case <-ctx.Done():
			return MailboxSummary{}, ctx.Err()
		case <-timeoutC:
			return MailboxSummary{}, fmt.Errorf("等待 FileChan 请求超时：%s", root)
		case <-ticker.C:
		}
	}
}

type pendingInfo struct {
	path string
	mod  time.Time
}

func findPending(root string) (pendingInfo, bool, error) {
	var found []pendingInfo
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "req-") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		replyPath := filepath.Join(filepath.Dir(path), "reply-"+strings.TrimSuffix(strings.TrimPrefix(d.Name(), "req-"), ".json")+".json")
		if st, err := os.Stat(replyPath); err == nil && st.Size() > 0 {
			return nil
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		found = append(found, pendingInfo{path: path, mod: st.ModTime()})
		return nil
	})
	if err != nil {
		return pendingInfo{}, false, err
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].mod.Equal(found[j].mod) {
			return found[i].path < found[j].path
		}
		return found[i].mod.Before(found[j].mod)
	})
	if len(found) == 0 {
		return pendingInfo{}, false, nil
	}
	return found[0], true, nil
}

func summarizeRequest(info pendingInfo) (MailboxSummary, error) {
	var snap requestFile
	if err := readJSON(info.path, &snap); err != nil {
		return MailboxSummary{}, fmt.Errorf("读取请求 %s: %w", info.path, err)
	}
	tools := make([]string, 0, len(snap.Tools))
	for _, tool := range snap.Tools {
		tools = append(tools, tool.Name)
	}
	start := len(snap.Messages) - 4
	if start < 0 {
		start = 0
	}
	preview := append([]Message(nil), snap.Messages[start:]...)
	for i := range preview {
		preview[i].Content = safety.RedactSensitiveText(preview[i].Content)
		for j := range preview[i].ToolCalls {
			preview[i].ToolCalls[j].Args = safety.RedactSensitiveText(preview[i].ToolCalls[j].Args)
		}
	}
	return MailboxSummary{
		Path: info.path, Turn: snap.Turn, Tools: tools, Preview: preview,
		ReplyPath: filepath.Join(filepath.Dir(info.path), "reply-"+strings.TrimSuffix(strings.TrimPrefix(filepath.Base(info.path), "req-"), ".json")+".json"),
	}, nil
}

// WriteMailboxReply validates tool names and JSON object arguments against the
// request schema summary, then atomically writes a mode-0600 reply file.
func WriteMailboxReply(requestPath string, data []byte) (string, int, error) {
	var snap requestFile
	if err := readJSON(requestPath, &snap); err != nil {
		return "", 0, fmt.Errorf("读取请求: %w", err)
	}
	var reply replyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil {
		return "", 0, fmt.Errorf("回复 JSON 无效: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return "", 0, fmt.Errorf("回复 JSON 尾部无效: %w", err)
	}
	allowed := make(map[string]struct{}, len(snap.Tools))
	for _, tool := range snap.Tools {
		allowed[tool.Name] = struct{}{}
	}
	for i := range reply.Calls {
		call := &reply.Calls[i]
		if _, ok := allowed[call.Name]; !ok {
			return "", 0, fmt.Errorf("第 %d 个调用工具 %q 不在本轮可用列表中", i+1, call.Name)
		}
		if len(call.Args) == 0 || bytes.Equal(bytes.TrimSpace(call.Args), []byte("null")) {
			call.Args = json.RawMessage(`{}`)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(call.Args, &object); err != nil || object == nil {
			return "", 0, fmt.Errorf("第 %d 个调用 %q 的 args 必须是 JSON 对象", i+1, call.Name)
		}
	}
	encoded, err := json.MarshalIndent(reply, "", "  ")
	if err != nil {
		return "", 0, err
	}
	name := filepath.Base(requestPath)
	if !strings.HasPrefix(name, "req-") || !strings.HasSuffix(name, ".json") {
		return "", 0, fmt.Errorf("请求文件名格式错误: %s", name)
	}
	replyPath := filepath.Join(filepath.Dir(requestPath), "reply-"+strings.TrimSuffix(strings.TrimPrefix(name, "req-"), ".json")+".json")
	if _, err := os.Stat(replyPath); err == nil {
		return "", 0, fmt.Errorf("回复已存在: %s", replyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, err
	}
	if err := writeAtomic(replyPath, encoded, 0o600); err != nil {
		return "", 0, err
	}
	return replyPath, len(reply.Calls), nil
}

func (f *FileChan) Chat(ctx context.Context, req Request) (Reply, error) {
	n := f.turn
	for {
		base := fmt.Sprintf("%03d", n)
		reqPath := filepath.Join(f.Dir, "req-"+base+".json")
		replyPath := filepath.Join(f.Dir, "reply-"+base+".json")
		_, reqErr := os.Stat(reqPath)
		_, replyErr := os.Stat(replyPath)
		reqExists := reqErr == nil
		replyExists := replyErr == nil
		if reqErr != nil && !errors.Is(reqErr, os.ErrNotExist) {
			return Reply{}, reqErr
		}
		if replyErr != nil && !errors.Is(replyErr, os.ErrNotExist) {
			return Reply{}, replyErr
		}
		if reqExists && !replyExists {
			return Reply{}, fmt.Errorf("发现未回复的旧请求 %s；请先用 `ctfagent mailbox wait/reply` 处理，避免跳过 FIFO 邮箱", reqPath)
		}
		if !reqExists && !replyExists {
			break
		}
		n++
	}
	f.turn = n + 1
	base := fmt.Sprintf("%03d", n)
	reqPath := filepath.Join(f.Dir, "req-"+base+".json")
	replyPath := filepath.Join(f.Dir, "reply-"+base+".json")

	snap := requestFile{
		Turn: n, System: req.System, Messages: req.Messages,
		Hint: "请先查看本轮请求，再用 `ctfagent mailbox reply --request " + reqPath + " --input <reply.json>` 写回；" +
			`回复格式：{"content":"一句话","calls":[{"name":"sh","args":{"command":"ls -la"}}]}` +
			"。也可直接原子写入 " + replyPath + "。",
	}
	for _, tool := range req.Tools {
		snap.Tools = append(snap.Tools, ToolBrief{Name: tool.Name, Description: tool.Description})
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return Reply{}, err
	}
	if err := writeAtomic(reqPath, data, 0o600); err != nil {
		return Reply{}, err
	}

	poll := f.PollInterval
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	var timeout *time.Timer
	var timeoutC <-chan time.Time
	if f.Timeout > 0 {
		timeout = time.NewTimer(f.Timeout)
		defer timeout.Stop()
		timeoutC = timeout.C
	}
	var invalidSince time.Time
	for {
		if b, err := os.ReadFile(replyPath); err == nil && len(bytes.TrimSpace(b)) > 0 {
			out, parseErr := parseReply(b, req.Tools, n)
			if parseErr == nil {
				return out, nil
			}
			if invalidSince.IsZero() {
				invalidSince = time.Now()
			} else if f.MalformedGrace <= 0 || time.Since(invalidSince) >= f.MalformedGrace {
				return Reply{}, fmt.Errorf("FileChan 回复无效 (%s): %w", replyPath, parseErr)
			}
		}
		select {
		case <-ctx.Done():
			return Reply{}, ctx.Err()
		case <-timeoutC:
			return Reply{}, fmt.Errorf("等待外部决策超时（%s）：没有收到有效回复 %s", f.Timeout, replyPath)
		case <-ticker.C:
		}
	}
}

func parseReply(data []byte, tools []Tool, turn int) (Reply, error) {
	var rf replyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		return Reply{}, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return Reply{}, fmt.Errorf("JSON 尾部无效: %w", err)
	}
	allowed := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		allowed[tool.Name] = struct{}{}
	}
	out := Reply{Message: Message{Role: "assistant", Content: rf.Content}}
	for i, call := range rf.Calls {
		if _, ok := allowed[call.Name]; !ok {
			return Reply{}, fmt.Errorf("工具 %q 不在可用列表中", call.Name)
		}
		args := bytes.TrimSpace(call.Args)
		if len(args) == 0 || bytes.Equal(args, []byte("null")) {
			args = []byte(`{}`)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(args, &object); err != nil || object == nil {
			return Reply{}, fmt.Errorf("工具 %q 的 args 必须是 JSON 对象", call.Name)
		}
		out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{
			ID: fmt.Sprintf("filechan_%d_%d_%s", turn, i, call.Name), Name: call.Name, Args: string(args),
		})
	}
	return out, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("存在多余 JSON 值")
	}
	return err
}

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".filechan-*tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("目标文件已存在: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmpName, path)
}

// Pending returns unanswered request filenames in lexical order.
func (f *FileChan) Pending() []string {
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "req-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		reply := "reply-" + strings.TrimSuffix(strings.TrimPrefix(name, "req-"), ".json") + ".json"
		if _, err := os.Stat(filepath.Join(f.Dir, reply)); errors.Is(err, os.ErrNotExist) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
