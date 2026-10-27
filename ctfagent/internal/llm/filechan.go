package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileChan 是一个"外部大脑"客户端：它把每一步的上下文写成文件，等人（或任何外部程序）
// 把决策写回来。
//
// 用途：在没有模型 API 的时候，让一个有推理能力的外部主体（人、另一个 agent、编辑器里的
// 助手）真正驱动解题内核——工具执行、沙箱、grounding、提交闸门全都真实跑，只有"决策"来自外部。
// 这比写死剧本强得多：外部主体能看到真实输出，再决定下一步。
//
//	dir/req-000.json   内核写：system prompt、历史消息、可用工具
//	dir/reply-000.json 外部写：{"content":"...","calls":[{"name":"sh","args":{"command":"ls"}}]}
type FileChan struct {
	Dir     string
	Timeout time.Duration // 单步等待上限，0 = 不限制（由 ctx 控制）
	turn    int
}

// NewFileChan 构造。目录不存在会被创建。
func NewFileChan(dir string) (*FileChan, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &FileChan{Dir: abs, Timeout: 30 * time.Minute}, nil
}

// Name 实现 Client。
func (f *FileChan) Name() string { return "filechan" }

// requestFile 是写给外部的快照。
type requestFile struct {
	Turn     int         `json:"turn"`
	System   string      `json:"system"`
	Messages []Message   `json:"messages"`
	Tools    []ToolBrief `json:"tools"`
	Hint     string      `json:"hint"`
}

// ToolBrief 只保留工具名与描述，schema 太长没必要。
type ToolBrief struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// replyFile 是外部写回的决定。
type replyFile struct {
	Content string     `json:"content"`
	Calls   []callSpec `json:"calls"`
}

type callSpec struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// Chat 实现 Client：写请求 → 等回复 → 解析。
func (f *FileChan) Chat(ctx context.Context, req Request) (Reply, error) {
	f.turn++
	n := f.turn - 1
	base := fmt.Sprintf("%03d", n)
	reqPath := filepath.Join(f.Dir, "req-"+base+".json")
	replyPath := filepath.Join(f.Dir, "reply-"+base+".json")

	snap := requestFile{
		Turn:     n,
		System:   req.System,
		Messages: req.Messages,
		Hint: "把决策写到 " + replyPath + " ；格式 " +
			`{"content":"一句话","calls":[{"name":"sh","args":{"command":"ls -la"}}]}` +
			" ；calls 为空表示只说话不调工具。",
	}
	for _, t := range req.Tools {
		snap.Tools = append(snap.Tools, ToolBrief{Name: t.Name, Description: t.Description})
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return Reply{}, err
	}
	if err := os.WriteFile(reqPath, data, 0o644); err != nil {
		return Reply{}, err
	}

	deadline := time.Time{}
	if f.Timeout > 0 {
		deadline = time.Now().Add(f.Timeout)
	}
	for {
		if b, err := os.ReadFile(replyPath); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			var rf replyFile
			if err := json.Unmarshal(b, &rf); err != nil {
				// 外部可能正在写，等下一次
				time.Sleep(300 * time.Millisecond)
				continue
			}
			out := Reply{Message: Message{Role: "assistant", Content: rf.Content}}
			for _, c := range rf.Calls {
				args := string(c.Args)
				if args == "" || args == "null" {
					args = "{}"
				}
				out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{
					ID:   fmt.Sprintf("call_%d_%s", n, c.Name),
					Name: c.Name,
					Args: args,
				})
			}
			return out, nil
		}
		select {
		case <-ctx.Done():
			return Reply{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return Reply{}, fmt.Errorf("等待外部决策超时（%s）：没有收到 %s", f.Timeout, replyPath)
		}
	}
}

// Pending 返回还没被回答的请求文件（调试用）。
func (f *FileChan) Pending() []string {
	entries, _ := os.ReadDir(f.Dir)
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "req-") {
			reply := "reply-" + strings.TrimSuffix(strings.TrimPrefix(e.Name(), "req-"), ".json") + ".json"
			if _, err := os.Stat(filepath.Join(f.Dir, reply)); err != nil {
				out = append(out, e.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}
