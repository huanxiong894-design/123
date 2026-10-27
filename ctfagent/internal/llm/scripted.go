package llm

import (
	"context"
	"fmt"
	"sync"
)

// Scripted 是一个"写死剧本"的假模型，用于：
//   - 单元测试：不花 token 也能验证整条 agent 回路；
//   - 现场演示：证明内核、工具、沙箱、提交闸门是通的；
//   - 回归：改了内核逻辑，用它跑一遍就知道有没有破坏行为。
//
// 它按顺序吐出预设的回复；剧本用完后再被调用，就回一句"我结束了"。
type Scripted struct {
	mu     sync.Mutex
	turns  []Reply
	idx    int
	OnCall func(turn int, req Request) // 观测用
}

// NewScripted 用给定剧本构造。
func NewScripted(turns ...Reply) *Scripted { return &Scripted{turns: turns} }

// Name 实现 Client。
func (s *Scripted) Name() string { return "scripted" }

// Chat 实现 Client。
func (s *Scripted) Chat(_ context.Context, req Request) (Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	turn := s.idx
	s.idx++
	if s.OnCall != nil {
		s.OnCall(turn, req)
	}
	if turn >= len(s.turns) {
		return Reply{Message: Message{Role: "assistant", Content: "剧本已结束。"}}, nil
	}
	return s.turns[turn], nil
}

// ---------------------------------------------------------------------------
// 剧本构造辅助（让测试读起来像人话）
// ---------------------------------------------------------------------------

// Say 构造一条纯文本回复。
func Say(text string) Reply {
	return Reply{Message: Message{Role: "assistant", Content: text}}
}

// Call 构造一条"调用单个工具"的回复。
func Call(tool string, argsJSON string) Reply {
	return Reply{Message: Message{
		Role:      "assistant",
		ToolCalls: []ToolCall{{ID: fmt.Sprintf("call_%s", tool), Name: tool, Args: argsJSON}},
	}}
}

// Calls 构造一条"同时调用多个工具"的回复。
func Calls(calls ...ToolCall) Reply {
	return Reply{Message: Message{Role: "assistant", ToolCalls: calls}}
}

// TC 构造一个工具调用。
func TC(tool, argsJSON string) ToolCall {
	return ToolCall{ID: fmt.Sprintf("call_%s", tool), Name: tool, Args: argsJSON}
}
