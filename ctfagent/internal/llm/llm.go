// Package llm 是与模型供应商无关的最小对话接口。
//
// 只依赖标准库：一个 OpenAI 兼容客户端 + 一个可编排的假客户端（测试/演示用）。
// 想接 Anthropic 原生协议？实现 Client 接口即可，内核不知道也不关心。
package llm

import (
	"context"
	"encoding/json"
	"fmt"
)

// Tool 是一个可被模型调用的工具声明。
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
}

// ToolCall 是模型发起的一次工具调用。Args 是原始 JSON 字符串。
type ToolCall struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Args string `json:"args"`
}

// Message 是一条对话消息。
// Role: system | user | assistant | tool
// 当 Role=tool 时，需要 ToolCallID 与 Name。
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// Usage 是 token 统计。
type Usage struct {
	In  int `json:"in"`
	Out int `json:"out"`
}

// Request 是一次补全请求。
type Request struct {
	Model       string
	System      string
	Messages    []Message
	Tools       []Tool
	Temperature float64
	MaxTokens   int
}

// Reply 是一次补全结果。
type Reply struct {
	Message Message
	Usage   Usage
}

// Client 是所有模型客户端的统一入口。
type Client interface {
	Chat(ctx context.Context, req Request) (Reply, error)
	Name() string
}

// Args 把工具调用的 JSON 参数解到目标结构。
func Args(tc ToolCall, dst any) error {
	if tc.Args == "" {
		tc.Args = "{}"
	}
	if err := json.Unmarshal([]byte(tc.Args), dst); err != nil {
		return fmt.Errorf("工具 %s 的参数不是合法 JSON: %w（原始：%.200s）", tc.Name, err, tc.Args)
	}
	return nil
}
