package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenAIRequestShape(t *testing.T) {
	var got map[string]any
	var auth, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("路径错了: %s", r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		ctype = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{
					"role":    "assistant",
					"content": "我看看",
					"tool_calls": []map[string]any{{
						"id": "call_1", "type": "function",
						"function": map[string]any{"name": "sh", "arguments": `{"command":"ls"}`},
					}},
				},
				"finish_reason": "tool_calls",
			}},
			"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 34},
		})
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL+"/v1", "sk-test")
	reply, err := c.Chat(context.Background(), Request{
		Model:       "deepseek-chat",
		System:      "你是解题专家",
		Temperature: 0.3,
		MaxTokens:   2048,
		Messages: []Message{
			{Role: "user", Content: "题目一"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "c0", Name: "sh", Args: `{"command":"pwd"}`}}},
			{Role: "tool", ToolCallID: "c0", Name: "sh", Content: "/work"},
		},
		Tools: []Tool{{
			Name: "sh", Description: "执行命令",
			Schema: map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer sk-test" || !strings.HasPrefix(ctype, "application/json") {
		t.Fatalf("鉴权头=%q content-type=%q", auth, ctype)
	}
	if got["model"] != "deepseek-chat" || got["max_tokens"].(float64) != 2048 {
		t.Fatalf("请求体=%v", got)
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("消息数=%d", len(msgs))
	}
	if msgs[0].(map[string]any)["role"] != "system" || msgs[0].(map[string]any)["content"] != "你是解题专家" {
		t.Fatalf("system 消息丢了: %v", msgs[0])
	}
	toolMsg := msgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "c0" || toolMsg["name"] != "sh" {
		t.Fatalf("tool 消息形状错误: %v", toolMsg)
	}
	tools := got["tools"].([]any)
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "sh" || fn["parameters"] == nil {
		t.Fatalf("tools 声明错误: %v", tools[0])
	}

	if reply.Message.Content != "我看看" || len(reply.Message.ToolCalls) != 1 {
		t.Fatalf("解析回复失败: %+v", reply.Message)
	}
	if tc := reply.Message.ToolCalls[0]; tc.ID != "call_1" || tc.Name != "sh" || tc.Args != `{"command":"ls"}` {
		t.Fatalf("tool_call=%+v", tc)
	}
	if reply.Usage.In != 12 || reply.Usage.Out != 34 {
		t.Fatalf("usage=%+v", reply.Usage)
	}
}

func TestOpenAIRetriesThenSucceeds(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream boom"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": "ok"}}},
		})
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "k")
	c.Retries = 3
	c.Backoff = 5 * time.Millisecond // 测试里把退避压短
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, err := c.Chat(ctx, Request{Model: "m", Messages: []Message{{Role: "user", Content: "hi"}}})
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if reply.Message.Content != "ok" || atomic.LoadInt32(&n) != 3 {
		t.Fatalf("尝试次数=%d reply=%+v", n, reply)
	}
}

func TestOpenAINoRetryOn4xx(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer srv.Close()
	c := NewOpenAI(srv.URL, "bad")
	if _, err := c.Chat(context.Background(), Request{Model: "m"}); err == nil {
		t.Fatal("401 应报错")
	} else if !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("错误信息应透传: %v", err)
	}
	if atomic.LoadInt32(&n) != 1 {
		t.Fatalf("4xx 不该重试，实际请求 %d 次", n)
	}
}

func TestOpenAIBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>gateway</html>`))
	}))
	defer srv.Close()
	c := NewOpenAI(srv.URL, "k")
	c.Retries = 1
	if _, err := c.Chat(context.Background(), Request{Model: "m"}); err == nil {
		t.Fatal("非 JSON 应报错")
	}
}

func TestArgs(t *testing.T) {
	var v struct {
		Command string `json:"command"`
		N       int    `json:"n"`
	}
	if err := Args(ToolCall{Name: "sh", Args: `{"command":"ls","n":2}`}, &v); err != nil {
		t.Fatal(err)
	}
	if v.Command != "ls" || v.N != 2 {
		t.Fatalf("%+v", v)
	}
	// 空参数要当 {} 处理，而不是报错
	if err := Args(ToolCall{Name: "finish"}, &v); err != nil {
		t.Fatalf("空参数应可用: %v", err)
	}
	// 非法 JSON 要指出是哪个工具
	err := Args(ToolCall{Name: "py", Args: `{code: 1}`}, &v)
	if err == nil || !strings.Contains(err.Error(), "py") {
		t.Fatalf("错误信息应包含工具名: %v", err)
	}
}

func TestScripted(t *testing.T) {
	s := NewScripted(Say("一"), Call("sh", `{"command":"ls"}`))
	if s.Name() != "scripted" {
		t.Fatalf("name=%s", s.Name())
	}
	var seen int
	s.OnCall = func(turn int, _ Request) { seen = turn + 1 }
	r1, _ := s.Chat(context.Background(), Request{})
	r2, _ := s.Chat(context.Background(), Request{})
	r3, _ := s.Chat(context.Background(), Request{})
	if r1.Message.Content != "一" {
		t.Fatalf("r1=%+v", r1.Message)
	}
	if len(r2.Message.ToolCalls) != 1 || r2.Message.ToolCalls[0].Name != "sh" {
		t.Fatalf("r2=%+v", r2.Message)
	}
	if !strings.Contains(r3.Message.Content, "剧本已结束") {
		t.Fatalf("剧本用完后应兜底: %+v", r3.Message)
	}
	if seen != 3 {
		t.Fatalf("OnCall 次数=%d", seen)
	}
}
