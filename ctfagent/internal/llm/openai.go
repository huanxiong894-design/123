package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAI 兼容客户端。
//
// 覆盖：OpenAI / DeepSeek / 通义（compatible-mode）/ 智谱 GLM / Kimi（Moonshot）/
// MiniMax / vLLM / Ollama / OpenRouter / 各类中转网关 —— 只要它说
// POST {base}/chat/completions 且支持 tools。
type OpenAI struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	// ExtraHeaders 用于个别网关要求的额外鉴权头。
	ExtraHeaders map[string]string
	// Retries 是 5xx/429/网络错误的重试次数（默认 3）。
	Retries int
	// Backoff 是首次重试的等待时间（默认 2s，之后翻倍）。
	Backoff time.Duration
}

// NewOpenAI 构造客户端。baseURL 形如 https://api.deepseek.com/v1。
func NewOpenAI(baseURL, apiKey string) *OpenAI {
	return &OpenAI{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		HTTP:    &http.Client{Timeout: 300 * time.Second},
		Retries: 3,
	}
}

// Name 实现 Client。
func (c *OpenAI) Name() string { return "openai:" + c.BaseURL }

type oaRequest struct {
	Model       string      `json:"model"`
	Messages    []oaMessage `json:"messages"`
	Tools       []oaTool    `json:"tools,omitempty"`
	ToolChoice  string      `json:"tool_choice,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Stream      bool        `json:"stream"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
	Name       string       `json:"name,omitempty"`
}

type oaToolCall struct {
	Index    int    `json:"index,omitempty"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type oaResponse struct {
	Choices []struct {
		Message      oaMessage `json:"message"`
		FinishReason string    `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Chat 实现 Client。
func (c *OpenAI) Chat(ctx context.Context, req Request) (Reply, error) {
	body := oaRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}
	if req.System != "" {
		body.Messages = append(body.Messages, oaMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		om := oaMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID, Name: m.Name}
		for _, tc := range m.ToolCalls {
			var otc oaToolCall
			otc.ID = tc.ID
			otc.Type = "function"
			otc.Function.Name = tc.Name
			otc.Function.Arguments = tc.Args
			om.ToolCalls = append(om.ToolCalls, otc)
		}
		body.Messages = append(body.Messages, om)
	}
	for _, t := range req.Tools {
		var ot oaTool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.Schema
		if ot.Function.Parameters == nil {
			ot.Function.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		body.Tools = append(body.Tools, ot)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Reply{}, err
	}

	attempts := c.Retries
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	backoff := c.Backoff
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return Reply{}, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		reply, retry, err := c.once(ctx, payload)
		if err == nil {
			return reply, nil
		}
		lastErr = err
		if !retry {
			return Reply{}, err
		}
	}
	return Reply{}, lastErr
}

func (c *OpenAI) once(ctx context.Context, payload []byte) (Reply, bool, error) {
	url := c.BaseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Reply{}, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	for k, v := range c.ExtraHeaders {
		httpReq.Header.Set(k, v)
	}

	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(httpReq)
	if err != nil {
		return Reply{}, true, fmt.Errorf("模型请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	if resp.StatusCode >= 400 {
		retry := resp.StatusCode == 429 || resp.StatusCode >= 500
		var er oaResponse
		_ = json.Unmarshal(raw, &er)
		msg := strings.TrimSpace(string(raw))
		if er.Error != nil && er.Error.Message != "" {
			msg = er.Error.Message
		}
		return Reply{}, retry, fmt.Errorf("模型返回 %d: %.400s", resp.StatusCode, msg)
	}

	var out oaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Reply{}, false, fmt.Errorf("模型响应不是合法 JSON: %w (%.200s)", err, raw)
	}
	if len(out.Choices) == 0 {
		return Reply{}, true, errors.New("模型返回空 choices")
	}
	msg := out.Choices[0].Message
	r := Reply{Usage: Usage{In: out.Usage.PromptTokens, Out: out.Usage.CompletionTokens}}
	r.Message.Role = "assistant"
	r.Message.Content = msg.Content
	for _, tc := range msg.ToolCalls {
		r.Message.ToolCalls = append(r.Message.ToolCalls, ToolCall{
			ID:   tc.ID,
			Name: tc.Function.Name,
			Args: tc.Function.Arguments,
		})
	}
	return r, false, nil
}
