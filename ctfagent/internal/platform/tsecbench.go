package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ctfagent/internal/core"
)

// TSecBench 是腾讯云鼎实验室的智能攻防评测平台。
//
// 注意：它是**被支持的平台之一**，不是本项目的设计中心。
// 这里只做字段翻译：平台题 → core.Challenge，core flag → 平台提交接口。
// 任何"为了 TSecBench 而扭曲内核"的改动都应该被拒绝。

const (
	tsecTokenHeader = "BENCHMARK_TOKEN"
	tsecChallenges  = "/openapi/v1/challenges"
	tsecVPNProbe    = "http://10.0.100.58"
)

// TSecConfig 是接入跑分任务所需的凭证。
type TSecConfig struct {
	BaseURL string
	Token   string
	Timeout time.Duration
	// VPNProbe 是靶场网段的健康检查地址，留空用 TSecBench 默认的探针。
	VPNProbe string
	// SkipVPNCheck 仅用于本地联调。
	SkipVPNCheck bool
}

// TSec 实现 Adapter。
type TSec struct {
	cfg  TSecConfig
	http *http.Client
}

// NewTSec 构造 TSecBench 适配器。
func NewTSec(cfg TSecConfig) *TSec {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.VPNProbe == "" {
		cfg.VPNProbe = tsecVPNProbe
	}
	return &TSec{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
}

// Name 实现 Adapter。
func (t *TSec) Name() string { return "tsecbench" }

// CheckVPN 在开跑前确认靶场网段可达（容器地址只在 VPN 内可达）。
func (t *TSec) CheckVPN(ctx context.Context) error {
	if t.cfg.SkipVPNCheck {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.cfg.VPNProbe, nil)
	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("VPN 预检失败（靶场容器只在 VPN 网段可达）: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Status string `json:"status"`
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("VPN 预检失败: 探针返回 %d", resp.StatusCode)
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
	if out.Status != "ok" {
		return fmt.Errorf("VPN 预检失败: status=%q", out.Status)
	}
	return nil
}

type tsecChallenge struct {
	UniqueCode       string   `json:"unique_code"`
	Difficulty       string   `json:"difficulty"`
	Level            int      `json:"level"`
	TotalScore       int      `json:"total_score"`
	FlagCount        int      `json:"flag_count"`
	CorrectFlagCount int      `json:"correct_flag_count"`
	IsCompleted      bool     `json:"is_completed"`
	Description      string   `json:"description"`
	ContainerStatus  string   `json:"container_status"`
	ContainerAddr    []string `json:"container_addr"`
}

// List 实现 Adapter：把平台题翻译成通用题目。
func (t *TSec) List(ctx context.Context) ([]core.Challenge, error) {
	var raw []tsecChallenge
	if err := t.do(ctx, http.MethodGet, tsecChallenges, nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]core.Challenge, 0, len(raw))
	for _, r := range raw {
		ch := core.Challenge{
			ID:        r.UniqueCode,
			Title:     r.UniqueCode,
			Category:  "unknown", // 平台不返回分类；难度只当参考，不当契约
			Prompt:    r.Description,
			Targets:   r.ContainerAddr,
			FlagCount: r.FlagCount,
			MaxScore:  r.TotalScore,
			Meta: map[string]string{
				"difficulty": r.Difficulty,
				"level":      fmt.Sprint(r.Level),
				"completed":  fmt.Sprint(r.IsCompleted),
				"correct":    fmt.Sprint(r.CorrectFlagCount),
			},
		}
		out = append(out, ch)
	}
	return out, nil
}

// Acquire 实现 Adapter：起容器，拿到可达地址。
func (t *TSec) Acquire(ctx context.Context, id string) (*Conn, error) {
	var raw struct {
		UniqueCode    string   `json:"unique_code"`
		ContainerAddr []string `json:"container_addr"`
	}
	q := url.Values{"unique_code": {id}}
	if err := t.do(ctx, http.MethodPost, tsecChallenges+"/start", q, nil, &raw); err != nil {
		return nil, err
	}
	return &Conn{
		Targets: raw.ContainerAddr,
		WorkDir: "/tmp/ctf", // 容器内自建工作目录（题面容器通常可写 /tmp）
		Release: func(c context.Context) error { return t.Release(c, id) },
	}, nil
}

// Release 实现 Adapter：关容器，释放并发名额。
func (t *TSec) Release(ctx context.Context, id string) error {
	q := url.Values{"unique_code": {id}}
	return t.do(ctx, http.MethodPost, tsecChallenges+"/close", q, nil, nil)
}

// Submit 实现 Adapter。
func (t *TSec) Submit(ctx context.Context, id, flag string) (SubmitResult, error) {
	body := map[string]string{"unique_code": id, "flag": flag}
	var raw struct {
		Correct          bool `json:"correct"`
		Awarded          int  `json:"awarded"`
		CumulativeScore  int  `json:"cumulative_score"`
		CorrectFlagCount int  `json:"correct_flag_count"`
		TotalFlagCount   int  `json:"total_flag_count"`
	}
	if err := t.do(ctx, http.MethodPost, tsecChallenges+"/submit", nil, body, &raw); err != nil {
		// 重复提交是幂等结果，不是失败。
		if errors.Is(err, errDuplicate) {
			return SubmitResult{Correct: true, Message: "重复提交（已计分）"}, nil
		}
		return SubmitResult{}, err
	}
	return SubmitResult{
		Correct:      raw.Correct,
		Awarded:      raw.Awarded,
		Cumulative:   raw.CumulativeScore,
		CorrectFlags: raw.CorrectFlagCount,
		TotalFlags:   raw.TotalFlagCount,
	}, nil
}

// Hint 实现 Adapter（平台会扣分，是否调用由内核策略决定）。
func (t *TSec) Hint(ctx context.Context, id string) (string, error) {
	q := url.Values{"unique_code": {id}}
	var raw struct {
		Hint string `json:"hint"`
	}
	if err := t.do(ctx, http.MethodGet, tsecChallenges+"/hint", q, nil, &raw); err != nil {
		return "", err
	}
	return raw.Hint, nil
}

// Policy 实现 Adapter：TSecBench v1 的 flag 是随机 UUID，同时兼容花括号形态。
func (t *TSec) Policy(*core.Challenge) core.FlagPolicy {
	p := core.DefaultPolicy()
	p.AllowUUID = true
	return p
}

// ---------------------------------------------------------------------------

var errDuplicate = errors.New("duplicate")

type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("平台返回 %d: %s", e.Status, e.Msg) }

func (t *TSec) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := t.cfg.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set(tsecTokenHeader, t.cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if resp.StatusCode == 409 || strings.Contains(strings.ToLower(msg), "duplicate") {
			return fmt.Errorf("%w: %s", errDuplicate, msg)
		}
		return &apiError{Status: resp.StatusCode, Msg: msg}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
