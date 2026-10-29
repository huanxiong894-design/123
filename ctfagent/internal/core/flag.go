package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// flag 处理是通用 CTF agent 最容易失分的地方：
// 模型拿不到 flag 不可怕，把幻觉/噪声当成 flag 交上去才可怕。
// 所以这里做三层：抽取（Extract）→ 归一化（Normalize）→ 闸门（Gate）。

// 默认形态：带花括号的 flag（flag{...} / CTF{...} / DASCTF{...}），
// 以及显式声明（FLAG: xxx / flag = xxx）。
var (
	reBraced   = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_]{0,20}\{[^{}"'` + "`" + `\n]{1,200}\}`)
	reDeclared = regexp.MustCompile(`(?i)\b(?:flag|answer)\s*[:=]\s*([A-Za-z0-9_+\-./{}=]{6,120})`)
	reUUID     = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
)

// 这些词所在的**同一行**出现 UUID 时，判定为噪声（会话/请求/trace 标识符）。
var noiseHints = []string{
	"session-id", "session_id", "sessionid", "request-id", "request_id",
	"trace-id", "trace_id", "span-id", "span_id", "correlation-id",
	"x-request-id", "csrf", "nonce", "x-amz-request-id", "etag",
}

// FlagPolicy 描述"什么样的字符串算 flag"。由平台适配器给出，缺省是通用策略。
type FlagPolicy struct {
	// Patterns 是额外的正则；为空则用默认集合。
	Patterns []string
	// AllowUUID 允许裸 UUID 形态（很多靶场用 UUID 当 flag）。
	AllowUUID bool
	// MinLen / MaxLen 限制单个 flag 长度。
	MinLen int
	MaxLen int
	// MaxCandidates 限制单次抽取的候选数量，防止一屏 base64 打满提交预算。
	MaxCandidates int
}

// DefaultPolicy 是通用 CTF 的默认策略：花括号 + 声明式 + UUID。
func DefaultPolicy() FlagPolicy {
	return FlagPolicy{AllowUUID: true, MinLen: 6, MaxLen: 200, MaxCandidates: 24}
}

// Compile 预编译正则（幂等，可重复调用）。
func (p *FlagPolicy) Compile() error {
	if p.MinLen == 0 {
		p.MinLen = 6
	}
	if p.MaxLen == 0 {
		p.MaxLen = 200
	}
	if p.MaxCandidates == 0 {
		p.MaxCandidates = 24
	}
	for _, s := range p.Patterns {
		if _, err := regexp.Compile(s); err != nil {
			return fmt.Errorf("flag 正则非法 %q: %w", s, err)
		}
	}
	return nil
}

// Extract 从任意文本抽取候选 flag，按出现顺序去重返回。
func (p FlagPolicy) Extract(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	type hit struct {
		pos int
		val string
	}
	var hits []hit
	add := func(re *regexp.Regexp, group int) {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if group*2+1 >= len(m) || m[group*2] < 0 {
				continue
			}
			hits = append(hits, hit{pos: m[group*2], val: text[m[group*2]:m[group*2+1]]})
		}
	}

	if len(p.Patterns) > 0 {
		for _, expr := range p.Patterns {
			if re, err := regexp.Compile(expr); err == nil {
				add(re, 0)
			}
		}
	} else {
		add(reBraced, 0)
		add(reDeclared, 1)
	}

	if p.AllowUUID {
		for _, m := range reUUID.FindAllStringIndex(text, -1) {
			start := m[0]
			lineStart := strings.LastIndexByte(text[:start], '\n') + 1
			line := text[lineStart:]
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			} else if rel := start - lineStart; rel >= 0 && rel < len(line) {
				line = line[:min(len(line), rel+64)]
			}
			if hasNoise(line) {
				continue
			}
			hits = append(hits, hit{pos: start, val: text[m[0]:m[1]]})
		}
	}

	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j-1].pos > hits[j].pos; j-- {
			hits[j-1], hits[j] = hits[j], hits[j-1]
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		v := Normalize(h.val, p)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= p.MaxCandidates {
			break
		}
	}
	return out
}

// Normalize 清洗候选。注意不要裁掉花括号——flag{...} 本身就以 } 结尾。
func Normalize(s string, p FlagPolicy) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'`<>()[]")
	s = strings.TrimRight(s, ".,;:!?、，。；：")
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	minLen, maxLen := p.MinLen, p.MaxLen
	if minLen == 0 {
		minLen = 6
	}
	if maxLen == 0 {
		maxLen = 200
	}
	if len(s) < minLen || len(s) > maxLen {
		return ""
	}
	return s
}

func hasNoise(line string) bool {
	l := strings.ToLower(line)
	for _, h := range noiseHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 提交闸门
// ---------------------------------------------------------------------------

// 闸门错误。
var (
	ErrAlreadySubmitted = errors.New("该 flag 已提交过")
	ErrTooManyWrong     = errors.New("本题错提次数已达上限")
	ErrCooldown         = errors.New("错提冷却中")
	ErrEmptyFlag        = errors.New("flag 为空")
)

// Gate 是"谁能被提交"的唯一裁判，跨重试共享，避免反复试同一个串。
type Gate struct {
	MaxWrong int             `json:"max_wrong"`
	Cooldown []time.Duration `json:"-"`

	mu     sync.Mutex
	seen   map[string]bool
	wrong  map[string]int
	consec map[string]int
	nextOK map[string]time.Time
}

// NewGate 构造闸门。maxWrong<=0 取 40。
func NewGate(maxWrong int) *Gate {
	if maxWrong <= 0 {
		maxWrong = 40
	}
	return &Gate{
		MaxWrong: maxWrong,
		Cooldown: []time.Duration{0, 30 * time.Second, 2 * time.Minute, 5 * time.Minute},
		seen:     map[string]bool{},
		wrong:    map[string]int{},
		consec:   map[string]int{},
		nextOK:   map[string]time.Time{},
	}
}

// Check 在真正提交前判定是否放行（按题目隔离计数）。
func (g *Gate) Check(challengeID, flag string) error {
	flag = strings.TrimSpace(flag)
	if flag == "" {
		return ErrEmptyFlag
	}
	key := challengeID + "\x00" + flag
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[key] {
		return ErrAlreadySubmitted
	}
	if g.wrong[challengeID] >= g.MaxWrong {
		return fmt.Errorf("%w（%d/%d）", ErrTooManyWrong, g.wrong[challengeID], g.MaxWrong)
	}
	if t, ok := g.nextOK[challengeID]; ok && time.Now().Before(t) {
		return fmt.Errorf("%w（还剩 %s）", ErrCooldown, time.Until(t).Round(time.Second))
	}
	return nil
}

// Record 记录一次真实提交结果。
func (g *Gate) Record(challengeID, flag string, correct bool) {
	flag = strings.TrimSpace(flag)
	key := challengeID + "\x00" + flag
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen[key] = true
	if correct {
		g.consec[challengeID] = 0
		g.nextOK[challengeID] = time.Time{}
		return
	}
	g.wrong[challengeID]++
	g.consec[challengeID]++
	idx := g.consec[challengeID] - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(g.Cooldown) {
		idx = len(g.Cooldown) - 1
	}
	if len(g.Cooldown) > 0 && g.Cooldown[idx] > 0 {
		g.nextOK[challengeID] = time.Now().Add(g.Cooldown[idx])
	}
}

// Wrong 返回某题错提次数。
func (g *Gate) Wrong(challengeID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.wrong[challengeID]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
