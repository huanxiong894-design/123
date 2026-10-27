// Package core 定义与平台无关的领域模型：题目、flag 策略、作战板（Board）。
//
// 设计红线：这里出现的任何字段都不能是某个评测平台特有的。
// 平台差异全部收敛到 platform.Adapter；能力差异全部收敛到 Board 与工具。
package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Attachment 是题目附件（二进制、源码包、流量包、图片…）。
// URL 与 Path 二选一：URL 由 agent 自行下载，Path 是已经落盘的本地文件。
type Attachment struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
	Path string `json:"path,omitempty"`
	Size int64  `json:"size,omitempty"`
}

// Challenge 是一道题。所有平台（CTFd、本地题库、TSecBench、自建）都映射到它。
//
// Category 只是**提示**而不是契约：解题内核不得因为分类而拒绝任何打法，
// 分类唯一的作用是给模型一句先验（以及给报告分组统计）。
type Challenge struct {
	ID          string            `json:"id"`
	Title       string            `json:"title,omitempty"`
	Category    string            `json:"category,omitempty"` // web/pwn/rev/crypto/misc/forensics/cloud/unknown
	Prompt      string            `json:"prompt,omitempty"`   // 题面原文
	Attachments []Attachment      `json:"attachments,omitempty"`
	Targets     []string          `json:"targets,omitempty"` // 可达地址：URL 或 host:port
	FlagPattern string            `json:"flag_pattern,omitempty"`
	FlagCount   int               `json:"flag_count,omitempty"` // 0 = 未知
	MaxScore    int               `json:"max_score,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// NewChallenge 做最基本的清洗，避免上游把空白字段塞进来。
func NewChallenge(id string) *Challenge {
	return &Challenge{ID: strings.TrimSpace(id), Meta: map[string]string{}}
}

// Summary 是一行摘要，用于列表与日志。
func (c *Challenge) Summary() string {
	cat := c.Category
	if cat == "" {
		cat = "unknown"
	}
	title := c.Title
	if title == "" {
		title = c.ID
	}
	return fmt.Sprintf("%-28s %-10s targets=%d attachments=%d", title, cat, len(c.Targets), len(c.Attachments))
}

// Brief 是喂给模型的第一段题面（不含平台内部字段）。
func (c *Challenge) Brief() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 题目 %s", c.ID)
	if c.Title != "" && c.Title != c.ID {
		fmt.Fprintf(&b, " · %s", c.Title)
	}
	b.WriteString("\n")
	if c.Category != "" {
		fmt.Fprintf(&b, "分类提示：%s（仅作参考，不要因为它限制思路）\n", c.Category)
	}
	if c.FlagCount > 0 {
		fmt.Fprintf(&b, "flag 数量：%d\n", c.FlagCount)
	}
	if c.Prompt != "" {
		b.WriteString("\n## 题面\n")
		b.WriteString(strings.TrimSpace(c.Prompt))
		b.WriteString("\n")
	}
	if len(c.Targets) > 0 {
		b.WriteString("\n## 可达目标\n")
		for _, t := range c.Targets {
			fmt.Fprintf(&b, "- %s\n", t)
		}
	}
	if len(c.Attachments) > 0 {
		b.WriteString("\n## 附件\n")
		for _, a := range c.Attachments {
			switch {
			case a.URL != "":
				fmt.Fprintf(&b, "- %s → %s\n", a.Name, a.URL)
			case a.Path != "":
				fmt.Fprintf(&b, "- %s → %s\n", a.Name, a.Path)
			default:
				fmt.Fprintf(&b, "- %s\n", a.Name)
			}
		}
	}
	return b.String()
}

// SubmitResult 是一次 flag 提交的结果。放在 core 里是因为内核（闸门/报告）
// 与平台适配器都要用它，而内核不应该 import platform。
type SubmitResult struct {
	Correct bool `json:"correct"`
	// Unverified 表示"flag 被记下了，但没有判题接口验证"。
	// prompt（提示词）接入模式下常见：平台只给题面，交 flag 要人工去网页点。
	Unverified   bool   `json:"unverified,omitempty"`
	Awarded      int    `json:"awarded,omitempty"`
	Cumulative   int    `json:"cumulative,omitempty"`
	CorrectFlags int    `json:"correct_flags,omitempty"`
	TotalFlags   int    `json:"total_flags,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ---------------------------------------------------------------------------
// 作战板：ARTEX 的双图在通用 CTF 里的对应物
// ---------------------------------------------------------------------------
//
// ARTEX 用「资产图 + 探索图」描述一次渗透。CTF 没有资产面，但同样需要外部状态：
//   - Fact     已经证实的事实（必须带证据）→ 对应 ARTEX 的 record_fact
//   - Idea     尚未验证的假设/待办方向      → 对应 ARTEX 的 intent
//   - Artifact 中间产物（文件、凭据、密钥、端点）→ 对应 ARTEX 的资产图
//   - Attempt  试过的动作与结论（防重复劳动）
//   - Flag     拿到的 flag 与提交结果
//
// 所有内容都会被压成一段「态势」注入每一步的上下文，这就是长时间任务不跑飞的关键。

// Fact 是一条有证据支撑的事实。
type Fact struct {
	ID       int       `json:"id"`
	Text     string    `json:"text"`
	Evidence string    `json:"evidence,omitempty"` // 引用自工具输出的一小段
	At       time.Time `json:"at"`
}

// Idea 是一个假设或待验证方向。
type Idea struct {
	ID      int    `json:"id"`
	Text    string `json:"text"`
	Status  string `json:"status"` // open | blocked | done
	Verdict string `json:"verdict,omitempty"`
}

// ArtifactKind 是中间产物的类型。
type ArtifactKind string

const (
	ArtifactFile     ArtifactKind = "file"
	ArtifactCred     ArtifactKind = "cred"
	ArtifactEndpoint ArtifactKind = "endpoint"
	ArtifactKey      ArtifactKind = "key"
	ArtifactOther    ArtifactKind = "other"
)

// Artifact 是一个可复用的中间产物。
type Artifact struct {
	ID    int          `json:"id"`
	Kind  ArtifactKind `json:"kind"`
	Value string       `json:"value"`
	Note  string       `json:"note,omitempty"`
}

// Attempt 是一次动作尝试（命令级），用于避免模型反复做同一件无效的事。
type Attempt struct {
	Cmd     string    `json:"cmd"`
	Exit    int       `json:"exit"`
	Verdict string    `json:"verdict,omitempty"` // ok | fail | partial
	At      time.Time `json:"at"`
}

// FlagHit 是一个候选 flag 及其提交结果。
type FlagHit struct {
	Value   string    `json:"value"`
	Correct bool      `json:"correct"`
	At      time.Time `json:"at"`
}

// Board 是单个题目的全部外部状态。并发安全。
type Board struct {
	ChallengeID string     `json:"challenge_id"`
	Title       string     `json:"title,omitempty"`
	Category    string     `json:"category,omitempty"`
	Goal        string     `json:"goal,omitempty"`
	Facts       []Fact     `json:"facts,omitempty"`
	Ideas       []Idea     `json:"ideas,omitempty"`
	Artifacts   []Artifact `json:"artifacts,omitempty"`
	Attempts    []Attempt  `json:"attempts,omitempty"`
	Flags       []FlagHit  `json:"flags,omitempty"`
	// Hints 是「平台已声明的约定」，来自 Challenge.Meta。
	// 例如 flag_paths 声明该平台把 flag 放在哪些固定位置——
	// 这类知识属于**平台契约**，由适配器注入，内核不内置任何平台的私有约定。
	Hints map[string]string `json:"hints,omitempty"`
	// PriorSummary 是上一轮/父任务的交接摘要（多轮重试时注入）。
	PriorSummary string    `json:"prior_summary,omitempty"`
	Steps        int       `json:"steps"`
	TokensIn     int       `json:"tokens_in"`
	TokensOut    int       `json:"tokens_out"`
	Started      time.Time `json:"started"`
}

// NewBoard 初始化作战板。
func NewBoard(ch *Challenge) *Board {
	cat := ch.Category
	if cat == "" {
		cat = "unknown"
	}
	hints := make(map[string]string, len(ch.Meta))
	for k, v := range ch.Meta {
		if strings.TrimSpace(v) != "" {
			hints[k] = v
		}
	}
	return &Board{
		ChallengeID: ch.ID,
		Title:       ch.Title,
		Category:    cat,
		Goal:        fmt.Sprintf("解出题目 %s 并拿到 flag", ch.ID),
		Hints:       hints,
		Started:     time.Now(),
	}
}

// AddFact 追加一条事实并返回 id。
func (b *Board) AddFact(text, evidence string) int {
	b.Facts = append(b.Facts, Fact{ID: len(b.Facts) + 1, Text: clip(text, 800), Evidence: clip(evidence, 400), At: time.Now()})
	return len(b.Facts)
}

// AddIdea 追加一个假设。
func (b *Board) AddIdea(text string) int {
	b.Ideas = append(b.Ideas, Idea{ID: len(b.Ideas) + 1, Text: clip(text, 400), Status: "open"})
	return len(b.Ideas)
}

// SetIdea 更新假设状态。
func (b *Board) SetIdea(id int, status, verdict string) bool {
	for i := range b.Ideas {
		if b.Ideas[i].ID == id {
			b.Ideas[i].Status = status
			if verdict != "" {
				b.Ideas[i].Verdict = clip(verdict, 300)
			}
			return true
		}
	}
	return false
}

// AddArtifact 追加一个中间产物（同值去重）。
func (b *Board) AddArtifact(kind ArtifactKind, value, note string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, a := range b.Artifacts {
		if a.Value == value {
			return false
		}
	}
	b.Artifacts = append(b.Artifacts, Artifact{ID: len(b.Artifacts) + 1, Kind: kind, Value: clip(value, 300), Note: clip(note, 200)})
	return true
}

// AddAttempt 记录一次动作。
func (b *Board) AddAttempt(cmd string, exit int, verdict string) {
	b.Attempts = append(b.Attempts, Attempt{Cmd: clip(cmd, 240), Exit: exit, Verdict: verdict, At: time.Now()})
	if len(b.Attempts) > 200 { // 只保留最近 200 条，完整记录在会话日志里
		b.Attempts = b.Attempts[len(b.Attempts)-200:]
	}
}

// RecordFlag 记录一次提交结果。
func (b *Board) RecordFlag(value string, correct bool) {
	for i := range b.Flags {
		if b.Flags[i].Value == value {
			b.Flags[i].Correct = correct
			return
		}
	}
	b.Flags = append(b.Flags, FlagHit{Value: value, Correct: correct, At: time.Now()})
}

// SolvedFlags 返回已确认正确的 flag 数。
func (b *Board) SolvedFlags() int {
	n := 0
	for _, f := range b.Flags {
		if f.Correct {
			n++
		}
	}
	return n
}

// SeenFlag 报告某个候选是否已经提交过。
func (b *Board) SeenFlag(v string) bool {
	for _, f := range b.Flags {
		if f.Value == v {
			return true
		}
	}
	return false
}

// TryCount 返回某个命令此前执行过的次数（用于重复检测）。
func (b *Board) TryCount(cmd string) int {
	n := 0
	for _, a := range b.Attempts {
		if a.Cmd == clip(cmd, 240) {
			n++
		}
	}
	return n
}

// Situation 把整块板子压成一段紧凑文本，注入每一步的上下文。
//
// 这是 ARTEX graph_overview 的等价物：模型不需要记住一切，只需要读这一屏。
// budget 是字符上限，超出时按"事实/假设优先、尝试记录先砍"的顺序裁剪。
func (b *Board) Situation(budget int) string {
	if budget <= 0 {
		budget = 4000
	}
	var b2 strings.Builder
	b2.WriteString("## 当前态势\n")
	fmt.Fprintf(&b2, "题目：%s（%s）· 目标：%s\n", b.ChallengeID, b.Category, b.Goal)
	fmt.Fprintf(&b2, "进度：step=%d 事实=%d 假设=%d 产物=%d 已确认flag=%d\n",
		b.Steps, len(b.Facts), openIdeas(b), len(b.Artifacts), b.SolvedFlags())

	if b.PriorSummary != "" {
		b2.WriteString("\n### 上一轮交接\n")
		b2.WriteString(clip(b.PriorSummary, 1200))
		b2.WriteString("\n")
	}

	if len(b.Flags) > 0 {
		b2.WriteString("\n### 已提交的 flag\n")
		for _, f := range b.Flags {
			state := "❌错误"
			if f.Correct {
				state = "✅正确"
			}
			fmt.Fprintf(&b2, "- %s %s\n", state, f.Value)
		}
	}

	if len(b.Facts) > 0 {
		b2.WriteString("\n### 已证实的事实\n")
		start := 0
		if len(b.Facts) > 12 {
			start = len(b.Facts) - 12
		}
		for _, f := range b.Facts[start:] {
			fmt.Fprintf(&b2, "- [%d] %s", f.ID, f.Text)
			if f.Evidence != "" {
				fmt.Fprintf(&b2, "（证据：%s）", clip(f.Evidence, 120))
			}
			b2.WriteString("\n")
		}
	}

	if open := openIdeaList(b); len(open) > 0 {
		b2.WriteString("\n### 待验证的假设\n")
		for _, i := range open {
			fmt.Fprintf(&b2, "- [%d] %s\n", i.ID, i.Text)
		}
	}

	if len(b.Artifacts) > 0 {
		b2.WriteString("\n### 中间产物\n")
		for _, a := range b.Artifacts {
			fmt.Fprintf(&b2, "- (%s) %s", a.Kind, a.Value)
			if a.Note != "" {
				fmt.Fprintf(&b2, " — %s", a.Note)
			}
			b2.WriteString("\n")
		}
	}

	if recent := recentAttempts(b, 8); len(recent) > 0 {
		b2.WriteString("\n### 最近动作（不要重复无效操作）\n")
		for _, a := range recent {
			fmt.Fprintf(&b2, "- `%s` → exit=%d %s\n", a.Cmd, a.Exit, a.Verdict)
		}
	}

	out := b2.String()
	if len(out) > budget {
		out = out[:budget] + "\n…（态势过长，已截断）\n"
	}
	return out
}

// Clone 深拷贝（交接时用，避免两个 goroutine 共享切片）。
func (b *Board) Clone() *Board {
	if b == nil {
		return nil
	}
	c := *b
	c.Facts = append([]Fact(nil), b.Facts...)
	c.Ideas = append([]Idea(nil), b.Ideas...)
	c.Artifacts = append([]Artifact(nil), b.Artifacts...)
	c.Attempts = append([]Attempt(nil), b.Attempts...)
	c.Flags = append([]FlagHit(nil), b.Flags...)
	return &c
}

// Handoff 生成给下一轮用的交接摘要。
func (b *Board) Handoff() string {
	var s strings.Builder
	fmt.Fprintf(&s, "上一轮跑了 %d 步，确认 flag %d 个。\n", b.Steps, b.SolvedFlags())
	if len(b.Facts) > 0 {
		s.WriteString("已证实：\n")
		start := 0
		if len(b.Facts) > 10 {
			start = len(b.Facts) - 10
		}
		for _, f := range b.Facts[start:] {
			fmt.Fprintf(&s, "- %s\n", clip(f.Text, 200))
		}
	}
	if open := openIdeaList(b); len(open) > 0 {
		s.WriteString("没走完的方向：\n")
		for _, i := range open {
			fmt.Fprintf(&s, "- %s\n", clip(i.Text, 160))
		}
	}
	fails := failedAttempts(b, 6)
	if len(fails) > 0 {
		s.WriteString("明确失败过的打法（别再试）：\n")
		for _, a := range fails {
			fmt.Fprintf(&s, "- %s\n", a.Cmd)
		}
	}
	return s.String()
}

func openIdeaList(b *Board) []Idea {
	var out []Idea
	for _, i := range b.Ideas {
		if i.Status == "open" {
			out = append(out, i)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func openIdeas(b *Board) int { return len(openIdeaList(b)) }

func recentAttempts(b *Board, n int) []Attempt {
	if len(b.Attempts) <= n {
		return b.Attempts
	}
	return b.Attempts[len(b.Attempts)-n:]
}

func failedAttempts(b *Board, n int) []Attempt {
	var out []Attempt
	for i := len(b.Attempts) - 1; i >= 0 && len(out) < n; i-- {
		if b.Attempts[i].Verdict == "fail" {
			out = append(out, b.Attempts[i])
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
