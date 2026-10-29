package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"ctfagent/internal/core"
	"ctfagent/internal/sandbox"
)

// Prompt（提示词接入）适配器。
//
// 有些评测/比赛不给你 API：题面是**一段文本**（网页上贴给你、或者你在会话里收到），
// 容器地址写在文本里，flag 也要人工去网页提交。这种模式没有 List/Submit 接口，
// 但它依然是"一道 CTF 题"，内核照样能解——差别只在题目从哪来、flag 交给谁。
//
// 所以这里把"题面"变成 PromptSpec：
//   - 从文件读（JSON），或从一段纯文本 + 若干 --target 拼出来；
//   - 工作目录/容器由 spec 指定，没指定就本地临时目录；
//   - 有判题接口就调它，没有就把 flag 记下来并标记 Unverified（人工去交）。
//
// 设计红线不变：内核不认识 "prompt 模式"，它只看到 core.Challenge 与 SubmitResult。
type Prompt struct {
	baseDir string
	specs   []PromptSpec
	// SubmitFn 非空时会真的提交（例如复用 TSecBench 的 openapi）。
	SubmitFn func(ctx context.Context, id, flag string) (SubmitResult, error)

	mu       sync.Mutex
	recorded []string          // 无判题接口时记下的 flag
	started  map[string]string // id -> 我们起的容器 id
	reset    map[string]bool
}

// PromptSpec 是一道"贴过来的题"。
type PromptSpec struct {
	ID          string            `json:"id"`
	Title       string            `json:"title,omitempty"`
	Category    string            `json:"category,omitempty"`
	Prompt      string            `json:"prompt"`
	Targets     []string          `json:"targets,omitempty"`
	Attachments []core.Attachment `json:"attachments,omitempty"`
	FlagCount   int               `json:"flag_count,omitempty"`
	FlagPattern string            `json:"flag_pattern,omitempty"`
	Hint        string            `json:"hint,omitempty"`
	// Container 是**已经起好的**容器（平台已经给你了），直接 docker exec 进去操作。
	Container string `json:"container,omitempty"`
	// Docker 是"需要我们自己起容器"的配置。
	Docker *PromptDocker `json:"docker,omitempty"`
	// WorkDir 指定宿主侧工作目录（默认 <baseDir>/.work/<id>）。
	WorkDir string `json:"workdir,omitempty"`
}

// NewPrompt 构造提示词接入适配器。baseDir 只用于放工作目录。
func NewPrompt(baseDir string, specs []PromptSpec) (*Prompt, error) {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = os.TempDir()
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range specs {
		if strings.TrimSpace(specs[i].ID) == "" {
			specs[i].ID = fmt.Sprintf("q%d", i+1)
		}
		if seen[specs[i].ID] {
			return nil, fmt.Errorf("题目 id 重复: %s", specs[i].ID)
		}
		seen[specs[i].ID] = true
	}
	return &Prompt{baseDir: abs, specs: specs, started: map[string]string{}, reset: map[string]bool{}}, nil
}

// LoadPromptSpecs 读一个或多个 JSON 文件；目录则读其中所有 *.json。
func LoadPromptSpecs(paths ...string) ([]PromptSpec, error) {
	var out []PromptSpec
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			var names []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					names = append(names, filepath.Join(p, e.Name()))
				}
			}
			sort.Strings(names)
			for _, n := range names {
				sp, err := readPromptSpec(n)
				if err != nil {
					return nil, err
				}
				out = append(out, sp...)
			}
			continue
		}
		sp, err := readPromptSpec(p)
		if err != nil {
			return nil, err
		}
		out = append(out, sp...)
	}
	return out, nil
}

func readPromptSpec(path string) ([]PromptSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 允许两种写法：单个对象，或对象数组。
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var arr []PromptSpec
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return arr, nil
	}
	var one PromptSpec
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return []PromptSpec{one}, nil
}

// Name 实现 Adapter。
func (p *Prompt) Name() string {
	if p.SubmitFn != nil {
		return "prompt+judge"
	}
	return "prompt"
}

// List 实现 Adapter：题目来自 spec，不是网络。
func (p *Prompt) List(context.Context) ([]core.Challenge, error) {
	out := make([]core.Challenge, 0, len(p.specs))
	for _, sp := range p.specs {
		ch := core.Challenge{
			ID:          sp.ID,
			Title:       sp.Title,
			Category:    sp.Category,
			Prompt:      sp.Prompt,
			Targets:     sp.Targets,
			Attachments: sp.Attachments,
			FlagPattern: sp.FlagPattern,
			FlagCount:   sp.FlagCount,
			Meta:        map[string]string{},
		}
		if sp.Container != "" {
			ch.Meta["container"] = sp.Container
		}
		if sp.Hint != "" {
			ch.Meta["hint"] = sp.Hint
		}
		out = append(out, ch)
	}
	return out, nil
}

// Acquire 实现 Adapter：已经给好容器就直接用，否则本地目录 / 自己起容器。
func (p *Prompt) Acquire(ctx context.Context, id string) (*Conn, error) {
	sp, err := p.spec(id)
	if err != nil {
		return nil, err
	}
	work := sp.WorkDir
	if work == "" {
		work = filepath.Join(p.baseDir, ".work", dirName(id))
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	if sp.Container != "" {
		wd := sp.Docker.WorkdirOrDefault()
		return &Conn{Container: sp.Container, WorkDir: wd, HostDir: work, Targets: sp.Targets}, nil
	}
	if sp.Docker != nil && sp.Docker.Image != "" {
		if err := sandbox.DockerAvailable(ctx); err != nil {
			return nil, err
		}
		ctr, err := runContainer(ctx, id, sp.Docker.Image, sp.Docker.Ports, sp.Docker.WorkdirOrDefault())
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.started[id] = ctr
		p.mu.Unlock()
		return &Conn{
			Container: ctr,
			WorkDir:   sp.Docker.WorkdirOrDefault(),
			HostDir:   work,
			Targets:   sp.Targets,
			Release: func(c context.Context) error {
				p.mu.Lock()
				delete(p.started, id)
				p.mu.Unlock()
				return removeContainer(c, ctr)
			},
		}, nil
	}
	return &Conn{WorkDir: work, HostDir: work, Targets: sp.Targets}, nil
}

// Release 实现 Adapter。
func (p *Prompt) Release(ctx context.Context, id string) error {
	p.mu.Lock()
	ctr, ok := p.started[id]
	delete(p.started, id)
	p.mu.Unlock()
	if !ok {
		return nil
	}
	return removeContainer(ctx, ctr)
}

// Submit 实现 Adapter：有判题接口就用，没有就记下来（Unverified）。
func (p *Prompt) Submit(ctx context.Context, id, flag string) (SubmitResult, error) {
	if p.SubmitFn != nil {
		return p.SubmitFn(ctx, id, flag)
	}
	p.mu.Lock()
	p.recorded = append(p.recorded, id+"\t"+flag)
	p.mu.Unlock()
	return SubmitResult{
		Correct:    true,
		Unverified: true,
		Message:    "本模式没有判题接口：flag 已记录，请人工提交",
	}, nil
}

// Recorded 返回本次运行中"记下来但没有验证"的 flag（按出现顺序）。
func (p *Prompt) Recorded() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.recorded...)
}

// Hint 实现 Adapter。
func (p *Prompt) Hint(_ context.Context, id string) (string, error) {
	sp, err := p.spec(id)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(sp.Hint) == "" {
		return "", Unsupported("这道题没有提供提示")
	}
	return sp.Hint, nil
}

// Policy 实现 Adapter。
func (p *Prompt) Policy(ch *core.Challenge) core.FlagPolicy {
	pol := core.DefaultPolicy()
	if ch != nil && ch.FlagPattern != "" {
		pol.Patterns = []string{ch.FlagPattern}
		pol.AllowUUID = false
	}
	return pol
}

func (p *Prompt) spec(id string) (PromptSpec, error) {
	for _, sp := range p.specs {
		if sp.ID == id {
			return sp, nil
		}
	}
	return PromptSpec{}, fmt.Errorf("没有这道题: %s", id)
}

// PromptDocker 描述"自己起容器"需要的参数。
type PromptDocker struct {
	Image   string   `json:"image"`
	Ports   []string `json:"ports,omitempty"`
	Workdir string   `json:"workdir,omitempty"`
}

// WorkdirOrDefault 返回容器内工作目录。
func (d *PromptDocker) WorkdirOrDefault() string {
	if d == nil || d.Workdir == "" {
		return "/work"
	}
	return d.Workdir
}

// ---------------------------------------------------------------------------
// 容器生命周期（docker run / rm）。失败了就退回 tail -f，兼容没有 sleep 的镜像。
// ---------------------------------------------------------------------------

func runContainer(ctx context.Context, id, image string, ports []string, workdir string) (string, error) {
	if workdir == "" {
		workdir = "/work"
	}
	args := []string{"run", "-d", "--rm", "--name", "ctfagent-" + dirName(id), "-w", workdir}
	for _, p := range ports {
		args = append(args, "-p", p)
	}
	base := append([]string(nil), args...)
	base = append(base, image, "sleep", "infinity")
	out, err := execDocker(ctx, base...)
	if err != nil {
		fallback := append([]string(nil), args...)
		fallback = append(fallback, image, "tail", "-f", "/dev/null")
		out, err = execDocker(ctx, fallback...)
		if err != nil {
			return "", fmt.Errorf("启动容器失败: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return strings.TrimSpace(string(out)), nil
}

func execDocker(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func removeContainer(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	_, _ = execDocker(ctx, "rm", "-f", id) // 容器可能已经被 --rm 收走，失败不算错
	return nil
}
