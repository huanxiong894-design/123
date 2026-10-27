package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"ctfagent/internal/core"
	"ctfagent/internal/sandbox"
)

// LocalSuite 是"本地题库"适配器。
//
// 它是本项目最重要的自测手段：**不用任何平台、不花钱、不联网**就能验证
// 解题内核是否在正常工作、改了提示词/工具之后有没有退化。
// TSecBench 只是最终度量，日常迭代都在这里做。
//
// 目录结构：
//
//	suite/
//	  warmup/
//	    challenge.json      ← 题目定义
//	    flag.txt            ← 期望的 flag（一行一个，可含多个）★不会进工作目录
//	    hint.txt            ← 可选 ★不会进工作目录
//	    files...            ← 附件（启动时复制进沙箱工作目录）
//
// 注意「答案隔离」：flag.txt / hint.txt / checker.sh 不会被复制到工作目录，
// 否则 agent 一个 `cat flag.txt` 就能"解出"所有题——这种自测毫无意义。
// 工作目录是 <suite>/.work/<id>/，跨轮保留（agent 的中间产物不丢），
// 加 --fresh 可以清空重来。
//
// challenge.json 示例：
//
//	{
//	  "id": "warmup",
//	  "title": "热身：base64 套娃",
//	  "category": "crypto",
//	  "prompt": "解出 secret.b64 得到 flag",
//	  "flag_pattern": "flag\\{[^}]+\\}",
//	  "flag_count": 1
//	}
//
// 需要容器环境时加：
//
//	"docker": {"image": "alpine:3.20", "ports": ["8080:80"], "workdir": "/work"}
type LocalSuite struct {
	Dir string
	// Fresh 为 true 时，每次 Acquire 前清空工作目录（默认 false：跨轮保留 agent 的产物）。
	Fresh bool

	mu         sync.Mutex
	containers map[string]string // challenge id -> container id
}

type localSpec struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Prompt      string   `json:"prompt"`
	Targets     []string `json:"targets"`
	FlagPattern string   `json:"flag_pattern"`
	FlagCount   int      `json:"flag_count"`
	MaxScore    int      `json:"max_score"`
	FlagFile    string   `json:"flag_file"` // 默认 flag.txt
	HintFile    string   `json:"hint_file"` // 默认 hint.txt
	Docker      *struct {
		Image   string   `json:"image"`
		Ports   []string `json:"ports"`
		Workdir string   `json:"workdir"`
	} `json:"docker"`
}

// NewLocalSuite 构造本地题库适配器。
func NewLocalSuite(dir string) (*LocalSuite, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("题库目录不存在: %s", abs)
	}
	return &LocalSuite{Dir: abs, containers: map[string]string{}}, nil
}

// Name 实现 Adapter。
func (s *LocalSuite) Name() string { return "local" }

// List 实现 Adapter：扫描所有含 challenge.json 的子目录。
func (s *LocalSuite) List(context.Context) ([]core.Challenge, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []core.Challenge
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		specPath := filepath.Join(s.Dir, e.Name(), "challenge.json")
		if _, err := os.Stat(specPath); err != nil {
			continue
		}
		sp, err := readSpec(specPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", specPath, err)
		}
		if sp.ID == "" {
			sp.ID = e.Name()
		}
		ch := core.Challenge{
			ID:          sp.ID,
			Title:       sp.Title,
			Category:    sp.Category,
			Prompt:      sp.Prompt,
			Targets:     sp.Targets,
			FlagPattern: sp.FlagPattern,
			FlagCount:   sp.FlagCount,
			MaxScore:    sp.MaxScore,
			Meta:        map[string]string{"dir": filepath.Join(s.Dir, e.Name())},
		}
		out = append(out, ch)
	}
	return out, nil
}

// Acquire 实现 Adapter：有 docker 配置就起容器，否则直接返回本地目录。
func (s *LocalSuite) Acquire(ctx context.Context, id string) (*Conn, error) {
	dir, spec, err := s.locate(id)
	if err != nil {
		return nil, err
	}
	workDir, err := s.prepareWork(id, dir, spec)
	if err != nil {
		return nil, err
	}
	if spec.Docker != nil && spec.Docker.Image != "" {
		ctr, err := s.startContainer(ctx, id, spec.Docker.Image, spec.Docker.Ports, spec.Docker.Workdir)
		if err != nil {
			return nil, err
		}
		wd := spec.Docker.Workdir
		if wd == "" {
			wd = "/work"
		}
		return &Conn{
			Container: ctr,
			WorkDir:   wd,
			HostDir:   workDir,
			Targets:   spec.Targets,
			Release: func(c context.Context) error {
				return s.stopContainer(c, id)
			},
		}, nil
	}
	return &Conn{
		WorkDir: workDir,
		HostDir: workDir,
		Targets: spec.Targets,
	}, nil
}

// prepareWork 准备隔离的工作目录：把附件复制进去，但把答案类文件留在题库里。
func (s *LocalSuite) prepareWork(id, dir string, spec *localSpec) (string, error) {
	work := filepath.Join(s.Dir, ".work", dirName(id))
	skip := map[string]bool{
		"challenge.json": true,
		"hint.txt":       true,
		"checker.sh":     true,
		"flag.txt":       true,
	}
	if spec != nil {
		if spec.FlagFile != "" {
			skip[spec.FlagFile] = true
		}
		if spec.HintFile != "" {
			skip[spec.HintFile] = true
		}
	}
	if s.Fresh {
		_ = os.RemoveAll(work)
	}
	if _, err := os.Stat(work); err == nil {
		return work, nil // 已准备好，跨轮保留 agent 的产物
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if skip[e.Name()] {
			continue
		}
		src := filepath.Join(dir, e.Name())
		dst := filepath.Join(work, e.Name())
		if err := copyTree(src, dst); err != nil {
			return "", fmt.Errorf("复制附件 %s 失败: %w", e.Name(), err)
		}
	}
	return work, nil
}

// ResetWork 清空某题的工作目录（CLI --fresh / 单元测试用）。
func (s *LocalSuite) ResetWork(id string) error {
	return os.RemoveAll(filepath.Join(s.Dir, ".work", dirName(id)))
}

func dirName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

func copyTree(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, st.Mode().Perm())
}

// Release 实现 Adapter。
func (s *LocalSuite) Release(ctx context.Context, id string) error {
	return s.stopContainer(ctx, id)
}

// Submit 实现 Adapter：与 flag 文件比对（或用 checker.sh 做自定义判定）。
func (s *LocalSuite) Submit(ctx context.Context, id, flag string) (SubmitResult, error) {
	dir, spec, err := s.locate(id)
	if err != nil {
		return SubmitResult{}, err
	}
	// 自定义判定脚本优先
	checker := filepath.Join(dir, "checker.sh")
	if st, err := os.Stat(checker); err == nil && !st.IsDir() {
		cmd := exec.CommandContext(ctx, "sh", checker, flag)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err == nil {
			return SubmitResult{Correct: true, Message: strings.TrimSpace(string(out))}, nil
		}
		return SubmitResult{Correct: false, Message: strings.TrimSpace(string(out))}, nil
	}

	flagFile := spec.FlagFile
	if flagFile == "" {
		flagFile = "flag.txt"
	}
	data, err := os.ReadFile(filepath.Join(dir, flagFile))
	if err != nil {
		return SubmitResult{}, fmt.Errorf("题库缺少 %s（或用 checker.sh 自定义判定）: %w", flagFile, err)
	}
	want := strings.TrimSpace(flag)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == want && want != "" {
			return SubmitResult{Correct: true}, nil
		}
	}
	return SubmitResult{Correct: false}, nil
}

// Hint 实现 Adapter。
func (s *LocalSuite) Hint(_ context.Context, id string) (string, error) {
	dir, spec, err := s.locate(id)
	if err != nil {
		return "", err
	}
	name := spec.HintFile
	if name == "" {
		name = "hint.txt"
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", Unsupported("该题没有提供提示")
	}
	return strings.TrimSpace(string(data)), nil
}

// Policy 实现 Adapter。
func (s *LocalSuite) Policy(ch *core.Challenge) core.FlagPolicy {
	p := core.DefaultPolicy()
	if ch != nil && ch.FlagPattern != "" {
		p.Patterns = []string{ch.FlagPattern}
		p.AllowUUID = false
	}
	return p
}

// ---------------------------------------------------------------------------

func readSpec(path string) (*localSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sp localSpec
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("challenge.json 解析失败: %w", err)
	}
	return &sp, nil
}

func (s *LocalSuite) locate(id string) (string, *localSpec, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return "", nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.Dir, e.Name())
		specPath := filepath.Join(dir, "challenge.json")
		if _, err := os.Stat(specPath); err != nil {
			continue
		}
		sp, err := readSpec(specPath)
		if err != nil {
			return "", nil, err
		}
		spID := sp.ID
		if spID == "" {
			spID = e.Name()
		}
		if spID == id {
			return dir, sp, nil
		}
	}
	return "", nil, fmt.Errorf("题库里没有这道题: %s", id)
}

func (s *LocalSuite) startContainer(ctx context.Context, id, image string, ports []string, workdir string) (string, error) {
	s.mu.Lock()
	if ctr, ok := s.containers[id]; ok {
		s.mu.Unlock()
		return ctr, nil
	}
	s.mu.Unlock()

	if err := sandbox.DockerAvailable(ctx); err != nil {
		return "", fmt.Errorf("这道题需要容器环境，但 %w", err)
	}
	if workdir == "" {
		workdir = "/work"
	}
	args := []string{"run", "-d", "--rm", "--name", "ctfagent-" + sanitize(id), "-w", workdir}
	for _, p := range ports {
		args = append(args, "-p", p)
	}
	args = append(args, image, "sleep", "infinity")
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		// 有些镜像没有 sleep，退回 tail
		args[len(args)-2] = "tail"
		args[len(args)-1] = "-f"
		args = append(args, "/dev/null")
		out, err = exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("启动容器失败: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	ctr := strings.TrimSpace(string(out))
	s.mu.Lock()
	s.containers[id] = ctr
	s.mu.Unlock()
	return ctr, nil
}

func (s *LocalSuite) stopContainer(ctx context.Context, id string) error {
	s.mu.Lock()
	ctr, ok := s.containers[id]
	delete(s.containers, id)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", ctr)
	_ = cmd.Run()
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-") + "-" + strconv.Itoa(os.Getpid())
}

var _ = errors.Is
