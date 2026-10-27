package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Local 在本机目录里执行命令。
//
// 用途：
//   - 本地题库（misc/rev/crypto 这类纯文件题）直接开箱即用；
//   - 开发调试：不想每次都起容器；
//   - 单元测试。
//
// 安全提示：它没有隔离。跑来源不明的题请用 Docker 运行时。
type Local struct {
	root     string
	spoolDir string
	targets  []string
}

// NewLocal 在 root 下构造本地运行时；root 会被创建。
func NewLocal(root string) (*Local, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &Local{root: abs, spoolDir: filepath.Join(abs, ".ctfagent", "spill")}, nil
}

// SetTargets 设置可达目标（例如本地起的服务地址）。
func (l *Local) SetTargets(t []string) { l.targets = append([]string(nil), t...) }

// Name 实现 Runtime。
func (l *Local) Name() string { return "local" }

// Workdir 实现 Runtime。
func (l *Local) Workdir() string { return l.root }

// Targets 实现 Runtime。
func (l *Local) Targets() []string { return l.targets }

// Close 实现 Runtime。
func (l *Local) Close(context.Context) error { return nil }

// Exec 实现 Runtime。
func (l *Local) Exec(ctx context.Context, spec ExecSpec) (Output, error) {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "sh", "-c", spec.Cmd)
	cmd.Dir = l.root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// 只杀 sh 不够：sh 拉起的子进程（sleep / python / 爆破脚本）会攥着管道不放，
	// cmd.Wait 会一直等到它们自己退出，超时就形同虚设。这里按进程组整组杀。
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	// 兜底：即使还有孙进程握着 fd，2 秒后也把管道关掉，不让 Wait 卡死。
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	out := Output{Duration: dur}
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
			if runCtx.Err() == context.DeadlineExceeded {
				exit = 124 // 与 coreutils timeout 对齐
				stderr.WriteString("\n[超时被杀]")
			}
		} else {
			return Output{}, err
		}
	}
	out.Exit = exit
	out.Stdout, out.Truncated = truncate(stdout.String(), spec.MaxBytes)
	if out.Truncated {
		out.SpillPath = spill(l.spoolDir, stdout.String())
	}
	out.Stderr, _ = truncate(stderr.String(), spec.MaxBytes/2)
	return out, nil
}

// WriteFile 把内容写进工作目录（相对路径）或绝对路径。
func (l *Local) WriteFile(_ context.Context, path string, data []byte) error {
	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(l.root, target)
	}
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(l.root)) && !filepath.IsAbs(path) {
		return fmt.Errorf("拒绝写到工作目录之外: %s", path)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

// ReadFile 读文件。
func (l *Local) ReadFile(_ context.Context, path string, maxBytes int64) ([]byte, error) {
	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(l.root, target)
	}
	f, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
