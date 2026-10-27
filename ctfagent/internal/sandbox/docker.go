package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Docker 通过 docker exec 在容器内执行命令。
//
// 两种典型用法：
//   - 平台给的是"靶场容器"（TSecBench 的题目容器）：agent 直接进去操作；
//   - 本地题库自带 docker 镜像：平台适配器负责 docker run，再把容器 id 交给这里。
//
// 只依赖 docker CLI，不引第三方 SDK —— 少一个依赖就少一类坑。
type Docker struct {
	Container string
	workDir   string
	targets   []string
	spoolDir  string
	// KeepAlive 保留容器不销毁（容器生命周期实际由平台适配器管理）。
	KeepAlive bool

	timeoutOnce sync.Once
	hasTimeout  bool
}

// NewDocker 构造容器运行时。
func NewDocker(container, workdir string, targets []string) (*Docker, error) {
	if strings.TrimSpace(container) == "" {
		return nil, errors.New("docker 运行时需要一个容器 id/name")
	}
	if workdir == "" {
		workdir = "/work"
	}
	return &Docker{Container: container, workDir: workdir, targets: targets}, nil
}

// SetSpoolDir 设置超长输出的落盘目录（宿主侧）。
func (d *Docker) SetSpoolDir(p string) { d.spoolDir = p }

// Name 实现 Runtime。
func (d *Docker) Name() string { return "docker:" + d.Container }

// Workdir 实现 Runtime。
func (d *Docker) Workdir() string { return d.workDir }

// Targets 实现 Runtime。
func (d *Docker) Targets() []string { return d.targets }

// Close 实现 Runtime：容器生命周期由平台适配器管理，这里不销毁。
func (d *Docker) Close(context.Context) error { return nil }

// Exec 实现 Runtime。
func (d *Docker) Exec(ctx context.Context, spec ExecSpec) (Output, error) {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 容器内的进程必须被容器里的 timeout 收掉：只杀本地 docker CLI，
	// 容器里的爆破脚本会继续跑到天荒地老，还占着 CPU。
	inner := spec.Cmd
	if d.probeTimeout(ctx) {
		sec := int(timeout.Seconds())
		if sec < 1 {
			sec = 1
		}
		inner = fmt.Sprintf("timeout -s KILL %d sh -c %s", sec, shellQuote(spec.Cmd))
	}

	args := []string{"exec"}
	if d.workDir != "" {
		args = append(args, "-w", d.workDir)
	}
	args = append(args, d.Container, "sh", "-c", inner)
	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	out := Output{Duration: time.Since(start)}

	if err != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			out.Exit = ee.ExitCode()
			if runCtx.Err() == context.DeadlineExceeded {
				out.Exit = 124
				stderr.WriteString("\n[超时被杀]")
			}
		default:
			return Output{}, fmt.Errorf("docker exec 失败: %w", err)
		}
	}
	out.Stdout, out.Truncated = truncate(stdout.String(), spec.MaxBytes)
	if out.Truncated {
		out.SpillPath = spill(d.spoolDir, stdout.String())
	}
	out.Stderr, _ = truncate(stderr.String(), spec.MaxBytes/2)
	return out, nil
}

// WriteFile 用 stdin 把内容灌进容器（不依赖宿主机与容器的共享目录）。
func (d *Docker) WriteFile(ctx context.Context, path string, data []byte) error {
	target := path
	if !strings.HasPrefix(target, "/") {
		target = strings.TrimRight(d.workDir, "/") + "/" + path
	}
	parent := target[:strings.LastIndex(target, "/")+1]
	if parent != "" && parent != "/" {
		mk := exec.CommandContext(ctx, "docker", "exec", d.Container, "mkdir", "-p", parent)
		if out, err := mk.CombinedOutput(); err != nil {
			return fmt.Errorf("创建目录失败: %v (%s)", err, out)
		}
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", d.Container, "sh", "-c", "cat > "+shellQuote(target))
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("写文件失败: %v (%s)", err, out)
	}
	return nil
}

// ReadFile 从容器读文件。
func (d *Docker) ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	target := path
	if !strings.HasPrefix(target, "/") {
		target = strings.TrimRight(d.workDir, "/") + "/" + path
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", d.Container, "cat", target)
	stdout, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if int64(len(stdout)) > maxBytes {
		stdout = stdout[:maxBytes]
	}
	return stdout, nil
}

// CopyTo 把宿主文件拷进容器（执行器上传附件时用）。
func (d *Docker) CopyTo(ctx context.Context, hostPath, dst string) error {
	cmd := exec.CommandContext(ctx, "docker", "cp", hostPath, d.Container+":"+dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker cp 失败: %v (%s)", err, out)
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// probeTimeout 探测容器里有没有 timeout 命令（busybox 通常有，精简镜像可能没有）；结果缓存。
func (d *Docker) probeTimeout(ctx context.Context) bool {
	d.timeoutOnce.Do(func() {
		chk, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := exec.CommandContext(chk, "docker", "exec", d.Container, "sh", "-c", "command -v timeout").Run()
		d.hasTimeout = err == nil
	})
	return d.hasTimeout
}

// DockerAvailable 供 doctor 与本地题库适配器判断环境。
func DockerAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg, _ := io.ReadAll(&stderr)
		return fmt.Errorf("docker 不可用: %v %s", err, strings.TrimSpace(string(msg)))
	}
	return nil
}

var _ = time.Second
