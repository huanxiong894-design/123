package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newLocal(t *testing.T) *Local {
	t.Helper()
	l, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLocalExecBasics(t *testing.T) {
	l := newLocal(t)
	ctx := context.Background()

	out, err := l.Exec(ctx, ExecSpec{Cmd: "echo out; echo err >&2; exit 3"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Exit != 3 {
		t.Fatalf("exit=%d", out.Exit)
	}
	text := out.Text()
	if !strings.Contains(text, "out") || !strings.Contains(text, "[stderr]") || !strings.Contains(text, "err") {
		t.Fatalf("stdout/stderr 合并异常:\n%s", text)
	}
}

func TestLocalExecWorkdir(t *testing.T) {
	l := newLocal(t)
	out, err := l.Exec(context.Background(), ExecSpec{Cmd: "pwd"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.Stdout) != l.Workdir() {
		t.Fatalf("工作目录=%q want %q", out.Stdout, l.Workdir())
	}
}

func TestLocalExecTimeoutKillsProcessGroup(t *testing.T) {
	l := newLocal(t)
	start := time.Now()
	out, err := l.Exec(context.Background(), ExecSpec{Cmd: "sleep 5", Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("超时没生效，耗时 %s", d)
	}
	if out.Exit != 124 {
		t.Fatalf("超时应统一为 exit=124，实际 %d", out.Exit)
	}
	if !strings.Contains(out.Text(), "超时") {
		t.Fatalf("应提示超时: %s", out.Text())
	}
}

func TestLocalTruncatesAndSpills(t *testing.T) {
	l := newLocal(t)
	// 生成 200KB 输出，限制 1KB
	out, err := l.Exec(context.Background(), ExecSpec{Cmd: "head -c 200000 /dev/zero | tr '\\0' 'a'", MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated {
		t.Fatal("应标记截断")
	}
	if len(out.Stdout) > 1100 {
		t.Fatalf("未截断: %d 字节", len(out.Stdout))
	}
	if out.SpillPath == "" {
		t.Fatal("截断后应落盘")
	}
	if st, err := os.Stat(out.SpillPath); err != nil || st.Size() != 200000 {
		t.Fatalf("落盘文件不对: %v size=%v", err, st)
	}
	if !strings.Contains(out.Text(), "完整内容见") {
		t.Fatalf("应提示落盘路径: %s", out.Text()[:200])
	}
}

func TestLocalWriteReadFile(t *testing.T) {
	l := newLocal(t)
	ctx := context.Background()
	if err := l.WriteFile(ctx, "a/b.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(l.Workdir(), "a", "b.txt")); err != nil {
		t.Fatalf("相对路径没写进工作目录: %v", err)
	}
	data, err := l.ReadFile(ctx, "a/b.txt", 100)
	if err != nil || string(data) != "hello" {
		t.Fatalf("读回=%q err=%v", data, err)
	}
	// 超过 maxBytes 只读这么多
	if data, _ := l.ReadFile(ctx, "a/b.txt", 2); string(data) != "he" {
		t.Fatalf("maxBytes 未生效: %q", data)
	}
	// 绝对路径允许（模型常写 /tmp/...）
	abs := filepath.Join(t.TempDir(), "abs.txt")
	if err := l.WriteFile(ctx, abs, []byte("x")); err != nil {
		t.Fatalf("绝对路径应允许: %v", err)
	}
}

func TestLocalPathTraversalBlocked(t *testing.T) {
	l := newLocal(t)
	if err := l.WriteFile(context.Background(), "../escape.txt", []byte("x")); err == nil {
		t.Fatal("拒绝写到工作目录之外")
	}
}

func TestLocalTargets(t *testing.T) {
	l := newLocal(t)
	l.SetTargets([]string{"http://127.0.0.1:8080"})
	if got := l.Targets(); len(got) != 1 || got[0] != "http://127.0.0.1:8080" {
		t.Fatalf("targets=%v", got)
	}
	if l.Name() != "local" || l.Workdir() == "" {
		t.Fatal("基本接口缺失")
	}
}

// Docker 运行时在没装 docker 的环境里必须优雅失败（doctor 依赖这个行为）。
func TestDockerUnavailableIsGraceful(t *testing.T) {
	err := DockerAvailable(context.Background())
	if err == nil {
		t.Skip("本机有 docker，跳过不可用分支")
	}
	if _, err := NewDocker("no-such-container", "/work", nil); err != nil {
		t.Fatalf("构造不该依赖 docker 存活: %v", err)
	}
}
