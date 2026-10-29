// Package sandbox 抽象"agent 能动手的地方"。
//
// 解题内核只认这个接口：它不关心目标是本机目录、docker 容器、还是远端 SSH。
// 新增一种运行环境 = 新增一个实现，内核零改动。
package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Output 是一次命令执行的结果。
type Output struct {
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Exit      int           `json:"exit"`
	Truncated bool          `json:"truncated"`
	SpillPath string        `json:"spill_path,omitempty"` // 输出过长时的落盘路径（模型可再读）
	Duration  time.Duration `json:"duration"`
}

// Text 把 stdout/stderr 合成模型可读的一段。
func (o Output) Text() string {
	var b strings.Builder
	b.WriteString(o.Stdout)
	if strings.TrimSpace(o.Stderr) != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("[stderr]\n")
		b.WriteString(o.Stderr)
	}
	if o.Truncated && o.SpillPath != "" {
		fmt.Fprintf(&b, "\n[输出已截断，完整内容见 %s]", o.SpillPath)
	}
	return b.String()
}

// ExecSpec 描述一次执行。
type ExecSpec struct {
	Cmd      string        // shell 命令（经 sh -c 执行）
	Timeout  time.Duration // 0 = 默认 120s
	MaxBytes int64         // 0 = 默认 32KB
}

// Runtime 是 agent 的操作面。
type Runtime interface {
	// Name 返回实现名（local/docker/ssh…），用于日志与报告。
	Name() string
	// Exec 在目标环境里执行命令。
	Exec(ctx context.Context, spec ExecSpec) (Output, error)
	// WriteFile 写文件（相对工作目录或绝对路径，由实现决定）。
	WriteFile(ctx context.Context, path string, data []byte) error
	// ReadFile 读文件，最多 maxBytes。
	ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error)
	// Workdir 返回工作目录（模型写文件时的默认根）。
	Workdir() string
	// Targets 返回可达目标（URL / host:port），供模型参考。
	Targets() []string
	// Close 释放资源。
	Close(ctx context.Context) error
}

const (
	defaultTimeout  = 120 * time.Second
	defaultMaxBytes = 32 << 10
)

var spillSeq atomic.Int64

// spill 把超长输出落到本地文件，返回路径。
// 注意：落盘位置在**agent 宿主**上，不一定是沙箱内；调用方需保证 spoolDir 可写。
func spill(spoolDir string, data string) string {
	if spoolDir == "" {
		return ""
	}
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		return ""
	}
	name := fmt.Sprintf("out-%d-%d.log", time.Now().UnixNano(), spillSeq.Add(1))
	p := filepath.Join(spoolDir, name)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		return ""
	}
	return p
}

// truncate 按字节截断（保持 UTF-8 边界安全）。
func truncate(s string, max int64) (string, bool) {
	if max <= 0 {
		max = defaultMaxBytes
	}
	if int64(len(s)) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // 回退到字符起点
		cut--
	}
	return s[:cut], true
}
