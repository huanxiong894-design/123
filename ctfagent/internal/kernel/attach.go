package kernel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/sandbox"
)

// 附件落地。
//
// 通用 CTF 里"附件"是最容易被忽略的一环：题目给的是一个下载链接，
// 而模型的第一反应是在**目标环境里** curl —— 但目标环境可能没有网络出口，
// 也可能根本没有 curl。所以 agent 侧先把附件抓下来、写进沙箱工作目录，
// 题面里再告诉模型"文件已经在 <路径>"。这一步做掉，rev/misc 题的成功率立刻不一样。
//
// 规则：
//   - URL 附件：agent 侧下载（带超时与大小上限），再写进沙箱；
//   - Path 附件：宿主侧读出来，写进沙箱（本地题库常用）；
//   - 失败不致命：记一条日志，题面里仍然保留原始 URL 供模型自己想办法。
const (
	attachTimeout  = 120 * time.Second
	attachMaxBytes = 256 << 20 // 单个附件上限 256MB
)

// stageAttachments 把附件放进沙箱工作目录，返回"已就绪"的说明行（喂给模型）。
func stageAttachments(ctx context.Context, rt sandbox.Runtime, ch *core.Challenge, logf func(string, ...any)) []string {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var notes []string
	for _, a := range ch.Attachments {
		name := safeName(a.Name)
		if name == "" {
			name = "attachment"
		}
		switch {
		case a.URL != "":
			data, err := fetchAttachment(ctx, a.URL)
			if err != nil {
				logf("[%s] 附件 %s 下载失败: %v", ch.ID, a.Name, err)
				continue
			}
			if err := rt.WriteFile(ctx, name, data); err != nil {
				logf("[%s] 附件 %s 写入沙箱失败: %v", ch.ID, a.Name, err)
				continue
			}
			notes = append(notes, fmt.Sprintf("- %s 已下载到工作目录：%s（%d 字节）", a.Name, name, len(data)))
			logf("[%s] 附件已就位: %s（%d 字节）", ch.ID, name, len(data))
		case a.Path != "":
			data, err := os.ReadFile(a.Path)
			if err != nil {
				logf("[%s] 附件 %s 读取失败: %v", ch.ID, a.Name, err)
				continue
			}
			if err := rt.WriteFile(ctx, name, data); err != nil {
				logf("[%s] 附件 %s 写入沙箱失败: %v", ch.ID, a.Name, err)
				continue
			}
			notes = append(notes, fmt.Sprintf("- %s 已就位：%s（%d 字节）", a.Name, name, len(data)))
		default:
			notes = append(notes, fmt.Sprintf("- %s（平台没有给出下载地址，可能需要在目标环境里找）", a.Name))
		}
	}
	return notes
}

func fetchAttachment(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("不支持的附件协议: %s", url)
	}
	dctx, cancel := context.WithTimeout(ctx, attachTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, attachMaxBytes))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// safeName 只保留基名，并挡掉 ../ 之类的路径穿越。
func safeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = filepath.Base(name)
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	return name
}
