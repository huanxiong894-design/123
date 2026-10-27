// Package platform 把"题目从哪来、flag 交给谁"抽象成一个极小的接口。
//
// 这是整个项目最重要的一条边界：
//   - 内核（kernel）只认 core.Challenge 和 core.SubmitResult；
//   - 平台差异（TSecBench / CTFd / 本地题库 / 自建 API）全部关在 Adapter 里。
//
// 于是同一套解题能力可以：今天跑 TSecBench 打榜，明天跑本地题库回归，后天接 CTFd 打比赛。
package platform

import (
	"context"

	"ctfagent/internal/core"
)

// Conn 是"这道题现在可以怎么动手"。
type Conn struct {
	// Targets 是可达地址（URL 或 host:port），会被写进题面。
	Targets []string
	// Container 非空表示需要在容器内操作（docker 运行时）。
	Container string
	// WorkDir 是沙箱内的工作目录（容器内绝对路径，或本地目录）。
	WorkDir string
	// HostDir 是宿主侧目录（本地题库用；用于落盘证据与中间产物）。
	HostDir string
	// Release 由适配器在收尾时调用（停靶场、删容器等）。
	Release func(ctx context.Context) error
}

// SubmitResult 是提交结果；定义在 core，平台层只做别名，避免内核反向依赖平台。
type SubmitResult = core.SubmitResult

// Adapter 是一个平台。
//
// Hint 与 Release 允许返回 ErrUnsupported —— 不是所有平台都有提示/靶场容器。
type Adapter interface {
	Name() string
	List(ctx context.Context) ([]core.Challenge, error)
	Acquire(ctx context.Context, id string) (*Conn, error)
	Release(ctx context.Context, id string) error
	Submit(ctx context.Context, id, flag string) (SubmitResult, error)
	Hint(ctx context.Context, id string) (string, error)
	Policy(ch *core.Challenge) core.FlagPolicy
}

// ErrUnsupported 表示该平台不提供这项能力。
type UnsupportedError struct{ What string }

func (e *UnsupportedError) Error() string { return "该平台不支持: " + e.What }

// Unsupported 构造一个"不支持"错误。
func Unsupported(what string) error { return &UnsupportedError{What: what} }
