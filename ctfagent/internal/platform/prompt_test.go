package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ctfagent/internal/core"
)

func TestLoadPromptSpecs(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "q1.json")
	if err := os.WriteFile(one, []byte(`{"id":"q1","prompt":"读 /flag","targets":["http://1.2.3.4:80"],"flag_count":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	arr := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(arr, []byte(`[{"id":"q2","prompt":"p2"},{"id":"q3","prompt":"p3"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	// 目录会读所有 *.json
	specs, err := LoadPromptSpecs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 3 {
		t.Fatalf("应读到 3 道题，实际 %d", len(specs))
	}
	byID := map[string]PromptSpec{}
	for _, sp := range specs {
		byID[sp.ID] = sp
	}
	if byID["q1"].Targets[0] != "http://1.2.3.4:80" {
		t.Fatalf("q1 解析错了: %+v", byID["q1"])
	}
	if byID["q2"].Prompt != "p2" || byID["q3"].Prompt != "p3" {
		t.Fatalf("数组文件解析错了: %+v", byID)
	}
	// 单文件
	one2, err := LoadPromptSpecs(one)
	if err != nil || len(one2) != 1 || one2[0].ID != "q1" {
		t.Fatalf("单文件解析失败: %v %+v", err, one2)
	}
}

func TestPromptAdapterLifecycle(t *testing.T) {
	root := t.TempDir()
	p, err := NewPrompt(root, []PromptSpec{
		{ID: "q1", Title: "第一题", Category: "web", Prompt: "题面一", Targets: []string{"http://t:8080"}, FlagCount: 1, Hint: "看看 /admin"},
		{ID: "q2", Prompt: "题面二"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	list, err := p.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if list[0].ID != "q1" || list[0].Prompt != "题面一" || len(list[0].Targets) != 1 {
		t.Fatalf("翻译错了: %+v", list[0])
	}

	conn, err := p.Acquire(ctx, "q1")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Container != "" {
		t.Fatal("没给容器就不该用 docker")
	}
	if _, err := os.Stat(conn.WorkDir); err != nil {
		t.Fatalf("工作目录应存在: %v", err)
	}
	if conn.Targets[0] != "http://t:8080" {
		t.Fatalf("targets=%v", conn.Targets)
	}
	if err := p.Release(ctx, "q1"); err != nil {
		t.Fatal(err)
	}

	// 没有判题接口 → 记下来，并明确标记"未验证"
	res, err := p.Submit(ctx, "q1", "flag{manual}")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Correct || !res.Unverified {
		t.Fatalf("无判题接口时应返回「已记录 + 未验证」: %+v", res)
	}
	if got := p.Recorded(); len(got) != 1 || got[0] != "q1\tflag{manual}" {
		t.Fatalf("recorded=%v", got)
	}
	if got := p.Name(); got != "prompt" {
		t.Fatalf("name=%s", got)
	}

	// 有判题接口就真的提交
	p.SubmitFn = func(_ context.Context, id, flag string) (SubmitResult, error) {
		return SubmitResult{Correct: flag == "flag{real}", Cumulative: 100}, nil
	}
	if got := p.Name(); got != "prompt+judge" {
		t.Fatalf("name=%s", got)
	}
	r2, err := p.Submit(ctx, "q1", "flag{real}")
	if err != nil || !r2.Correct || r2.Unverified || r2.Cumulative != 100 {
		t.Fatalf("有判题接口时应走真实提交: %+v err=%v", r2, err)
	}
}

func TestPromptHintAndPolicy(t *testing.T) {
	p, err := NewPrompt(t.TempDir(), []PromptSpec{
		{ID: "q1", Hint: "就在 /admin?debug=1"},
		{ID: "q2"},
		{ID: "q3", FlagPattern: `DASCTF\{[a-z0-9_]+\}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hint(context.Background(), "q1")
	if err != nil || h != "就在 /admin?debug=1" {
		t.Fatalf("hint=%q err=%v", h, err)
	}
	if _, err := p.Hint(context.Background(), "q2"); err == nil {
		t.Fatal("没提示应报错")
	} else {
		var u *UnsupportedError
		if !errors.As(err, &u) {
			t.Fatalf("应是 Unsupported: %v", err)
		}
	}
	pol := p.Policy(&core.Challenge{FlagPattern: `DASCTF\{[a-z0-9_]+\}`})
	if pol.AllowUUID || len(pol.Patterns) != 1 {
		t.Fatalf("自定义 flag 形态应覆盖默认策略: %+v", pol)
	}
	if def := p.Policy(nil); !def.AllowUUID {
		t.Fatal("默认策略应允许 UUID")
	}
}

func TestPromptSpecValidation(t *testing.T) {
	if _, err := NewPrompt(t.TempDir(), []PromptSpec{{ID: "x"}, {ID: "x"}}); err == nil {
		t.Fatal("重复 id 应报错")
	}
	// 空 id 自动编号
	p, err := NewPrompt(t.TempDir(), []PromptSpec{{Prompt: "a"}, {Prompt: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.specs[0].ID != "q1" || p.specs[1].ID != "q2" {
		t.Fatalf("自动编号失败: %+v", p.specs)
	}
	if _, err := p.Acquire(context.Background(), "nope"); err == nil {
		t.Fatal("不存在的题目应报错")
	}
}
