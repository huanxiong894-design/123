package core

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractCommonForms(t *testing.T) {
	p := DefaultPolicy()
	_ = p.Compile()
	text := `
$ cat /flag
flag{h3llo_w0rld_2026}
$ cat /root/uuid
9f2c1d4a-7b3e-4c8d-9a11-0e5f6b7c8d90
FLAG: another_one_here
`
	got := p.Extract(text)
	want := []string{
		"flag{h3llo_w0rld_2026}",
		"9f2c1d4a-7b3e-4c8d-9a11-0e5f6b7c8d90",
		"another_one_here",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestExtractSkipsSessionNoise(t *testing.T) {
	p := DefaultPolicy()
	_ = p.Compile()
	text := `HTTP/1.1 200 OK
X-Session-Id: 11111111-2222-3333-4444-555555555555
Set-Cookie: trace-id=66666666-7777-8888-9999-000000000000
{"real":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`
	got := p.Extract(text)
	if len(got) != 1 || got[0] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("噪声 UUID 未被过滤: %v", got)
	}
}

func TestNormalizeKeepsBraces(t *testing.T) {
	p := DefaultPolicy()
	cases := map[string]string{
		`"flag{abc}"`:   "flag{abc}",
		`flag{abc},`:    "flag{abc}",
		`  flag{abc}  `: "flag{abc}",
		`two words xy`:  "",
		`ab`:            "",
	}
	for in, want := range cases {
		if got := Normalize(in, p); got != want {
			t.Fatalf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestExtractCustomPattern(t *testing.T) {
	p := DefaultPolicy()
	p.Patterns = []string{`DASCTF\{[a-z0-9_]+\}`}
	p.AllowUUID = false
	if err := p.Compile(); err != nil {
		t.Fatal(err)
	}
	got := p.Extract("x DASCTF{abc123} y flag{should_not_match} z")
	if len(got) != 1 || got[0] != "DASCTF{abc123}" {
		t.Fatalf("自定义正则未生效: %v", got)
	}
}

func TestExtractCandidateCap(t *testing.T) {
	p := DefaultPolicy()
	p.AllowUUID = false
	p.MaxCandidates = 3
	_ = p.Compile()
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("flag{candidate_number_")
		b.WriteByte(byte('a' + i))
		b.WriteString("}\n")
	}
	if got := p.Extract(b.String()); len(got) != 3 {
		t.Fatalf("候选上限失效: %d %v", len(got), got)
	}
}

func TestGateDedupAndBudget(t *testing.T) {
	g := NewGate(2)
	g.Cooldown = nil // 关冷却，专注验证计数

	if err := g.Check("c1", "flag{a}"); err != nil {
		t.Fatalf("首次应放行: %v", err)
	}
	g.Record("c1", "flag{a}", false)
	if err := g.Check("c1", "flag{a}"); !errors.Is(err, ErrAlreadySubmitted) {
		t.Fatalf("重复应被拦, got %v", err)
	}
	g.Record("c1", "flag{b}", false)
	if err := g.Check("c1", "flag{c}"); !errors.Is(err, ErrTooManyWrong) {
		t.Fatalf("超过上限应锁定, got %v", err)
	}
	if err := g.Check("c2", "flag{c}"); err != nil {
		t.Fatalf("按题隔离，c2 不该被锁: %v", err)
	}
	if err := g.Check("c1", "  "); !errors.Is(err, ErrEmptyFlag) {
		t.Fatalf("空 flag 应拒绝, got %v", err)
	}
	if g.Wrong("c1") != 2 {
		t.Fatalf("Wrong=%d", g.Wrong("c1"))
	}
}

func TestGateCooldown(t *testing.T) {
	g := NewGate(10)
	g.Record("c1", "flag{bad}", false) // 第 1 次错，冷却 0s（无感）
	if err := g.Check("c1", "flag{next1}"); err != nil {
		t.Fatalf("首次错提后不该立即冷却: %v", err)
	}
	g.Record("c1", "flag{bad2}", false) // 第 2 次错 → 冷却 30s
	if err := g.Check("c1", "flag{next2}"); !errors.Is(err, ErrCooldown) {
		t.Fatalf("应进入冷却, got %v", err)
	}
	g.Record("c1", "flag{ok}", true) // 答对即清零
	if err := g.Check("c1", "flag{next3}"); err != nil {
		t.Fatalf("答对后应解除冷却: %v", err)
	}
}

func TestBoardSituationAndHandoff(t *testing.T) {
	ch := &Challenge{ID: "c1", Category: "web", FlagCount: 2}
	b := NewBoard(ch)
	b.AddFact("存在 SQL 注入", "sqlmap: parameter 'id' is vulnerable")
	b.AddIdea("试试 SSTI")
	b.AddArtifact(ArtifactCred, "admin:admin123", "登录框爆破")
	b.RecordFlag("flag{real}", true)

	s := b.Situation(4000)
	for _, frag := range []string{"已证实的事实", "存在 SQL 注入", "待验证的假设", "试试 SSTI", "admin:admin123", "flag{real}"} {
		if !strings.Contains(s, frag) {
			t.Fatalf("态势缺少 %q：\n%s", frag, s)
		}
	}

	b.SetIdea(1, "done", "试过了，无 SSTI")
	if strings.Contains(b.Situation(4000), "试试 SSTI") {
		t.Fatal("已完成假设仍出现在待验证列表")
	}

	h := b.Handoff()
	if !strings.Contains(h, "存在 SQL 注入") || !strings.Contains(h, "跑了") {
		t.Fatalf("交接摘要不完整:\n%s", h)
	}
	if b.SolvedFlags() != 1 {
		t.Fatalf("SolvedFlags=%d", b.SolvedFlags())
	}
}

func TestBoardDedupAndClone(t *testing.T) {
	b := NewBoard(&Challenge{ID: "x"})
	if !b.AddArtifact(ArtifactFile, "/tmp/a", "") {
		t.Fatal("首次应成功")
	}
	if b.AddArtifact(ArtifactFile, "/tmp/a", "") {
		t.Fatal("重复应返回 false")
	}
	if len(b.Artifacts) != 1 {
		t.Fatalf("len=%d", len(b.Artifacts))
	}
	b.AddAttempt("ls", 0, "ok")
	c := b.Clone()
	c.AddFact("只出现在副本", "")
	if len(b.Facts) != 0 {
		t.Fatal("Clone 未深拷贝")
	}
}

func TestSituationBudget(t *testing.T) {
	b := NewBoard(&Challenge{ID: "y"})
	for i := 0; i < 50; i++ {
		b.AddFact(strings.Repeat("很长的证据事实", 20), "")
	}
	s := b.Situation(600)
	if len(s) > 700 {
		t.Fatalf("态势未按预算裁剪: %d", len(s))
	}
}
