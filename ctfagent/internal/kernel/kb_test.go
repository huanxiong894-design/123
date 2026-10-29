package kernel

import (
	"strings"
	"testing"
)

// TestKBReachable 锁住「每种漏洞类的关键词都能检索到对应技术卡」。
// 卡片名/关键词变体都可以改，但每个大类必须有落点。
func TestKBReachable(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	cases := map[string]string{
		`{"query":"参数名 爆破 接口发现"}`:                                         "interface-discovery",
		`{"query":"端口 php-fpm 服务枚举"}`:                                     "service-enum",
		`{"query":"unix socket 提权后"}`:                                     "post-exploitation",
		`{"query":"ssrf 内网 绕过"}`:                                          "ssrf",
		`{"query":"500 状态码 oracle"}`:                                      "http-signals",
		`{"query":"cookie 八进制 解析怪癖"}`:                                     "parser-quirks",
		`{"query":"sql 注入 union"}`:                                        "sqli",
		`{"query":"模板 ssti jinja"}`:                                       "ssti",
		`{"query":"文件读取 穿越"}`:                                             "file-read",
		`{"query":"上传 后缀"}`:                                               "upload",
		`{"query":"命令注入 拼接"}`:                                             "cmdi",
		`{"query":"反序列化 pickle"}`:                                         "deser",
		`{"query":"认证 绕过 jwt"}`:                                           "auth-bypass",
		`{"query":"对象存储 sas 凭证代理"}`:                                       "cloud-storage",
		`{"query":"python 沙箱 逃逸 builtins"}`:                               "python-sandbox",
		`{"query":"nodejs vm2 逃逸 process"}`:                               "node-sandbox",
		`{"query":"yara 检测规避 shellcode"}`:                                 "detection-evasion",
		`{"query":"dns 隧道 外带 分块"}`:                                        "exfiltration",
		`{"query":"侦察 指纹 目录"}`:                                            "web-recon",
		`{"query":"无回显 盲执行 探针 写回读"}`:                                      "blind-exec",
		`{"query":"面板 安全入口 验证码 登录"}`:                                      "panels",
		`{"query":"内网 横向 跳板 ssh 弱口令"}`:                                    "pivot",
		`{"query":"多阶段 链条 推进清单 每台机器"}`:                                    "flag-chain",
		`{"query":"云 元数据 函数 环境变量 联邦"}`:                                    "cloud-identity",
		`{"query":"限时 分诊 时间预算 低垂果实"}`:                                     "triage",
		`{"query":"xml 外部实体 doctype 解析器"}`:                                "xxe",
		`{"query":"逆向 解码 缓冲区 不打印 ptrace"}`:                                "rev-pipeline",
		`{"query":"web ctf evidence session traversal"}`:                  "web-ctf-workflow",
		`{"query":"pwn binary canary rop alignment"}`:                     "pwn-pipeline",
		`{"query":"reverse engineering data flow binary"}`:                "reverse-triage",
		`{"query":"misc forensics pcap archive trailing bytes"}`:          "misc-forensics",
		`{"query":"zero-width unicode invisible codepoint encoding"}`:     "misc-forensics",
		`{"query":"TCP reassemble HTTP Content-Length request body"}`:     "misc-forensics",
		`{"query":"pickle text wrapper whitespace split UTF-8 protocol"}`: "pwn-pipeline",
	}
	for q, want := range cases {
		out := call(t, ts, "kb", q)
		if !strings.Contains(out, want) {
			t.Errorf("kb(%s) 没命中 %s:\n%s", q, want, trimSnippet(out, 400))
		}
	}
}

// TestKBNotesArePlatformAgnostic 防止「把某道题的解法写进知识库」。
// 知识库只允许「与题目无关的技术手法」：不允许出现题号、flag 值、平台私有路径。
func TestKBNotesArePlatformAgnostic(t *testing.T) {
	banned := []string{"TSecBench", "tsecbench", "challenge/flag", "flag{", "internal-api", "a-01", "a-13", "a-18"}
	dir, err := kbFS.ReadDir("prompts/kb")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range dir {
		b, err := kbFS.ReadFile("prompts/kb/" + e.Name())
		if err != nil {
			continue
		}
		text := string(b)
		for _, w := range banned {
			if strings.Contains(text, w) {
				t.Errorf("%s 含有平台/题目专属标记 %q：知识库必须是通用手法", e.Name(), w)
			}
		}
	}
}

// TestSolverPromptIsPlatformAgnostic 同理，系统提示词里也不能写死某题/某平台。
func TestSolverPromptIsPlatformAgnostic(t *testing.T) {
	for _, w := range []string{"TSecBench", "challenge/flag", "a-18", "a-14"} {
		if strings.Contains(DefaultSystemPrompt, w) {
			t.Errorf("系统提示词含有平台/题目专属标记 %q", w)
		}
	}
}

func TestReferenceLessonsRemainGeneralAndAddressable(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	checks := map[string][]string{
		"node-sandbox":      {"版本、封装器和结果捕获路径", "跨 realm", "无害错误对象"},
		"detection-evasion": {"分层校验", "非线性交互", "不要把 500 当作崩溃"},
		"http-signals":      {"状态码只是线索", "相同的通用 5xx", "不能据此推断服务端接受"},
	}
	for name, terms := range checks {
		out := call(t, ts, "kb", `{"name":"`+name+`"}`)
		for _, term := range terms {
			if !strings.Contains(out, term) {
				t.Errorf("%s 缺少通用参考经验 %q", name, term)
			}
		}
	}
}

func TestCategoryWorkflowCardsAreAddressable(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	for _, name := range []string{"solver-loop", "web-ctf-workflow", "pwn-pipeline", "reverse-triage", "misc-forensics"} {
		out := call(t, ts, "kb", `{"name":"`+name+`"}`)
		if !strings.Contains(out, "# "+name) || len(out) < 250 {
			t.Errorf("knowledge card %q was not returned in full: %s", name, trimSnippet(out, 300))
		}
		if strings.Contains(out, "CTF2{") || strings.Contains(out, "flag{") {
			t.Errorf("knowledge card %q contains a hard-coded answer", name)
		}
	}
}

func TestSolverPromptContainsScopeAndCategoryRouting(t *testing.T) {
	for _, want := range []string{
		"不使用互联网搜索或外部题解",
		"严格限制目标范围",
		"web-ctf-workflow",
		"pwn-pipeline",
		"reverse-triage",
		"misc-forensics",
		"solver-loop",
		"提交被拒后停止",
		"通用 5xx",
		"连续三步无 Board 进展",
	} {
		if !strings.Contains(DefaultSystemPrompt, want) {
			t.Errorf("solver prompt missing %q", want)
		}
	}
}
