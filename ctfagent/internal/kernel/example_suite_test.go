package kernel_test

// 这是一条**集成**测试：用 examples/suite 里真正发出去的题库，走完整的
// 平台适配器 → 沙箱 → 工具 → grounding → 提交 → 报告 链路。
//
// 模型是剧本（Scripted），所以不需要 API key；剧本写的动作和真人 agent 会做的
// 完全一样（解 base64、推 XOR key、拼 ELF 里的字符串、开立方根），
// 所以它同时验证了「这几道示例题确实可解、且解出来的串能通过 grounding」。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/kernel"
	"ctfagent/internal/llm"
	"ctfagent/internal/platform"
)

type exampleCase struct {
	id     string
	script []llm.Reply
}

func exampleSuiteDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "examples", "suite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("示例题库不存在: %v", err)
	}
	return dir
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExampleSuiteIsSolvable(t *testing.T) {
	suite := exampleSuiteDir(t)
	cases := []exampleCase{
		{
			id: "warmup-b64",
			script: []llm.Reply{
				llm.Call("sh", `{"command":"head -c 120 secret.txt"}`),
				llm.Call("py", mustJSON(t, map[string]string{
					"name": "decode",
					"code": `import base64
s = open("secret.txt").read().strip()
for _ in range(5):
    if s.startswith("flag{"):
        break
    s = base64.b64decode(s).decode()
print(s)`,
				})),
				llm.Call("submit", `{"flag":"flag{b4se64_is_not_encryption}","evidence":"flag{b4se64_is_not_encryption}"}`),
			},
		},
		{
			id: "xor-crypto",
			script: []llm.Reply{
				llm.Call("py", mustJSON(t, map[string]string{
					"name": "xor",
					"code": `data = open("cipher.bin","rb").read()
key = data[0] ^ ord("f")          # 已知明文前缀 flag{
print(bytes(b ^ key for b in data).decode())`,
				})),
				llm.Call("submit", `{"flag":"flag{xor_with_single_byte_key}","evidence":"flag{xor_with_single_byte_key}"}`),
			},
		},
		{
			id: "rev-binary",
			script: []llm.Reply{
				llm.Call("sh", `{"command":"file check && strings -a check | grep -n 'flag\\|_is\\|r3v\\|strings'"}`),
				llm.Call("py", mustJSON(t, map[string]string{
					"name": "join_parts",
					"code": `import re
data = open("check","rb").read()
strs = re.findall(rb"[\x20-\x7e]{4,}", data)
parts = [s.decode() for s in strs if re.match(r"^(flag\{|_is_|t_reading|_strings\})", s.decode())]
print("".join(parts))`,
				})),
				llm.Call("submit", `{"flag":"flag{r3v_is_just_reading_strings}","evidence":"flag{r3v_is_just_reading_strings}"}`),
			},
		},
		{
			id: "rsa-small-e",
			script: []llm.Reply{
				llm.Call("sh", `{"command":"cat params.json"}`),
				llm.Call("py", mustJSON(t, map[string]string{
					"name": "cube_root",
					"code": `import json
def iroot(n, k):
    lo, hi = 0, 1 << (n.bit_length() // k + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n: lo = mid
        else: hi = mid - 1
    return lo
p = json.load(open("params.json"))
m = iroot(p["c"], p["e"])
assert pow(m, p["e"]) == p["c"], "c 不是完全 e 次方，说明假设不成立"
print(m.to_bytes((m.bit_length() + 7) // 8, "big").decode())`,
				})),
				llm.Call("submit", `{"flag":"flag{sm4ll_e_no_p4dding}","evidence":"flag{sm4ll_e_no_p4dding}"}`),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			ad, err := platform.NewLocalSuite(suite)
			if err != nil {
				t.Fatal(err)
			}
			ad.Fresh = true
			t.Cleanup(func() { _ = ad.ResetWork(tc.id) })

			list, err := ad.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var target *core.Challenge
			for i := range list {
				if list[i].ID == tc.id {
					target = &list[i]
				}
			}
			if target == nil {
				t.Fatalf("题库里没有 %s", tc.id)
			}

			model := llm.NewScripted(tc.script...)
			rep, err := kernel.NewOrchestrator(ad, model, kernel.RunConfig{
				Concurrency: 1,
				Rounds:      []time.Duration{20 * time.Second},
				Solver:      kernel.Config{MaxSteps: 8, Budget: 20 * time.Second, SituationBudget: 3000},
			}).Run(context.Background(), []core.Challenge{*target})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Solved != 1 {
				t.Fatalf("示例题 %s 没有解出：%+v", tc.id, rep.Challenges)
			}
			if !strings.HasPrefix(rep.Challenges[0].Flags[0], "flag{") {
				t.Fatalf("flag 异常: %v", rep.Challenges[0].Flags)
			}
			t.Logf("%s 解出：%v（%d 步）", tc.id, rep.Challenges[0].Flags, rep.Challenges[0].Steps)
		})
	}
}
