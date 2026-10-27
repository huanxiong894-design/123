# ctfagent — 通用 CTF 自动解题 agent

给一道 CTF 题（题面 + 可达目标 + 附件），agent 自己在环境里侦察、利用、拿 flag、按平台接口提交；
一道题解不出就换路线，卡住就交接给下一轮，全部过程都有证据链。

**它是通用的，不是某个比赛的附件。** TSecBench 在这里只是一个平台适配器（`internal/platform/tsecbench.go`），
跟"本地题库"平级。想接 CTFd、自己公司的靶场、或者比赛方临时给的 API，加一个适配器即可，内核一行都不用改。

```
$ ctfagent demo
...
──────── local · scripted ────────
CHALLENGE                    CATEGORY   SOLVED STEPS  耗时       结论
demo-hello                   misc       YES    4      0s       solved

总计：1/1 题解出 · flag 1 · 耗时 0s · token 0/0
```

---

## 1. 快速开始

```bash
# 0) 需要 Go 1.23+（只用标准库，无第三方依赖）
make build            # 产出 ./ctfagent

# 1) 不花钱先验证整条链路：剧本模型 + 临时题库
./ctfagent demo

# 2) 环境自检（模型连通性 / docker / 题库 / 平台）
./ctfagent doctor --platform local --suite examples/suite

# 3) 看示例题库里有什么
./ctfagent list --platform local --suite examples/suite

# 4) 用真实模型跑整批（DeepSeek / 通义 / Kimi / vLLM / Ollama 都可以）
export CTFAGENT_MODEL=deepseek-chat
export CTFAGENT_LLM_URL=https://api.deepseek.com/v1
export CTFAGENT_API_KEY=sk-xxx
./ctfagent run --platform local --suite examples/suite --concurrency 2 --out report.json

# 5) 单题调试
./ctfagent solve --platform local --suite examples/suite --id rev-binary -v
```

跑 TSecBench（评测 = 度量，不是开发目标）：

```bash
export BENCHMARK_BASE_URL=https://<平台地址>
export BENCHMARK_TOKEN=<你的 token>

./ctfagent doctor --platform tsec          # 会做 VPN 预检 + 拉题
./ctfagent run --platform tsec \
    --concurrency 3 \                      # 平台上限 3 个容器并发
    --rounds 30m,20m \                     # 两轮：先 30 分钟，卡住的再给 20 分钟
    --total-budget 5h30m \                 # 单题上限 1 小时，留出收尾时间
    --out tsec-report.json
```

> 提示：`--hints` 会向平台要提示（官方会扣分），默认关闭。
> 平台规则若收紧成"单题串行"，把 `--concurrency` 改成 1 即可——调度层与平台规则无关。
> 单题预算别贴着 1 小时上限设（超时直接判失败，连 flag 都交不上去），30m + 20m 两轮更稳。

---

## 2. 它长什么样

```
cmd/ctfagent/main.go        CLI：demo | list | solve | run | doctor | version
internal/
├── core/                   领域模型（**不 import 任何平台**）
│   ├── challenge.go        Challenge / Board（事实·假设·产物·尝试·flag）/ Situation / Handoff
│   └── flag.go             flag 抽取 + 归一化 + 提交闸门（去重/错提上限/指数冷却）
├── llm/                    模型接口（**不 import 任何 UI 或平台**）
│   ├── openai.go           OpenAI 兼容客户端（tools / 重试 / 退避）
│   └── scripted.go         剧本模型：单测、演示、回归都用它，零成本
├── sandbox/                "agent 能动手的地方"
│   ├── local.go            本机目录（进程组超时、输出落盘、路径逃逸防护）
│   └── docker.go           docker exec（容器内 timeout、stdin 写文件）
├── platform/               "题目从哪来、flag 交给谁"
│   ├── platform.go         Adapter / Conn / SubmitResult —— 唯一平台边界
│   ├── localsuite.go       本地题库（challenge.json + flag.txt，答案隔离）
│   └── tsecbench.go        TSecBench OpenAPI
└── kernel/                 解题与调度（**只依赖 core / llm / sandbox / platform 接口**）
    ├── solver.go           单题循环：态势回灌 → 模型 → 工具 → 进展检测 → 交接
    ├── tools.go            通用工具集 + grounding 证据池 + 提交闸门
    ├── orchestrator.go     批量调度：优先级、并发、多轮重试、熔断、报告
    ├── prompt.go           内嵌中文系统提示词
    └── prompts/solver.md   提示词正文（分类打法、铁律、收工条件）
```

依赖方向是单向的：

```
core ← llm ← kernel → sandbox
                 ↘ platform → (core)
```

`kernel` 里出现 `tsecbench`、`benchmark_token`、`10.0.100.58` 这类字样，就是设计事故。
`go vet` 之外我还在 `internal/platform/tsecbench_test` 里用 `httptest` 假扮平台跑契约测试——**没有真平台也能验证适配器**。

---

## 3. 五个关键设计

### 3.1 一切状态都在「作战板」（Board）里，不在上下文里

ARTEX 用资产图 + 探索图做外置状态；CTF 没有资产面，但同样需要外置状态。
这里把状态压成五类，每一步都以「当前态势」的形式回灌一次：

| Board 里的东西 | 来自哪 | 作用 |
|---|---|---|
| `Fact`（事实 + 逐字证据） | `fact` 工具 | 防止"我记得是 nginx 1.18"式的幻觉 |
| `Idea`（假设 / 状态 / 结论） | `idea` 工具 | 卡住时知道还有哪些方向没试 |
| `Artifact`（文件 / 凭据 / 端点 / key） | `artifact` 工具、自动登记 | 跨轮复用，不用重新找 |
| `Attempt`（命令 + exit + 判定） | 每次 `sh`/`py` 自动记录 | 重复检测、交接里列出"明确失败过的打法" |
| `Flag`（候选 + 是否正确） | `submit` 工具 | 去重、部分得分进度 |

上下文超长时不靠"模型自己记得"，而是 `Board.Situation()` 重新压一遍，旧消息按窗口裁剪，
裁剪掉的用 `Board.Handoff()` 折成一段摘要——这就是 ARTEX "cold digest" 的等价物。

### 3.2 反幻觉三件套（这是能不能上分的关键）

1. **grounding**：`submit` 要求 flag 字面量**逐字出现**在最近工具输出里（空白可归一化）；
   `fact` 的 evidence 也一样。推理出来、拼出来、"应该长这样"的串，一个字都交不上去。
2. **提交闸门**（`core.Gate`）：同一题同一个串只交一次；错提到上限就锁定；错提后按 0s → 30s → 2m → 5m 指数冷却。
   官方虽然不惩罚错交，但错交会烧掉时间预算，也会污染模型对"我试过什么"的判断。
3. **停滞检测**：连续 5 步没有任何新事实/假设/产物/flag，就注入"你在原地打转，换机理不同的路线"；
   连续两轮纯聊天不调工具，强制推动或收工。**不打转比聪明更重要。**

另外 25 条实测踩到的坑都写进了测试（见第 7 节），比如：`Normalize` 不能把 `flag{...}` 的右花括号 trim 掉；
UUID 形态的 flag 要过滤 `x-session-id` / `trace-id` 这类噪声；`sh -c` 超时必须整组杀进程，否则 `sleep` 会拖着 `Wait` 不放。

### 3.3 工具：少而通用 + 一套「协议层」与「载荷构造」能力

| 工具 | 干什么 |
|---|---|
| `sh` / `py` | 任意命令 / 写脚本再执行（一切的基础） |
| `http` | agent 侧直连 HTTP，**自带会话**（Set-Cookie 跨调用保持）；`inject={param,value}` 把整段 query 注进参数值（打凭证代理），`raw_query` 原样拼接，`gzip_body` 压缩请求体绕网关，回显实际 URL |
| `recon` | 指纹 + 目录 + 敏感文件 + 跳转/401/403/405 分组 + 假 200 基线，一次调用出全图 |
| `fuzz` | `FUZZ` 占位并发爆破；`diff=true` 时**只报告与基线不同的响应** |
| `ports` | 端口扫描 + 协议指纹（HTTP / FastCGI / MySQL / Redis / Docker…） |
| `paramfuzz` | 参数名爆破：公开词典 + 复合命名规则，响应差异做 oracle，命中即停 |
| `fcgi` | 直连 php-fpm 执行 PHP（`auto_prepend_file=php://input`） |
| `unix` | 走 unix socket 发 HTTP（本地 agent 类服务） |
| `raw` | 裸 TCP（Redis / MySQL / SMTP / 自研协议，文本或 hex） |
| `pickle` | 把一条 Python 表达式翻成 pickle opcode（只走 `getattr`），专治「白名单只放行无害函数」的反序列化题 |
| `jwt` | JWT 通用编解码/伪造：`decode`（payload + 时间字段 + 可疑 claim 提示）/ `sign`（HS256/384/512，可带 `kid`/`jku`）/ `none`（两段式变体）/ `jwks`（发布 `oct` JWKS 供 `jku` 自签）；密钥与声明全部由调用方提供 |
| `polyglot` | 造「主格式合法 + 第二格式可解析」的复合文件（png/gif/jpg/pdf × PHP/JS/ZIP） |
| `tunnel` | 分块 + 编码 + 序号/会话的文件外带（DNS label、URL、请求头都行） |
| `unmix` | 「静态密文 + 已知明文格式」的按字节去混淆穷举：给高熵块 + 候选常量表，把 `rot(blob OP1 key) OP2 c` 的整个组合空间枚举掉，以**全部可打印**为 oracle，按"像凭据"排序返回变换描述与明文 |
| `kb` | 检索内置技术卡（29 篇，见 1.1） |
| `read` / `write` | 读写目标环境文件 |
| `fact` / `idea` / `artifact` | 外置状态：事实（带证据）/ 假设 / 中间产物 |
| `submit` / `finish` | 唯一出口（闸门 → grounding → 平台）/ 收工 |

**为什么要内置「协议层 + 载荷构造」工具**：`nmap`/`sqlmap` 这类依赖外部二进制，容器里有没有不由我们决定，
专用逻辑应当由模型写成脚本。但 **FastCGI、unix socket、裸 TCP** 不是"工具"，而是"能不能说上话"——
说不上话，后面所有推理都无从谈起，所以必须内置成一次调用。
同理，`pickle` / `polyglot` / `tunnel` 这类载荷**构造**也是「稍错一个字节就整条废掉」的活：
手拼 pickle opcode、算 PNG tEXt 的 CRC 与偏移、按通道切块编码，本质是在做编译器该做的事。
把它们做成工具，模型就能把注意力放在「用哪条链」而不是「怎么把字节写对」。

### 3.4 调度只认"题"，不认"内容"

`Orchestrator` 负责：优先级排序（分值高的先跑，同分里 flag 少的先跑）、并发窗口、
多轮重试（每轮一个新的时间片，带着上一轮的 Board 交接）、总预算、模型熔断、报告。

它不知道什么是 web、什么是 pwn。所以同一个调度器跑本地题库和跑 TSecBench 完全一样——
区别只在 `platform.Adapter` 的实现。

### 3.5 附件先落地，再分析

题目给的附件（下载链接或本地路径）在**开跑前**就被抓进沙箱工作目录，题面里直接告诉模型"文件已经在
`xxx.bin`"。这一步花 200ms，能省掉模型"目标环境里能不能联网/有没有 curl"的几轮摸索——
rev / misc / crypto 题尤其明显。下载失败不致命，题面里仍保留原始 URL 让模型自己想办法。

路径是净化过的（只取 basename，挡 `../`），单个附件上限 256MB。

### 3.6 平台适配器只有 6 个方法

```go
type Adapter interface {
    Name() string
    List(ctx) ([]core.Challenge, error)                                  // 题目
    Acquire(ctx, id) (*Conn, error)                                      // 起环境 / 拿地址
    Release(ctx, id) error                                               // 关环境
    Submit(ctx, id, flag) (core.SubmitResult, error)                     // 交 flag
    Hint(ctx, id) (string, error)                                        // 取提示（可不支持）
    Policy(ch *core.Challenge) core.FlagPolicy                           // 这平台的 flag 长什么样
}
```

接一个新平台 ≈ 写 6 个方法 + 一个 `httptest` 契约测试，半天工作量。TSecBench 就是个例子：
`unique_code` → `Challenge.ID`、`container_addr` → `Conn.Targets`、`correct` → `SubmitResult.Correct`，
重复提交的 409 被翻译成"已计分"而不是错误（否则会白白重试）。

---

## 4. 命令行

| 命令 | 作用 |
|---|---|
| `ctfagent demo` | 不用 API key，用剧本模型跑通"侦察 → 读 flag → 提交 → 收工" |
| `ctfagent list` | 列题目 |
| `ctfagent solve --id X` | 解一道题（调试用） |
| `ctfagent run` | 跑整批，出报告（`--out report.json`） |
| `ctfagent prompt` | **提示词接入**：题面是贴过来的文本，没有 List/Submit 接口也能跑 |
| `ctfagent doctor` | 自检：模型连通性、docker、题库、平台、VPN |
| `ctfagent version` | 版本 |

常用参数：

```
--platform local|tsec     平台（默认 local）
--suite DIR               本地题库目录
--base-url / --token      TSecBench 地址与 token（也可用 BENCHMARK_BASE_URL / BENCHMARK_TOKEN）
--skip-vpn                跳过 VPN 预检（仅本地联调）
--model / --llm-url / --api-key
                          模型（也可用 CTFAGENT_MODEL / CTFAGENT_LLM_URL / CTFAGENT_API_KEY）
--concurrency N           并发题数（TSecBench 上限 3）
--rounds 30m,20m          每轮的单题预算，长度 = 最多跑几轮
--total-budget 5h30m      整场预算
--max-steps 40            单题最大步数
--budget 30m              单题时间预算（覆盖调度默认值）
--grounding=false         关闭"flag 必须出现在真实输出里"的校验（不建议）
--hints                   允许向平台取提示（官方会扣分）
--fresh                   本地题库：清空工作目录后重跑
--only id1,id2            只跑这些题
--trace trace.jsonl       把每一步（模型原话/工具/参数/输出）写成 JSONL，赛后复盘用
--out report.json         报告路径
```

退出码：`0` 正常（`solve` 时表示解出）；`1` 运行错误或未解出；`2` 参数错误。`Ctrl-C` 会优雅收尾（关容器、写报告）。

### 4.1 提示词接入（没有 API 的评测/比赛）

有些平台只给你一段题面（网页上贴的、会话里发的），容器地址写在文本里，flag 要人工去提交。
这种模式没有 `List`/`Submit` 接口，但题还是那道题：

```bash
# 直接贴文本 + 目标地址（容器地址在题面里看到什么就填什么）
./ctfagent prompt --text-file q1.txt --id q1 --category web \
    --target http://10.0.1.5:8080 \
    --workdir ./work/q1 \
    --trace q1.trace.jsonl

# 或者写成 spec，一次跑多题（也支持传目录）
./ctfagent prompt --spec q1.json --spec q2.json --concurrency 1

# 如果平台其实还有 openapi 能交 flag，就接上——这样提交是**真验证**的
./ctfagent prompt --spec q1.json --submit-tsec --base-url https://... --token ...
```

两种收尾方式，报告里区分得很清楚：

| 场景 | 提交结果 | 报告 |
|---|---|---|
| 有判题接口（`--submit-tsec`） | 平台返回 `correct=true` | `YES` |
| 没有判题接口 | 只记录，不验证 | `YES?` + 结尾打印「需要人工提交的 flag」清单 |

如果平台已经起好容器并给了容器 id，加 `--container <id>`，agent 会直接 `docker exec` 进去操作。

`q1.json` 的样子见 `examples/prompt/q1.example.json`：`prompt` 是题面原文，`targets` 是可达地址，
`attachments` 支持 `url`（agent 侧下载）和 `path`（本地文件），`flag_pattern` 决定"什么算 flag"。

### 4.2 复盘：跑完怎么知道它哪里不行

加 `--trace` 就能拿到每一步的原始记录（JSONL）：

```bash
jq -r '[.challenge, .kind, (.step|tostring), (.tool // "-")] | @tsv' run.trace.jsonl | head -40

# 每道题走了多少步、卡在哪个工具上
jq -r 'select(.kind=="tool") | [.challenge, .tool] | @tsv' run.trace.jsonl | sort | uniq -c | sort -rn

# 重复执行同一条命令（典型的原地打转）
jq -r 'select(.kind=="tool" and .tool=="sh") | [.challenge, .args] | @tsv' run.trace.jsonl | sort | uniq -c | sort -rn | head
```

这三个查询正好对应"能力评估"要看的三件事：**步骤效率、工具偏科、原地打转**。

---

## 5. 自带题库：`examples/suite`

四道**离线可解**的题，覆盖 misc / crypto / rev，答案隔离（`flag.txt` 不会被复制进工作目录）：

| 题目 | 练什么 | 解法 |
|---|---|---|
| `warmup-b64` | 多层 base64 | 逐层 decode |
| `xor-crypto` | 单字节 XOR | 用已知明文前缀 `flag{` 反推 key |
| `rev-binary` | ELF 静态字符串 | `strings` 找到 4 段，按 `parts` 顺序拼 |
| `rsa-small-e` | RSA 小 e 无填充 | `c = m^3` 直接开立方根 |

写自己的题：建一个子目录，放 `challenge.json` + `flag.txt`（+ 可选 `hint.txt`、任意附件、`checker.sh`）。

```json
{
  "id": "warmup",
  "title": "热身：base64 套娃",
  "category": "crypto",
  "prompt": "解出 secret.b64 得到 flag",
  "flag_pattern": "flag\\{[^}]+\\}",
  "flag_count": 1
}
```

需要容器环境时加 `"docker": {"image": "alpine:3.20", "ports": ["8080:80"], "workdir": "/work"}`，
适配器会 `docker run` 并以容器为沙箱（`docker` 运行时）。

---

## 6. 加东西的正确姿势

**加一个平台**：实现 `platform.Adapter` 六个方法，在 `cmd/ctfagent/main.go` 的 `adapter()` 里加一个分支。
不要为了新平台去改 `kernel`。

**加一种运行环境**（SSH、k8s pod、远端 jumpbox）：实现 `sandbox.Runtime`（`Exec/WriteFile/ReadFile/Workdir/Targets/Close`）。

**加一个模型协议**（Anthropic 原生、Gemini）：实现 `llm.Client`（`Chat` + `Name`）。

**改行为**：优先改提示词（`internal/kernel/prompts/solver.md`，编译期内嵌，`--prompt` 可外部覆盖），
其次改工具描述，最后才改内核。

---

## 7. 测试

```bash
make test         # 68 个测试，~1.5s
make race         # -race
make check        # vet + fmt + test
```

覆盖到的真实坑（都有测试兜着）：

- `flag{...}` 归一化不能 trim 掉 `}`；自定义 `flag_pattern` 要能覆盖默认形态。
- UUID flag 与 `x-session-id` / `trace-id` 噪声的区分；候选数量上限。
- 闸门：去重、错提上限、指数冷却、答对清零、按题隔离。
- 工具：`sh`/`py`/`read`/`write` 真的在沙箱工作目录里生效；未知工具要报错；
  `fact` 假证据被拒、真证据通过；`submit` 未接地气被拒、接地气成功、重复提交被闸门拦。
- 解题循环：完整回路、纯聊天两次后被推动收工、连续 5 步无进展被提醒、多轮交接、预算耗尽、`finish` 三种状态、
  UUID flag。
- 调度：优先级顺序、重跑带交接、起环境失败不炸、并发无数据竞争、grounding 默认开启且可显式关闭、总预算。
- 沙箱：`sh -c` 超时**整组杀进程**（`sleep` 不能拖住 `Wait`）、输出截断并落盘、路径逃逸被拒。
- 平台：本地题库的答案隔离与跨轮保留；TSecBench 契约（token 头、5 个接口、409 幂等、错误不吞）。
- 集成：`examples/suite` 四道题用剧本模型全部解出（`TestExampleSuiteIsSolvable`）。

诚实说明：**这些都是"内核正确"的证据，不是"能力"的证据。** 能力要靠真实模型跑真实题来度量——
那就是 TSecBench 存在的意义。

---

## 8. 已知边界

- 不做"批量扫全网"：agent 只打题目给的目标，提示词里明确禁止横向到题外。
- 本地运行时没有隔离。跑来源不明的题请用 `docker` 运行时。
- 提示词是中文的（面向中文题目环境）。换语言改 `prompts/solver.md` 即可，逻辑与语言解耦。
- 单机进程内并发，没有分布式队列；63 题 × 3 并发已经够用，再大就该上 k8s 了。
- `--hints` 默认关闭：提示会掉分，而且会让"能力度量"失真。

---

## 9. 与 ARTEX 的关系

ARTEX 是一个成熟的多智能体渗透系统（95k 行 Go + PostgreSQL）。本项目**借鉴了它的架构思想，但没有抄它的复杂度**：

| ARTEX | 这里 | 为什么改 |
|---|---|---|
| 资产图 + 探索图（双图状态） | `core.Board` 五类状态 | CTF 没有资产面，五类足够 |
| planner 生成 intent → worker 执行 | 模型自己调 `idea` / 工具 | 单题目标收敛，每步一轮 planner 的固定成本大于收益 |
| `record_fact` 要证据 | `fact` 工具 + grounding | 同一哲学，直接继承 |
| `graph_overview` 周期性回灌 | `Board.Situation(budget)` 每步注入 | 长任务不跑飞的核心 |
| cold digest 压缩冷节点 | 历史裁剪 + `Board.Handoff()` | 等价物，但实现只有几十行 |
| CAS 抢单、多 worker 协同 | 并发在**题目**粒度 | 单题内不需要抢单，反而会互相打断 |
| PostgreSQL + 迁移 + UI | 内存 + JSON 报告 | 单机 CLI，够用就行 |

结论：ARTEX 值得学的是**状态外置 + 证据接地 + 交接重跑**这三件事；
其余（资产图、任务队列、数据库、权限体系）是渗透业务的复杂度，CTF 不需要。

上一阶段的 ARTEX 分析与改造方案在 `../ARTEX-CTF/`（含可直接应用的 patch），现在作为**参考实现/对照物**保留。

---

## 9.5 能力边界：什么进框架，什么不进

这个框架的目标是**通用解题能力**，不是某个评测平台的题库答案。所以有一条硬边界：

**不放进框架的**（会污染通用性，且多数平台禁止）：

- 某道题的解法、payload、flag、容器地址
- 某个平台私有的路径约定（例如"flag 固定放在 X 目录"）
- 任何"看到 A 就发 B"的题级 if-else

**放进框架的**（换平台依然成立）：

| 层 | 内容 | 在哪 |
|---|---|---|
| **tool** | 协议与探测能力：端口扫描、参数名爆破、FastCGI、unix socket、裸 TCP、差分爆破、会话保持 | `internal/kernel/*.go` |
| **skill** | 漏洞类的通用技术卡：信号 → 探测手法 → payload 家族 → 判定 → 坑（含 `triage` 限时分诊、`cloud-identity` 云身份、`flag-chain` 多阶段推进） | `internal/kernel/prompts/kb/*.md`（29 篇） |
| **prompt** | 决策策略：先扫端口、前端不是事实来源、状态码是情报、支线设预算、源码优先、拿权后先读说明、**代理类端点先问"注入到哪个参数"** | `internal/kernel/prompts/solver.md` |
| **platform** | 平台契约：如何起题/提交/取容器地址；平台若公开了"flag 在哪个目录"，由适配器写进 `Challenge.Meta["flag_paths"]` | `internal/platform/*.go` |

第 4 层是关键：**平台约定由适配器注入，内核不内置任何平台的私有规则**。
内核只提供"通用落点"（`/flag`、`flag.txt`、`/etc/passwd` 这类到处都有的路径）。

### 这些能力是怎么被验证的

不用真题做回归（那等于把答案写进测试），而是自己搭一个**合成靶场**：
`internal/kernel/range_test.go` 里起一套与任何平台无关的漏洞靶（参数名不一致 + SSRF + 命令注入 +
非标端口 + unix socket agent），断言"框架能否自己发现并打通"。

```
$ go test ./internal/kernel -run TestRange -v
--- PASS: TestRangeParamDiscoveryAndCmdInjection   (0.06s)
--- PASS: TestRangeEndToEndSubmit                  (0.00s)
--- PASS: TestFuzzDiffModeOnlyReportsChanges       (0.01s)
```

合成靶场里专门有一组「凭证代理」用例（`range_proxy_test.go`）：后端只认 `sig` 参数、
代理把 `?sas=` 的值原样拼进后端 URL。断言的是：

- 直连读对象 —— 能读
- 把 `comp=list` 塞进 **path 段** —— 失败（复刻"注入位置选错"）
- 用 `inject` 把 `restype=container&comp=list&sig=...` 注进 **`sas` 的值** —— 成功列举
- 配合 `%2e%2e%2f` 路径穿越 —— 能穿回目标桶并列到 key

再加两条**防腐测试**，防止以后又把题目信息塞回来：

```
TestKBNotesArePlatformAgnostic   —— 技术卡里出现平台名/题号/flag 值就红
TestSolverPromptIsPlatformAgnostic —— 系统提示词同理
```

## 10. 路线图

- [ ] 更多平台适配器：CTFd（`/api/v1`）、自建 HTTP 靶场
- [ ] 附件落地后自动跑一遍 `file` / `binwalk` 摘要，省掉模型的第一步
- [ ] 多 flag 题的进度利用：拿到 1/3 个 flag 后如何系统性搜索剩余 flag
- [ ] 战术库：把常见套路（伪加密、JWT 爆破、SSTI 指纹、padding oracle）做成可检索的 skill 提示，按需加载
- [ ] 失败归因：跑完自动生成"这题为什么没解出来"的分类报告（没找到入口 / 找到了打不动 / 拿到线索没利用）
- [ ] 报告增强：每题的时间线（哪一步拿到了关键信息），便于赛后复盘
