package kernel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/sandbox"
)

// 工具面设计原则：
//   - 少而通用：8 个工具覆盖六大方向，不为某个分类加专用工具（专用逻辑写在脚本里）。
//   - 一切都留下痕迹：每个工具的执行结果都会进「近期输出」环，供 grounding 校验。
//   - 状态必须写进 Board：模型不能只在嘴里说"我发现了 X"，要调 fact/artifact。

// ToolSet 是一道题的工具体。
type ToolSet struct {
	rt      sandbox.Runtime
	board   *core.Board
	policy  core.FlagPolicy
	gate    *core.Gate
	hooks   Hooks
	stepIdx int

	mu         sync.Mutex
	web        *http.Client // 带 cookie jar 的会话客户端（登录态跨调用保持）
	jar        http.CookieJar
	recent     []string // 近期工具输出（grounding 证据池）
	recentLen  int
	solved     bool
	unverified bool
	finishMsg  string
	finishWhy  string
}

const recentCap = 512 << 10 // 证据池上限 512KB

// NewToolSet 构造工具体。
func NewToolSet(rt sandbox.Runtime, board *core.Board, policy core.FlagPolicy, gate *core.Gate, hooks Hooks) *ToolSet {
	jar, _ := cookiejar.New(nil)
	return &ToolSet{
		rt: rt, board: board, policy: policy, gate: gate, hooks: hooks,
		jar: jar,
		web: &http.Client{
			Timeout: 60 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Solved 报告是否已经有正确 flag。
func (t *ToolSet) Solved() bool { return t.solved }

// Unverified 报告本次拿到的是不是"没有判题接口、只是记下来的" flag。
func (t *ToolSet) Unverified() bool { return t.unverified }

// Finish 返回模型的收尾说明。
func (t *ToolSet) Finish() (string, string) { return t.finishWhy, t.finishMsg }

// Definitions 返回给模型的工具声明。
func (t *ToolSet) Definitions() []llm.Tool {
	return []llm.Tool{
		{
			Name: "sh",
			Description: "在目标环境里执行一条 shell 命令（经 sh -c）。用于侦察、读文件、跑工具。" +
				"输出过长会被截断并落盘，落盘路径会在结果里给出。",
			Schema: obj(map[string]any{
				"command":   str("要执行的 shell 命令"),
				"timeout_s": num("超时秒数，默认 120，长任务可设大"),
			}, "command"),
		},
		{
			Name: "py",
			Description: "写一段 Python 到目标环境并执行（适合写漏洞利用/解码/爆破脚本，pwn 方向必备）。" +
				"脚本会保存到工作目录，便于下次修改复用。",
			Schema: obj(map[string]any{
				"code":      str("完整 Python 源码"),
				"name":      str("脚本文件名，默认 solve.py"),
				"timeout_s": num("超时秒数，默认 120"),
			}, "code"),
		},
		{
			Name: "recon",
			Description: "一把梭侦察：HTTP 指纹（server/powered-by/title/技术线索）+ 并发目录与敏感文件探测 + 跳转/403 清单。" +
				"开始打任何 web 目标先跑这个，胜过十条零散 curl。paths 可覆盖内置字典。",
			Schema: obj(map[string]any{
				"url":       str("目标根地址，如 http://1.2.3.4:8080"),
				"paths":     arr("可选：自定义路径列表（覆盖内置字典）"),
				"wordlist":  str("可选：dirs = 叠加内置 ~4700 条大字典（先跑高价值路径，再跑全量）"),
				"threads":   num("并发数，默认 24（大字典建议 48）"),
				"timeout_s": num("单请求超时秒数，默认 8"),
			}, "url"),
		},
		{
			Name: "fuzz",
			Description: "并发字典爆破 / 差分探测：url 或 body 里用 FUZZ 占位。" +
				"内置字典：dirs / api / files / params / numbers / traversal / ssti / cmdi / cmdi-bypass / sqli / ssrf-hosts。" +
				"开 diff=true 时只报告「响应与基线不同」的命中（自动过滤假 200 与无感位置），" +
				"这是判断「哪个输入真的被消费」最快的方式。",
			Schema: obj(map[string]any{
				"url":       str("含 FUZZ 占位符的 URL"),
				"words":     arr("内联字典（字符串数组）"),
				"wordlist":  str("内置字典名：dirs / api / files / params / numbers / traversal / ssti / cmdi / cmdi-bypass / sqli / ssrf-hosts"),
				"method":    str("HTTP 方法，默认 GET"),
				"headers":   obj(map[string]any{}, ""),
				"body":      str("请求体（同样支持 FUZZ）"),
				"threads":   num("并发数，默认 24（大字典建议 48）"),
				"match":     arr("只保留这些状态码"),
				"hide":      arr("过滤这些状态码"),
				"timeout_s": num("单请求超时，默认 8"),
				"diff":      obj(map[string]any{"type": "boolean"}, "差分模式：只报告与基线不同的响应（强烈建议开）"),
				"preview":   obj(map[string]any{"type": "boolean"}, "命中时附响应片段"),
			}, "url"),
		},
		{
			Name: "ports",
			Description: "TCP 端口扫描 + 协议指纹（HTTP/FastCGI/MySQL/Redis/Docker...）。" +
				"**拿到任何目标的第一件事**：真正的入口常常是没经过前置网关的旁路端口，" +
				"只扫 80/8080 会直接错过主线。ports=quick 扫常见端口，ports=all 扫全量。",
			Schema: obj(map[string]any{
				"host":       str("目标主机（IP 或域名，可带 http:// 前缀）"),
				"ports":      str("quick（默认，~100 个常见端口）/ all（1-65535）/ 9000 / 1-10000 / 80,443,9000"),
				"threads":    num("并发，默认 300"),
				"timeout_ms": num("单端口连接超时毫秒，默认 900"),
				"banner":     obj(map[string]any{"type": "boolean"}, "对每个开放端口抓 banner（默认对可疑端口抓）"),
			}, "host"),
		},
		{
			Name: "paramfuzz",
			Description: "参数名大字典爆破（数千候选，热门词优先，默认命中即停），用响应变化做 oracle。" +
				"**前端 JS 里的参数名经常与服务端不一致**。用法：先把接口的固定错误串填进 baseline，" +
				"命中项会列出状态码/长度/响应片段。",
			Schema: obj(map[string]any{
				"url":       str("接口地址"),
				"method":    str("HTTP 方法，默认 POST"),
				"location":  str("参数位置：body（JSON，默认）/ query / form"),
				"baseline":  str("可选：基线响应里的独有特征串，如 \"URL is required\"（不填则自动用探针响应全文）"),
				"value":     str("给每个候选参数填的值，默认 http://127.0.0.1:1/"),
				"words":     arr("可选：内联候选名（覆盖内置 6491 词）"),
				"headers":   obj(map[string]any{}, ""),
				"threads":   num("并发，默认 50"),
				"timeout_s": num("单请求超时秒数，默认 8"),
				"scan_all":  obj(map[string]any{"type": "boolean"}, "跑完全部候选（默认命中第一个就停，几秒出结果）"),
				"max_scan":  num("最多试多少个候选（默认全量 6491）"),
			}, "url"),
		},
		{
			Name: "fcgi",
			Description: "直连 php-fpm / FastCGI（默认 9000）执行任意 PHP，绕过前置网关鉴权。" +
				"自动带 PHP_VALUE=auto_prepend_file=php://input 与 allow_url_include=On。" +
				"给 command 即可跑 shell 命令；给 code 可执行任意 PHP。",
			Schema: obj(map[string]any{
				"host":       str("目标主机"),
				"port":       num("FastCGI 端口，默认 9000"),
				"script":     str("站点里真实存在的 .php 绝对路径，默认 /var/www/html/index.php"),
				"command":    str("要执行的 shell 命令（等价于 shell_exec）"),
				"code":       str("要执行的 PHP 代码（可省略 <?php）"),
				"query":      str("可选 QUERY_STRING"),
				"req_uri":    str("可选 REQUEST_URI"),
				"timeout_s":  num("超时秒数，默认 20"),
				"extra_vars": obj(map[string]any{}, "额外 FastCGI 参数（可覆盖 PHP_VALUE 等）"),
			}, "host"),
		},
		{
			Name: "unix",
			Description: "走 unix domain socket 发 HTTP 请求。容器内的本地 agent（metadata/runtime api）" +
				"常只监听 socket 且权限宽松，这是 TCP/HTTP 之外的第三条通道。" +
				"先用 find / -name '*.sock' 找到路径。",
			Schema: obj(map[string]any{
				"socket":  str("socket 路径（先用 find / -name '*.sock' 找到再填）"),
				"path":    str("HTTP 路径，默认 /latest/flag"),
				"method":  str("方法，默认 GET"),
				"host":    str("Host 头，默认 localhost"),
				"body":    str("可选请求体"),
				"command": str("可选：改为在目标环境执行 shell（如 curl --unix-socket ...）"),
			}),
		},
		{
			Name:        "raw",
			Description: "裸 TCP 收发（Redis/MySQL/SMTP/自研协议）。可发文本或 hex 载荷，回显可打印化。",
			Schema: obj(map[string]any{
				"host":      str("目标主机"),
				"port":      num("端口"),
				"payload":   str("要发送的文本载荷"),
				"hex":       str("或者：十六进制载荷（空格/冒号可选）"),
				"timeout_s": num("超时秒数，默认 8"),
			}, "host", "port"),
		},
		{
			Name: "pickle",
			Description: "把一条 Python 表达式翻译成 pickle opcode 流（默认 base64 输出）。" +
				"专治「RestrictedUnpickler 只放行 getattr 之类无害函数」的反序列化题：把所有属性访问都编成 getattr(obj,'name')，" +
				"只要白名单里有 getattr 就能一路走到 __globals__。\n" +
				"支持的字面量/语法：() (a,b) [a,b] 'text' 141 None True False、名字（builtins.getattr / os.system）、" +
				"后缀 .attr [idx] (args)。写普通 Python 表达式即可，不必手拼 opcode。\n" +
				"返回：编码后的载荷 + opcode 预览 + 用到的 GLOBAL 列表（先看这个判断会不会被白名单拦）。",
			Schema: obj(map[string]any{
				"expr":     str("Python 表达式，如 ().__class__.__base__.__subclasses__()[0].__init__.__globals__['popen']('id').read()"),
				"encoding": str("base64（默认）/ hex / raw"),
			}, "expr"),
		},
		{
			Name: "jwt",
			Description: "JWT 通用编解码/伪造：decode 解出 header 与 payload（含时间字段与可疑 claim 提示）；" +
				"sign 用给定 HMAC 密钥签一个（可带 kid/jku）；none 生成 alg=none 变体；" +
				"jwks 把密钥发布成 oct JWKS（给 jku 自签用）。密钥/声明全部由调用方提供，工具不含任何内置值。",
			Schema: obj(map[string]any{
				"action":  str("decode（默认）/ sign / none / jwks"),
				"token":   str("decode 用：待解析的 JWT"),
				"payload": str("sign / none 用：JSON 对象串"),
				"header":  str("可选：附加 header 字段（JSON 对象串），如 {\"kid\":\"k1\",\"jku\":\"/files/a/jwks.json\"}"),
				"secret":  str("sign / jwks 用：HMAC 密钥"),
				"alg":     str("HS256（默认）/ HS384 / HS512"),
				"kid":     str("可选：header.kid，jwks 里同名"),
				"jku":     str("可选：header.jku"),
			}, "action"),
		},
		{
			Name: "polyglot",
			Description: "造一个「主格式合法 + 同时能被第二种解析器读」的复合文件（上传题常用）。" +
				"carrier=png/gif/jpg/pdf；embed=text（塞进元数据块，结构最干净）或 append（追加到文件尾）。" +
				"会回报主格式判别结果和检测到的第二格式（PHP/HTML/JS/ZIP/ELF/PE）及偏移。" +
				"detect=<路径> 时只分析已有文件、不生成。",
			Schema: obj(map[string]any{
				"carrier": str("png / gif / jpg / pdf，默认 png"),
				"payload": str("要藏进去的内容，如 <?php system($_GET[0]); ?>"),
				"embed":   str("text（元数据块，默认）/ append（文件尾）"),
				"save_to": str("写到目标环境的路径；给了就直接落盘，省一次 write"),
				"detect":  str("只分析这个已有文件，不生成新文件"),
			}),
		},
		{
			Name: "tunnel",
			Description: "把数据切块、编码、按模板塞进协议通道发出去，最后回头取结果。" +
				"适用于一切「一次只能带一点、但可以发很多次」的通道（DNS label、URL 路径、请求头、分片表单）。" +
				"自动处理分块、序号/总数、会话复用。template 支持 {seq} {total} {chunk} {session} 占位。" +
				"数据可以直接给（data）或从 URL 取（source，会自动从 JSON 的 content/data 字段里解一层）。",
			Schema: obj(map[string]any{
				"source":        str("数据源 URL（与 data 二选一）"),
				"data":          str("直接给数据"),
				"endpoint":      str("发送目标 URL"),
				"template":      str("通道格式，默认 {seq}-{total}-{chunk}"),
				"encoding":      str("base32（默认）/ base64 / hex / raw"),
				"chunk_size":    num("每块原始字节数，默认 32"),
				"json_field":    str("POST JSON 里装载荷的字段，默认 query"),
				"session_field": str("会话字段名，默认 session"),
				"method":        str("POST（默认，JSON）/ GET（拼 query）"),
				"query_param":   str("GET 时的参数名，默认 query"),
				"finish":        str("收尾请求，如 GET http://h/retrieve?session={session}"),
				"headers":       obj(map[string]any{}, ""),
				"pad":           obj(map[string]any{"type": "boolean"}, "base64/base32 保留 = 填充（默认去掉）"),
			}, "endpoint"),
		},
		{
			Name: "unmix",
			Description: "「静态密文 + 已知明文格式」的按字节去混淆穷举。给一段高熵常量（hex / 转义串 / 文件+offset）和程序里的小常量表（keys），" +
				"工具把 `rot( blob[i] OP1 key[i%L] , r ) OP2 c` 这整个组合空间枚举掉（OP1 ∈ xor/add/sub/subr，r ∈ 0..7 双向，OP2 ∈ +c/-c/^c），" +
				"只保留**全部落 printable** 的候选，并按「像凭据」排序（花括号成对、字符集集中、命中 prefix）。\n" +
				"用途：二进制里找不到解密代码、或校验路径只打印占位符时，凭据往往就是那块常量被这种按字节混淆过。" +
				"keys 要多给几个候选（.data/.rodata 任意连续窗口、立即数、字符串），brute=1 会再叠加单字节键。" +
				"返回每条候选的变换描述 + 明文 + hex；prefix 命中说明格式对上了。",
			Schema: obj(map[string]any{
				"hex":         str("密文 hex（空格/冒号可有可无）"),
				"text":        str("或者：含 \\xNN 转义的字符串（可直接贴 objdump 里的输出）"),
				"file":        str("或者：目标环境里的文件路径"),
				"offset":      num("配合 file：起始偏移"),
				"length":      num("配合 file：长度（默认到文件尾）"),
				"keys":        arr("候选表（hex 串，可多给几个；每个表的 1..16 字节连续窗口都会作为循环键试一遍）"),
				"periods":     arr("可选：直接指定循环周期"),
				"prefix":      str("已知明文前缀（平台约定的花括号头），命中直接顶到最前"),
				"top":         num("最多返回多少条，默认 8"),
				"brute":       num("0/1/2：是否追加 1 字节、1~2 字节的裸键穷举"),
				"max_key_len": num("表窗口的最大长度，默认 16"),
			}),
		},
		{
			Name: "kb",
			Description: "检索内置打法笔记（25 篇，按「类」组织：web / 云 / 认证 / 注入 / 文件 / 上传 / 反序列化 / 沙箱逃逸 / 检测规避 / 外带 / 面板 / 内网横向 / 行协议内存安全 / 逆向取数 / 字节码虚拟机…）。" +
				"卡在某类漏洞时先查，直接拿可复制的 payload，别凭记忆猜。不传参数则列出全部笔记名。",
			Schema: obj(map[string]any{
				"query":     str("关键词，如 \"jinja ssti\"、\"jwt none\""),
				"name":      str("直接取某篇全文，如 sqli"),
				"max_chars": num("每篇最多返回多少字符，默认 3000"),
			}),
		},
		{
			Name: "http",
			Description: "发一个原始 HTTP 请求（agent 侧直连目标，不依赖沙箱里有没有 curl）。" +
				"**自带会话**：响应里的 Set-Cookie 会保存下来，后续调用自动携带（多步登录链不必手工传 cookie）。" +
				"可选把响应体存进目标环境的文件。\n" +
				"**注入用**：目标若把某个参数原样拼进后端 URL（凭证代理、取图/取链接口、SSO 回调），" +
				"用 inject={param,value} 把整段 query 注进那个参数的值里（value 不做编码）；" +
				"或用 raw_query 直接给整段 query。返回值第一行会回显实际发出的 URL，先确认拼接是否符合预期再分析响应。",
			Schema: obj(map[string]any{
				"method":        str("HTTP 方法，默认 GET"),
				"url":           str("完整 URL"),
				"headers":       obj(map[string]any{}, ""),
				"body":          str("请求体"),
				"save_to":       str("可选：把响应体写到目标环境的这个路径"),
				"timeout_s":     num("超时秒数，默认 30"),
				"reset_session": obj(map[string]any{"type": "boolean"}, "先清空该站点的会话 cookie（重登/对比用）"),
				"raw_query":     str("整段 query string，原样拼到 URL 后，不做任何编码（自己负责转义）"),
				"gzip_body":     obj(map[string]any{"type": "boolean"}, "把 body 用 gzip 压缩并自动加 Content-Encoding: gzip —— 绕开会解压不了请求体的 WAF/网关"),
				"inject": obj(map[string]any{
					"param": str("参数名，如 sas / token / sig"),
					"value": str("要注入的整段 query（如 restype=container&comp=list&sig=...）。工具只转义 & + # 空格，%2B %3D 这类已编码的写法原样保留"),
				}, "把 param=value 原样拼进 query，value 不做 URL 编码"),
			}, "url"),
		},
		{
			Name:        "read",
			Description: "读目标环境里的文件（截断到 max_bytes）。",
			Schema: obj(map[string]any{
				"path":      str("文件路径（相对工作目录或绝对路径）"),
				"max_bytes": num("最多读多少字节，默认 65536"),
			}, "path"),
		},
		{
			Name:        "write",
			Description: "在目标环境里写文件（附件利用、生成 payload、保存中间结果）。",
			Schema: obj(map[string]any{
				"path":    str("文件路径"),
				"content": str("文件内容"),
			}, "path", "content"),
		},
		{
			Name: "fact",
			Description: "记录一条已证实的事实（例如「版本是 nginx 1.18」「存在 SQL 注入」）。" +
				"evidence 必须逐字摘自你看过的工具输出，否则会被拒绝。",
			Schema: obj(map[string]any{
				"text":     str("一句话结论"),
				"evidence": str("支撑该结论的工具输出原文片段（逐字复制）"),
			}, "text", "evidence"),
		},
		{
			Name: "idea",
			Description: "登记/更新一个待验证的假设。不传 id 时新建；传 id 时更新状态（open/done/blocked）。" +
				"卡住时先看看还有哪些 open 的假设没试。",
			Schema: obj(map[string]any{
				"text":    str("假设内容（新建时必填）"),
				"id":      num("要更新的假设 id"),
				"status":  str("open / done / blocked"),
				"verdict": str("结论说明"),
			}),
		},
		{
			Name:        "artifact",
			Description: "登记一个可复用的中间产物：file（下载的附件）/ cred（账号密码）/ endpoint / key / other。",
			Schema: obj(map[string]any{
				"kind":  str("file / cred / endpoint / key / other"),
				"value": str("产物内容（路径、凭据、地址等）"),
				"note":  str("备注"),
			}, "kind", "value"),
		},
		{
			Name: "submit",
			Description: "提交 flag。只有**逐字出现在真实工具输出中**的字符串才能提交（会被 grounding 校验）。" +
				"提交后看返回：correct=true 才算拿到。",
			Schema: obj(map[string]any{
				"flag":     str("flag 原文"),
				"evidence": str("该 flag 出现在哪条命令/文件的输出里"),
			}, "flag"),
		},
		{
			Name: "finish",
			Description: "结束本题。status: solved（已拿到 flag）/ stuck（确实走不通）/ out_of_scope（环境有问题）。" +
				"结束前把没走完的方向写进 idea，下一轮会用到。",
			Schema: obj(map[string]any{
				"status":  str("solved / stuck / out_of_scope"),
				"summary": str("这一轮做了什么、结论是什么、还剩什么没试"),
			}, "status", "summary"),
		},
	}
}

// Call 执行一次工具调用，返回给模型看的文本。
func (t *ToolSet) Call(ctx context.Context, tc llm.ToolCall) string {
	t.mu.Lock()
	t.stepIdx++
	t.mu.Unlock()

	var out string
	switch tc.Name {
	case "sh":
		out = t.doShell(ctx, tc)
	case "py":
		out = t.doPython(ctx, tc)
	case "recon":
		out = t.doRecon(ctx, tc)
	case "fuzz":
		out = t.doFuzz(ctx, tc)
	case "ports":
		out = t.doPorts(ctx, tc)
	case "paramfuzz":
		out = t.doParamFuzz(ctx, tc)
	case "fcgi":
		out = t.doFCGI(ctx, tc)
	case "unix":
		out = t.doUnixHTTP(ctx, tc)
	case "raw":
		out = t.doRaw(ctx, tc)
	case "pickle":
		out = t.doPickle(tc)
	case "jwt":
		out = t.doJWT(tc)
	case "polyglot":
		out = t.doPolyglot(ctx, tc)
	case "tunnel":
		out = t.doTunnel(ctx, tc)
	case "unmix":
		out = t.doUnmix(ctx, tc)
	case "kb":
		out = t.doKB(tc)
	case "http":
		out = t.doHTTP(ctx, tc)
	case "read":
		out = t.doRead(ctx, tc)
	case "write":
		out = t.doWrite(ctx, tc)
	case "fact":
		out = t.doFact(ctx, tc)
	case "idea":
		out = t.doIdea(tc)
	case "artifact":
		out = t.doArtifact(tc)
	case "submit":
		out = t.doSubmit(ctx, tc)
	case "finish":
		out = t.doFinish(tc)
	default:
		out = fmt.Sprintf("未知工具 %q。可用：sh, py, http, recon, fuzz, ports, paramfuzz, fcgi, unix, raw, unmix, jwt, kb, read, write, fact, idea, artifact, submit, finish", tc.Name)
	}
	t.remember(out)
	return out
}

// ---------------------------------------------------------------------------
// 具体实现
// ---------------------------------------------------------------------------

func (t *ToolSet) doShell(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Command  string `json:"command"`
		TimeoutS int    `json:"timeout_s"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if strings.TrimSpace(a.Command) == "" {
		return "command 不能为空"
	}
	o, err := t.rt.Exec(ctx, sandbox.ExecSpec{
		Cmd:      a.Command,
		Timeout:  secs(a.TimeoutS),
		MaxBytes: t.hooks.OutputBytes,
	})
	if err != nil {
		t.board.AddAttempt(a.Command, -1, "fail")
		return "执行失败: " + err.Error()
	}
	verdict := "ok"
	if o.Exit != 0 {
		verdict = "fail"
	}
	t.board.AddAttempt(a.Command, o.Exit, verdict)
	t.scanForFlags(o.Text())
	return fmt.Sprintf("exit=%d 用时=%s\n%s", o.Exit, o.Duration.Round(time.Millisecond), o.Text())
}

func (t *ToolSet) doPython(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Code     string `json:"code"`
		Name     string `json:"name"`
		TimeoutS int    `json:"timeout_s"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	name := strings.TrimSpace(a.Name)
	if name == "" {
		name = fmt.Sprintf("solve_%d.py", t.stepIdx)
	}
	if !strings.HasSuffix(name, ".py") {
		name += ".py"
	}
	if err := t.rt.WriteFile(ctx, name, []byte(a.Code)); err != nil {
		return "写入脚本失败: " + err.Error()
	}
	cmd := "python3 " + shellQuote(name)
	if strings.Contains(a.Code, "pwn") || strings.Contains(a.Code, "remote(") {
		cmd = "python3 " + shellQuote(name)
	}
	o, err := t.rt.Exec(ctx, sandbox.ExecSpec{Cmd: cmd, Timeout: secs(a.TimeoutS), MaxBytes: t.hooks.OutputBytes})
	if err != nil {
		t.board.AddAttempt("py:"+name, -1, "fail")
		return "执行失败: " + err.Error()
	}
	verdict := "ok"
	if o.Exit != 0 {
		verdict = "fail"
	}
	t.board.AddAttempt("py:"+name, o.Exit, verdict)
	t.scanForFlags(o.Text())
	return fmt.Sprintf("脚本 %s 已保存并执行，exit=%d\n%s", name, o.Exit, o.Text())
}

func (t *ToolSet) doHTTP(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Method   string            `json:"method"`
		URL      string            `json:"url"`
		Headers  map[string]string `json:"headers"`
		Body     string            `json:"body"`
		SaveTo   string            `json:"save_to"`
		TimeoutS int               `json:"timeout_s"`
		Reset    bool              `json:"reset_session"` // 清空会话 cookie
		RawQuery string            `json:"raw_query"`     // 整段 query，原样拼接
		GzipBody bool              `json:"gzip_body"`     // 压缩请求体（Content-Encoding: gzip）
		Inject   *struct {         // 把 param=value 原样拼进 query（value 不编码）
			Param string `json:"param"`
			Value string `json:"value"`
		} `json:"inject"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.Method == "" {
		a.Method = "GET"
	}
	timeout := secs(a.TimeoutS)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if a.Reset && t.jar != nil {
		if u, err := parseURL(a.URL); err == nil {
			for _, c := range t.jar.Cookies(u) {
				c.MaxAge = -1
				t.jar.SetCookies(u, []*http.Cookie{c})
			}
		}
	}
	target := a.URL
	injected := false
	bodyReader := strings.NewReader(a.Body)
	if a.GzipBody {
		var zbuf bytes.Buffer
		zw := gzip.NewWriter(&zbuf)
		if _, err := zw.Write([]byte(a.Body)); err != nil {
			return "gzip 压缩失败: " + err.Error()
		}
		if err := zw.Close(); err != nil {
			return "gzip 压缩失败: " + err.Error()
		}
		bodyReader = strings.NewReader(zbuf.String())
	}
	if a.Inject != nil && a.Inject.Param != "" {
		// value 只转义「会破坏 query 结构」的字符，其余原样保留 ——
		// 因为注入的正是「后端将要原样解析的 query」，已经写好的 %2B / %3D 不能再被编码一次。
		target = appendRawQuery(target, a.Inject.Param+"="+escapeInjectValue(a.Inject.Value))
		injected = true
	}
	if a.RawQuery != "" {
		target = appendRawQuery(target, a.RawQuery)
		injected = true
	}
	req, err := http.NewRequestWithContext(rctx, strings.ToUpper(a.Method), target, bodyReader)
	if err != nil {
		return "构造请求失败: " + err.Error()
	}
	for k, v := range a.Headers {
		req.Header.Set(k, fmt.Sprint(v))
	}
	if a.GzipBody && req.Header.Get("Content-Encoding") == "" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	client := t.web
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		t.board.AddAttempt(a.Method+" "+a.URL, -1, "fail")
		return "请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	limit := t.hooks.OutputBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	text := string(body)
	if a.SaveTo != "" {
		if err := t.rt.WriteFile(ctx, a.SaveTo, body); err == nil {
			text += fmt.Sprintf("\n[已保存到 %s]", a.SaveTo)
		}
	}
	var hdr strings.Builder
	for k := range resp.Header {
		fmt.Fprintf(&hdr, "%s: %s\n", k, resp.Header.Get(k))
	}
	t.board.AddAttempt(a.Method+" "+a.URL, resp.StatusCode, "ok")
	t.scanForFlags(text)
	session := ""
	if t.jar != nil {
		if u, err := parseURL(a.URL); err == nil {
			for _, c := range t.jar.Cookies(u) {
				session += fmt.Sprintf("%s=%s; ", c.Name, c.Value)
			}
		}
	}
	if session != "" {
		session = "会话 cookie: " + session + "\n"
	}
	shown := ""
	if injected {
		// 回显实际拼出来的 URL：注入类漏洞的成败全看这一步拼对没有
		shown = "实际请求: " + target + "\n"
	}
	return fmt.Sprintf("HTTP %d\n%s%s%s\n%s", resp.StatusCode, shown, session, hdr.String(), text)
}

// escapeInjectValue 把注入用的整段 query 变成「能安全作为一个参数值传输」的形式。
//
// 只处理会破坏 query 结构的字符：& 会被当成参数分隔符，+ 会被服务端解码成空格，
// 空格与 # 同理。**不碰 %**：value 里的 %2B / %3D 是调用方写好的，再编码一次就废了。
func escapeInjectValue(s string) string {
	return strings.NewReplacer("&", "%26", "+", "%2B", "#", "%23", " ", "%20").Replace(s)
}

// appendRawQuery 把 extra 原样接到 rawURL 的 query 上，不做任何编码。
// 刻意不用 net/url 重新序列化：那样会把 %2e%2e 之类的路径编码改写掉，
// 而「注入类」请求的正确性恰恰依赖原始字节不被改动。
func appendRawQuery(rawURL, extra string) string {
	if extra == "" {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + extra
}

func (t *ToolSet) doRead(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Path     string `json:"path"`
		MaxBytes int64  `json:"max_bytes"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.MaxBytes <= 0 {
		a.MaxBytes = 64 << 10
	}
	data, err := t.rt.ReadFile(ctx, a.Path, a.MaxBytes)
	if err != nil {
		return "读文件失败: " + err.Error()
	}
	text := string(data)
	t.scanForFlags(text)
	return text
}

func (t *ToolSet) doWrite(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if err := t.rt.WriteFile(ctx, a.Path, []byte(a.Content)); err != nil {
		return "写文件失败: " + err.Error()
	}
	t.board.AddArtifact(core.ArtifactFile, a.Path, fmt.Sprintf("%d 字节", len(a.Content)))
	return fmt.Sprintf("已写入 %s（%d 字节）", a.Path, len(a.Content))
}

// doFact 强制证据接地：evidence 必须是近期真实输出里的原文片段。
func (t *ToolSet) doFact(_ context.Context, tc llm.ToolCall) string {
	var a struct {
		Text     string `json:"text"`
		Evidence string `json:"evidence"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if strings.TrimSpace(a.Text) == "" {
		return "text 不能为空"
	}
	ev := strings.TrimSpace(a.Evidence)
	if ev == "" {
		return "证据不能为空：请把你看到它的那段工具输出逐字复制到 evidence（防止把猜测当事实）"
	}
	if !t.grounded(ev) {
		return "证据校验失败：evidence 没有出现在你最近看到的工具输出里。\n" +
			"请逐字复制真实输出的一小段（不要改写、不要凭记忆复述），再记录这条事实。"
	}
	id := t.board.AddFact(a.Text, ev)
	return fmt.Sprintf("已记录事实 #%d", id)
}

func (t *ToolSet) doIdea(tc llm.ToolCall) string {
	var a struct {
		Text    string `json:"text"`
		ID      int    `json:"id"`
		Status  string `json:"status"`
		Verdict string `json:"verdict"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.ID > 0 {
		st := a.Status
		if st == "" {
			st = "done"
		}
		if !t.board.SetIdea(a.ID, st, a.Verdict) {
			return fmt.Sprintf("没有 id=%d 的假设", a.ID)
		}
		return fmt.Sprintf("假设 #%d 已标记为 %s", a.ID, st)
	}
	if strings.TrimSpace(a.Text) == "" {
		return "新建假设需要 text"
	}
	id := t.board.AddIdea(a.Text)
	return fmt.Sprintf("已登记假设 #%d", id)
}

func (t *ToolSet) doArtifact(tc llm.ToolCall) string {
	var a struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Note  string `json:"note"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	kind := core.ArtifactKind(strings.ToLower(strings.TrimSpace(a.Kind)))
	switch kind {
	case core.ArtifactFile, core.ArtifactCred, core.ArtifactEndpoint, core.ArtifactKey, core.ArtifactOther:
	default:
		kind = core.ArtifactOther
	}
	if !t.board.AddArtifact(kind, a.Value, a.Note) {
		return "该产物已存在或为空"
	}
	return "已记录产物"
}

// doSubmit 是唯一出口：闸门 → grounding → 平台提交。
func (t *ToolSet) doSubmit(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Flag     string `json:"flag"`
		Evidence string `json:"evidence"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	flag := core.Normalize(a.Flag, t.policy)
	if flag == "" {
		return "flag 格式不合法或为空"
	}
	if err := t.gate.Check(t.board.ChallengeID, flag); err != nil {
		return "⛔ 未提交：" + err.Error()
	}
	if t.hooks.Grounding {
		ev := strings.TrimSpace(a.Evidence)
		if ev == "" || !t.grounded(ev) || !t.grounded(flag) {
			return "⛔ 未提交：grounding 校验失败。\n" +
				"flag 必须逐字出现在你**已经看到**的工具输出里（不是推理出来的）。\n" +
				"请先用 sh/read 把它打印出来，再复制原文提交。"
		}
	}
	res, err := t.hooks.Submit(ctx, flag)
	if err != nil {
		return "提交失败（平台错误）: " + err.Error()
	}
	t.gate.Record(t.board.ChallengeID, flag, res.Correct)
	t.board.RecordFlag(flag, res.Correct)
	if res.Correct {
		t.solved = true
		if res.Unverified {
			t.unverified = true
			return fmt.Sprintf("📝 flag 已记录（本模式没有判题接口，需要人工提交）：%s", flag)
		}
		msg := fmt.Sprintf("✅ flag 正确：%s", flag)
		if res.Cumulative > 0 || res.Awarded > 0 {
			msg += fmt.Sprintf("（得分 +%d，累计 %d）", res.Awarded, res.Cumulative)
		}
		if res.TotalFlags > 0 {
			msg += fmt.Sprintf(" 进度 %d/%d", res.CorrectFlags, res.TotalFlags)
		}
		return msg
	}
	return "❌ flag 不正确。不要连猜变体，回到输出里找完整原文。"
}

func (t *ToolSet) doFinish(tc llm.ToolCall) string {
	var a struct {
		Status  string `json:"status"`
		Summary string `json:"summary"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	why := strings.TrimSpace(a.Status)
	if why == "" {
		why = "stuck"
	}
	t.finishWhy = why
	t.finishMsg = a.Summary
	return "已结束。"
}

// ---------------------------------------------------------------------------
// grounding 证据池
// ---------------------------------------------------------------------------

// scanForFlags 不自动提交（把决定权留给模型），只把候选登记进 Board 的提示里。
// 通用 CTF 场景下"自动提交"容易误交（题面里常有假 flag），所以默认交给模型判断，
// 语义上仍由 submit 工具过闸门。
func (t *ToolSet) scanForFlags(text string) {
	for _, cand := range t.policy.Extract(text) {
		t.board.AddArtifact(core.ArtifactOther, cand, "输出中出现的候选 flag 形态")
	}
}

func (t *ToolSet) remember(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recent = append(t.recent, s)
	t.recentLen += len(s)
	for t.recentLen > recentCap && len(t.recent) > 1 {
		t.recentLen -= len(t.recent[0])
		t.recent = t.recent[1:]
	}
}

// grounded 判断一段文本是否出现在近期工具输出里（允许空白归一化）。
func (t *ToolSet) grounded(needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, chunk := range t.recent {
		if strings.Contains(chunk, needle) {
			return true
		}
	}
	// 退化匹配：去掉所有空白后再试一次（应对换行/缩进差异）。
	flatNeedle := squeeze(needle)
	if len(flatNeedle) < 6 {
		return false
	}
	for _, chunk := range t.recent {
		if strings.Contains(squeeze(chunk), flatNeedle) {
			return true
		}
	}
	return false
}

func squeeze(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------

func obj(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func num(desc string) map[string]any { return map[string]any{"type": "number", "description": desc} }

func arr(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func secs(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var _ = json.Marshal
