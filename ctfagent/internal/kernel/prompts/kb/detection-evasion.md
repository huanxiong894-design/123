# 检测规避（制品过关类）

有些题不要求「打穿」，而是要求「交一个东西，它得功能成立、同时不被检测规则命中」。
评分通常是**双轨**：flag（过关）+ 制品质量（越干净越高）。

## 0. 先把评测器当成 oracle 来问

这类服务几乎都会回显「命中了什么」：

```json
{"status":"detected","triggered_rules":5,"total_rules":5}
{"status":"detected","message":"Your payload was detected by the current ruleset."}
{"status":"passed","detected_type":"png","message":"clean file, no secondary format detected"}
```

**逐条探规则**比一次交完整成品有效得多：

1. 先交「绝对干净」的基线（确认什么算通过）
2. 每次只改**一个**特征（一个 API 名、一个字节、一个字符串）
3. 记录 `triggered_rules` 的变化 → 就是在做**逐条反向工程**

## 1. 二进制 / shellcode 躲 YARA

典型规则长这样（命中任一即算检出）：

```yara
rule execve { strings: $a = { 0f 05 } condition: $a }          // syscall
rule binsh  { strings: $a = "/bin/sh" condition: $a }
rule nops   { strings: $a = { 90 90 90 90 } condition: $a }
rule shell  { strings: $a = { 48 31 f6 } condition: $a }        // xor rsi,rsi
```

绕过思路：

| 规则盯的 | 换掉 |
|---|---|
| `0f 05`（syscall） | `sysenter`、走 libc、`call [rip+x]` 间接 |
| `/bin/sh` 字面量 | 运行时拼字符串、`push 0x68` 逐字节入栈 |
| `90 90` NOP sled | `xchg eax,eax`、`inc/dec` 成对、`lea` 空转 |
| 固定寄存器置零序列 | 换指令：`sub rax,rax` / `mov rax,0` / `push 0; pop rax` |

**最低成本的做法**：先交一段**确实像 x86_64 指令、但没有任何危险语义**的字节
（例如 `48 c7 c0 01 00 00 00 c3` = `mov rax,1; ret`）。很多规则只匹配真正的 shellcode 特征，
这种「干净但像代码」的载荷直接过 —— 而题面说的「功能等价」往往只校验字节层面。

服务若抱怨 `does not appear to contain x86_64 instructions`，说明它有一个**指令合法性预检**，
那就必须放几条真实指令（`push/mov/lea`）进去，但仍不碰 syscall / `/bin/sh`。

## 2. 多格式文件躲「文件类型校验」

上传题的校验链条通常是：**魔术字节 → 结构完整性 → 第二格式扫描 → 交给下游解析器**。
绕过点是最后两跳之间：

- 主格式必须**真的合法**（magic + 结构 + 结束标记都在），否则第一跳就挂
- 第二格式要在**下游解析器认、上游扫描器不认**的位置

用 `polyglot` 工具直接造：

```json
{"carrier":"png","payload":"<?php system($_GET[0]); ?>","save_to":"/tmp/x.png","embed":"text"}
```

常见组合与落点：

| 主格式 | 藏法 | 下游谁认 |
|---|---|---|
| PNG | `tEXt` 块里放 `<?php` / `<svg>` | PHP 引擎、浏览器 |
| PNG / JPG / GIF | 文件尾追加（`EXIF` 之后） | PHP、多数解释器 |
| PDF | `%%EOF` 之后追加 | PHP、解压器 |
| GIF | 注释扩展块 `21 FE len data 00` | PHP、浏览器 |
| ZIP+图片 | 先造 ZIP 再把图当第一个成员 | 解压器、图片查看器 |

**判定口径**：服务说 `clean file, no secondary format detected` = 你的第二格式不在它扫的范围内
（换位置/换格式），说 `Polyglot detected!` = 过（通常直接给 flag）。

## 3. 代码躲「行为检测」

规则通常按 API 名 / 危险调用图匹配：

| 规则盯的 | 换掉 |
|---|---|
| `OpenProcess` / `VirtualAllocEx` / `CreateRemoteThread` | 换成 `NtAllocateVirtualMemory` / `NtWriteVirtualMemory` / `NtCreateThreadEx`（ntdll 层） |
| 直接注入 | 换成同进程内 `mmap(PROT_EXEC)` + 函数指针调用 |
| 字符串常量 | 运行时拼接（`"Open" + "Process"`）、base64 解码、`getattr` 间接调用 |
| 明文字节数组 | 运行时解密 / 从资源段读 |

> ⚠️ 若评测器**解析不了你的代码**（返回 500），不是「你过了」，是它的分析器崩了 ——
> 这时换回最朴素的写法，再逐项降低可疑度。**能跑通的分析器才给分。**

## 4. 通用套路总结

1. **把评测器当黑盒 oracle**，一次只改一个变量
2. **先要「过」，再要「好」**：拿到 flag 之后再看有没有余力提高制品质量分
3. **规则匹配的是字面/字节，不是语义**：等价改写几乎总能绕
4. 服务端崩了（500）**不算通过**，说明你踩到了它的解析边界，退一步

## 边界设备（WAF / 网关 / 反代）：拦的是"形态"，不是"能力"

这类题的通病是：**检测层与应用解析层对同一份字节的理解不一致**。
所以要找的不是"更狠的 payload"，而是**让检测层看不到真实语义的那层皮**。

| 检测层看到的 | 解析层实际执行的 | 一张皮 |
|---|---|---|
| 只匹配 `../` | 绝对路径也能读 | `?file=/etc/passwd`（不写 `../`） |
| 只匹配明文字符串 | UTF-16 / UTF-7 解码后才解析 | 整篇 XML/正文按 UTF-16 带 BOM 投递 |
| 不解压 | 后端解压后再解析 | `Content-Encoding: gzip` 压缩请求体 |
| 不重组分块 | 后端按 chunked 重组 | `Transfer-Encoding: chunked` 分片投递 |
| 只拦"危险扩展名" | Web 服务器按配置解析 | 上传 `.htaccess` 改 `AddType`，再传 `.txt` |
| 只查 `_.` 这种分隔符 | 库把 `\\.` 也当分隔符 | 用 `\\.` 拼属性路径 |
| 只查 host 里的关键字 | HTTP 客户端会做百分号解码 | `internal%2dapi`（`%2d` = `-`） |
| 只拦 `<?php`/`<?=` | 短标签同样执行 | 用 `<?` |
| 只拦 `' or 1=1` 这类完整串 | SQL 注释同样能截断 | `admin'-- -`、`admin'#` |

**操作顺序**（成本从低到高，别一上来就上编码）：

1. **等价语义替换**：换命令（`cat`→`head/tac/grep`）、换注释符（`-- -`/`#`）、换绝对路径；
2. **换传输编码**：gzip → chunked → UTF-16 → 双重 URL 编码；
3. **换位置**：参数名/头部/JSON 嵌套/路径段；
4. **换载体**：上传/回调/内部服务代理，让真正解析的那一层去解析。

**判据**：同一语义用「明文 / 编码 / 分块」三种形态各发一次 —— 只有一种被拦，就是形态问题；
三种都拦，才是内容规则，回头做等价替换。

## 检测规则之外：还有"运行时"这一层

- 沙箱类：白名单放行的**每一项**都是逃逸入口（放行 `getattr`/`type` 等于放行整个属性图）；
- 静态检测（YARA/特征）：恶意语义越少越容易过，**不是特征越多越好**；同一语义换实现比加壳更有效；
- 黑盒 oracle：每次只改一个变量，连续两次同样结果就说明变量没变对。
