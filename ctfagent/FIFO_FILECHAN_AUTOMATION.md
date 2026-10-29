# FIFO 与 FileChan 自动化更新（2026-10-29）

## 调度行为

- `ctfagent drive` 默认 `--schedule fifo`，严格保留传入的题目顺序并单题串行。
- 在 FIFO 模式下 `--agents` 必须为 1；想并发时必须显式指定 `--schedule priority`。
- `--only id1,id2,...` 现在严格遵从参数顺序；重复或不存在的 ID 会报错，不再静默跳题。
- 启动日志显示实际调度顺序。Orchestrator 也有 FIFO 回归测试，防止分值优先级覆盖输入顺序。

示例：

```bash
ctfagent drive --platform tsec --only d-01,d-02,d-03
ctfagent drive --platform tsec --schedule priority --agents 3 --only id1,id2,id3
```

## FileChan 邮箱助手

```bash
ctfagent mailbox wait --root <本次 run 目录> --timeout 30m
ctfagent mailbox reply --request <req-NNN.json> --input reply.json
```

`wait` 自动等待最早的未回复请求，输出工具列表、路径和经过敏感字段/令牌/flag 过滤的上下文预览。原始请求仍可供当前 agent 读取；新建邮箱目录为 0700，req/reply 文件为 0600。`reply` 校验 JSON 结构、可用工具名和对象形 args，原子写入并拒绝覆盖已有回复。FileChan 本体也使用原子写入、100ms ticker 等待、可中断超时、无效回复宽限期和明确错误；检测到同目录里残留未回复请求时会停止并指向 mailbox helper，不再静默越过。

Trace 默认以 0600 权限保存，并对常见密码、Authorization/Cookie、API key、token、JWT、签名查询参数和 `flag{...}` 做脱敏。过滤只作用于预览/trace，不改变实时求解证据。原始 req 文件仍可能含凭据，应在受控权限下保管并按保留策略清理。

FileChan 仍不自动调用模型服务：目前环境采用外部 agent 决策，helper 自动化的是等待、解析验证、原子写回和安全预览。
