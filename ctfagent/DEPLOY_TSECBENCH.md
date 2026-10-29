# TSecBench 托管镜像

## 固定行为与密钥边界

- 镜像目标为 `linux/amd64`，容器启动即执行 `ctfagent run --platform tsec`，最多 3 个并行 solver。
- DeepSeek 请求由入口脚本固定发送到 `http://api.deepseek.com.tsecbench.gw/v1`；即使运行时传入其他 `CTFAGENT_LLM_URL` 也会被覆盖，不会回退到公网 DeepSeek URL。
- `CTFAGENT_API_KEY`（或 `DEEPSEEK_API_KEY`）、`BENCHMARK_BASE_URL`、`BENCHMARK_TOKEN` 只从运行时环境变量读取。不要使用 Docker `ARG`、在 Dockerfile 写 `ENV`、或把 `.env`/凭证文件放进构建上下文。
- 容器输出报告和检查点仅写入 `/tmp`；容器使用非 root 用户运行。
- 镜像包含通用 agent 程序与泛化知识库，不把题目专属 flag、历史答案、工作目录、报告或解题记录打入镜像。

## 构建

在本目录（`ctfagent/` 源码根目录）执行：

```sh
docker build --platform linux/amd64 -f Dockerfile.tsecbench -t ctfagent:tsecbench .
```

在有 Docker Buildx 的环境可使用：

```sh
docker buildx build --platform linux/amd64 --load -f Dockerfile.tsecbench -t ctfagent:tsecbench .
```

注意：旧归档/旧镜像至少有五类运行风险：工具 JSON Schema 格式错误；上下文裁剪可能把 `tool` 回复与前置的 assistant `tool_calls` 分开；提交校验把可选 `evidence` 备注也要求逐字命中，造成 flag 明明出现在工具输出却被拒；多个 TSecBench 题目共用 `/tmp/ctf`，导致跨题遗留文件污染。当前源码修复了前四项，并在连续相同工具调用时增加循环提醒。**上传前必须按当前源码重新构建镜像并重新导出归档，不能复用之前生成的镜像或 tar.gz。**

从源码根目录构建并导出：

```sh
docker buildx build --platform linux/amd64 --load -f Dockerfile.tsecbench -t ctfagent:tsecbench .
docker save ctfagent:tsecbench | gzip -c > ../ctfagent-tsecbench-linux-amd64-runtimefix.tar.gz
gzip -t ../ctfagent-tsecbench-linux-amd64-runtimefix.tar.gz
sha256sum ../ctfagent-tsecbench-linux-amd64-runtimefix.tar.gz > ../ctfagent-tsecbench-linux-amd64-runtimefix.tar.gz.sha256
```

归档内应有 Docker `manifest.json`，并包含 OCI 所需的 `oci-layout` 和 `index.json`；若本机 Docker 导出不包含这两项，而平台要求 OCI 格式，请按构建包 README 中的 Buildx `type=oci` 方法生成 OCI 原生归档。

## 运行变量

任务创建时，TSecBench 会把粘贴的 `.env` 内容解析为运行时环境变量；镜像入口直接读取进程环境，不需要也不会在镜像内查找 `.env` 文件。可按平台提示填入以下变量（占位值请在平台密钥管理界面替换，**不要把密钥发到聊天或打进镜像**）：

```dotenv
CTFAGENT_API_KEY=<DeepSeek 官方 API Key>
BENCHMARK_BASE_URL=<TSecBench 提供的答题 API 地址>
BENCHMARK_TOKEN=<TSecBench 平台 token>
CTFAGENT_MODEL=deepseek-chat
```

其中 `DEEPSEEK_API_KEY` 也可代替 `CTFAGENT_API_KEY`。`CTFAGENT_LLM_URL` 无需粘贴；容器入口会固定设为 `http://api.deepseek.com.tsecbench.gw/v1`。缺少必需变量时入口会退出并只报告缺少的变量名，不打印变量值。TSecBench API 地址应由平台提供；此镜像不猜测/替换它，也不把它与模型网关地址混为一谈。

## 本地验证与发布门槛

本地先做不连接真实题目的测试：

```sh
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o /tmp/ctfagent ./cmd/ctfagent
/tmp/ctfagent --help
```

TSecBench API 契约测试使用 `httptest` 本地假服务验证 list/start/submit/duplicate/hint/close，不会创建真实靶场实例或提交答案：

```sh
go test ./internal/platform -run 'TestTSec(Contract|ErrorsAreNotSwallowed|VPNCheckFailsFast)$' -count=1
```

真实平台连通性/本地模式实测需要可用的运行时 DeepSeek Key、TSecBench 地址和 token，以及平台靶场网络。完成该实测并确认记录后再上传镜像。Docker 镜像构建也必须在装有 Docker/Buildx 的环境中完成；不要因本机没有 Docker 而改用公网模型端点。
