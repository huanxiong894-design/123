# 示例题库

四道**离线可解**的题。它们不是玩具：`TestExampleSuiteIsSolvable` 会用剧本模型
（模拟真人的动作序列）把它们全部解出来，所以这份题库同时是**集成测试**。

```bash
./ctfagent list --platform local --suite examples/suite
./ctfagent run  --platform local --suite examples/suite --concurrency 2
```

## 规则

- 每题一个子目录，必须有 `challenge.json` 和 `flag.txt`。
- **答案隔离**：`flag.txt` / `hint.txt` / `checker.sh` / `challenge.json` **不会**被复制进 agent 的工作目录。
  否则 `cat flag.txt` 就能"解出"所有题，自测毫无意义。
- 工作目录是 `examples/suite/.work/<id>/`，跨轮保留（agent 的中间产物不丢）。加 `--fresh` 清空。
- 可选文件：`hint.txt`（提示）、`checker.sh`（自定义判定，收到 flag 作为 `$1`，exit 0 表示正确）。
- 如果你的题目附件本身就叫 `flag.txt`（比如里面是密文），把**答案文件**改成别的名字，并在
  `challenge.json` 里写 `"flag_file": "answer.txt"` —— 默认的 `flag.txt` 永远是判题答案，不会下发。

## 题目

### warmup-b64 · misc · 100 分

`secret.txt` 是三层 base64。**解法**：循环 `base64.b64decode` 直到出现 `flag{`。

### xor-crypto · crypto · 200 分

`cipher.bin` 是单字节 XOR 密文。**解法**：明文中已知 `flag{` 前缀，`key = cipher[0] ^ ord('f')`，
再整体异或回去。

### rev-binary · rev · 300 分

`check` 是个 ELF，flag 被拆成 4 段存在 `parts[]` 里，运行时才 `strcat` 拼接。
**解法**：`strings -a check`（或读 `.rodata`）找到 `flag{r3v` / `_is_jus` / `t_reading` / `_strings}`，按顺序拼起来。

### rsa-small-e · crypto · 250 分

`params.json` 给了 `n, e=3, c`，加密无填充且 `m^3 < n`。
**解法**：`c` 就是 `m` 的三次方本身，直接对 `c` 开立方根（纯整数二分即可，不需要大数库）。

## 加一道自己的题

```bash
mkdir -p examples/suite/my-task
cd examples/suite/my-task
cat > challenge.json <<'EOF'
{
  "id": "my-task",
  "title": "我的题",
  "category": "pwn",
  "prompt": "附件是 ...，目标是 ...",
  "flag_pattern": "flag\\{[^}]+\\}",
  "flag_count": 1,
  "max_score": 500
}
EOF
echo 'flag{your_answer}' > flag.txt
# 把附件放进同目录，启动时会自动复制进工作目录
```

需要容器环境（真实服务类题目）：

```json
{
  "docker": {"image": "my-image:latest", "ports": ["8080:8080"], "workdir": "/work"}
}
```

`docker run` 由适配器负责，容器 id 会交给 `sandbox.Docker`，之后 agent 的每条命令都走
`docker exec`（并自动用容器内的 `timeout` 收掉超时进程）。注意此时工作目录是容器里的
`workdir`，宿主目录通过 `HostDir` 仍然可见。

多 flag 题：`"flag_count": 2`，`flag.txt` 一行一个。
