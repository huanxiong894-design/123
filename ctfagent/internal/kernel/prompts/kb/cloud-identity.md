# 云身份 / 元数据 / 托管服务：凭据都藏在"自述"和"制品"里

云题（对象存储、云函数、元数据服务、OIDC、联邦登录）几乎不靠"打穿"，靠**读懂它自己报出来的东西**。
按下面顺序走，通常 10 分钟内能定位到凭据落在哪一层。

## 一、先读自述接口（零成本，最高命中率）

| 路径 | 常见内容 |
|---|---|
| `/`、`/api/docs`、`/openapi.json`、`/swagger.json` | 接口清单（很多题直接把能用的接口列出来） |
| `/api/status`、`/api/health`、`/api/config` | **内部服务名、元数据端点、区域、桶列表** |
| `/api/functions`、`/api/lambdas`、`/api/services` | 云函数/服务清单 |
| `/api/functions/<name>/config` | **函数配置 = 环境变量 = 数据库口令/密钥** |
| `/api/containers`、`/api/buckets`、`/api/storage` | 存储清单 |

- 云函数的**环境变量**是最高频的凭据存放点：拿到"列函数"权限后，逐个读 `config`。
- `/api/status` 里若出现 `metadata_endpoint` / `internal_services`，那就是下一跳地址。

## 二、元数据服务（IMDS）：用**题目给的内部名**，不要用公网地址

```
http://<内部服务名>/latest/meta-data/                         目录
http://<内部服务名>/latest/meta-data/iam/security-credentials/ 角色名
http://<内部服务名>/latest/meta-data/iam/security-credentials/<role>  临时凭据
http://<内部服务名>/latest/user-data/
```

- 容器化靶场里 `169.254.169.254` **通常不通**（没有真 IMDS），但会有一个同网段的模拟服务
  （`imds:8080`、`metadata:8080` 之类）。**先用 `/api/status` 拿名字，再打**。
- 有的实现要 IMDSv2：先 `PUT /latest/api/token` 拿 token 再带 `X-aws-ec2-metadata-token` 请求；
  先试直接 GET，401/403 再补 token。
- 打不到元数据 ≠ 没有利用点：同一台机器上的 `/latest/user-data/`、`/latest/dynamic/` 也常带初始化脚本和凭据。
- 元数据 JSON 里的 `SecretAccessKey`、`Token`、`InstanceProfileArn` 本身就是答案或下一跳。

## 三、OAuth / OIDC：先看"流程里少没少那一步"

| 现象 | 缺陷 |
|---|---|
| 设备码流程：`POST /devicecode` 之后**不校验是否已被用户批准**，直接拿 `device_code` 换 token | 缺"人工批准"这一环 → 直接签发高权限 token |
| token 端点接受任意 `grant_type`、`client_id` 不做绑定 | 拿别人签的 token 直接换 |
| 返回的 `access_token` / `id_token` 里带业务字段 | **JWT payload 直接 base64url 解码就能读**，不需要验签 |
| `jku` / `x5u` 只校验前缀（`/files/`、`/uploads/`） | 上传自己的 JWKS 自签（见 `kb cloud-storage` §5） |

- 解 JWT：直接用 `jwt(action=decode, token=...)` —— 它会把 header/payload、时间字段和"值得动的 claim"一起给出；
  要伪造时 `jwt(action=sign|none, payload=..., secret=...)`，要 `jku` 自签时 `jwt(action=jwks, secret=..., kid=...)` 拿 JWKS 原文。
- 常见误读：base64 串里出现形似 `flags` 的前缀时，解码后其实是答案前缀（少一个字母）。**先解码再判断**，别被字面骗。
- 设备码流程拿到 token 后，别忘了同一响应里的 `refresh_token` / `id_token` 可能各有不同字段。

## 四、制品泄露：比接口更容易被忽略

拿到任意"读对象/读文件"的能力后，优先翻这几类文件（它们常直接是 root 凭据）：

```
*.tfstate  *.tfvars            基础设施状态：明文 AK/SK、root 口令
*.yaml / *.yml / *.env / *.ini 连接串、API Key、SMTP、数据库
api-keys.json / credentials.txt / *-passwords.txt
config-backup.*  /  README / notes / runbook（提示"root 材料在哪"）
```

- 先用"公开/低权限"通道把**文档类对象**读一遍：题目常在 README 或 runbook 里写出相邻私有桶名、
  组名、以及"凭据在 state 里"这类指路语。**盲猜名字不如读文档。**
- 拿到的高权限凭据再回头打目标桶/库；`state` 里的 root 凭据经常能开最后一个桶。

## 五、凭据先看"范围"，再看"能不能用"

| 看到 | 看什么 |
|---|---|
| SAS `sp=` / `srt=` | `srt=sco` = 账号级；`sp=rwdlac` = 读写删列全通 |
| STS 响应 `bucket_scope` / `policy` | 这一把钥匙开哪个桶 |
| JWT `scope` / `roles` / `group` | 能调哪些接口 |
| AK/SK | 先列桶、再列对象，别直接猜对象名 |

## 六、高频误判

- **预填账号不能直接登录**：登录页给的账号常常要先"注册"再登录（`/api/auth/register`）。
- **只暴露一个桶是设计**：`/files/<bucket>/...` 只放行公开桶时，不要在这里硬试其他桶名，
  去别的接口（`/api/storage/*`、STS 换来的 scope）拿权限。
- **禁出网**：所有指向公网/经典元数据地址的请求都会超时；这不代表服务坏了，换内部名。
- **模拟实现会挑字段**：报 `ResourceNotFoundException` / `NoSuchBucket` / `unsupported federation algorithm`
  说明它按真实云 API 语义实现，**按官方语义构造**而不是猜。
