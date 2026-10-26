#!/usr/bin/env bash
# 便捷启动脚本：首次运行自动创建 .venv（Python 3.11）并安装核心依赖。
# 用法：./run.sh --mock
set -euo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.11}"
if [ ! -x "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3.11 || true)"
fi
if [ -z "${PYTHON_BIN}" ] || [ ! -x "$PYTHON_BIN" ]; then
  echo "错误：找不到 Python 3.11（可用 PYTHON_BIN=/path/to/python3.11 ./run.sh 指定）" >&2
  exit 2
fi

if [ ! -x .venv/bin/python ]; then
  echo "[run.sh] 创建 .venv（$PYTHON_BIN）…"
  if ! "$PYTHON_BIN" -m venv .venv 2>/dev/null; then
    # Debian/Kali 未安装 python3.11-venv 时退回到 virtualenv
    command -v virtualenv >/dev/null 2>&1 || {
      echo "错误：缺少 venv 支持。请安装 python3.11-venv，或安装 virtualenv。" >&2
      exit 2
    }
    virtualenv -p "$PYTHON_BIN" .venv
  fi
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python run.py "$@"
