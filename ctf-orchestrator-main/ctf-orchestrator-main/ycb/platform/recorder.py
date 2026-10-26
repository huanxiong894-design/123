"""被动网络录制：只保存答题相关的 JSON 响应，供发现校准/排障。

安全边界：
- 只录制白名单路径（player/ctf、answer-panel 等），不录制登录/用户接口；
- 不保存请求头、Cookie、Authorization；
- 对 token/password/secret 等字段递归脱敏；
- 单条响应上限 2MB，内存只保留最近 200 条。
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_INTERESTING = (
    "/slab-match/api/v1/player/",
    "/slab-match/api/v1/stage/",
    "/slab-match/api/v1/corpus/",
)
_SECRET_KEYS = re.compile(r"(token|password|passwd|secret|authorization|cookie|session)", re.I)
_MAX_BODY = 2 * 1024 * 1024


def redact(value: Any) -> Any:
    """递归脱敏；只处理 JSON 可序列化结构。"""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if _SECRET_KEYS.search(str(key)):
                out[key] = "***"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class NetworkRecorder:
    def __init__(self, debug_dir: Path, *, max_records: int = 200):
        self.debug_dir = debug_dir
        self.debug_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.debug_dir.chmod(0o700)
        except OSError:  # pragma: no cover
            pass
        self._records: deque[dict[str, Any]] = deque(maxlen=max_records)
        self._tasks: set[asyncio.Task] = set()
        self._file = self.debug_dir / f"network-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
        self._fh = None
        try:
            self._fh = self._file.open("a", encoding="utf-8")
            self._file.chmod(0o600)
        except OSError:  # pragma: no cover
            log.warning("无法创建网络录制文件 %s", self._file)

    @staticmethod
    def interesting(url: str) -> bool:
        return any(part in url for part in _INTERESTING)

    def attach(self, page) -> None:
        page.on("response", self._on_response)

    def _on_response(self, response) -> None:
        try:
            url = response.url
        except Exception:  # pragma: no cover
            return
        if not self.interesting(url):
            return
        try:
            task = asyncio.create_task(self._capture(response, url))
        except RuntimeError:  # pragma: no cover - 事件循环已关闭
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _capture(self, response, url: str) -> None:
        try:
            content_type = (await response.header_value("content-type")) or ""
            if "json" not in content_type.lower():
                return
            body = await response.body()
            if not body or len(body) > _MAX_BODY:
                return
            payload = json.loads(body)
        except Exception:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "url": url,
            "status": response.status,
            "payload": redact(payload),
        }
        self._records.append(record)
        if self._fh is not None:
            try:
                self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                self._fh.flush()
            except OSError:  # pragma: no cover
                pass

    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def latest(self, needle: str) -> dict[str, Any] | None:
        for record in reversed(self._records):
            if needle in record["url"]:
                return record
        return None

    def clear(self) -> None:
        self._records.clear()

    async def close(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:  # pragma: no cover
                pass
            self._fh = None
