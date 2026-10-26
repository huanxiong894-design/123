"""验证码识别：ddddocr 懒加载，在线程池执行，失败交给人工。"""

from __future__ import annotations

import asyncio
import logging
import re

from ycb.adapters.base import NeedsHuman

log = logging.getLogger(__name__)

_MAX_ANSWER = 12


class CaptchaSolver:
    """ddddocr 包装器。

    ddddocr 首次初始化会加载 ONNX 模型（数百毫秒），因此延迟到第一次真正
    需要识别时再加载；识别本身是 CPU 密集的，放到线程池避免卡事件循环。
    """

    def __init__(self, *, timeout: float = 20.0):
        self.timeout = timeout
        self._ocr = None
        self._lock = asyncio.Lock()

    def _load(self):
        try:
            import ddddocr  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - 依赖缺失时转人工
            raise NeedsHuman(f"未安装 ddddocr：{exc}") from exc
        try:
            return ddddocr.DdddOcr(show_ad=False)
        except TypeError:  # 兼容老版本
            return ddddocr.DdddOcr()

    @staticmethod
    def _clean(value: str) -> str:
        text = re.sub(r"\s+", "", str(value or ""))
        text = re.sub(r"[^0-9A-Za-z]", "", text)
        return text[:_MAX_ANSWER]

    async def solve(self, image: bytes) -> str:
        if not image:
            raise NeedsHuman("验证码图片为空")
        async with self._lock:
            if self._ocr is None:
                self._ocr = await asyncio.to_thread(self._load)
            try:
                raw = await asyncio.wait_for(
                    asyncio.to_thread(self._ocr.classification, image), timeout=self.timeout
                )
            except asyncio.TimeoutError as exc:
                raise NeedsHuman(f"验证码识别超时（>{self.timeout:.0f}s）") from exc
            except Exception as exc:
                raise NeedsHuman(f"验证码识别失败：{exc}") from exc
        answer = self._clean(raw)
        if not answer:
            raise NeedsHuman("验证码识别结果为空")
        log.info("验证码识别完成 len=%d", len(answer))
        return answer
