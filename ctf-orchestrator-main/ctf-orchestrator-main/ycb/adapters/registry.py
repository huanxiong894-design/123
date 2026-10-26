"""适配器注册表：``platform.active`` -> 实现类。

换平台 = 新增 adapters/<name>.py + 注册一行；解题内核零改动。
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

from ycb.adapters.base import PlatformAdapter
from ycb.config import Config

log = logging.getLogger(__name__)

_BUILTINS: dict[str, tuple[str, str]] = {
    "mock": ("ycb.adapters.mock", "MockAdapter"),
    "ycb": ("ycb.adapters.ycb", "YCBAdapter"),
    "ctfd": ("ycb.adapters.ctfd", "CTFDAdapter"),
}

_CUSTOM: dict[str, tuple[str, str]] = {}


def register(name: str, module: str, class_name: str) -> None:
    _CUSTOM[name.lower()] = (module, class_name)


def available() -> list[str]:
    return sorted({*_BUILTINS, *_CUSTOM})


def create_adapter(config: Config, **kwargs: Any) -> PlatformAdapter:
    name = config.platform.active.lower()
    target = _CUSTOM.get(name) or _BUILTINS.get(name)
    if target is None:
        raise ValueError(f"未知平台 {name!r}，可用：{', '.join(available())}")
    module_name, class_name = target
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    adapter = cls(config, **kwargs)
    if adapter.name != name and name not in {"mock"}:
        log.warning("适配器 %s 的 name=%s 与配置平台 %s 不一致", cls.__name__, adapter.name, name)
    return adapter
