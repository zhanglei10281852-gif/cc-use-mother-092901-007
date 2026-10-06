"""车规语义的版本号与版本区间解析。

版本号采用点分数字（1 / 1.2 / 1.2.3），区间使用逗号分隔的比较符，
例如 ">=2.4,<2.5"；"*" 或空串表示不限版本。
"""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Tuple

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_PART_RE = re.compile(r"^\s*(>=|<=|==|!=|>|<|=)?\s*(\d+(?:\.\d+)*|\*)\s*$")


@total_ordering
class Version:
    """规范化的点分数字版本。"""

    __slots__ = ("text", "parts")

    def __init__(self, text: str) -> None:
        text = (text or "").strip()
        if not _VERSION_RE.match(text):
            raise ValueError(f"非法版本号: {text!r}")
        self.text = text
        self.parts: Tuple[int, ...] = tuple(int(p) for p in text.split("."))

    def _key(self, width: int) -> Tuple[int, ...]:
        if len(self.parts) >= width:
            return self.parts
        return self.parts + (0,) * (width - len(self.parts))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        width = max(len(self.parts), len(other.parts))
        return self._key(width) == other._key(width)

    def __lt__(self, other: "Version") -> bool:
        width = max(len(self.parts), len(other.parts))
        return self._key(width) < other._key(width)

    def __hash__(self) -> int:
        # 归一化到 4 位再哈希，使 1.2 与 1.2.0 视为同一版本
        return hash(self._key(4))

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"Version({self.text!r})"


class VersionRange:
    """版本区间，支持 >=、<=、>、<、==、!= 与通配符。"""

    __slots__ = ("spec", "_constraints", "any")

    def __init__(self, spec: str) -> None:
        self.spec = spec or "*"
        spec = (spec or "*").strip()
        self._constraints = []
        self.any = spec in ("", "*")
        if self.any:
            return
        for raw in spec.split(","):
            match = _PART_RE.match(raw)
            if not match:
                raise ValueError(f"非法版本区间: {spec!r}")
            op, value = match.groups()
            if value == "*":
                # 单独的通配符与其他比较符没有意义
                if op is not None or spec.strip() != "*":
                    raise ValueError(f"非法版本区间: {spec!r}")
                self.any = True
                self._constraints = []
                return
            self._constraints.append((op or "==", Version(value)))

    def contains(self, version: str | Version) -> bool:
        ver = version if isinstance(version, Version) else Version(version)
        if self.any:
            return True
        for op, bound in self._constraints:
            if op == ">=" and not ver >= bound:
                return False
            if op == "<=" and not ver <= bound:
                return False
            if op == ">" and not ver > bound:
                return False
            if op == "<" and not ver < bound:
                return False
            if op in ("==", "=") and not ver == bound:
                return False
            if op == "!=" and ver == bound:
                return False
        return True

    def __str__(self) -> str:
        return self.spec

    def __repr__(self) -> str:
        return f"VersionRange({self.spec!r})"
