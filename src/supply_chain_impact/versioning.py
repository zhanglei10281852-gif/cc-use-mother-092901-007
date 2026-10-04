"""版本解析与区间匹配。

采用务实的分段比较规则（非完整 SemVer）：

- 版本按 ``.`` ``-`` ``+`` ``_`` 切分为标识符序列；
- 纯数字标识符按数值比较，其余按字典序比较；
- 数字标识符排在非数字标识符之前；
- 缺失的尾部标识符按 0 补齐，因此 ``1.2`` 与 ``1.2.0`` 相等；
- 预发布后缀（如 ``1.2.3-rc1``）按上述规则排在同号正式版之后，
  与 SemVer 的优先级约定不同，调用方不应依赖预发布排序。

区间表达式为逗号分隔的子句（逻辑与），支持 ``>=`` ``<=`` ``>`` ``<``
``==`` ``!=``、裸版本（等价 ``==``）以及 ``*``（匹配任意版本）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_IDENT_SPLIT = re.compile(r"[.\-+_]")
_INT_RE = re.compile(r"^\d+$")
_RUN_SPLIT = re.compile(r"\d+|\D+")
_OPERATORS = (">=", "<=", "==", "!=", ">", "<")


def _tokenize(version: str) -> tuple:
    tokens = []
    for part in _IDENT_SPLIT.split(version.strip()):
        for run in _RUN_SPLIT.findall(part):
            if _INT_RE.match(run):
                tokens.append((0, int(run)))
            else:
                tokens.append((1, run))
    return tuple(tokens)


def compare_versions(left: str, right: str) -> int:
    """比较两个版本号，返回 -1 / 0 / 1。"""
    a, b = _tokenize(left), _tokenize(right)
    zero = (0, 0)
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else zero
        y = b[i] if i < len(b) else zero
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1
    return 0


@dataclass(frozen=True)
class VersionRange:
    """逗号分隔的版本区间，所有子句同时满足才算命中。"""

    raw: str
    clauses: tuple  # ((op, version), ...)；空元组表示匹配任意版本

    @classmethod
    def parse(cls, raw: str) -> "VersionRange":
        if raw is None:
            raise ValueError("版本范围不能为空")
        text = raw.strip()
        if not text:
            raise ValueError("版本范围不能为空")
        if text == "*":
            return cls(raw=text, clauses=())
        clauses = []
        for piece in text.split(","):
            piece = piece.strip()
            if not piece:
                raise ValueError(f"版本范围含空子句: {raw!r}")
            op = "=="
            version = piece
            for candidate in _OPERATORS:
                if piece.startswith(candidate):
                    op = candidate
                    version = piece[len(candidate):].strip()
                    break
            if not version:
                raise ValueError(f"版本范围子句缺少版本号: {piece!r}")
            clauses.append((op, version))
        return cls(raw=text, clauses=tuple(clauses))

    def matches(self, version: str) -> bool:
        for op, target in self.clauses:
            outcome = compare_versions(version, target)
            if op == ">=" and outcome < 0:
                return False
            if op == "<=" and outcome > 0:
                return False
            if op == ">" and outcome <= 0:
                return False
            if op == "<" and outcome >= 0:
                return False
            if op == "==" and outcome != 0:
                return False
            if op == "!=" and outcome == 0:
                return False
        return True
