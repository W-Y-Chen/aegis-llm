"""指令层级隔离（对应防护链路·S3 步骤）。

为系统指令、用户指令与外部数据分配不同信任层级标签；
对携带外部数据标签的内容剥夺指令执行权，仅作为数据处理对象。
当外部数据中出现高于其信任层级的指令时，判定层级冲突并标记。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class TrustLevel(IntEnum):
    """信任层级：数值越大权限越高。"""

    EXTERNAL = 1  # 外部数据（检索文档、工具返回、第三方内容）：只作数据，无指令权
    USER = 2      # 用户指令：常规指令权
    SYSTEM = 3    # 系统指令：最高指令权


@dataclass(frozen=True)
class TaggedContent:
    """携带信任层级标签的内容单元。"""

    text: str
    level: TrustLevel = TrustLevel.USER
    source: str = ""  # 来源说明（如 retrieval:doc-12 / tool:web_search）


# 指令性语句模式：祈使/元指令特征（试图定义、覆盖或逃逸指令的语句）
_INSTRUCTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)",
    r"(?i)forget\s+(everything|all|your\s+instructions?)",
    r"(?i)you\s+(are|must\s+act\s+as)\s+(now\s+)?a?\s*(new|different)",
    r"(?i)new\s+instructions?\s*[:：]",
    r"(?i)system\s*(prompt)?\s*[:：]",
    r"忽略.{0,12}(之前|以上|先前|原有).{0,8}(指令|指示|要求|设定|规则)",
    r"无视.{0,12}(之前|以上|先前|原有).{0,8}(指令|指示|要求|规则)",
    r"忘记.{0,8}(你|所有|一切).{0,8}(指令|设定|规则)",
    r"(现在|从此刻?起?).{0,6}你是.{1,20}",
    r"(你|请).{0,4}必须.{0,10}(执行|遵守|按照)",
    r"以(管理员|root|系统|开发者|运维)(身份|权限|模式)",
]


@dataclass
class LevelConflict:
    """一次层级冲突标记：低信任内容中检出指令性语句。"""

    excerpt: str
    pattern: str
    level: TrustLevel


@dataclass
class HierarchyChecker:
    """指令层级隔离检查器。"""

    patterns: tuple[str, ...] = tuple(_INSTRUCTION_PATTERNS)
    _compiled: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_compiled", [re.compile(p) for p in self.patterns])

    def find_instructions(self, text: str) -> list[tuple[str, str]]:
        """返回 (命中片段, 命中模式) 列表。"""
        hits: list[tuple[str, str]] = []
        for cp in self._compiled:
            for m in cp.finditer(text):
                hits.append((m.group(0)[:60], cp.pattern))
        return hits

    def check(self, content: TaggedContent) -> list[LevelConflict]:
        """检测层级冲突：内容信任层级低于 USER 却携带指令性语句。"""
        if content.level >= TrustLevel.USER:
            return []  # 用户/系统层本身拥有指令权，不构成冲突
        return [
            LevelConflict(excerpt=ex, pattern=pat, level=content.level)
            for ex, pat in self.find_instructions(content.text)
        ]
