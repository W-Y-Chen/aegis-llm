"""aegis.report —— 对标 GB/T 45654—2025 的合规报告生成器。

输入攻击链证据（.evidence/*.json）与目标模型档案，
输出含风险分级、攻击链复现路径、合规对照表与整改建议的 HTML 报告。
"""

from .generator import ReportGenerator
from .model import (
    ClauseResult,
    ComplianceReport,
    Conclusion,
    Finding,
    Severity,
    family_of,
)

__all__ = [
    "ReportGenerator",
    "ComplianceReport",
    "Finding",
    "ClauseResult",
    "Conclusion",
    "Severity",
    "family_of",
]
