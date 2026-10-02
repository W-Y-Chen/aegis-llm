"""aegis.audit —— 智能体工具调用链审计与越权行为检测（对应审计模块）。

以 SDK 方式嵌入智能体运行时采集"感知—决策—调用—返回"四元组轨迹，
执行"权限规则 → 序列异常 → 数据流向"三级检测与目标漂移校验，
输出风险定位（调用序号/涉事工具/数据流）与分级处置建议。
"""

from .baseline import BaselineBuilder, BehaviorBaseline
from .detector import AuditReport, ChainAuditDetector, Disposal, RiskEvent, RiskLevel, edit_distance
from .events import DataLabel, ToolCallEvent, TraceRecorder
from .net import extract_host, is_external_destination, is_internal_destination

__all__ = [
    "DataLabel",
    "ToolCallEvent",
    "TraceRecorder",
    "BehaviorBaseline",
    "BaselineBuilder",
    "ChainAuditDetector",
    "AuditReport",
    "RiskEvent",
    "RiskLevel",
    "Disposal",
    "edit_distance",
    "is_external_destination",
    "is_internal_destination",
    "extract_host",
]
