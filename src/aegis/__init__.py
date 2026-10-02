"""鉴安 AegisLLM —— 大模型与智能体安全评测防护一体化平台（开源社区版）。

仅用于获得书面授权的目标系统的防御性安全测试。

模块地图：
- 评测（redteam）：state / operators / agent / evaluator / evidence / scenarios / target
- 防护（shield）：语义级提示注入检测与阻断网关（防护网关）
- 审计（audit）：智能体工具调用链越权行为检测（审计模块）
- 报告（report）：对标 GB/T 45654—2025 的合规报告生成
"""

__version__ = "0.3.1"

from .state import DialogueState, StateMachine
from .agent import AttackAgent
from .evaluator import DefensePosture, HeuristicEvaluator
from .evidence import EvidenceRecorder
from .scenarios import Scenario, load_scenario

__all__ = [
    "DialogueState",
    "StateMachine",
    "AttackAgent",
    "DefensePosture",
    "HeuristicEvaluator",
    "EvidenceRecorder",
    "Scenario",
    "load_scenario",
]
