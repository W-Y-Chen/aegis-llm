"""`aegis.redteam` 命名空间（评测引擎的语义子包）。

修复项：README/ARCHITECTURE 反复引用 `aegis.redteam`，但代码实际是扁平的
`aegis.state / aegis.agent / aegis.evaluator / ...`，照文档写
`from aegis.redteam import AttackAgent` 会直接 ImportError。

本模块把扁平模块按语义聚合为 `aegis.redteam` 命名空间，文档与代码对齐；
同时保留原有的扁平导入路径，向后兼容。
"""

from .agent import AttackAgent
from .evaluator import DefensePosture, HeuristicEvaluator
from .evidence import AttackChain, EvidenceRecorder, Redaction
from .harm import HarmDiscriminator, HarmVerdict, judge
from .operators import OPERATORS, AttackOperator
from .orchestrator import BatchOrchestrator, BatchResult
from .scenarios import Scenario, load_scenario, load_scenarios
from .state import DialogueState, StateMachine, Transition
from .target import OpenAICompatibleTarget, TargetModel, TargetProfile

__all__ = [
    "AttackAgent",
    "DefensePosture",
    "HeuristicEvaluator",
    "AttackChain",
    "EvidenceRecorder",
    "Redaction",
    "HarmDiscriminator",
    "HarmVerdict",
    "judge",
    "OPERATORS",
    "AttackOperator",
    "BatchOrchestrator",
    "BatchResult",
    "Scenario",
    "load_scenario",
    "load_scenarios",
    "DialogueState",
    "StateMachine",
    "Transition",
    "OpenAICompatibleTarget",
    "TargetModel",
    "TargetProfile",
]
