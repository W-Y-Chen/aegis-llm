"""aegis.shield —— 语义级提示注入检测与阻断网关（对应防护网关）。

以轻量代理方式串接于业务应用与语言模型之间：
输入文本经"指令意图空间 + 上下文一致性 + 指令层级隔离"三路信号
融合判定，输出放行 / 清洗 / 阻断决策，单次推理微秒级（约束 <50ms）。
"""

from .context import ConsistencySignal, DialogueContext
from .detector import Action, HeuristicInjectionDetector, UnsanitizablePolicy, Verdict
from .gateway import GatewayResult, ShieldGateway, sanitize
from .hierarchy import HierarchyChecker, LevelConflict, TaggedContent, TrustLevel
from .prototypes import DEFAULT_CLUSTERS, InjectionPrototypeCluster, IntentSignal, PrototypeSpace
from .sanitizer import wrap_untrusted
from .updater import PrototypeUpdater

__all__ = [
    "Action",
    "Verdict",
    "UnsanitizablePolicy",
    "HeuristicInjectionDetector",
    "ShieldGateway",
    "GatewayResult",
    "sanitize",
    "wrap_untrusted",
    "DialogueContext",
    "ConsistencySignal",
    "TrustLevel",
    "TaggedContent",
    "HierarchyChecker",
    "LevelConflict",
    "InjectionPrototypeCluster",
    "IntentSignal",
    "PrototypeSpace",
    "DEFAULT_CLUSTERS",
    "PrototypeUpdater",
]
