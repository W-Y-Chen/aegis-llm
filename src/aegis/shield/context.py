"""上下文一致性校验（对应防护链路·S2 步骤）。

校验输入文本与当前会话合法任务上下文的一致性，维度包括：
- 任务主题连续性：输入与既有任务主题的语义重合度；
- 指令来源合法性：指令语句是否来源于检索数据/工具返回/第三方内容（设计要点 4）；
- 指令同历史意图的一致性：与历史用户意图的偏离程度。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hierarchy import HierarchyChecker, TaggedContent, TrustLevel
from .prototypes import _ngram_jaccard


@dataclass
class DialogueContext:
    """当前会话的合法任务上下文。"""

    task_topic: str = ""                       # 本会话声明的合法任务主题
    history_intents: list[str] = field(default_factory=list)  # 历史用户意图摘要


@dataclass
class ConsistencySignal:
    """第二检测信号：一致性得分（越高越一致）与异常维度。"""

    score: float                    # 0~1，一致性得分
    topic_continuity: float = 0.0
    source_legitimacy: bool = True  # 指令来源是否合法
    intent_alignment: float = 0.0
    anomalies: list[str] = field(default_factory=list)


class ConsistencyChecker:
    """上下文一致性校验器（MVP：n-gram 重合度代理语义一致性）。"""

    def __init__(self) -> None:
        self._hier = HierarchyChecker()

    def check(self, text: str, content: TaggedContent, context: DialogueContext | None) -> ConsistencySignal:
        anomalies: list[str] = []

        # 维度一：任务主题连续性
        if context and context.task_topic:
            topic_score = _ngram_jaccard(text.lower(), context.task_topic.lower(), n=2)
            if topic_score < 0.02:
                anomalies.append("任务主题不连续：输入与当前任务主题几乎无重合")
        else:
            topic_score = 1.0  # 无上下文基线时不降权

        # 维度二：指令来源合法性（设计要点 4）
        source_legit = True
        if content.level == TrustLevel.EXTERNAL and self._hier.find_instructions(text):
            source_legit = False
            anomalies.append(f"指令来源非法：外部数据（{content.source or 'unknown'}）中夹带指令语句")

        # 维度三：与历史意图的一致性
        if context and context.history_intents:
            align = max((_ngram_jaccard(text.lower(), h.lower()) for h in context.history_intents), default=0.0)
            if align < 0.02 and topic_score < 0.02:
                anomalies.append("意图漂移：输入与全部历史意图均无重合")
            intent_score = align
        else:
            intent_score = topic_score

        score = (topic_score * 0.4 + intent_score * 0.3 + (1.0 if source_legit else 0.0) * 0.3)
        return ConsistencySignal(
            score=round(score, 4),
            topic_continuity=round(topic_score, 4),
            source_legitimacy=source_legit,
            intent_alignment=round(intent_score, 4),
            anomalies=anomalies,
        )
