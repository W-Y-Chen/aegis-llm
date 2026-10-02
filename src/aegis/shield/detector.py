"""融合判定与阻断（对应防护链路·S4 步骤，设计要点 5/7）。

三路检测信号（指令意图空间 / 上下文一致性 / 指令层级隔离）输入融合判定器，
输出放行 / 清洗 / 阻断决策及判定依据。MVP 采用加权规则融合，
单次推理实测微秒级，满足 <50ms 约束；单实例吞吐 >> 200 QPS。
"""

from __future__ import annotations

import re
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum

from .context import ConsistencyChecker, DialogueContext
from .hierarchy import HierarchyChecker, TaggedContent, TrustLevel
from .prototypes import PrototypeSpace
from .sanitizer import sanitize


class Action(str, Enum):
    ALLOW = "allow"        # 放行
    SANITIZE = "sanitize"  # 清洗（剥离指令性片段后作为数据处理）
    BLOCK = "block"        # 阻断


class UnsanitizablePolicy(str, Enum):
    """判定为高危、但清洗器删不掉时如何处理（H3 的两种取向）。

    两种策略不是"安全 vs 不安全"的对立，而是**风险与数据价值的权衡**：

    - `BLOCK`（默认，安全优先）
      整段阻断，丢弃该文档本可保留的数据价值。
      适用：内容来源不可信、业务对该文档依赖度低、或无法承受任何残余风险。

    - `SANITIZE_MARKED`（数据价值优先，配合指令权剥夺）
      清洗后**带显式不可信标记**放行：把残余内容降级为纯数据、剥夺其指令执行权，
      而不是裸放行。这与防护链路·S3「指令层级隔离」的主张一致——
      对外部数据不是简单丢弃，而是剥夺指令权后仅作数据处理对象。
      适用：RAG 检索文档、工具返回等有明确数据价值且必须送模型的场景。

    注意 `SANITIZE_MARKED` 的残余风险是**真实存在且未被消除**的，必须如实标注，
    不得表述为"已清洗干净"。
    """

    BLOCK = "block"
    SANITIZE_MARKED = "sanitize_marked"


@dataclass
class Verdict:
    """融合判定结果。"""

    action: Action
    score: float                      # 融合风险得分 0~1
    rationale: str                    # 判定依据（命中簇/一致性/层级冲突）
    signals: dict = field(default_factory=dict)  # 三路信号明细
    latency_ms: float = 0.0
    # 预演清洗后仍残留的指令意图风险（0 表示清洗已消除风险）
    # 仅在数据通道（EXTERNAL）判定为清洗/阻断时计算
    residual_risk: float = 0.0
    # 是否属于"判定高危但清洗器删不掉"（UnsanitizablePolicy.SANITIZE_MARKED 下据此加标记）
    unsanitizable: bool = False


class HeuristicInjectionDetector:
    """注入检测器（MVP：加权规则融合；V2 可平替为梯度提升树/浅层神经网络）。

    用法（串接于业务应用与语言模型之间）::

        detector = HeuristicInjectionDetector()
        verdict = detector.detect(user_text)
        if verdict.action is Action.BLOCK:
            return safe_reply
    """

    def __init__(
        self,
        w_intent: float = 0.45,
        w_context: float = 0.20,
        w_hierarchy: float = 0.35,
        block_threshold: float = 0.72,
        sanitize_threshold: float = 0.40,
        extra_patterns: dict[str, tuple[tuple[str, float], ...]] | None = None,
        unsanitizable_policy: UnsanitizablePolicy = UnsanitizablePolicy.BLOCK,
    ) -> None:
        self._space = PrototypeSpace(extra_patterns=extra_patterns)
        self._consistency = ConsistencyChecker()
        self._hier = HierarchyChecker()
        self.w = (w_intent, w_context, w_hierarchy)
        self.block_threshold = block_threshold
        self.sanitize_threshold = sanitize_threshold
        self.unsanitizable_policy = UnsanitizablePolicy(unsanitizable_policy)

    def load_proposed_patterns(
        self,
        proposals: list[dict],
        approved_clusters: dict[str, str] | None = None,
        default_weight: float = 0.9,
        only_approved: bool = True,
    ) -> int:
        """装载反馈闭环产出的候选模式（防护链路·S5 的终点）。

        这是 MVP 有意保留的人工环节：候选模式来自高频漏判片段的字面转义，
        泛化能力与误命中风险需人工确认后才能生效。
        `only_approved=True` 时只装载簇归属已确定的项（`suggested_cluster` 非空
        或在 `approved_clusters` 中被显式指定），无法归类的留待进一步分析。

        **默认权重取 0.9 是有数值依据的**：融合得分 = Σ wᵢ·sᵢ，而 s1 的权重
        w_intent = 0.45，此处样本 s2/s3 均为 0，故总分 = 0.45 × 模式权重。
        清洗阈值 sanitize_threshold = 0.40，要求 0.45w ≥ 0.40 ⇒ **w ≥ 0.889**。
        权重低于该值时（实测 0.6 仅得 0.3825），模式虽已装载却永远无法改变判定——
        闭环会名义连通但实际失效。0.9 同时还能触发 `s1.risk ≥ 0.9` 的
        得分抬升规则（`score = max(score, 0.80)`），直接落入阻断区间。

        返回实际装载的条数。
        """
        approved_clusters = approved_clusters or {}
        grouped: dict[str, list[tuple[str, float]]] = {}

        def note(msg: str) -> None:
            warnings.warn(f"load_proposed_patterns: {msg}", RuntimeWarning, stacklevel=2)

        for p in proposals:
            if p.get("status") != "pending_human_review" and only_approved:
                # 已是成品/已废弃的建议不重复装载
                continue
            pattern = p.get("pattern")
            if not pattern:
                continue
            cid = approved_clusters.get(p.get("literal", "")) or p.get("suggested_cluster")
            if not cid:
                if only_approved:
                    continue
                cid = "override"
            try:
                re.compile(pattern)
            except re.error:
                note(f"跳过非法正则：{pattern!r}")
                continue
            grouped.setdefault(cid, []).append((pattern, float(p.get("weight", default_weight))))

        if not grouped:
            return 0
        return self._space.extend({k: tuple(v) for k, v in grouped.items()})

    def _can_downgrade(self, text: str) -> tuple[bool, float]:
        """是否可以把"阻断"降级为"清洗"，以及清洗后的残余风险。

        前提一（业务）：指令片段占比不高，文档仍有数据价值，值得保留而非整段丢弃。
        前提二（安全，H3 的关键约束）：清洗确实降低了风险。

        原实现只有前提一。由于 `HierarchyChecker` / `_INSTRUCTIVE_SENTENCE` 的规则覆盖面
        落后于 `PrototypeSpace`（后者在 v0.2.1 补了大量中文口语化与多语言模式），
        出现"检测器判定 0.80 高危、清洗器却一条都删不掉"的组合，
        此时无条件降级等于把完整注入原样送交模型——一条完整的防护绕过路径。

        返回 `(是否可降级, 清洗后残余风险)`。残余风险无论走哪条策略都要如实上报：
        - `UnsanitizablePolicy.BLOCK`：残余 ≥ sanitize_threshold 时保持阻断；
        - `UnsanitizablePolicy.SANITIZE_MARKED`：一律降级放行，但由网关给内容加上
          不可信标记、剥夺其指令权（见 `sanitizer.wrap_untrusted`）。

        注意：清洗后为空的情形返回 `True, 0.0` 是安全的——`ShieldGateway` 会把空结果
        升级为阻断（`if not cleaned` 分支）。
        """
        hit_len = sum(len(h[0]) for h in self._hier.find_instructions(text))
        if hit_len / max(len(text), 1) > 0.40:
            return False, 0.0
        cleaned, _ = sanitize(text, checker=self._hier)
        if not cleaned.strip():
            return True, 0.0  # 清洗到空 ⇒ 等价于阻断，由 gateway 兜底升级
        residual = self._space.first_signal(cleaned).risk
        if self.unsanitizable_policy is UnsanitizablePolicy.SANITIZE_MARKED:
            return True, residual
        return residual < self.sanitize_threshold, residual

    def detect(
        self,
        text: str,
        context: DialogueContext | None = None,
        trust_level: TrustLevel = TrustLevel.USER,
        source: str = "",
    ) -> Verdict:
        t0 = time.perf_counter()

        content = TaggedContent(text=text, level=trust_level, source=source)

        # S1：指令意图空间 —— 第一检测信号
        s1 = self._space.first_signal(text)

        # S2：上下文一致性 —— 第二检测信号（风险 = 1 - 一致性）
        s2 = self._consistency.check(text, content, context)
        ctx_risk = 1.0 - s2.score

        # S3：指令层级隔离 —— 第三检测信号
        conflicts = self._hier.check(content)
        s3 = 1.0 if conflicts else 0.0

        # S4：融合判定（加权规则）
        w1, w2, w3 = self.w
        score = w1 * s1.risk + w2 * ctx_risk + w3 * s3
        # 高危原型簇强命中（≥0.9）直接抬升至阻断区间——
        # 避免无上下文基线时一致性满分稀释掉确定性注入特征
        if s1.risk >= 0.9:
            score = max(score, 0.80)
        # 层级冲突与高危原型簇命中具有一票加权权：上限抬升至可阻断区间
        if conflicts and s1.risk >= 0.7:
            score = max(score, 0.85)

        if score >= self.block_threshold:
            action = Action.BLOCK
        elif score >= self.sanitize_threshold:
            action = Action.SANITIZE
        else:
            action = Action.ALLOW

        # 数据通道（检索文档/工具返回）且指令片段占比不高时，优先"清洗"而非整段阻断：
        # 业务上应保留文档的数据价值，只剥离其中的指令性内容。
        # 纯靠加权分值时清洗档位几乎不可达（信号非 0 即 1），此处补上语义规则。
        # 但降级必须以"清洗确实能消除风险"为前提，详见 _can_downgrade（H3）。
        residual = 0.0
        if action is Action.BLOCK and trust_level == TrustLevel.EXTERNAL:
            can_downgrade, residual = self._can_downgrade(text)
            if can_downgrade:
                action = Action.SANITIZE

        rationale_parts = [
            f"意图空间风险={s1.risk:.2f}" + (f"（命中{s1.cluster_name}）" if s1.cluster_id else ""),
            f"上下文一致性={s2.score:.2f}",
            f"层级冲突={'有' if conflicts else '无'}",
        ]
        if s2.anomalies:
            rationale_parts.append("异常维度：" + "；".join(s2.anomalies))

        unsanitizable = residual >= self.sanitize_threshold
        if unsanitizable:
            rationale_parts.append(
                f"清洗后残余风险={residual:.2f}（未被消除，"
                + ("已按策略加不可信标记放行" if action is Action.SANITIZE
                   else "已按策略保持阻断")
                + "）"
            )

        return Verdict(
            action=action,
            score=round(score, 4),
            rationale=" | ".join(rationale_parts),
            signals={
                "intent": {"risk": s1.risk, "cluster": s1.cluster_id, "matched": s1.matched},
                "context": {"score": s2.score, "anomalies": s2.anomalies},
                "hierarchy": {"conflicts": len(conflicts), "level": int(trust_level)},
                "sanitize": {"residual_risk": residual, "unsanitizable": unsanitizable},
            },
            latency_ms=round((time.perf_counter() - t0) * 1000, 3),
            residual_risk=residual,
            unsanitizable=unsanitizable,
        )
