"""三级越权检测 + 目标漂移 + 风险定位与分级处置（对应审计链路·S3/S4/S5 步骤）。

- 第一级 权限规则检测：工具授权清单、敏感资源指向、参数取值域越界（设计要点 2）；
- 第二级 序列异常检测：调用序列相对行为基线的偏离度
  = 序列编辑距离 + 转移概率偏离 加权（设计要点 3，原先只有转移概率）；
- 第三级 数据流向检测：标签沿调用链传播 + 会话级污点，堵住"自身产出敏感数据
  并外发"的漏报路径（设计要点 4）；
- S4 目标漂移检测；S5 风险定位与分级处置。

修复项：
1. L3 原先只算 refs 传播标签，不含事件自身 data_label 与会话级污点，
   导致"工具自己返回 SECRET 再 POST 外部（无 refs）"零告警；
2. 外部地址判定改为 URL host 解析（见 net.py），修复双向失效；
3. 空基线不再静默放行：缺失授权清单/基线时显式输出"无法校验"风险事件。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..shield.prototypes import _ngram_jaccard
from .baseline import BehaviorBaseline
from .events import DataLabel, ToolCallEvent
from .net import is_external_destination


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Disposal(str, Enum):
    ALERT = "alert"
    CONFIRM = "confirm"
    BLOCK = "block"
    FUSE = "fuse"


_DISPOSAL_MAP = {
    RiskLevel.LOW: Disposal.ALERT,
    RiskLevel.MEDIUM: Disposal.CONFIRM,
    RiskLevel.HIGH: Disposal.BLOCK,
    RiskLevel.CRITICAL: Disposal.FUSE,
}

_SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "idcard", "id_card", "ssn", "private_key", "credential",
    "密码", "密钥", "身份证", "凭据",
}
_SENSITIVE_PATH_HINTS = ("/etc/", "/root/", "~/.ssh", "id_rsa", ".env", "shadow")


@dataclass
class RiskEvent:
    level: str
    risk: RiskLevel
    disposal: Disposal
    seq: int
    tool: str
    detail: str


@dataclass
class AuditReport:
    task_id: str
    events_checked: int
    risk_events: list[RiskEvent] = field(default_factory=list)

    @property
    def max_risk(self) -> RiskLevel:
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        if not self.risk_events:
            return RiskLevel.LOW
        return max((e.risk for e in self.risk_events), key=order.index)

    @property
    def passed(self) -> bool:
        return not any(e.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) for e in self.risk_events)


def edit_distance(seq_a: list[str], seq_b: list[str]) -> int:
    """Levenshtein 编辑距离（纯标准库 DP 实现）。"""
    m, n = len(seq_a), len(seq_b)
    if m == 0:
        return n
    if n == 0:
        return m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if seq_a[i - 1] == seq_b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


class ChainAuditDetector:
    """工具调用链越权行为检测器。"""

    def __init__(
        self,
        baseline: BehaviorBaseline | None = None,
        seq_deviation_threshold: float = 0.6,
        drift_similarity_threshold: float = 0.05,
        drift_window: int = 2,
    ) -> None:
        self.baseline = baseline or BehaviorBaseline()
        self.seq_threshold = seq_deviation_threshold
        self.drift_sim_threshold = drift_similarity_threshold
        self.drift_window = drift_window

    # ---------- 第一级：权限规则检测 ----------
    def check_l1(self, ev: ToolCallEvent, authorized_tools: set[str] | None) -> list[RiskEvent]:
        risks: list[RiskEvent] = []
        allowed = authorized_tools if authorized_tools is not None else self.baseline.allowed_tools

        if allowed and ev.tool not in allowed:
            risks.append(RiskEvent(
                level="L1_permission", risk=RiskLevel.HIGH, disposal=_DISPOSAL_MAP[RiskLevel.HIGH],
                seq=ev.seq, tool=ev.tool,
                detail=f"工具「{ev.tool}」不在当前会话授权清单内",
            ))
        elif not allowed:
            risks.append(RiskEvent(
                level="L1_permission", risk=RiskLevel.LOW, disposal=_DISPOSAL_MAP[RiskLevel.LOW],
                seq=ev.seq, tool=ev.tool,
                detail="缺失授权清单与行为基线，无法完成权限校验（fail-open，需补齐基线）",
            ))

        lowered = {k.lower() for k in ev.params_keys}
        hit = lowered & _SENSITIVE_PARAM_NAMES
        if hit:
            risks.append(RiskEvent(
                level="L1_permission", risk=RiskLevel.MEDIUM, disposal=_DISPOSAL_MAP[RiskLevel.MEDIUM],
                seq=ev.seq, tool=ev.tool,
                detail=f"调用参数指向预设敏感资源字段：{sorted(hit)}",
            ))
        for k in ev.params_keys:
            if any(h in k.lower() for h in _SENSITIVE_PATH_HINTS):
                risks.append(RiskEvent(
                    level="L1_permission", risk=RiskLevel.MEDIUM, disposal=_DISPOSAL_MAP[RiskLevel.MEDIUM],
                    seq=ev.seq, tool=ev.tool,
                    detail=f"调用参数指向敏感路径：{k}",
                ))
                break

        # 参数取值域提示（设计要点 2）
        # 说明：参数以摘要哈希入基线，故只能判定"取值未在历史取值域中出现"，
        # 这属于新颖性提示而非越权证据——按 LOW 告警，避免对正常业务误伤。
        domains = self.baseline.param_domains.get(ev.tool, {})
        for key in ev.params_keys:
            known = domains.get(key)
            if known and ev.params_digest not in known:
                risks.append(RiskEvent(
                    level="L1_permission", risk=RiskLevel.LOW, disposal=_DISPOSAL_MAP[RiskLevel.LOW],
                    seq=ev.seq, tool=ev.tool,
                    detail=f"参数取值新异性：{ev.tool}.{key} 未出现在基线取值域（已知 {len(known)} 个取值），建议抽样复核",
                ))
        return risks

    # ---------- 第二级：序列异常检测（设计要点 3） ----------
    def _sequence_deviation(self, tools: list[str]) -> tuple[float, str]:
        """偏离度 = 0.5×编辑距离偏离 + 0.5×转移概率偏离。"""
        prob_devs = [1.0 - self.baseline.transition_probability(a, b) for a, b in zip(tools, tools[1:])]
        prob_dev = (sum(prob_devs) / len(prob_devs)) if prob_devs else 0.0

        edit_dev, detail = 0.0, ""
        if self.baseline.sequences:
            best = None
            for canonical in self.baseline.sequences:
                d = edit_distance(tools, list(canonical))
                if best is None or d < best[0]:
                    best = (d, canonical)
            if best:
                edit_dev = min(best[0] / max(len(best[1]), len(tools), 1), 1.0)
                detail = f"，最近基线序列编辑距离 {best[0]}（{'→'.join(best[1])}）"

        deviation = 0.5 * edit_dev + 0.5 * prob_dev
        return deviation, f"编辑偏离 {edit_dev:.2f} + 转移偏离 {prob_dev:.2f}{detail}"

    def check_l2(self, trace: list[ToolCallEvent]) -> list[RiskEvent]:
        if len(trace) < 2:
            return []
        if not self.baseline.transition_prob and not self.baseline.sequences:
            return [RiskEvent(
                level="L2_sequence", risk=RiskLevel.LOW, disposal=_DISPOSAL_MAP[RiskLevel.LOW],
                seq=trace[-1].seq, tool=trace[-1].tool,
                detail="无行为基线可用，序列异常检测跳过（fail-open）",
            )]
        tools = [ev.tool for ev in trace]
        deviation, info = self._sequence_deviation(tools)
        if deviation <= self.seq_threshold:
            return []
        return [RiskEvent(
            level="L2_sequence", risk=RiskLevel.MEDIUM, disposal=_DISPOSAL_MAP[RiskLevel.MEDIUM],
            seq=trace[-1].seq, tool=tools[-1],
            detail=f"调用序列偏离基线：偏离度 {deviation:.2f} > 阈值 {self.seq_threshold}（{info}）",
        )]

    # ---------- 索引完整性校验（H2） ----------
    def check_trace_integrity(self, trace: list[ToolCallEvent]) -> list[RiskEvent]:
        """校验轨迹索引（seq）的完整性。

        污点传播完全依赖 seq 建立索引（label_by_seq）与引用（refs_data_from）。
        若索引不可信，以下三种情况会**静默**削弱检测：
        1. seq 重复 —— 后一事件覆盖前一事件的标签，污点被降级；
        2. 引用不存在的 seq —— .get(ref, PUBLIC) 静默降级为 PUBLIC，传播链断裂；
        3. 前向引用（引用大于自身的 seq）—— 时序上不可能，属伪造轨迹。

        三者都不会抛错，只会让 L3 检测悄悄失效，因此必须显式检出。
        """
        risks: list[RiskEvent] = []
        if not trace:
            return risks

        counts: dict[int, int] = {}
        for ev in trace:
            counts[ev.seq] = counts.get(ev.seq, 0) + 1
        known = set(counts)

        dup = sorted(s for s, c in counts.items() if c > 1)
        if dup:
            risks.append(RiskEvent(
                level="trace_integrity", risk=RiskLevel.HIGH,
                disposal=_DISPOSAL_MAP[RiskLevel.HIGH],
                seq=dup[0], tool="(trace)",
                detail=f"轨迹索引被篡改：seq {dup} 重复出现，污点标签可能被覆盖降级，"
                       f"L3 数据流向检测结果不可信",
            ))

        dangling: list[tuple[int, list[int]]] = []
        forward: list[tuple[int, list[int]]] = []
        for ev in trace:
            refs = list(ev.refs_data_from or ())
            miss = sorted(r for r in refs if r not in known)
            # 前向引用只在"被引用的 seq 确实存在"时才成立；否则已按悬空引用计，
            # 避免同一处问题被重复报两次而虚增风险数量
            fwd = sorted(r for r in refs if r in known and r > ev.seq)
            if miss:
                dangling.append((ev.seq, miss))
            if fwd:
                forward.append((ev.seq, fwd))

        if dangling:
            s, m = dangling[0]
            risks.append(RiskEvent(
                level="trace_integrity", risk=RiskLevel.HIGH,
                disposal=_DISPOSAL_MAP[RiskLevel.HIGH],
                seq=s, tool="(trace)",
                detail=f"seq{s} 引用了不存在的 seq{m}，污点传播被静默降级为 PUBLIC；"
                       f"共 {len(dangling)} 处悬空引用",
            ))
        if forward:
            s, m = forward[0]
            risks.append(RiskEvent(
                level="trace_integrity", risk=RiskLevel.HIGH,
                disposal=_DISPOSAL_MAP[RiskLevel.HIGH],
                seq=s, tool="(trace)",
                detail=f"seq{s} 前向引用 seq{m}（引用晚于自身发生），时序矛盾，疑似伪造轨迹；"
                       f"共 {len(forward)} 处",
            ))
        return risks

    # ---------- 第三级：数据流向检测（设计要点 4） ----------
    def check_l3(self, trace: list[ToolCallEvent]) -> list[RiskEvent]:
        risks: list[RiskEvent] = []
        if not trace:
            return risks
        label_by_seq: dict[int, DataLabel] = {ev.seq: ev.data_label for ev in trace}
        session_taint = DataLabel.PUBLIC   # 会话级污点：本会话出现过的最高敏感级别

        for ev in trace:
            inherited = DataLabel.PUBLIC
            for ref in ev.refs_data_from:
                inherited = max(inherited, label_by_seq.get(ref, DataLabel.PUBLIC))
            # 修复项：纳入事件自身产出的标签（原实现完全忽略自身 data_label）
            effective = max(inherited, ev.data_label, DataLabel.PUBLIC)
            session_taint = max(session_taint, effective)

            if effective >= DataLabel.SENSITIVE and not self.baseline.allows_flow(effective, ev.tool):
                risks.append(RiskEvent(
                    level="L3_dataflow", risk=RiskLevel.CRITICAL, disposal=_DISPOSAL_MAP[RiskLevel.CRITICAL],
                    seq=ev.seq, tool=ev.tool,
                    detail=f"{effective.name} 级数据流入未授权工具「{ev.tool}」"
                           + (f"（传播自 seq{sorted(ev.refs_data_from)}）" if ev.refs_data_from
                              else "（本调用自身产出）"),
                ))

            # 外发检测：URL host 判定修正（原 startswith 前缀法双向失效）
            if ev.destination and is_external_destination(ev.destination):
                if session_taint >= DataLabel.SENSITIVE or effective >= DataLabel.SENSITIVE:
                    risks.append(RiskEvent(
                        level="L3_dataflow", risk=RiskLevel.CRITICAL, disposal=_DISPOSAL_MAP[RiskLevel.CRITICAL],
                        seq=ev.seq, tool=ev.tool,
                        detail=f"疑似敏感数据外发：会话最高 {session_taint.name} 级数据流向外部地址 {ev.destination}",
                    ))
                elif inherited >= DataLabel.INTERNAL or effective >= DataLabel.INTERNAL:
                    risks.append(RiskEvent(
                        level="L3_dataflow", risk=RiskLevel.MEDIUM, disposal=_DISPOSAL_MAP[RiskLevel.MEDIUM],
                        seq=ev.seq, tool=ev.tool,
                        detail=f"内部数据流向外部地址 {ev.destination}，建议人工确认业务必要性",
                    ))
        return risks

    # ---------- S4：目标漂移检测 ----------
    def check_drift(self, original_intent: str, subgoals: list[str]) -> list[RiskEvent]:
        if not original_intent or len(subgoals) < self.drift_window:
            return []
        streak = 0
        for i, g in enumerate(subgoals):
            sim = _ngram_jaccard(g.lower(), original_intent.lower())
            streak = streak + 1 if sim < self.drift_sim_threshold else 0
            if streak >= self.drift_window:
                return [RiskEvent(
                    level="goal_drift", risk=RiskLevel.HIGH, disposal=_DISPOSAL_MAP[RiskLevel.HIGH],
                    seq=i + 1, tool="(subgoal)",
                    detail=f"目标漂移：连续 {streak} 个子目标与原始意图语义相似度低于阈值"
                           f"（原始意图：{original_intent[:30]}…；当前子目标：{g[:30]}…）",
                )]
        return []

    # ---------- 汇总审计 ----------
    def audit(
        self,
        trace: list[ToolCallEvent],
        authorized_tools: set[str] | None = None,
        original_intent: str = "",
        subgoals: list[str] | None = None,
    ) -> AuditReport:
        report = AuditReport(task_id=trace[0].task_id if trace else "", events_checked=len(trace))
        # 索引完整性先行：seq 不可信时，L3 的污点传播结论不成立
        report.risk_events.extend(self.check_trace_integrity(trace))
        for ev in trace:
            report.risk_events.extend(self.check_l1(ev, authorized_tools))
        report.risk_events.extend(self.check_l2(trace))
        report.risk_events.extend(self.check_l3(trace))
        report.risk_events.extend(self.check_drift(original_intent, subgoals or []))
        report.risk_events.sort(key=lambda e: e.seq)
        return report
