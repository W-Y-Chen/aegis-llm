"""行为基线建模（对应审计链路·S2 步骤，设计要点 2）。

以"任务意图—工具序列—数据流向"为特征，对同类任务的合法调用链
进行统计建模，形成行为基线库：
- 合法工具集合；
- 工具调用顺序约束（相邻工具对转移概率）；
- 参数取值域约束；
- 数据流向白名单（各类敏感级别数据允许流向的工具范围）。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .events import DataLabel, ToolCallEvent


@dataclass
class BehaviorBaseline:
    """行为基线库。"""

    allowed_tools: set[str] = field(default_factory=set)
    transition_prob: dict[tuple[str, str], float] = field(default_factory=dict)  # 相邻工具对转移概率
    tool_freq: dict[str, float] = field(default_factory=dict)
    param_domains: dict[str, dict[str, set]] = field(default_factory=dict)       # tool -> param -> 取值域
    flow_whitelist: dict[DataLabel, set[str]] = field(default_factory=dict)      # 敏感级别 -> 允许流向的工具集合
    sequences: list[tuple[str, ...]] = field(default_factory=list)               # 合法调用链序列（供编辑距离比对）

    def transition_probability(self, a: str, b: str) -> float:
        return self.transition_prob.get((a, b), 0.0)

    def allows_flow(self, label: DataLabel, tool: str) -> bool:
        """数据流向白名单校验：限定各类敏感级别数据允许流向的工具范围。

        最小授权原则：敏感级别（SENSITIVE/SECRET）无显式白名单条目时默认拒绝。
        """
        wl = self.flow_whitelist.get(label)
        if wl is None:
            return label < DataLabel.SENSITIVE
        return tool in wl


class BaselineBuilder:
    """从合法调用链样本统计构建行为基线（设计要点 2）。"""

    def __init__(self, min_tool_freq: float = 0.05, min_transition_prob: float = 0.05):
        self.min_tool_freq = min_tool_freq
        self.min_transition_prob = min_transition_prob

    def fit(self, traces: list[list[ToolCallEvent]]) -> BehaviorBaseline:
        tool_counter: Counter = Counter()
        pair_counter: Counter = Counter()
        param_values: dict[str, dict[str, set]] = {}
        flow: dict[DataLabel, set[str]] = {}
        total = max(len(traces), 1)

        for trace in traces:
            tools = [ev.tool for ev in trace]
            tool_counter.update(set(tools))  # 按任务计出现频次（文档频率）
            for a, b in zip(tools, tools[1:]):
                pair_counter[(a, b)] += 1
            for ev in trace:
                pd = param_values.setdefault(ev.tool, {})
                for k in ev.params_keys:
                    pd.setdefault(k, set()).add(ev.params_digest)  # 取值域以摘要去重
                flow.setdefault(ev.data_label, set()).add(ev.tool)

        tool_freq = {t: c / total for t, c in tool_counter.items()}
        allowed = {t for t, f in tool_freq.items() if f >= self.min_tool_freq}
        sequences = [tuple(ev.tool for ev in trace) for trace in traces]

        # 转移概率：P(b|a) = count(a,b) / count(a 作为前驱)
        out_counter: Counter = Counter()
        for (a, _), c in pair_counter.items():
            out_counter[a] += c
        transition_prob = {
            pair: c / out_counter[pair[0]]
            for pair, c in pair_counter.items()
            if c / out_counter[pair[0]] >= self.min_transition_prob
        }

        return BehaviorBaseline(
            allowed_tools=allowed,
            transition_prob=transition_prob,
            tool_freq=tool_freq,
            param_domains=param_values,
            flow_whitelist=flow,
            sequences=sequences,
        )
