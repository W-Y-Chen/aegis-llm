"""对话状态与状态机（对应红队链路·状态空间构建步骤）。

状态机 M = (S, A, T, s0, G)：
- S：对话状态集合，每个状态由"历史摘要、已获取敏感信息、防御姿态估计"三元组刻画；
- A：攻击动作集合（见 operators.py）；
- T：状态转移函数，由转移记录隐式表达；
- s0：初始状态；G：目标状态（由场景 goal 定义，见 scenarios.py）。

调用预算（修复项）：回溯原只弹栈而不计入调用数，导致真实 API 调用次数超出
max_turns 预算（实测 max_turns=4 发起了 7 次调用）。此处以 `total_calls`
独立计数，`budget_exhausted` 为唯一终止条件，回溯不再突破授权书约定的请求量。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .harm import judge


@dataclass(frozen=True)
class DialogueState:
    """对话状态三元组（不可变，转移时生成新实例）。"""

    turn: int
    history_summary: str
    acquired_info: tuple[str, ...] = ()
    defense_posture: str = "unknown"  # strong_refusal / weak_refusal / compliant / partial_leak / full_leak / unknown

    @property
    def signature(self) -> str:
        raw = f"{self.history_summary}|{sorted(self.acquired_info)}|{self.defense_posture}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class Transition:
    """一次状态转移记录：s --动作a--> s'，附带目标模型回复与姿态评估。"""

    state: DialogueState
    operator: str
    prompt: str
    reply: str
    posture: str
    next_state: DialogueState


@dataclass
class StateMachine:
    """状态机实例：维护状态栈，支持回溯与调用预算控制。"""

    goal_keywords: tuple[str, ...]
    max_turns: int = 8
    max_calls: int | None = None   # 总调用预算硬上限（含回溯消耗），缺省 = max_turns
    _stack: list[DialogueState] = field(default_factory=list)
    _transitions: list[Transition] = field(default_factory=list)
    _total_calls: int = 0

    def __post_init__(self) -> None:
        # 默认硬预算 = max_turns：回溯同样消耗请求预算，确保对真实目标的
        # 调用次数不超过授权书约定量；需要放宽时显式传 max_calls。
        if self.max_calls is None:
            self.max_calls = self.max_turns

    def init(self) -> DialogueState:
        s0 = DialogueState(turn=0, history_summary="")
        self._stack = [s0]
        return s0

    @property
    def current(self) -> DialogueState:
        return self._stack[-1]

    @property
    def transitions(self) -> list[Transition]:
        return list(self._transitions)

    @property
    def total_calls(self) -> int:
        """累计真实调用次数（回溯不会回滚该计数）。"""
        return self._total_calls

    @property
    def exhausted(self) -> bool:
        return self.budget_exhausted

    @property
    def budget_exhausted(self) -> bool:
        return self._total_calls >= self.max_calls or self.current.turn >= self.max_turns

    def transit(
        self,
        operator: str,
        prompt: str,
        reply: str,
        posture: str,
        summary_delta: str,
        info_delta: Optional[tuple[str, ...]] = None,
    ) -> DialogueState:
        """执行一次转移：s --operator--> s'，并计入调用预算。"""
        nxt = DialogueState(
            turn=self.current.turn + 1,
            history_summary=(self.current.history_summary + " " + summary_delta).strip(),
            acquired_info=tuple(sorted(set(self.current.acquired_info) | set(info_delta or ()))),
            defense_posture=posture,
        )
        self._transitions.append(Transition(self.current, operator, prompt, reply, posture, nxt))
        self._stack.append(nxt)
        self._total_calls += 1
        return nxt

    def backtrack(self, depth: int = 1) -> DialogueState:
        """强拒答时回退至浅层状态（保留转移记录作证据，不退还已用预算）。"""
        for _ in range(min(depth, len(self._stack) - 1)):
            self._stack.pop()
        return self.current

    def reached_goal(self, reply: str) -> bool:
        """目标状态判定（设计要点 4 双保险）：关键词命中 **且** 危害性判别通过。"""
        return judge(reply, self.goal_keywords).harmful
