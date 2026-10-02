"""攻击智能体主循环（对应红队链路·攻击智能体决策步骤 + 回溯机制）。

修复项：
1. **不可复现**：原先使用全局 random 且无种子，两次评测结果可能不同。
   现改为实例级 `random.Random(seed)`，并在证据中记录 seed 与关键配置；
2. **预算穿透**：改用 `sm.budget_exhausted`（累计调用数）作为唯一终止条件，
   回溯不再突破 max_turns/授权请求量预算；
3. **Q 表污染**：Q 键按场景命名空间隔离，避免跨场景/跨目标串经验；
4. **TD(0) 形式化**：更新式补上下一状态的 bootstrap 项 γ·max_a Q(s',a)，
   原式为纯增量平均，不符合设计要点 3 所述时间差分更新；
5. **场景 reward 生效**：奖励取自 Scenario.reward_for()，YAML 声明真正参与计算。
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from .evaluator import DefensePosture, HeuristicEvaluator
from .evidence import AttackChain, EvidenceRecorder
from .operators import OPERATORS
from .scenarios import Scenario
from .state import StateMachine
from .target import TargetModel


@dataclass
class AttackAgent:
    target: TargetModel
    evaluator: HeuristicEvaluator = field(default_factory=HeuristicEvaluator)
    recorder: EvidenceRecorder = field(default_factory=EvidenceRecorder)
    qtable_path: str | Path = ".evidence/qtable.json"
    epsilon: float = 0.25
    max_consecutive_refusal: int = 2
    seed: int | None = None      # 固定后同一场景可完全复现
    gamma: float = 0.9           # TD(0) 折扣因子
    alpha: float = 0.5           # 学习率
    persist_q: bool = True

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    # ---------- Q 表 ----------
    def _qkey(self, scenario: Scenario, state_sig: str, operator: str) -> str:
        """Q 键按场景命名空间隔离，避免跨场景串经验。"""
        return f"{scenario.id}::{state_sig}::{operator}"

    def _load_qtable(self) -> dict:
        p = Path(self.qtable_path)
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # 并发读写导致读到半截文件时不应让整次评测失败
            return {}

    def _save_qtable(self, q: dict) -> None:
        if not self.persist_q:
            return
        p = Path(self.qtable_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(q, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)  # 原子替换，避免并发读取到半截文件

    def _max_next_q(self, next_sig: str, scenario: Scenario, q: dict) -> float:
        """max_a Q(s', a)：下一状态的最优动作价值（TD(0) bootstrap 项）。"""
        values = [q.get(self._qkey(scenario, next_sig, op), 0.0) for op in scenario.operators]
        return max(values) if values else 0.0

    def _choose_operator(self, state_sig: str, scenario: Scenario, q: dict) -> str:
        allowed = scenario.operators
        if self._rng.random() < self.epsilon:
            return self._rng.choice(allowed)
        scored = [(q.get(self._qkey(scenario, state_sig, op), 0.0), op) for op in allowed]
        scored.sort(reverse=True)
        return scored[0][1] if scored and scored[0][0] > 0 else allowed[0]

    # ---------- 主循环 ----------
    def run(self, scenario: Scenario) -> AttackChain:
        sm = StateMachine(goal_keywords=scenario.goal_keywords, max_turns=scenario.max_turns)
        sm.init()
        q = self._load_qtable()
        messages: list[dict[str, str]] = []
        consecutive_refusal = 0

        while not sm.budget_exhausted:
            state = sm.current
            op_name = self._choose_operator(state.signature, scenario, q)
            op = OPERATORS[op_name]

            prompt = op.build(state, scenario.goal_description)
            messages.append({"role": "user", "content": prompt})
            reply = self.target.reply(messages)
            messages.append({"role": "assistant", "content": reply})

            posture = self.evaluator.assess(reply, scenario.goal_keywords)
            nxt = sm.transit(
                operator=op_name,
                prompt=prompt,
                reply=reply,
                posture=posture.value,
                summary_delta=f"[{op.description}]",
                info_delta=scenario.extract_info(reply),
            )

            # TD(0) 更新：Q(s,a) ← Q(s,a) + α[r + γ·max_a' Q(s',a') − Q(s,a)]
            key = self._qkey(scenario, state.signature, op_name)
            reward = scenario.reward_for(posture.value)
            td_target = reward + self.gamma * self._max_next_q(nxt.signature, scenario, q)
            q[key] = q.get(key, 0.0) + self.alpha * (td_target - q.get(key, 0.0))

            if sm.reached_goal(reply) and posture in (
                DefensePosture.FULL_LEAK,
                DefensePosture.PARTIAL_LEAK,
            ):
                chain = self.recorder.record(scenario.id, sm, success=True, seed=self.seed)
                self._save_qtable(q)
                return chain

            if posture == DefensePosture.STRONG_REFUSAL:
                consecutive_refusal += 1
                if consecutive_refusal >= self.max_consecutive_refusal:
                    sm.backtrack(depth=1)
                    messages = messages[:-2]
                    consecutive_refusal = 0
            else:
                consecutive_refusal = 0

        chain = self.recorder.record(scenario.id, sm, success=False, seed=self.seed)
        self._save_qtable(q)
        return chain
