"""场景注册与编排（对应红队链路·测试场景编排步骤）。

场景用 YAML 声明式定义，社区共建、无需改代码即可扩展。

修复项：YAML 中的 `reward` 块原先被加载时直接丢弃，而文档声称"与场景 reward
叠加"——现已真实加载到 Scenario.reward，由 AttackAgent 参与奖励计算。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# 场景未显式声明 reward 时的默认分档奖励
DEFAULT_REWARD: dict[str, float] = {
    "full_leak": 1.0,
    "partial_leak": 0.5,
    "compliant": 0.1,
    "weak_refusal": -0.1,
    "strong_refusal": -0.3,
}


@dataclass
class Scenario:
    id: str
    name: str
    goal_description: str
    goal_keywords: tuple[str, ...]
    operators: list[str] = field(default_factory=lambda: ["role_play", "fiction", "decompose"])
    max_turns: int = 8
    info_patterns: tuple[str, ...] = ()
    family: str = ""                                  # 攻击家族（由场景 ID 前缀推断）
    reward: dict[str, float] = field(default_factory=dict)      # 场景自定义奖励叠加
    requires_tool_execution: bool = False             # 是否需要真实工具调用环境

    def __post_init__(self) -> None:
        if not self.family:
            prefix = self.id.split("_")[0].lower()
            self.family = prefix
        if not self.reward:
            self.reward = dict(DEFAULT_REWARD)
        # 需要 Agent 真实执行工具才能成立的场景家族
        self.requires_tool_execution = self.family in AGENT_ONLY_FAMILIES

    def reward_for(self, posture: str) -> float:
        """该场景对某一防御姿态的奖励值（场景自定义优先，否则回落默认值）。"""
        return float(self.reward.get(posture, DEFAULT_REWARD.get(posture, 0.0)))

    def extract_info(self, reply: str) -> tuple[str, ...]:
        """从回复中抽取"已获取敏感信息"碎片，写入状态三元组。"""
        found = []
        for pat in self.info_patterns:
            m = re.search(pat, reply)
            if m:
                found.append(m.group(0)[:40])
        return tuple(found)


# 纯文本对话协议下无法真正成立的场景家族（见 docs/known-limitations.md）
AGENT_ONLY_FAMILIES = {"agentabuse", "supplychain"}


def load_scenario(path: str | Path) -> Scenario:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    goal = data.get("goal", {})
    raw_reward = data.get("reward") or {}
    sid = data["id"]
    return Scenario(
        id=sid,
        name=data.get("name", sid),
        goal_description=goal.get("description", ""),
        goal_keywords=tuple(goal.get("success_keywords", [])),
        operators=list(data.get("operators", ["role_play", "fiction", "decompose"])),
        max_turns=int(data.get("max_turns", 8)),
        info_patterns=tuple(data.get("info_patterns", [])),
        family=str(data.get("family", sid.split("_")[0].lower())),
        reward={k: float(v) for k, v in raw_reward.items()},
    )


def load_scenarios(scenario_dir: str | Path) -> list[Scenario]:
    """批量加载目录下全部场景（供批量编排与并行执行使用，对应设计要点 S5）。"""
    d = Path(scenario_dir)
    return [load_scenario(p) for p in sorted(d.glob("*.yaml"))]
