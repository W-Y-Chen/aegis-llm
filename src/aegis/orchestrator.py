"""批量编排与并行执行（对应红队链路·S5 步骤）。

原缺口：设计要点 S5 声明"对多个测试场景进行批量编排与并行执行"，
此前代码中完全没有编排层——只能逐场景手工调用 `AttackAgent.run`。

本模块提供：
- 场景批量加载与筛选（自动跳过需要真实工具执行环境才成立的场景，见
  `scenarios.AGENT_ONLY_FAMILIES` 与 docs/known-limitations.md）；
- 线程池并行执行，每个子任务独立 AttackAgent 与确定性种子，结果可复现；
- 共享目标的调用串行化开关，避免并行打爆目标 QPS 或超出授权请求量；
- 汇总输出攻击链证据与统计，直接喂给 report 生成体检报告。
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Iterable

from .agent import AttackAgent
from .evidence import AttackChain, EvidenceRecorder, Redaction
from .report.model import family_of
from .scenarios import Scenario, load_scenarios
from .state import StateMachine  # noqa: F401  (保持导入兼容)
from .target import TargetModel

# 批次元数据文件名。ReportGenerator 会在证据目录中查找它，用于标注"未覆盖"要求域（M8）。
_META_FILENAME = "batch_meta.json"


class _CountingTarget:
    """对目标调用统一计数，并按需串行化。

    M9 修复：早期实现用 `getattr(proxy, "calls", 0)` 取计数，而 proxy 只在
    `serialize_calls=True` 时才存在；关闭串行化时 `_target_proxy` 就是裸目标，
    没有 `calls` 属性 → `total_calls` 恒为 0（实测目标真实调用 6 次、报告 0 次）。
    现在无论是否串行化都包这一层，计数由编排器自己持有，不依赖目标的私有属性。
    """

    def __init__(self, inner: TargetModel, lock: Lock | None = None) -> None:
        self._inner = inner
        self._lock = lock
        self.calls = 0

    def reply(self, messages: list[dict[str, str]]) -> str:
        if self._lock is not None:
            with self._lock:
                self.calls += 1
                return self._inner.reply(messages)
        self.calls += 1
        return self._inner.reply(messages)


@dataclass
class BatchResult:
    """一次批量评测的汇总结果。"""

    chains: list[AttackChain] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    workers: int = 1
    total_calls: int = 0

    @property
    def succeeded(self) -> list[AttackChain]:
        return [c for c in self.chains if c.success]

    @property
    def skipped_families(self) -> set[str]:
        """被跳过场景所属的攻击家族（供报告把对应要求域标注为"未覆盖"，M8）。"""
        return {family_of(sid) for sid in self.skipped}

    def save_meta(self, out_dir: str | Path = ".evidence") -> Path:
        """落盘批次元数据（含被跳过的家族），供报告生成时标注"未覆盖"。

        之所以落盘而不是只留在内存：调用方往往是在**另一次进程**里生成报告的
        （典型是 CLI `aegis report`）。若要求调用方手动传递 skipped_families，
        一旦遗漏，报告就会把"根本没测"写成"已测未检出"（M8）。
        落盘后 ReportGenerator 会自动读取，无需调用方显式传参。
        """
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / _META_FILENAME
        path.write_text(json.dumps({
            "skipped_scenarios": self.skipped,
            "skipped_families": sorted(self.skipped_families),
            "elapsed": self.elapsed,
            "workers": self.workers,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @property
    def attack_success_rate(self) -> float:
        return len(self.succeeded) / len(self.chains) if self.chains else 0.0

    def summary(self) -> str:
        return (
            f"场景 {len(self.chains)} 个（跳过 {len(self.skipped)}），"
            f"检出 {len(self.succeeded)} 条可利用路径，攻击成功率 {self.attack_success_rate:.0%}，"
            f"耗时 {self.elapsed:.1f}s，目标调用 {self.total_calls} 次，并行度 {self.workers}"
        )


class BatchOrchestrator:
    """批量场景编排器（S5）。"""

    def __init__(
        self,
        target: TargetModel,
        workers: int = 4,
        seed: int | None = None,
        redaction: Redaction = Redaction.EXCERPT,
        qtable_path: str | Path = ".evidence/qtable.json",
        serialize_calls: bool = True,
    ) -> None:
        self.target = target
        self.workers = max(1, workers)
        self.seed = seed
        self.redaction = redaction
        self.qtable_path = qtable_path
        self.serialize_calls = serialize_calls
        self._lock = Lock()
        # 无论是否串行化都包一层，保证调用量始终由编排器自己统计（M9）
        self._target_proxy = _CountingTarget(target, self._lock if serialize_calls else None)

    def _run_one(self, scenario: Scenario, idx: int) -> AttackChain:
        # Q 表按场景隔离存放，避免并行任务争用同一个文件
        qpath = Path(self.qtable_path)
        per_scenario = qpath.with_name(f"{qpath.stem}_{scenario.id}{qpath.suffix}")
        agent = AttackAgent(
            target=self._target_proxy,
            recorder=EvidenceRecorder(redaction=self.redaction),
            qtable_path=per_scenario,
            seed=None if self.seed is None else self.seed + idx,
        )
        return agent.run(scenario)

    def run(
        self,
        scenarios: Iterable[Scenario] | None = None,
        scenario_dir: str | Path = "scenarios",
        include_tool_scenarios: bool = False,
    ) -> BatchResult:
        """执行批量评测。默认跳过需要真实工具执行环境才成立的场景家族。"""
        items: list[Scenario] = list(scenarios) if scenarios is not None else load_scenarios(scenario_dir)
        result = BatchResult(workers=self.workers)
        usable: list[Scenario] = []
        for sc in items:
            if sc.requires_tool_execution and not include_tool_scenarios:
                result.skipped.append(sc.id)
            else:
                usable.append(sc)

        t0 = time.time()
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._run_one, sc, i): sc for i, sc in enumerate(usable)}
            for fut in as_completed(futures):
                result.chains.append(fut.result())
        result.elapsed = time.time() - t0
        result.chains.sort(key=lambda c: c.scenario_id)
        result.total_calls = self._target_proxy.calls
        return result
