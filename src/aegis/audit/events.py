"""轨迹事件模型与采集 SDK（对应审计链路·S1 步骤，设计要点 7）。

每一轨迹事件以"感知—决策—调用—返回"四元组表示，
至少包括任务标识、调用序号、工具标识、调用参数的结构化摘要、
返回数据的敏感级别标签以及时间戳。
采集方式：SDK 嵌入（本模块）；代理网关/内核探针为部署侧扩展。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class DataLabel(IntEnum):
    """返回数据敏感级别标签（数值越大越敏感）。"""

    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2
    SECRET = 3

    @classmethod
    def parse(cls, s: str) -> "DataLabel":
        return cls[s.strip().upper()]


@dataclass(frozen=True)
class ToolCallEvent:
    """工具调用链轨迹事件（"感知—决策—调用—返回"四元组的结构化记录）。"""

    task_id: str
    seq: int                    # 调用序号（任务内单调递增）
    tool: str                   # 工具标识
    params_digest: str          # 调用参数的结构化摘要（哈希，脱敏）
    data_label: DataLabel       # 返回数据敏感级别标签
    ts: float
    params_keys: tuple[str, ...] = ()   # 参数名集合（供敏感资源指向检测）
    destination: str = ""               # 外发地址（若有，如 http 请求目标）
    refs_data_from: tuple[int, ...] = ()  # 本调用参数引用了哪些 seq 的返回数据（标签传播边）

    @staticmethod
    def digest_params(params: dict) -> str:
        """参数结构化摘要：规范化后取 SHA-256 短哈希，明文不落盘。"""
        raw = json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class TraceRecorder:
    """轨迹采集 SDK：嵌入智能体运行时，按调用序记录事件。

    用法::

        rec = TraceRecorder()
        rec.start_task("task-001", intent="整理会议纪要并发邮件")
        rec.record(tool="read_file", params={"path": "a.docx"}, data_label=DataLabel.INTERNAL)
    """

    def __init__(self) -> None:
        self.task_id: str = ""
        self.intent: str = ""
        self._seq = 0
        self.events: list[ToolCallEvent] = []
        self.subgoals: list[str] = []  # 智能体当前执行的子目标序列（供目标漂移检测）

    def start_task(self, task_id: str, intent: str = "") -> None:
        self.task_id, self.intent = task_id, intent
        self._seq = 0
        self.events = []
        self.subgoals = []

    def record(
        self,
        tool: str,
        params: dict | None = None,
        data_label: DataLabel = DataLabel.PUBLIC,
        destination: str = "",
        refs_data_from: tuple[int, ...] = (),
        subgoal: str = "",
    ) -> ToolCallEvent:
        params = params or {}
        self._seq += 1
        if subgoal:
            self.subgoals.append(subgoal)
        ev = ToolCallEvent(
            task_id=self.task_id,
            seq=self._seq,
            tool=tool,
            params_digest=ToolCallEvent.digest_params(params),
            data_label=data_label,
            ts=time.time(),
            params_keys=tuple(sorted(params.keys())),
            destination=destination,
            refs_data_from=refs_data_from,
        )
        self.events.append(ev)
        return ev

    def dump(self, out_path: str | Path) -> Path:
        """轨迹持久化（JSONL，脱敏：仅存参数摘要哈希）。"""
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for ev in self.events:
                f.write(json.dumps({
                    "task_id": ev.task_id, "seq": ev.seq, "tool": ev.tool,
                    "params_digest": ev.params_digest, "data_label": ev.data_label.name,
                    "ts": ev.ts, "params_keys": list(ev.params_keys),
                    "destination": ev.destination, "refs_data_from": list(ev.refs_data_from),
                }, ensure_ascii=False) + "\n")
        return out
