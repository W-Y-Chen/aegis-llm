"""攻击链证据记录（对应红队链路·路径记录与证据生成步骤）。

脱敏策略（修复项）：原实现默认把回复明文前 160 字写进证据，而泄漏内容本身
往往就是敏感数据，报告页脚却宣称"仅存摘要与哈希"——文案与实现不符。
现改为三档显式策略：

- `Redaction.HASH_ONLY`：仅存回复哈希与长度，**不落任何回复文本**（推荐用于高危场景）；
- `Redaction.EXCERPT`：存前 N 字摘要（默认，明确KNOWN：摘要可能含泄漏片段，报告中据此标注）；
- `Redaction.FULL`：完整明文，需显式开启，用于自建靶场复现调试。

策略会写入证据文件的 `redaction` 字段，报告据此生成对应页脚，不再空口承诺。
另修复：文件名按微秒命名避免同秒覆盖；每步保留真实时间戳；记录 seed 便于复现。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from .state import StateMachine


class Redaction(str, Enum):
    HASH_ONLY = "hash_only"   # 仅哈希 + 长度
    EXCERPT = "excerpt"       # 截取摘要（默认，可能含泄漏片段）
    FULL = "full"             # 完整明文（显式开启）


@dataclass
class ChainStep:
    turn: int
    operator: str
    prompt_hash: str
    reply_excerpt: str
    posture: str
    ts: float
    reply_hash: str = ""
    reply_len: int = 0


@dataclass
class AttackChain:
    scenario_id: str
    success: bool
    turns_used: int
    steps: list[ChainStep] = field(default_factory=list)
    redaction: str = Redaction.EXCERPT.value
    seed: int | None = None
    created_at: float = field(default_factory=time.time)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=indent)


class EvidenceRecorder:
    """把状态机的转移记录固化为可复现的攻击链证据。"""

    def __init__(
        self,
        redaction: Redaction = Redaction.EXCERPT,
        excerpt_len: int = 160,
        keep_plaintext: bool = False,
    ):
        # 兼容旧参数：keep_plaintext=True 等价于 FULL
        if keep_plaintext:
            redaction = Redaction.FULL
        self.redaction = Redaction(redaction)
        self.excerpt_len = excerpt_len

    def _render_reply(self, text: str) -> tuple[str, str, int]:
        """按脱敏策略渲染回复：返回 (excerpt, 哈希, 长度)。"""
        rhash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        if self.redaction is Redaction.HASH_ONLY:
            return "", rhash, len(text)
        if self.redaction is Redaction.FULL:
            return text, rhash, len(text)
        return text[: self.excerpt_len], rhash, len(text)

    def record(
        self,
        scenario_id: str,
        sm: StateMachine,
        success: bool,
        seed: int | None = None,
    ) -> AttackChain:
        chain = AttackChain(
            scenario_id=scenario_id,
            success=success,
            turns_used=sm.current.turn,
            redaction=self.redaction.value,
            seed=seed,
        )
        for t in sm.transitions:
            excerpt, rhash, rlen = self._render_reply(t.reply)
            chain.steps.append(
                ChainStep(
                    turn=t.next_state.turn,
                    operator=t.operator,
                    prompt_hash=hashlib.sha256(t.prompt.encode("utf-8")).hexdigest()[:16],
                    reply_excerpt=excerpt,
                    posture=t.posture,
                    ts=time.time(),
                    reply_hash=rhash,
                    reply_len=rlen,
                )
            )
        return chain

    def save(self, chain: AttackChain, out_dir: str | Path = ".evidence") -> Path:
        """证据落盘：微秒级时间戳命名，避免同秒两次运行互相覆盖。"""
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        # L6：必须单次取值。分两次调用 time.time() 时，秒级部分与微秒部分可能
        # 落在不同的秒上（"跨秒"），文件名的时间戳会不自洽。
        now = time.time()
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now)) + f"-{int(now * 1_000_000) % 1_000_000:06d}"
        path = out / f"{chain.scenario_id}_{stamp}.json"
        path.write_text(chain.to_json(), encoding="utf-8")
        return path
