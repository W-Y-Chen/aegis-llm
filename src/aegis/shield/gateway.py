"""防护网关（对应防护链路·S4 步骤的落地形态）。

原缺口：此前 shield 只有一个"判定函数"，S4 输出了 sanitize（清洗）决策
却没有任何清洗实现，也不存在可真正串接在业务与模型之间的网关代码——
"保镖/阻断网关"名不副实。

本模块提供可内联的网关：
- `sanitize()`：剥离输入中的指令性语句，仅保留数据部分（清洗决策的落地实现）；
- `ShieldGateway.process()`：allow → 原样放行给模型；sanitize → 清洗后再放行；
  block → 直接返回安全回复，**不调用模型**（实现"阻断"而非"提示"）。

`sanitize()` 的实现已移至 `sanitizer.py` 并在此 re-export：判定侧（detector）需要在
决定是否降级为清洗时预演清洗效果，两侧必须共用同一份实现，否则会出现
「检测器判定的高危内容清洗器删不掉」的绕过路径（编号 H3）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .context import DialogueContext
from .detector import Action, HeuristicInjectionDetector, UnsanitizablePolicy, Verdict
from .hierarchy import HierarchyChecker, TrustLevel
from .sanitizer import (  # noqa: F401  (兼容性 re-export)
    _INSTRUCTIVE_SENTENCE,
    _SENT_SPLIT,
    sanitize,
    wrap_untrusted,
)

__all__ = ["GatewayResult", "ShieldGateway", "sanitize"]


@dataclass
class GatewayResult:
    """网关处理结果。"""

    action: Action
    output: str               # 最终输出（模型回复，或阻断时的安全回复）
    verdict: Verdict
    removed: tuple = ()       # 清洗时被剥离的指令性片段
    model_called: bool = True
    input_text: str = ""      # 实际交给模型的文本（清洗后的结果，便于审计核对）
    # 以下两项仅在"判定高危但清洗不掉"时非空，供审计与下游决策使用
    residual_risk: float = 0.0   # 清洗后仍残留的指令意图风险
    untrusted_wrapped: bool = False  # 是否已加不可信标记（剥夺指令权）后放行


class ShieldGateway:
    """串接于业务应用与语言模型之间的防护网关。"""

    def __init__(
        self,
        detector: HeuristicInjectionDetector | None = None,
        model_call: Callable[[list[dict[str, str]]], str] | None = None,
        block_reply: str = "该请求包含提示注入特征，已被安全网关阻断。",
        unsanitizable_policy: UnsanitizablePolicy | None = None,
        mark_untrusted: bool = True,
    ) -> None:
        # 策略既可直接传给网关，也可由传入的 detector 自带；显式入参优先。
        self.detector = detector or HeuristicInjectionDetector(
            unsanitizable_policy=unsanitizable_policy or UnsanitizablePolicy.BLOCK)
        if unsanitizable_policy is not None and detector is not None:
            self.detector.unsanitizable_policy = UnsanitizablePolicy(unsanitizable_policy)
        self.model_call = model_call
        self.block_reply = block_reply
        # 关闭后，SANITIZE_MARKED 策略下将裸放行残余风险内容——仅建议用于
        # 下游另有隔离机制（如结构化分隔/沙箱）的场景，一般不应关闭。
        self.mark_untrusted = mark_untrusted

    def process(
        self,
        text: str,
        context: DialogueContext | None = None,
        trust_level: TrustLevel = TrustLevel.USER,
        source: str = "",
        messages: list[dict[str, str]] | None = None,
    ) -> GatewayResult:
        verdict = self.detector.detect(text, context=context, trust_level=trust_level, source=source)

        # 残余风险与"是否删不掉"的标记对两条路径都成立，必须一并返回：
        # 阻断路径若把 residual_risk 留成默认值 0.0，审计侧会误读为"无残余风险"，
        # 而实际上残余风险正是本次阻断的理由（其值只存在于 verdict 中会造成两处口径打架）。
        residual = float(getattr(verdict, "residual_risk", 0.0) or 0.0)
        unsanitizable = bool(getattr(verdict, "unsanitizable", False))

        if verdict.action is Action.BLOCK:
            return GatewayResult(Action.BLOCK, self.block_reply, verdict, (), model_called=False,
                                 input_text="", residual_risk=residual)

        wrapped = False

        if verdict.action is Action.SANITIZE:
            cleaned, removed = sanitize(text)
            if not cleaned:  # 清洗后无有效内容，等价于阻断
                return GatewayResult(Action.BLOCK, self.block_reply, verdict, tuple(removed),
                                     model_called=False, input_text="",
                                     residual_risk=residual)
            text = cleaned
            removed_out = tuple(removed)
            # 清洗未能消除风险（判定高危却删不掉）：按策略加不可信标记，
            # 剥夺指令权后放行。绝不可裸放行——那等同于把注入原样交给模型。
            if unsanitizable and self.mark_untrusted:
                text = wrap_untrusted(text, source=source or "外部数据")
                wrapped = True
        else:
            removed_out = ()

        if self.model_call is None:
            return GatewayResult(verdict.action, text, verdict, removed_out,
                                 model_called=False, input_text=text,
                                 residual_risk=residual, untrusted_wrapped=wrapped)

        msgs = list(messages or []) + [{"role": "user", "content": text}]
        return GatewayResult(verdict.action, self.model_call(msgs), verdict, removed_out,
                             model_called=True, input_text=text,
                             residual_risk=residual, untrusted_wrapped=wrapped)
