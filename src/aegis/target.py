"""目标模型适配层：任何 OpenAI 兼容 API / 本地模型均可接入。

合规设计：TargetProfile 要求提供 authorization_ref（授权书编号/路径）。
**措辞修正**：该校验只能确认"调用方填写了凭证字段"，无法核验凭证真伪，
文档中不得表述为"强制授权"——真实授权由流程与合同保证，代码只做提醒。

修复项（原实现只有 sleep 限速）：
1. 增加失败重试（指数退避）与连续失败熔断，避免单点抖动导致整轮评测作废；
2. 网络/HTTP 异常统一包装为 TargetCallError，不再把原始异常抛给上层主循环；
3. 支持从环境变量读取 API Key，避免 `--api-key` 明文留在 shell 历史中。
"""

from __future__ import annotations

import os
import time
import warnings
from dataclasses import dataclass
from typing import Protocol

from .audit.net import is_internal_destination

DEFAULT_KEY_ENV = "AEGIS_API_KEY"


class TargetCallError(RuntimeError):
    """目标调用失败（网络/HTTP/协议异常的统一包装）。"""


class TargetCircuitOpen(RuntimeError):
    """熔断器已打开：连续失败次数超过阈值，停止继续调用目标。"""


class TargetModel(Protocol):
    """目标模型协议：输入一段对话历史，返回一轮回复。"""

    def reply(self, messages: list[dict[str, str]]) -> str: ...


@dataclass
class TargetProfile:
    name: str
    authorization_ref: str  # 授权书编号或扫描件路径

    def check_authorized(self) -> None:
        if not self.authorization_ref:
            raise PermissionError(
                "缺少授权凭证（authorization_ref）。鉴安平台仅对获得书面授权的目标执行评测；"
                "注意：本校验仅检查凭证字段是否填写，不核验凭证真伪。"
            )


class OpenAICompatibleTarget:
    """OpenAI 兼容接口的目标模型（QPS 限速 + 失败重试 + 连续失败熔断）。"""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        model: str = "",
        profile: TargetProfile | None = None,
        qps: float = 1.0,
        timeout: float = 60.0,
        max_retries: int = 2,
        circuit_threshold: int = 5,
        circuit_reset_after: float = 60.0,
    ):
        profile = profile or TargetProfile(name=model or "target", authorization_ref="")
        profile.check_authorized()
        # 优先使用环境变量，避免 API Key 明文出现在命令行历史中
        self.api_key = api_key or os.environ.get(DEFAULT_KEY_ENV, "")
        if not self.api_key:
            raise ValueError(
                f"缺少 API Key：请设置环境变量 {DEFAULT_KEY_ENV}，或显式传入 api_key。"
            )
        self.base_url = base_url.rstrip("/")
        self._enforce_transport_security(self.base_url)
        self.model = model
        self.min_interval = 1.0 / max(qps, 0.01)
        self.timeout = timeout
        self.max_retries = max_retries
        self.circuit_threshold = circuit_threshold
        self.circuit_reset_after = circuit_reset_after
        self._last_call = 0.0
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self.calls = 0

    @staticmethod
    def _enforce_transport_security(base_url: str) -> None:
        """传输安全约束（H1）：禁止以明文 HTTP 向外部地址发送 API Key。

        OpenAI 兼容接口以 Bearer Token 鉴权，明文 HTTP 会让凭证在链路上可被窃听。
        内部地址（localhost / 127.0.0.1 / 私网 / .local 等）放行——
        本地 vLLM、Ollama 等常见部署就是明文 HTTP，强制 HTTPS 会直接不可用；
        但复用 audit.net 的判定而非 startswith，避免 localhost.evil.com 之类的绕过。
        """
        if not base_url.lower().startswith("http://"):
            return
        if is_internal_destination(base_url):
            warnings.warn(
                f"正在以明文 HTTP 连接内部地址 {base_url}；仅限本地测试，"
                "生产环境请改用 HTTPS。",
                RuntimeWarning,
                stacklevel=3,
            )
            return
        raise ValueError(
            f"拒绝以明文 HTTP 向外部地址发送 API Key：{base_url}。"
            "请改用 HTTPS；若确为本地/内网服务，请确认其主机属于内部地址范围。"
        )

    def _check_circuit(self) -> None:
        if self._consecutive_failures < self.circuit_threshold:
            return
        if time.time() - self._opened_at >= self.circuit_reset_after:
            # 冷却结束进入半开；必须同时清空 _opened_at，否则下次熔断时
            # 因 _opened_at 非零而不再更新，判定条件永久成立，熔断器形同失效（M1）
            self._consecutive_failures = 0
            self._opened_at = 0.0
            return
        raise TargetCircuitOpen(
            f"连续失败 {self._consecutive_failures} 次，熔断中；"
            f"{self.circuit_reset_after:.0f}s 后自动半开重试"
        )

    def _throttle(self) -> None:
        wait = self.min_interval - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)

    def reply(self, messages: list[dict[str, str]]) -> str:
        import httpx  # 延迟导入，保持核心零重依赖

        self._check_circuit()
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                resp = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "messages": messages, "temperature": 0.7},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                self._last_call = time.time()
                self.calls += 1
                # 成功即完全复位：连续失败计数与熔断时间戳必须一起清零，
                # 否则 _opened_at 残留会让后续熔断无法重新计时（M1）
                self._consecutive_failures = 0
                self._opened_at = 0.0
                return resp.json()["choices"][0]["message"]["content"]
            except Exception as exc:  # 网络/HTTP/解析异常统一处理
                last_err = exc
                self._last_call = time.time()
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.circuit_threshold and not self._opened_at:
                    self._opened_at = time.time()
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 8))  # 指数退避
        raise TargetCallError(f"目标调用失败（已重试 {self.max_retries} 次）：{last_err}")
