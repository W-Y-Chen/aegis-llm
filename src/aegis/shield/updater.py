"""对抗自适应更新（对应防护链路·S5 步骤）。

收集在线运行中的漏判/误判样本，持久化为 JSONL 反馈集，
并从中提议新的候选指令模式，供原型簇扩参评审。

**MVP 边界（对外表述须严格照此）**

- 已完成：样本收集（`record`）、统计（`summarize`）、候选模式提议（`propose_patterns`）；
- **未完成**：无需人工介入的自动在线更新。候选模式一律带 `status="pending_human_review"`，
  必须经人工评审通过后，由 `HeuristicInjectionDetector.load_proposed_patterns()` 显式装载。
  「对比学习训练的语义编码器 + 原型簇自动在线更新」属 V2。

早期版本只有前两步且**全仓无调用点**，等于 S5 只画了半条链路（编号 M13）。
本模块现在提供完整的、可运行的 `record → summarize → propose_patterns → 装载` 通路。
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

# 簇归属建议的轻量路由线索（仅供人工评审参考，不做自动决策）
_CLUSTER_HINTS: dict[str, tuple[str, ...]] = {
    "override": ("忽略", "作废", "别管", "不算", "无视", "ignore", "disregard",
                 "forget", "override", "無視", "olvida", "oubliez"),
    "role_hijack": ("模式", "扮演", "角色", "限制", "规矩", "约束", "DAN",
                    "developer mode", "jailbreak", "unrestricted"),
    "prompt_leak": ("提示词", "设定", "指令", "prompt", "reveal", "泄露", "复述", "输出"),
    "encoding_smuggle": ("base64", "解码", "hex", "rot13", "\\x", "摩斯"),
    "multilingual_mix": ("instructions", "instrucciones", "指示", "instrucciones"),
}


class PrototypeUpdater:
    """漏判/误判样本收集器 + 候选原型提议器。"""

    def __init__(self, feedback_path: str | Path = ".evidence/shield_feedback.jsonl"):
        self.path = Path(feedback_path)

    def record(self, text: str, label: str, verdict_action: str, note: str = "") -> None:
        """label: false_negative(漏判) / false_positive(误判)。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.time(),
            "label": label,
            "verdict": verdict_action,
            "text_excerpt": text[:200],
            "note": note,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _iter_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # 并发追加可能留下半行，跳过即可
        return entries

    def summarize(self, top_k: int = 10) -> dict:
        """统计反馈集：漏判/误判量与高频片段（供原型簇扩参评审）。"""
        entries = self._iter_entries()
        fn = fp = 0
        missed: Counter = Counter()
        for entry in entries:
            if entry.get("label") == "false_negative":
                fn += 1
                missed[entry.get("text_excerpt", "")[:40]] += 1
            else:
                fp += 1
        return {
            "total": fn + fp,
            "false_negative": fn,
            "false_positive": fp,
            "top_missed": missed.most_common(top_k),
        }

    def propose_patterns(
        self,
        top_k: int = 10,
        min_hits: int = 2,
        fragment_len: int = 12,
    ) -> list[dict[str, Any]]:
        """从高频漏判片段提议候选模式。

        返回的建议一律为 `pending_human_review`：
        由高频片段转义出的正则只是**起点**，其泛化能力与误命中风险必须由人确认。
        这是 MVP 有意保留的人工环节——自动在线更新属 V2。
        """
        grouped: dict[str, dict[str, Any]] = {}
        for entry in self._iter_entries():
            if entry.get("label") != "false_negative":
                continue
            frag = (entry.get("text_excerpt") or "").strip()[:fragment_len]
            if len(frag) < 4:
                continue
            slot = grouped.setdefault(frag, {"count": 0, "samples": [], "verdicts": set()})
            slot["count"] += 1
            slot["verdicts"].add(entry.get("verdict", ""))
            if len(slot["samples"]) < 3:
                slot["samples"].append((entry.get("text_excerpt") or "")[:80])

        ranked = sorted(grouped.items(), key=lambda kv: kv[1]["count"], reverse=True)
        proposals: list[dict[str, Any]] = []
        for frag, info in ranked[:top_k]:
            if info["count"] < min_hits:
                continue
            proposals.append({
                "pattern": re.escape(frag),
                "literal": frag,
                "hit_count": info["count"],
                "observed_verdict": sorted(info["verdicts"]),
                "suggested_cluster": self._suggest_cluster(frag),
                "samples": info["samples"],
                "status": "pending_human_review",
            })
        return proposals

    @staticmethod
    def _suggest_cluster(fragment: str) -> str:
        """按关键词线索给出簇归属建议（候选为空时表示需人工归类）。"""
        low = fragment.lower()
        for cid, hints in _CLUSTER_HINTS.items():
            if any(h.lower() in low for h in hints):
                return cid
        return ""

    def export_patterns(self, out_path: str | Path, **kwargs) -> Path:
        """把候选模式导出为 JSON 文件，便于评审后回填。"""
        proposals = self.propose_patterns(**kwargs)
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(proposals, ensure_ascii=False, indent=2), encoding="utf-8")
        return out
