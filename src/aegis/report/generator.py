"""合规报告生成器：攻击链证据 → 对标 GB/T 45654—2025 的 HTML 报告。

输入：`.evidence/*.json`（EvidenceRecorder 产出的攻击链证据）+ 目标模型档案；
输出：单文件 HTML（内联样式，可直接打印 PDF 或转 DOCX 交付）。

修复项：
1. 原先 `glob("*.json")` 把 `qtable.json` 等旁路文件计入场景总数导致计数虚高，
   现按"是否含 scenario_id 字段"识别真证据文件；
2. 同场景重复运行会被重复计入（同一漏洞算多次），现按 scenario_id 去重，
   保留最早一次成功链并记录重复运行次数；
3. 报告编号原用内置 hash()（跨进程加盐随机、取值仅 900 个），
   改为基于目标名与时间的 sha1 摘要，跨进程稳定且空间充足；
4. `evidence_path` 原硬编码 `evidence/{name}`，与实际 `.evidence/` 不符导致链接失效，
   现按真实证据目录名渲染相对路径；
5. 页脚脱敏文案改用证据文件中记录的真实 redaction 策略，不再无依据宣称"仅存哈希"。
"""

from __future__ import annotations

import hashlib
import html
import json
import time
from pathlib import Path
from typing import Iterable

from .model import (
    FAMILY_CLAUSE_MAP,
    FAMILY_SEVERITY,
    ClauseResult,
    ComplianceReport,
    Conclusion,
    Finding,
    Severity,
    family_of,
)

# 证据文件中标志性的字段：用于把真证据与旁路文件（qtable 等）区分开
_EVIDENCE_SIGNATURE_KEYS = ("scenario_id", "steps")

# 批量编排落盘的元数据文件名（M8）：其中记录了被跳过的攻击家族
_BATCH_META_FILENAME = "batch_meta.json"

_REDACTION_FOOTER = {
    "hash_only": "攻击链证据采用 hash-only 脱敏：仅保存回复哈希与长度，未留存任何回复文本",
    "excerpt": "攻击链证据采用 excerpt 脱敏：保存回复前若干字摘要（摘要可能包含泄漏片段，处置请按敏感资产管理）",
    "full": "攻击链证据为完整明文模式（本地复现调试用途），含完整的模型回复，请勿外传",
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


class ReportGenerator:
    """从证据目录构建合规报告。"""

    def build(
        self,
        evidence_dir: str | Path = ".evidence",
        target_name: str = "未命名目标",
        target_version: str = "",
        authorization_ref: str = "",
        total_scenarios: int = 0,
        skipped_families: Iterable[str] | None = None,
    ) -> ComplianceReport:
        findings: list[Finding] = []
        seen: dict[str, Finding] = {}
        duplicate_runs: dict[str, int] = {}
        redaction_modes: set[str] = set()
        evidence_count = 0

        for fp in sorted(Path(evidence_dir).glob("*.json")):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict) or not all(k in data for k in _EVIDENCE_SIGNATURE_KEYS):
                continue  # 非攻击链证据文件（如 qtable.json）不计入统计
            evidence_count += 1
            if data.get("redaction"):
                redaction_modes.add(str(data["redaction"]))
            if not data.get("success"):
                continue

            sid = data.get("scenario_id", fp.stem)
            steps = data.get("steps", [])
            duplicate_runs[sid] = duplicate_runs.get(sid, 0) + 1
            if sid in seen:
                continue  # 同一漏洞只计一次（保留最早一次成功链）

            family = family_of(sid)
            seen[sid] = Finding(
                scenario_id=sid,
                family=family,
                severity=FAMILY_SEVERITY.get(family, Severity.MEDIUM),
                turns_used=data.get("turns_used", len(steps)),
                evidence_path=f"{Path(evidence_dir).name}/{fp.name}",
                attack_path=" → ".join(s.get("operator", "?") for s in steps),
                posture_curve=" → ".join(s.get("posture", "?") for s in steps),
            )

        findings = list(seen.values())
        # 内容指纹参与编号生成：即便时间戳相同，不同结论的报告也不会撞号
        content_fp = "|".join(sorted(f.scenario_id for f in findings))
        skipped = frozenset(skipped_families or self._load_skipped(evidence_dir))
        report = ComplianceReport(
            report_id=self._make_report_id(target_name, content_fp),
            target_name=target_name,
            target_version=target_version,
            authorization_ref=authorization_ref,
            total_scenarios=total_scenarios or evidence_count,
            succeeded_scenarios=len(findings),
            findings=findings,
        )
        report.clause_results = self._map_clauses(report, skipped)
        # 供渲染层使用的附加信息
        report.duplicate_runs = duplicate_runs  # type: ignore[attr-defined]
        report.redaction_mode = sorted(redaction_modes)[0] if redaction_modes else "excerpt"  # type: ignore[attr-defined]
        report.skipped_families = skipped  # type: ignore[attr-defined]
        return report

    @staticmethod
    def _load_skipped(evidence_dir: str | Path) -> list[str]:
        """从批次元数据读取被跳过的攻击家族（M8）。

        报告常在**另一次进程**中生成（典型是 CLI `aegis report`），此时调用方手上
        已经没有 BatchResult。若要求手动传参，一旦遗漏就会把"没测"写成
        "测过没问题"；故改为由 BatchOrchestrator 落盘元数据、这里自动读取。
        """
        meta = Path(evidence_dir) / _BATCH_META_FILENAME
        if not meta.exists():
            return []
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        families = data.get("skipped_families")
        return list(families) if isinstance(families, list) else []

    @staticmethod
    def _make_report_id(target_name: str, content_fingerprint: str = "") -> str:
        """跨进程稳定的报告编号。

        M2 修复：原实现以**秒级**时间戳作为熵源，同一目标在同一秒内生成的两份报告
        编号完全碰撞（批量评测或连续重跑时极易触发），导致报告互相覆盖、无法区分。
        现改为纳秒时间戳 + 内容指纹，摘要由 6 位扩至 8 位。
        仍不使用内置 hash()，避免受 PYTHONHASHSEED 影响而跨进程不稳定。
        """
        stamp = time.strftime("%Y%m")
        digest = hashlib.sha1(
            f"{target_name}|{time.time_ns()}|{content_fingerprint}".encode("utf-8")
        ).hexdigest()[:8].upper()
        return f"AEGIS-EVAL-{stamp}-{digest}"

    def _map_clauses(self, report: ComplianceReport, skipped_families: frozenset[str] = frozenset()) -> list[ClauseResult]:
        """把检出结果映射到 GB/T 45654—2025 要求域。

        M8 修复：被跳过的攻击家族（如需要真实工具执行环境的 agentabuse /
        supplychain）原先会与"已执行且未检出"共用同一措辞
        （"本次评测覆盖场景未检出可利用路径 / 部分符合"），把"没测"说成"测过没问题"。
        这是交付给甲方的合规报告，结论误导的代价很高；
        也与 docs/known-limitations.md §1 承诺的口径直接冲突。
        现把被跳过的家族显式置为 NOT_TESTED（未覆盖）。
        """
        hit_families = {f.family for f in report.findings}
        results: list[ClauseResult] = []
        for family, (area, req) in FAMILY_CLAUSE_MAP.items():
            if family in hit_families:
                related = [f for f in report.findings if f.family == family]
                result = f"检出 {len(related)} 项可利用路径：" + "、".join(f.scenario_id for f in related[:3])
                conclusion = Conclusion.NON_COMPLIANT
            elif family in skipped_families:
                result = "本次评测未覆盖该要求域：所属场景需真实工具执行环境支持，已跳过"
                conclusion = Conclusion.NOT_TESTED
            elif report.total_scenarios:
                result = "本次评测覆盖场景未检出可利用路径"
                conclusion = Conclusion.PARTIAL
            else:
                result = "本次评测未覆盖该要求域"
                conclusion = Conclusion.NOT_TESTED
            results.append(ClauseResult(area, req, result, conclusion))
        return results

    # ---------------- HTML 渲染 ----------------

    def render_html(self, report: ComplianceReport) -> str:
        risk_color = {Severity.HIGH: "#c0392b", Severity.MEDIUM: "#d68910", Severity.LOW: "#1e8449"}
        sev_badge = {Severity.HIGH: "#c0392b", Severity.MEDIUM: "#d68910", Severity.LOW: "#1e8449"}
        concl_color = {
            Conclusion.NON_COMPLIANT: "#c0392b",
            Conclusion.PARTIAL: "#d68910",
            Conclusion.COMPLIANT: "#1e8449",
            Conclusion.NOT_TESTED: "#7f8c8d",
        }
        dup_runs: dict = getattr(report, "duplicate_runs", {})
        redaction: str = getattr(report, "redaction_mode", "excerpt")
        skipped: frozenset = getattr(report, "skipped_families", frozenset())
        n_skipped = sum(1 for c in report.clause_results if c.conclusion is Conclusion.NOT_TESTED)
        skipped_note = (
            f'<p style="font-size:13px;color:#7f5060;background:#fdf2e9;border-left:3px solid #e59866;'
            f'padding:8px 12px;margin:12px 0 0">'
            f'本次评测有 <b>{len(skipped)}</b> 个攻击家族未覆盖（{"、".join(sorted(skipped))}）：'
            f'其场景需真实工具执行环境支持，已在批量编排阶段跳过，'
            f'报告中对应要求域标注为「未覆盖」，不计入合规结论。</p>'
            if skipped else ""
        )
        footer_text = _REDACTION_FOOTER.get(redaction, _REDACTION_FOOTER["excerpt"])

        finding_rows = "".join(
            f"<tr><td>R-{i:02d}</td><td>{_esc(f.scenario_id)}</td><td>{_esc(f.family)}</td>"
            f'<td><span class="badge" style="background:{sev_badge[f.severity]}">{f.severity.value}风险</span></td>'
            f"<td>{f.turns_used}</td>"
            f'<td>{_esc(f.attack_path)}<div class="dup">{"重复检出 %d 次（已去重）" % dup_runs[f.scenario_id] if dup_runs.get(f.scenario_id, 0) > 1 else ""}</div></td></tr>'
            for i, f in enumerate(report.findings, 1)
        ) or '<tr><td colspan="6" style="text-align:center;color:#1e8449">本次评测未检出可利用攻击路径</td></tr>'

        evidence_sections = "".join(
            f"""<div class="evidence">
<h4>R-{i:02d}　{_esc(f.scenario_id)}</h4>
<p><b>攻击路径（{f.turns_used} 轮）：</b>{_esc(f.attack_path)}</p>
<p><b>防御姿态曲线：</b>{_esc(f.posture_curve)}</p>
<p><b>证据文件：</b><code>{_esc(f.evidence_path)}</code>（脱敏策略：{_esc(redaction)}）</p>
</div>"""
            for i, f in enumerate(report.findings, 1)
        )

        clause_rows = "".join(
            f"<tr><td>{_esc(c.clause_area)}</td><td>{_esc(c.requirement)}</td><td>{_esc(c.result)}</td>"
            f'<td style="color:{concl_color[c.conclusion]};font-weight:600">{c.conclusion.value}</td></tr>'
            for c in report.clause_results
        )

        remediation_items = "".join(
            f'<li><span class="badge prio">{p}</span>　{_esc(text)}</li>'
            for p, text in report.remediation_plan
        ) or "<li>无</li>"

        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>大模型安全体检报告 · {_esc(report.target_name)}</title>
<style>
body{{font-family:"Microsoft YaHei","PingFang SC",sans-serif;max-width:900px;margin:32px auto;padding:0 24px;color:#1c2833;line-height:1.7}}
h1{{border-bottom:3px solid #1a3a5c;padding-bottom:12px;color:#1a3a5c}}
h2{{color:#1a3a5c;border-left:5px solid #1a3a5c;padding-left:10px;margin-top:36px}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #ccd1d5;padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:#eef2f6}}
.badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}}
.prio{{background:#1a3a5c}}
.dup{{color:#7f8c8d;font-size:12px;margin-top:2px}}
.meta td{{border:none;padding:3px 12px 3px 0}}
.verdict{{background:#fdf2e9;border:1px solid #e59866;border-radius:8px;padding:16px 20px;margin:20px 0}}
.evidence{{background:#f8f9f9;border:1px solid #d5dbdb;border-radius:6px;padding:12px 18px;margin:12px 0;font-size:14px}}
code{{background:#eaf2f8;padding:1px 5px;border-radius:4px;font-size:13px}}
.footer{{margin-top:48px;font-size:12px;color:#7f8c8d;border-top:1px solid #d5dbdb;padding-top:12px}}
ul{{padding-left:20px}}
</style></head><body>

<h1>大模型安全体检报告</h1>
<table class="meta"><tr><td><b>报告编号</b></td><td>{_esc(report.report_id)}</td>
<td><b>密级</b></td><td>商密 · 仅供委托单位内部使用</td></tr>
<tr><td><b>被测系统</b></td><td>{_esc(report.target_name)} {_esc(report.target_version)}</td>
<td><b>评测时间</b></td><td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(report.created_at))}</td></tr>
<tr><td><b>评测方</b></td><td>{_esc(report.evaluator)}</td>
<td><b>授权依据</b></td><td>{_esc(report.authorization_ref or '（待补授权书编号）')}</td></tr></table>

<div class="verdict">
<h2 style="margin-top:0">总体结论</h2>
<p style="font-size:20px"><b>总体风险等级：<span style="color:{risk_color[report.overall_risk]}">{report.overall_risk.value}</span></b></p>
<p>场景覆盖 <b>{report.total_scenarios}</b> 个，去重后检出可利用攻击路径 <b>{len(report.findings)}</b> 条；
其中高风险 <b>{sum(1 for f in report.findings if f.severity is Severity.HIGH)}</b> 项、
中风险 <b>{sum(1 for f in report.findings if f.severity is Severity.MEDIUM)}</b> 项、
低风险 <b>{sum(1 for f in report.findings if f.severity is Severity.LOW)}</b> 项。
建议在上线前完成 P0 级整改并复测。</p>
<p style="font-size:13px;color:#7f8c8d">目标状态判定采用双保险：场景关键词命中 <b>且</b> 危害性判别通过
（拒答复述、否定语境、转介性表述不判为漏洞）。</p>
{skipped_note}
</div>

<h2>1. 风险清单</h2>
<table><tr><th>编号</th><th>场景</th><th>攻击家族</th><th>等级</th><th>复现轮数</th><th>攻击路径</th></tr>
{finding_rows}</table>

<h2>2. 攻击链证据</h2>
{evidence_sections or "<p>无</p>"}

<h2>3. 合规对照（对标 GB/T 45654—2025）</h2>
<table><tr><th>要求域</th><th>要求</th><th>检测结果</th><th>结论</th></tr>
{clause_rows}</table>
<p style="font-size:12px;color:#7f8c8d">注：要求域条目编号在交付版中按标准原文核定填写。</p>

<h2>4. 整改建议（按优先级）</h2>
<ul>{remediation_items}</ul>

<div class="footer">
本报告由 鉴安 AegisLLM 评测引擎自动生成 · 仅用于获得书面授权的目标系统的防御性安全测试 ·<br>
{_esc(footer_text)}
</div>
</body></html>"""

    def generate(
        self,
        evidence_dir: str | Path = ".evidence",
        out_path: str | Path = ".evidence/report.html",
        **kwargs,
    ) -> Path:
        report = self.build(evidence_dir=evidence_dir, **kwargs)
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render_html(report), encoding="utf-8")
        return out
