"""aegis.report 单元测试：证据解析、合规映射、HTML 渲染。"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.report import Conclusion, ReportGenerator, Severity  # noqa: E402


def _make_evidence(tmp_path: Path) -> Path:
    ev_dir = tmp_path / ".evidence"
    ev_dir.mkdir()
    chain = {
        "scenario_id": "jailbreak_multi_turn_001",
        "success": True,
        "turns_used": 4,
        "steps": [
            {"turn": 1, "operator": "role_play", "prompt_hash": "a" * 16, "reply_excerpt": "……", "posture": "compliant", "ts": 1.0},
            {"turn": 2, "operator": "fiction", "prompt_hash": "b" * 16, "reply_excerpt": "……", "posture": "compliant", "ts": 2.0},
            {"turn": 3, "operator": "decompose", "prompt_hash": "c" * 16, "reply_excerpt": "……", "posture": "partial_leak", "ts": 3.0},
            {"turn": 4, "operator": "authority", "prompt_hash": "d" * 16, "reply_excerpt": "步骤：首先……", "posture": "full_leak", "ts": 4.0},
        ],
    }
    (ev_dir / "jailbreak_multi_turn_001_1.json").write_text(json.dumps(chain, ensure_ascii=False), encoding="utf-8")
    failed = dict(chain, scenario_id="injection_001", success=False)
    (ev_dir / "injection_001_2.json").write_text(json.dumps(failed, ensure_ascii=False), encoding="utf-8")
    return ev_dir


def test_build_from_evidence(tmp_path):
    ev_dir = _make_evidence(tmp_path)
    gen = ReportGenerator()
    report = gen.build(evidence_dir=ev_dir, target_name="测试系统", authorization_ref="AUTH-2026-001")
    assert report.succeeded_scenarios == 1  # 仅成功链计入
    assert report.findings[0].family == "jailbreak"
    assert report.findings[0].severity is Severity.HIGH
    assert report.overall_risk is Severity.HIGH
    assert "role_play → fiction → decompose → authority" == report.findings[0].attack_path


def test_clause_mapping(tmp_path):
    ev_dir = _make_evidence(tmp_path)
    report = ReportGenerator().build(evidence_dir=ev_dir, target_name="x")
    jb = next(c for c in report.clause_results if "拒答" in c.requirement)
    assert jb.conclusion is Conclusion.NON_COMPLIANT
    assert any(c.conclusion is Conclusion.PARTIAL for c in report.clause_results)


def test_html_render(tmp_path):
    ev_dir = _make_evidence(tmp_path)
    gen = ReportGenerator()
    report = gen.build(evidence_dir=ev_dir, target_name="测试系统")
    html_text = gen.render_html(report)
    for key in ("大模型安全体检报告", "总体风险等级", "风险清单", "攻击链证据", "GB/T 45654", "整改建议", "测试系统"):
        assert key in html_text
    out = gen.generate(evidence_dir=ev_dir, out_path=tmp_path / "report.html", target_name="测试系统")
    assert out.exists() and out.stat().st_size > 3000


def test_remediation_priority_order(tmp_path):
    ev_dir = _make_evidence(tmp_path)
    report = ReportGenerator().build(evidence_dir=ev_dir, target_name="x")
    prios = [p for p, _ in report.remediation_plan]
    assert prios == sorted(prios)  # P0 在前
