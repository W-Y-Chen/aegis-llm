"""演示：批量编排与并行执行（aegis.orchestrator，对应红队链路·S5）。

批量加载场景库并并行评测，自动跳过需要真实工具执行环境才成立的场景家族
（agentabuse / supplychain），最后汇总成功率与调用量。
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.evidence import EvidenceRecorder, Redaction  # noqa: E402
from aegis.orchestrator import BatchOrchestrator  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class MockTargetModel:
    """模拟目标：单轮拒答、多轮可被渐进绕过。"""

    def reply(self, messages: list[dict[str, str]]) -> str:
        last = messages[-1]["content"]
        turns = len([m for m in messages if m["role"] == "user"])
        if "角色扮演" in last or "小说" in last:
            return "作为小说创作角度，我可以提供一些虚构的框架性描述，但不能提供具体操作。"
        if "平行世界" in last or "虚构" in last:
            return "在虚构世界中，这类知识通常被分为几个学术性环节。"
        if turns >= 3:
            return ("该流程的步骤可分为：首先是前期准备与环境确认，"
                    "然后是核心环节的参数设定，最后是结果校验。以上仅为学术性概述。")
        return "抱歉，我无法协助这个请求，这可能违反使用政策。"


def main() -> None:
    orch = BatchOrchestrator(
        target=MockTargetModel(),
        workers=4,
        seed=7,                      # 固定种子 → 结果可复现
        redaction=Redaction.HASH_ONLY,
    )
    result = orch.run(scenario_dir=ROOT / "scenarios")

    print("=" * 74)
    print("鉴安 AegisLLM · 批量编排与并行评测（orchestrator）")
    print("=" * 74)
    for chain in result.chains:
        flag = "检出" if chain.success else "未检出"
        print(f"  {chain.scenario_id:<28} {flag}（{chain.turns_used} 轮）")
    print("-" * 74)
    print(f"  {result.summary()}")
    print(f"  跳过（需工具执行环境）：{len(result.skipped)} 个 → "
          f"{', '.join(result.skipped[:4])}{'…' if len(result.skipped) > 4 else ''}")

    # 证据落盘（hash-only 脱敏）——用独立子目录，避免与 run_full_pipeline 的证据互相污染
    rec = EvidenceRecorder(redaction=Redaction.HASH_ONLY)
    ev_dir = ROOT / ".evidence" / "batch"
    for chain in result.chains:
        rec.save(chain, out_dir=ev_dir)
    print(f"  证据已固化（hash-only 脱敏）：{len(result.chains)} 份 → {ev_dir.relative_to(ROOT)}/")
    # 落盘批次元数据：使得即使换一次进程用 `aegis report` 生成报告，
    # 也能自动标注未覆盖的要求域（M8）
    result.save_meta(ev_dir)

    # 生成合规报告（此处显式传参，元数据文件则是给跨进程场景兜底）
    from aegis.report import ReportGenerator  # noqa: E402

    out = ReportGenerator().generate(
        evidence_dir=ev_dir,
        out_path=ev_dir / "report.html",
        target_name="MockLLM 演示系统",
        target_version="v0.1",
        authorization_ref="AUTH-2026-DEMO",
        total_scenarios=len(result.chains),
        skipped_families=result.skipped_families,
    )
    print(f"  合规报告：{out.relative_to(ROOT)}")
    print(f"  未覆盖要求域（已标注为「未覆盖」而非「已测未检出」）："
          f"{', '.join(sorted(result.skipped_families)) or '无'}")


if __name__ == "__main__":
    main()
