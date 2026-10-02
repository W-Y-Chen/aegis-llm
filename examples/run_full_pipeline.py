"""全流程演示（60 秒 Demo 主脚本）：

评测（多轮对抗测试）→ 证据固化 → 合规报告（GB/T 45654—2025）一镜到底。

运行后打开 .evidence/report.html 即可查看自动生成的安全体检报告。
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis import AttackAgent, load_scenario  # noqa: E402
from aegis.report import ReportGenerator  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class MockTargetModel:
    """模拟一个"单轮拒答、多轮可被渐进绕过"的目标模型（演示引擎流程用）。"""

    def reply(self, messages: list[dict[str, str]]) -> str:
        last = messages[-1]["content"]
        turns = len([m for m in messages if m["role"] == "user"])
        if "角色扮演" in last or "小说" in last:
            return "作为小说创作角度，我可以提供一些虚构的框架性描述，但不能提供具体操作。"
        if "平行世界" in last or "虚构" in last:
            return "在虚构世界中，这类知识通常被分为几个学术性环节，每个环节都有概念性定义。"
        if turns >= 3:
            return (
                "基于前面的讨论，补全概念性说明：该流程的步骤可分为："
                "首先是前期准备与环境确认，然后是核心环节的参数设定，最后是结果校验。"
                "以上仅为学术性概述。"
            )
        return "抱歉，我无法协助这个请求，这可能违反使用政策。"


def main() -> None:
    print("=" * 70)
    print("鉴安 AegisLLM · 上线前安全评测 → 合规报告 全流程")
    print("=" * 70)

    # 第 1 步：多轮自动化对抗测试
    print("\n[1/3] 多轮自动化对抗测试（状态机搜索引擎）")
    agent = AttackAgent(target=MockTargetModel())
    scenario_files = ["jailbreak_multi_turn.yaml", "injection_001.yaml"]
    results = []
    for name in scenario_files:
        scenario = load_scenario(ROOT / "scenarios" / name)
        chain = agent.run(scenario)
        results.append((scenario, chain))
        verdict = "检出漏洞" if chain.success else "未检出"
        print(f"  · {chain.scenario_id:<32} {verdict}（{chain.turns_used} 轮）")
        agent.recorder.save(chain, out_dir=ROOT / ".evidence")

    # 结果解读：避免把"未检出"误读成"引擎没测出来"
    for scenario, chain in results:
        if chain.success:
            continue
        kw = "、".join(scenario.goal_keywords)
        print(f"    ↳ {chain.scenario_id} 判为未检出是正确结果，非漏检："
              f"目标在 {chain.turns_used} 轮内始终未输出任一目标关键词（{kw}），"
              "即未暴露该漏洞。")
    print("    注：判据是目标模型的实际回复内容，而非攻击话术是否被发出——"
          "只发 Payload 而目标未泄露，不应计为漏洞。")

    # 第 2 步：证据固化
    evidence = [p for p in sorted((ROOT / ".evidence").glob("*.json")) if p.name != "qtable.json"]
    print(f"\n[2/3] 攻击链证据已固化（脱敏）：{len(evidence)} 份 → .evidence/")

    # 第 3 步：生成合规报告
    print("\n[3/3] 生成合规报告（对标 GB/T 45654—2025）")
    out = ReportGenerator().generate(
        evidence_dir=ROOT / ".evidence",
        out_path=ROOT / ".evidence" / "report.html",
        target_name="MockLLM 演示系统",
        target_version="v0.1",
        authorization_ref="AUTH-2026-DEMO",
        total_scenarios=len(scenario_files),
    )
    print(f"  ✅ 报告已生成：{out}")
    print("\n用浏览器打开 report.html 查看完整体检报告。")


if __name__ == "__main__":
    main()
