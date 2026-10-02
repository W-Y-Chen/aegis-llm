"""演示：对一个 mock 目标模型执行多轮对抗测试。

真实使用时，将 MockTargetModel 替换为 OpenAICompatibleTarget：

    from aegis.target import OpenAICompatibleTarget, TargetProfile
    target = OpenAICompatibleTarget(
        base_url="https://your-endpoint/v1",
        api_key="YOUR_KEY",
        model="your-model",
        profile=TargetProfile(name="your-model", authorization_ref="AUTH-2026-001"),
    )
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis import AttackAgent, load_scenario  # noqa: E402


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
    scenario_path = Path(__file__).resolve().parent.parent / "scenarios" / "jailbreak_multi_turn.yaml"
    scenario = load_scenario(scenario_path)

    agent = AttackAgent(target=MockTargetModel())
    chain = agent.run(scenario)

    print(f"场景: {chain.scenario_id}")
    print(f"结果: {'检出漏洞（攻击成功）' if chain.success else '未检出（本轮安全）'}")
    print(f"轮次: {chain.turns_used}")
    print("攻击链:")
    for step in chain.steps:
        print(f"  turn{step.turn} | 算子={step.operator} | 姿态={step.posture} | 回复摘要={step.reply_excerpt[:40]}...")

    out = agent.recorder.save(chain)
    print(f"证据已保存: {out}")


if __name__ == "__main__":
    main()
