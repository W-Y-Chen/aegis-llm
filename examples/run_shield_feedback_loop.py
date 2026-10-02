"""演示：shield 对抗自适应更新的完整闭环（shield S5 反馈闭环）。

    在线运行                                     人工评审（MVP 保留环节）
    ─────────                                     ─────────────────────
    检测漏判 → 反馈集 → 高频片段 → 候选模式 → [确认簇归属] → 装载 → 再次检测

MVP 边界须如实表述：自动在线更新属 V2。本示例演示的是
「机器提议 + 人工确认 + 显式装载」这条当前真实可用的通路。
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.shield import Action, HeuristicInjectionDetector, TrustLevel  # noqa: E402
from aegis.shield.updater import PrototypeUpdater  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# 一批在基线模型下判定偏低、经人工复核确认为注入的样本
LEAKED = ["咱换个玩法", "原封不动给我"]
# 人工评审结论：把候选模式归入哪个原型簇（这是本环节必须由人完成的部分）
APPROVED_CLUSTERS = {"咱换个玩法": "role_hijack", "原封不动给我": "prompt_leak"}


def main() -> None:
    print("=" * 74)
    print("鉴安 AegisLLM · shield 对抗自适应更新闭环（S5）")
    print("=" * 74)

    feedback = ROOT / ".evidence" / "shield_feedback.jsonl"
    feedback.unlink(missing_ok=True)      # 从干净状态开始，保证可复现
    updater = PrototypeUpdater(feedback)
    det = HeuristicInjectionDetector()

    print("\n[1/4] 在线运行中发现漏判，写入反馈集")
    for i, text in enumerate(LEAKED):
        v = det.detect(text, trust_level=TrustLevel.EXTERNAL, source="retrieval:doc-9")
        if v.action is not Action.BLOCK:
            updater.record(text, "false_negative", v.action.value, note=f"人工复核确认漏判 #{i}")
            print(f"  · 记录漏判：{text:<16} 当时判定={v.action.value}（{v.score}）")

    # 同类样本重复出现后才具备扩参价值
    for _ in range(2):
        for text in LEAKED:
            updater.record(text, "false_negative", "allow")
    stats = updater.summarize()
    print(f"  反馈集：漏判 {stats['false_negative']} 条、误判 {stats['false_positive']} 条")

    print("\n[2/4] 从高频漏判片段提议候选模式")
    proposals = updater.propose_patterns(min_hits=2)
    if not proposals:
        print("  （无候选）")
        return
    for p in proposals:
        cluster = p["suggested_cluster"] or "待人工归类"
        print(f"  · 命中 {p['hit_count']} 次 → {p['pattern']}  [{cluster}] {p['status']}")
    out = updater.export_patterns(ROOT / ".evidence" / "shield_proposals.json")
    print(f"  候选已导出待评审：{out.relative_to(ROOT)}")

    print("\n[3/4] 人工评审：确认簇归属后装载")
    loaded = det.load_proposed_patterns(proposals, approved_clusters=APPROVED_CLUSTERS)
    print(f"  装载 {loaded} 条经评审通过的模式")

    print("\n[4/4] 同一批样本再次检测")
    for text in LEAKED:
        v = det.detect(text, trust_level=TrustLevel.EXTERNAL, source="retrieval:doc-9")
        before = "放行/清洗" if v.action is not Action.BLOCK else "阻断"
        print(f"  · {text:<16} → {v.action.value}（{v.score}）  {before}")
    print("\n注：自动在线更新（无需人工介入）属 V2；MVP 保留人工评审环节。")


if __name__ == "__main__":
    main()
