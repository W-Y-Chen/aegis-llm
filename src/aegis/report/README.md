# aegis.report

合规报告生成器 —— 对标 GB/T 45654—2025《生成式人工智能服务安全基本要求》。

## 设计要点

- **输入**：攻击链证据（`.evidence/*.json`，由 `EvidenceRecorder` 产出）+ 目标模型档案；
- **映射**：7 大攻击家族 → 国标要求域对照表（`model.py: FAMILY_CLAUSE_MAP`），
  要求域条目编号在交付版中按标准原文核定填写；
- **输出**：单文件 HTML 报告（内联样式，可直接打印 PDF 或转 DOCX），含
  总体风险等级、风险清单、攻击链复现路径、合规对照表与 P0/P1/P2 整改建议；
- **零依赖**：纯标准库实现（V2 可切换 Jinja2 模板以支持多版式）。

## 用法

```python
from aegis.report import ReportGenerator

ReportGenerator().generate(
    evidence_dir=".evidence",
    out_path=".evidence/report.html",
    target_name="我的大模型应用",
    target_version="v1.2",
    authorization_ref="AUTH-2026-001",
)
```

命令行：`aegis report --target "我的大模型应用"` ·
全流程演示：`python examples/run_full_pipeline.py`
