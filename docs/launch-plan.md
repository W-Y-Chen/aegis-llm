# GitHub 冷启动与 Star 增长计划

目标：开源发布后 90 天内达到 **500+ stars**，形成可被比赛评委与投资人验证的社区影响力证据。

## 〇、发布前置条件

- [x] 仓库不含任何内部材料（竞赛方案、商业计划、客户信息均在本仓库之外）；
- [ ] 与学校科研处确认作品的对外公开口径；
- [ ] README 首屏具备一句话定位 + 截图 + Quick start；
- [ ] `python examples/run_full_pipeline.py` 在干净环境中跑通。

## 一、发布前清单（仓库侧）

- [x] 中英双语 README（中文为主，英文版 README_EN.md 互链）
- [x] Apache-2.0 LICENSE、CONTRIBUTING、CITATION.cff
- [x] CI（pytest + 场景校验徽章）
- [x] Issue/PR 模板
- [ ] **Demo 视频/GIF**（最高优先级）：录制 60 秒演示——跑 `run_evaluation.py` 展示 4 轮攻击链 + 打开控制台原型。放在 README 顶部（README 有图无视频，star 转化率差 3 倍以上）
- [ ] GitHub Topics 配置：`llm-security` `prompt-injection` `jailbreak` `red-teaming` `ai-safety` `llm-agent` `ai-governance` `security-testing` `chinese` `agent-security`
- [ ] About 一句话：`Multi-turn red-teaming engine for LLM & agent applications | 大模型与智能体安全评测引擎`
- [ ] 首个 Release：v0.1.0，附场景库清单与 roadmap

## 二、发布节奏（4 周）

| 周 | 动作 | 渠道 |
|---|------|------|
| W1 | 主发布：中文长文《我们把大模型越狱攻击做成了状态机搜索引擎》 | 掘金、知乎专栏、OSC 开源中国、公众号 |
| W1 | 英文发布：Show HN + Reddit | Hacker News (Show HN: AegisLLM – multi-turn red-teaming for LLM agents)、r/LocalLLaMA、r/MachineLearning |
| W2 | 技术深潜文：多轮对话状态机如何实现（含攻击链图） | 掘金/知乎 + 安全社区（FreeBuf、先知、看雪） |
| W2 | 进入 Awesome 清单：向 awesome-llm-security、awesome-ai-safety、awesome-prompt-injection 提 PR | GitHub |
| W3 | 场景库共建活动：发布"50→200 场景"召集令，设 good-first-issue | 社区 + 高校安全社团/CTF 群 |
| W4 | 与国产模型社区联动：提交到模型厂商的安全工具生态页 | 各家模型社区 |

## 三、内容弹药库（直接可用）

- 主标题候选：《给大模型做"自动化红队"：一个开源的状态机越狱引擎》《1112 款大模型备案之后，安全评测该怎么做》
- 核心卖点三句话：单轮模板测不出的多轮越狱，我们用状态机搜出来；一次评测从 2 周缩到 4 小时；50 个场景开箱即用
- 配图：控制台截图 + 攻击链证据 JSON 截图 + 状态机示意图

## 四、Star 转化技巧（实测有效）

1. **README 前 3 屏定生死**：第一屏必须是一句话定位 + 60 秒 Demo GIF + Quick start；
2. **蹭政策热点**：GB/T 45654 实施、备案数破千都是天然流量词，标题带上；
3. **每周五更新**：保持 commit 频率，GitHub Trending 对活跃仓库更友好；
4. **回复每个 Issue/Star 用户**：前 100 个用户逐一互动，转化为贡献者；
5. **高校渠道**：安全社团、CTF 战队、研究生实验室——既是用户也是比赛背书。

## 五、里程碑与度量

| 时间 | 目标 | 度量 |
|------|------|------|
| 发布后 2 周 | 100 stars | 至少 2 篇渠道文章阅读过万 |
| 发布后 1 月 | 200 stars / 10 forks | 进入 1 个 Awesome 清单 |
| 发布后 3 月 | 500 stars / 5 个外部 PR | 场景库被贡献 10+ 个 |

> 所有数据截图归档至 `01-竞赛材料/社区证据/`，作为国创赛与融资的社区影响力证明。
