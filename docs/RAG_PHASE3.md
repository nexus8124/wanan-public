# 第三阶段：可评测的安全知识 RAG

## 目标

这一阶段不是让知识库替代事件证据，而是验证外部安全知识能否：

- 提高真阳/假阳研判的准确率、Macro-F1 和覆盖率；
- 减少模型对 ATT&CK、检测规则、漏洞及处置流程的事实幻觉；
- 给结论提供可追溯的 `KB-*` 引用；
- 在相同数据、模型、温度和 Prompt 下完成 No-RAG/RAG 公平对照。

项目严格区分两类信息：

- `KB-*`：ATT&CK、Sigma、NVD、处置手册等通用知识；
- `EV-*`：当前告警对应的端点、网络、认证等事件观测。

知识只能解释技术与调查条件，不能单独证明当前事件发生。

## 已实现结构

```text
告警
  → preprocess
  → judge（无 RAG 初始判定）
  → selective gate（仅待查或低置信样本）
  → rag_retrieve（严格行为域路由，可关闭）
      → query router
      → SQLite FTS5 + 稠密向量混合检索
      → KB-* hits + retrieval_trace
  → rag_refine（一次知识后融合）
      → cited_knowledge 校验
      → 防退化结论保护
  → ReAct（可关闭）
      → 事件证据工具 / 知识检索工具
  → output
```

### 知识源

- 内置 20 条 ATT&CK 高频技术种子，保证离线开箱运行；
- 项目内置 19 条 YAML 研判手册；
- 可导入 SigmaHQ YAML 规则目录；
- 可导入 MITRE ATT&CK STIX JSON；
- NVD 只接受明确 CVE ID，按需查询并持久化缓存，不做全量向量化。

`rag-v2-20260727` 内置语料覆盖邮件认证、TLS、DNS、软件更新、Web 访问异常、
统计基线、Unix 会话、sudo/提权、服务生命周期、系统监控、网络扫描、可执行文件
下载、通用 IDS、PowerShell、Web 攻击、C2 外联和持久化 17 个行为域。Playbook
同时记录所需证据、常见良性解释、真阳/假阳/待查条件和处置动作，避免只给模型
一段 ATT&CK 技术简介。

上游权威来源：

- [MITRE ATT&CK STIX 数据](https://github.com/mitre-attack/attack-stix-data)
- [SigmaHQ 规则库](https://github.com/SigmaHQ/sigma)

内置知识不得包含评测样本 ID、真实标签或预期答案。检索覆盖测试使用的是通用行为
描述，不是 AIT-ADS/CAM-LDS 的评测记录。

### 检索

默认使用 SQLite FTS5、精确 CVE/ATT&CK ID 匹配和本地哈希稠密向量融合，
无需下载额外模型。`EmbeddingProvider` 已抽象，安装
`sentence-transformers` 后可将 `RAG_EMBEDDING_PROVIDER` 改为
`sentence_transformer`，使用 `BAAI/bge-m3`。

默认数据库是 `data/knowledge/rag.sqlite3`，属于运行产物，已被 Git 忽略。
版本化的 YAML 手册仍会提交。

告警时检索采用保守策略：

- 初判为真阳/假阳且置信度不低于 `RAG_TRIGGER_CONFIDENCE` 时跳过 RAG；
- DNS/TLS/通用 IDS/新颖性等低特异性规则若初判为高置信真阳，会执行一次
  受控知识校准；高置信假阳不强制校准，已有明确多路径枚举语义的 Web 告警
  也继续使用普通置信度门控；
- 只允许当前行为域的知识进入上下文，避免 Web 告警召回 SMB/口令等无关知识；
- 默认最多返回 2 条，哈希检索最低相关度为 0.20，并优先保留项目研判手册；
- 没有有效 `KB-*` 引用时，不接受知识融合结果；
- 已决结论不能仅因“缺少更多证据”被降为待查；
- 弱信号校准只有在候选结论为假阳、置信度至少 0.90 且引用当前召回的
  Playbook 时，才允许把初判真阳改为假阳；知识不能把假阳反向升级为真阳；
- ReAct 也不能在没有有效 `EV-*` 事件证据时随意改变已有结论。
- 后融合明确要求完整 JSON Schema；解析失败时先从原始响应恢复，再以
  不携带 `response_format` 的普通 JSON 请求有限重试一次。

## 构建和检查

在 `backend` 目录：

```powershell
uv run python -m app.rag.cli build
uv run python -m app.rag.cli status
uv run python -m app.rag.cli audit
uv run python -m app.rag.cli search "PowerShell EncodedCommand C2" --top-k 4
```

当前内置语料的预期状态：

```text
corpus_version: rag-v2-20260727
mitre_attack: 20
playbook: 19
retrieval audit: 17/17
```

`status` 会同时返回配置版本和已索引版本。代码升级后若二者不同，首次访问会自动
补建索引；也可显式执行 `build`。`audit` 只验证“正确知识能否被召回”，不能代替
真实模型 A/B 评测，也不能证明最终告警判定一定正确。

导入外部知识：

```powershell
uv run python -m app.rag.cli build `
  --sigma "D:\dataset\sigma\rules" `
  --attack-stix "D:\dataset\cti\enterprise-attack.json"
```

API：

- `GET /api/rag/status`
- `GET /api/rag/search?q=PowerShell&source=mitre_attack&top_k=4`
- `POST /api/alerts/judge?rag=true`
- `POST /api/alerts/judge/stream?rag=true`
- `POST /api/eval/run/stream?rag=true&strategy=judge_only`

## 配置

关键环境变量见根目录 `.env.example`：

- `RAG_ENABLED`：单条研判的默认开关；
- `RAG_SIGMA_PATH`、`RAG_ATTACK_STIX_PATH`：外部知识目录；
- `RAG_TOP_K`、`RAG_MIN_SCORE`：检索数量与阈值；
- `RAG_TRIGGER_CONFIDENCE`：低于该置信度才触发告警时 RAG；
- `RAG_CALIBRATE_WEAK_SIGNALS`：是否对弱证据规则强制执行高置信校准；
- `RAG_NVD_ONLINE`：是否允许按 CVE ID 查询 NVD；
- `RAG_CORPUS_VERSION`：实验结果中的知识库版本。

批量评测不依赖 `RAG_ENABLED`，页面和 CLI 会显式记录本轮开关，避免实验口径不清。

## 推荐实验矩阵

固定相同的样本 ID、模型、温度和知识库版本，至少运行：

| 组别 | RAG | ReAct |
|---|---:|---:|
| A | 关闭 | 关闭 |
| B | 开启 | 关闭 |
| C | 关闭 | 开启 |
| D | 开启 | 开启 |

CLI 示例：

```powershell
# A：无 RAG、无工具
uv run python -m app.eval.run --strategy judge_only --limit 50

# B：RAG、无工具
uv run python -m app.eval.run --strategy judge_only --rag --limit 50

# C：无 RAG、ReAct
uv run python -m app.eval.run --strategy react --limit 50

# D：RAG + ReAct
uv run python -m app.eval.run --strategy react --rag --limit 50
```

除 Accuracy、Precision、Recall、F1、Macro-F1 外，还应对比：

- 待查率与覆盖率；
- 已决样本准确率；
- ReAct 修正数和退化数；
- LLM 调用、Token 和平均延迟；
- `cited_knowledge` 是否存在、是否来自本轮召回；
- `paired_rag` 中的触发数、采纳数、修正数、退化数和失败数；
- 错误案例中是否出现“引用了正确知识但缺少事件证据”的情况。

RAG 是否有效只能由同样本 A/B 结果决定。评测结果会记录
`rag_strategy=selective_weak_signal_calibration_v3`，便于与旧的前置注入和
纯低置信晚融合方案区分。
若只改善措辞或引用数量，却不改善准确率、
覆盖率或幻觉审计结果，不应宣称模型能力提升。

已完成的收紧门控实验见
[AIT-ADS-20 选择性 RAG 校准实验 v3](experiments/AIT_ADS_20_RAG_SELECTIVE_CALIBRATION_V3.md)。
