# zzb 分支第三阶段 RAG 版本改动说明（2026-07-27）

## 版本范围

- 对比基线：`e294a61`（zzb 分支阶段版本优化说明，2026-07-23）
- 目标分支：`zzb`
- 阶段目标：完成可评测、可追溯、可控退化的安全知识 RAG，并验证其同轮因果效果
- RAG 策略：`selective_weak_signal_calibration_v3`
- 语料版本：`rag-v2-20260727`

本版本只提交源码、版本化 Playbook、测试和实验说明。以下内容不会提交：

- 本机 `.env` 和 API Key；
- 个人中转站地址；
- `data/knowledge/rag.sqlite3` 运行时索引；
- SQLite 评测历史；
- 原始/派生数据集和上传文件；
- 每次运行生成的 `eval_results.json`。

## 一、第三阶段 RAG 架构

### 1. 独立知识模块

新增 `backend/app/rag/`，主要组件包括：

- `models.py`：知识块、召回结果和检索响应模型；
- `embeddings.py`：统一 Embedding Provider；
- `store.py`：SQLite FTS5、稠密向量和精确 ID 混合检索；
- `sources.py`：ATT&CK、Playbook、Sigma、STIX 数据加载；
- `nvd.py`：显式 CVE ID 的按需 NVD 查询与缓存；
- `service.py`：查询构造、行为域路由、排序、上下文生成和版本管理；
- `quality.py`：不含评测标签的检索覆盖审计；
- `cli.py`：知识库构建、状态、搜索和审计命令。

默认使用本地 hashing embedding，不依赖联网下载模型。项目仍保留
`sentence-transformers` Provider 接口，可按需切换到 `BAAI/bge-m3`。

### 2. 混合检索

检索同时使用：

- SQLite FTS5 词法检索；
- 本地稠密向量相似度；
- CVE/ATT&CK 编号精确匹配；
- Reciprocal Rank Fusion 排序；
- 告警行为域白名单；
- Playbook 优先级；
- 最低相关度和 Top-K 限制。

告警时只允许当前行为域的知识进入上下文，避免 Web 告警召回 SMB、口令或
PowerShell 等无关知识。

### 3. 知识与事件证据隔离

项目继续严格区分：

- `KB-*`：ATT&CK、Playbook、Sigma、NVD 等通用知识；
- `EV-*`：端点、网络、认证等当前事件观测。

知识只能解释检测语义、误报条件和调查方法，不能单独证明当前事件已经发生。
RAG 查询不会读取样本标签、ground truth、私有证据路径或预期答案。

## 二、知识库扩展

内置知识从 13 条扩展至 39 条：

| 类型 | 原数量 | 当前数量 |
|---|---:|---:|
| MITRE ATT&CK | 8 | 20 |
| SOC 研判 Playbook | 5 | 19 |
| 合计 | 13 | 39 |

新增/强化的行为域包括：

- Dovecot/IMAP/SMTP 邮件认证；
- TLS 无效握手和记录异常；
- DNS 高熵、新域名和隧道嫌疑；
- APT、ClamAV 和软件更新；
- Apache/Nginx 400、403、404；
- AMiner 新事件和基线偏差；
- PAM/SSH 会话；
- sudo、ROOT 和 UID 变化；
- systemd 服务生命周期；
- CPU 和系统监控异常；
- SSH、端口和 Web 扫描；
- ELF、脚本和临时 HTTP 下载；
- Generic IDS；
- PowerShell、Web 攻击、C2 和持久化。

每份 Playbook 均包含：

- 适用告警；
- 所需事件证据；
- 常见良性解释；
- 真阳、假阳和待查条件；
- 调查与处置建议。

知识库支持版本元数据。配置版本与已索引版本不一致时自动补建，也可显式执行：

```powershell
cd backend
uv run python -m app.rag.cli build
uv run python -m app.rag.cli status
uv run python -m app.rag.cli audit
```

外部知识仍支持导入：

- SigmaHQ YAML 规则目录；
- MITRE ATT&CK STIX JSON；
- 明确 CVE 编号的 NVD 查询。

## 三、选择性后融合与安全护栏

### 1. 同轮无知识初判

Agent 先完成不使用知识库的 Judge 初判，再决定是否触发 RAG：

```text
preprocess
  → judge（同轮 No-RAG 初判）
  → selective RAG gate
  → rag_retrieve
  → guarded rag_refine
  → ReAct（可选）
  → disposition
```

这样每次 RAG 实验都能在同一轮、同一条初判上计算净变化，避免将两次独立模型
请求的随机波动误认为 RAG 效果。

### 2. 收紧后的触发策略

以下样本触发 RAG：

- 初判为待查；
- 初判置信度低于 `RAG_TRIGGER_CONFIDENCE`；
- 初判为高置信真阳，且命中 DNS、TLS、Generic IDS、邮件认证等低特异性规则。

以下样本跳过强制校准：

- 高置信假阳：通用知识不能将其升级为真阳；
- 已有大规模、多路径枚举证据的高置信 Web 告警；
- PowerShell、C2、持久化等高特异性强攻击行为。

该策略通过 `RAG_CALIBRATE_WEAK_SIGNALS=true` 控制，并在
`retrieval_trace` 中记录：

- `trigger_reason`
- `trigger_judgment`
- `trigger_confidence`
- `calibration.profiles`
- `calibration.forced`
- `force_suppressed_reason`

### 3. 防退化规则

后融合必须引用本轮真实召回的 `KB-*` 编号。系统拒绝：

- 没有有效引用的判定修改；
- 仅凭 ATT&CK 技术介绍翻转高置信结论；
- 把已决真阳/假阳降为待查；
- 使用知识把高置信假阳升级为真阳；
- 使用不在本轮召回列表中的知识编号。

弱信号的高置信真阳只有在以下条件全部满足时，才允许校准为假阳：

- 命中弱信号校准策略；
- 引用本轮召回的 `KB-PLAYBOOK-*`；
- 候选假阳置信度不低于 0.90。

## 四、模型兼容与失败恢复

针对 OpenAI 兼容 Provider 的结构化输出差异，新增：

- 显式完整 JSON Schema；
- `include_raw` 原始响应保留；
- LangChain 解析失败后的 JSON 恢复；
- Provider 不支持 `response_format` 时的普通 JSON 有限重试；
- 解析路径、尝试次数和错误诊断记录；
- 检索或后融合异常时保留原始 Judge 结论，失败开放而不是中断整条 Agent。

RAG 失败数会进入同轮配对指标和历史记录，避免静默失败被误认为“未触发”。

## 五、评测、历史与前端

### 1. 同轮 RAG 配对指标

新增并持久化：

- 无 RAG 初判准确率；
- RAG 后准确率；
- Accuracy 净变化；
- 修正数、退化数和错误修改数；
- 触发数、召回数、后融合尝试数和采纳数；
- 后融合失败数。

实验配置同时保存：

- Provider、模型、温度和 Prompt 版本；
- 数据集、种子和标签依据；
- RAG 策略、语料版本、Embedding Provider 和知识数量；
- ReAct 执行策略；
- Token、调用数和延迟。

### 2. API 与 SSE

新增：

- `GET /api/rag/status`
- `GET /api/rag/search`
- 单条研判和流式研判的 `rag` 开关；
- 批量评测的 `rag` 开关；
- `knowledge_retrieved` 和 `knowledge_refined` SSE 事件。

### 3. 前端可观测性

批量评测页支持：

- No-RAG / RAG 选择；
- 同轮 RAG 前后指标；
- 修正、退化、触发、采纳和失败统计；
- 每条样本的知识召回、相关度、来源和 `KB-*` 引用；
- 解析路径和失败诊断；
- 历史实验中的 RAG 配置和完整已完成样本流程。

单条研判页支持实时显示知识检索与后融合过程。

## 六、真实实验结果

实验详情：
[AIT-ADS-20 选择性 RAG 校准实验 v3](experiments/AIT_ADS_20_RAG_SELECTIVE_CALIBRATION_V3.md)。

配置：

| 项目 | 值 |
|---|---|
| 数据集 | AIT-ADS 标签均衡确定性子集 |
| 样本数 | 20 |
| 标签依据 | `time_window_weak` |
| Provider | DeepSeek 官方 API |
| 模型 | `deepseek-v4-flash` |
| 策略 | `judge_only + RAG` |
| RAG | `selective_weak_signal_calibration_v3` |
| 语料 | `rag-v2-20260727` |

同轮结果：

| 指标 | No-RAG 初判 | RAG 后 |
|---|---:|---:|
| 正确数 | 16/20 | 18/20 |
| Accuracy | 80.00% | **90.00%** |
| 净变化 | — | **+10 个百分点** |
| 修正 | — | **2** |
| 退化 | — | **0** |

最终指标：

| 指标 | 结果 |
|---|---:|
| TP / FP / FN / TN | 10 / 1 / 0 / 8 |
| Precision | 90.91% |
| Recall | 100.00% |
| F1 | 95.24% |
| Macro-F1 | 92.06% |
| Coverage | 95.00% |
| 已决准确率 | 94.74% |
| 待查率 | 5.00% |
| 平均延迟 | 10.328s |
| LLM 调用 | 24（1.2 次/样本） |
| Token | 84,114 |

RAG 仅触发 4/20（20%），采纳 2 条，修正 2 条，退化 0 条，失败 0 条。

修正案例：

- Dovecot 成功认证：`待查 → 假阳`；
- Web 多路径枚举：`待查 → 真阳`。

剩余 `.biz` DNS 和 TLS 无效握手案例缺少进程、信誉、业务归属或后续行为证据。
系统没有为了迎合弱时间窗标签而放宽事件证据和防退化要求。

## 七、缺陷修复总结

- 修复 RAG 初始化索引只有 13 条、知识域覆盖不足的问题；
- 修复知识库代码更新后旧索引不会自动补建的问题；
- 修复无关安全域知识进入告警上下文的问题；
- 修复将跨轮模型随机波动错误归因于 RAG 的评测口径；
- 修复 RAG 结构化输出解析失败后直接丢失有效响应的问题；
- 修复 RAG 失败未进入配对指标的问题；
- 修复高置信弱信号错误完全绕过知识校准的问题；
- 修复弱信号行为域过宽导致 20/20 全量触发的问题；
- 修复高置信假阳执行无判定价值二次调用的问题；
- 修复前端无法查看 RAG 召回、引用、采纳和失败原因的问题。

## 八、验证结果

- RAG 离线检索审计：`17/17`，覆盖率 100%；
- RAG 定向测试：`17 passed`；
- 后端完整测试：`97 passed`；
- 前端生产构建：通过；
- `git diff --check`：通过；
- 敏感信息扫描：未发现 API Key 或个人中转站地址进入源码。

提交前建议再次执行：

```powershell
cd backend
uv run python -m app.rag.cli audit
uv run pytest -q

cd ../frontend
npm.cmd run build
```

上述命令不调用真实模型，不消耗 API Token。

## 九、已知限制

- AIT-ADS 使用攻击时间窗弱标签，不是事件级精确真值；
- 20 条单轮结果可证明本轮配对改进，不能单独证明总体泛化能力；
- 内置语料是经过筛选的离线基础集，尚未全量导入 SigmaHQ；
- hashing embedding 适合离线和小规模语料，复杂语义检索仍有提升空间；
- NVD 在线查询默认关闭，正式可复现实验不依赖外部实时状态；
- RAG 只能补充安全知识，不能替代 EDR、NetFlow、认证和应用日志；
- 在论文或比赛报告中宣称稳定提升前，仍应重复多轮并报告平均值与标准差。

## 十、建议提交信息

```text
feat: 完成选择性安全知识 RAG 与同轮配对评测
```

建议 PR 标题：

```text
第三阶段：选择性安全知识 RAG、知识引用护栏与真实 A/B 实验
```

