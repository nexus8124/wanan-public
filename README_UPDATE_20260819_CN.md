# 中文更新说明（更新至 2026-09-10）

## 一、本次更新解决了什么问题

项目原有评测主要依赖小规模演示数据和 AIT-ADS 时间窗弱标签。它们适合验证工程流程，但不足以支持“模型准确率可信达到 85%”这一结论。

本次更新完成两条相互独立的评测路线：

1. 将 AIT-ADS 升级为事件标签与时间标签一致、按场景隔离的案例级正式评测集，用于未来验收可信 85%。
2. 接入 ToN_IoT 网络流和 Modbus 遥测，用于将项目验证为“工业互联网多源安全事件研判智能体”。

本次只完成数据构造、代码接入和测试，没有调用 DeepSeek，也没有运行真实模型全量评测。因此，当前可以表述为“可信 85% 的评测基础设施已经完成”，不能表述为“模型已经达到 85%”。

## 二、AIT-ADS 正式案例级评测

### 1. 真值升级

新增 `backend/app/data/ait_event_gold.py`，读取 AIT 官方事件标签表。只有以下记录可以进入正式二分类评测：

- 真阳：记录位于攻击时间窗内，并且存在事件级攻击标签。
- 假阳：记录位于 `false_positive` 时间窗内，并且不存在事件级攻击标签。
- 冲突记录：时间标签和事件标签不一致，全部排除。

构造程序共扫描 2,655,821 条官方记录，排除 91,755 条标签冲突记录。

### 2. 告警风暴去重

正式评测不再把同一攻击步骤产生的大量重复告警逐条计分，而是使用以下案例键进行一分钟聚合：

```text
(scenario, detector, rule_name, host, ip, 1-minute bucket)
```

这样可以避免模型仅靠重复告警获得虚高准确率。

### 3. 场景隔离拆分

| 集合 | 场景 | 真阳 | 假阳 | 总数 | 用途 |
|---|---|---:|---:|---:|---|
| development | fox、shaw、wardbeck | 300 | 300 | 600 | 开发与调试 |
| validation | santos、wheeler | 100 | 100 | 200 | 阈值选择与预验收 |
| test_frozen | harrison、russellmitchell、wilson | 500 | 500 | 1000 | 最终冻结验收 |

三个集合使用不同场景，避免同场景信息同时进入开发集和测试集。冻结测试集不应参与 Prompt 修改、规则调整或阈值选择。

### 4. 标签防泄漏

- Agent 接收的 `alerts` 不包含真阳/假阳标签。
- 真值单独保存在 `ground_truth` 中，只由评测器在推理结束后读取。
- 时间标签、事件标签和攻击类型不会进入 Agent 可见的原始载荷。
- 每个案例使用不透明证据引用查询真实的 Wazuh、AMiner 或 Suricata 邻域记录。
- 正式评测样本不会回退到演示 Mock 威胁情报和 Mock 历史告警。

## 三、可信 85% 验收门槛

新增 Wilson 95% 置信下界与组合验收门槛。冻结测试集必须同时满足：

| 指标 | 门槛 |
|---|---:|
| 总准确率 | ≥ 88% |
| 总准确率 Wilson 95% 下界 | ≥ 85% |
| Macro-F1 | ≥ 85% |
| 假阳类 F1 | ≥ 85% |
| 覆盖率 | ≥ 90% |

`待查` 只是一种模型预测，在总准确率中按照错误计算。不能用“排除待查后的选择性准确率”代替总准确率。

## 四、ToN_IoT 工业互联网双模态验证

### 1. 接入的数据

新增 `backend/app/data/ton_iot.py`，接入：

- 211,043 条 ToN_IoT 网络流记录。
- 287,194 条 ToN_IoT Modbus 工业设备遥测记录。

构造程序生成 2,000 条冻结外部验证样本：

| 模态 | 真阳 | 假阳 | 总数 |
|---|---:|---:|---:|
| 网络流 | 500 | 500 | 1000 |
| Modbus 遥测 | 500 | 500 | 1000 |

攻击样本覆盖 backdoor、DDoS、DoS、injection、MITM、password、ransomware、scanning 和 XSS。

### 2. 工具接入

- 网络流样本可调用 `inspect_alert_context` 和 `fetch_network_flows`。
- Modbus 样本可调用 `inspect_alert_context` 和 `fetch_endpoint_logs`。
- 多智能体协调器先根据告警、当前假设和 `evidence_capabilities` 自主规划，再由框架过滤掉不可用、越权、重复或目标不合法的任务。
- ToN_IoT 正式样本不会使用项目内置的演示 Mock 证据。

### 3. 必须保留的限制说明

公开的 `train_test_network.csv` 没有原始时间戳，因此无法与 Modbus 遥测建立可信的跨源时间关联。

本项目只把 ToN_IoT 用作：

- 工业互联网网络流和设备遥测双模态覆盖验证。
- 工具路由验证。
- 跨数据集、跨场景泛化验证。

不能把当前 ToN_IoT 验证集描述为“同一攻击事件的跨源关联案例集”，也不能把它的准确率与 AIT-ADS 冻结测试集混合计算。

## 五、评测集页面与命令行接入

评测数据集目录现在支持读取一层嵌套目录。生成正式数据后，可以在前端批量评测页面直接选择：

- AIT-ADS development。
- AIT-ADS validation。
- AIT-ADS frozen test。
- ToN_IoT industrial external validation。

构造 AIT-ADS 正式评测集：

```bash
cd backend
uv run python -m app.data.catalog prepare-ait-event-gold
```

构造 ToN_IoT 工业外部验证集：

```bash
cd backend
uv run python -m app.data.catalog prepare-ton-iot
```

运行指定评测集的示例：

```bash
cd backend
uv run python -m app.eval.run \
  --dataset ../data/processed/ait_ads_event_gold/ait_ads_event_gold_validation.json \
  --strategy multi_agent
```

## 六、主要代码变更

| 文件 | 作用 |
|---|---|
| `backend/app/data/ait_event_gold.py` | AIT-ADS 事件/时间一致的正式评测集构造器与证据存储 |
| `backend/app/data/ton_iot.py` | ToN_IoT 网络流和 Modbus 双模态冻结验证集构造器 |
| `backend/app/data/source_catalog.json` | 固定数据来源、版本和完整性校验信息 |
| `backend/app/data/catalog.py` | 增加两套正式评测集的一键构造命令 |
| `backend/app/agent/tools.py` | 接入 AIT 官方证据、ToN_IoT 网络流和 Modbus 遥测工具 |
| `backend/app/agent/multi_agent.py` | 多智能体自主规划、专业取证、观察反馈和动态重规划 |
| `backend/app/agent/prompts.py` | 增加证据类型、ToN_IoT 时间限制和禁止夸大规则 |
| `backend/app/eval/metrics.py` | 增加 Wilson 下界与可信 85% 组合门槛 |
| `backend/app/eval/dataset.py` | 支持前端发现和选择嵌套目录中的正式评测集 |
| `docs/FORMAL_EVALUATION_PROTOCOL.md` | 完整评测口径、数据拆分和发布表述规范 |

## 七、测试与审计结果

- 不调用真实模型的后端回归测试：128 项通过。
- AIT 三个拆分之间不存在案例 ID 重叠。
- 四个正式数据文件都可以被统一评测加载器读取。
- Agent 可见数据中不存在 `label` 和 `type` 真值字段。
- ToN_IoT 网络与 Modbus 原始文件通过固定版本完整性校验。
- 数据集目录能够发现全部三个 AIT 正式拆分和 ToN_IoT 外部验证集。

## 八、2026-09-10 SuperAgent 自主闭环升级

- 多智能体与 ReAct 已合并为同一执行链，不再二选一。
- 首轮任务由模型根据告警和真实证据能力自主制定，不再按固定顺序派工。
- 每次专业智能体返回工具观测后，协调器会重新判断下一步：继续原路线、改查其他证据，或进入最终验证。
- 任务只有通过工具所有权、数据能力、真实查询目标、重复调用和步数预算校验后才会执行。
- 前端会展示自主重规划次数，流式事件会显示“协调器根据新证据重新规划”。
- 本次仍只生成封禁、隔离或加白建议工单，不会真实调用防火墙或 EDR；这是后续第三个问题的范围。

## 九、数据文件为什么没有直接提交到 Git

AIT-ADS 原始归档仍由 `.gitignore` 排除；为了保证克隆或部署仓库后前端可以直接发现正式评测集，仓库现在随附已经构造完成的三个 AIT-ADS 分片及其 1,800 份案例证据：

- `data/processed/ait_ads_event_gold/ait_ads_event_gold_development.json`（600 条）
- `data/processed/ait_ads_event_gold/ait_ads_event_gold_validation.json`（200 条）
- `data/processed/ait_ads_event_gold/ait_ads_event_gold_test_frozen.json`（1,000 条）
- `data/processed/ait_ads_event_evidence/event-gold-v1-20260819/`（案例证据）

仓库同时提交：

- 可复现的数据下载与完整性验证信息。
- 确定性数据构造代码。
- 固定拆分、去重和标签隔离规则。
- 测试与正式评测协议。

使用前述 `prepare-*` 命令仍可在本地从官方原始数据重新生成相同的评测结构。ToN_IoT 外部验证集可继续按需构造；已部署环境中已有的 ToN_IoT 文件不会被覆盖。

## 十、当前可以和不可以宣称的结果

可以宣称：

> 项目已经完成 AIT-ADS 事件级正式评测基础设施，并接入 ToN_IoT 网络流与 Modbus 遥测双模态工业外部验证。

当前不可以宣称：

> 模型已经达到可信 85%。

只有在最终模型、Prompt 和阈值全部冻结后，真实运行 1000 条 AIT-ADS 冻结测试集并通过全部组合门槛，才可以发布该结论。
