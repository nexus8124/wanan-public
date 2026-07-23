# zzb 分支阶段版本优化说明（2026-07-23）

数据集来源与下载

### AIT Alert Data Set（AIT-ADS）

- 官方发布页：<https://zenodo.org/records/8263181>
- DOI：<https://doi.org/10.5281/zenodo.8263181>
- 数据压缩包：<https://zenodo.org/records/8263181/files/ait_ads.zip?download=1>
- 标签文件：<https://zenodo.org/records/8263181/files/labels.csv?download=1>
- 官方代码：<https://github.com/ait-aecid/alert-data-set>
- 许可证：Creative Commons Attribution 4.0 International（CC BY 4.0）
- `ait_ads.zip` MD5：`43db6b1f0996e0024befd617706c50e9`
- `labels.csv` MD5：`60ff33796c77fd2136c4d1a4bc841bd9`

### Cyber Attack Manifestations Log Data Set（CAM-LDS）

- 官方发布页（v2）：<https://zenodo.org/records/18861762>
- DOI：<https://doi.org/10.5281/zenodo.18861762>
- 本项目使用的过滤数据：
  <https://zenodo.org/records/18861762/files/manifestations_filtered.zip?download=1>
- 官方处理与 LLM 实验代码：
  <https://github.com/ait-aecid/attack-manifestations-interpretation>
- 论文：<https://arxiv.org/abs/2603.04186>
- 许可证：Creative Commons Attribution 4.0 International（CC BY 4.0）
- `manifestations_filtered.zip` MD5：`cfc14140b2e396a60989b8379eafca1f`
## 版本范围

- 对比基线：`bc4bebe`（增加流式评测、历史持久化及第三方模型兼容）
- 目标分支：`zzb`
- 阶段目标：建立可信评测基线，完成受控 ReAct 执行层，并接入真实多源安全数据 Pilot
- 下一阶段：RAG 安全知识库与同样本 A/B 实验

本文记录的是上次推送 `zzb` 分支后产生的改动。原始数据集、派生评测集、
SQLite 评测历史、上传文件、`.env` 和 API Key 均不属于本版本源码。

## 一、可信评测基线

### 1. AIT-ADS 数据适配

- 新增 AIT-ADS 适配器，支持流式读取 Wazuh、Suricata、AMiner JSONL。
- 使用 `labels.csv` 的攻击时间窗生成弱标签评测集，不使用告警文本猜测标签。
- 按场景、检测器和攻击阶段分层抽样，固定随机种子，保证实验可复现。
- 为入选告警建立前后时间窗的无标签检测器上下文，恢复扫描、暴破等频率证据。
- 告警 ID 改为稳定 UUID，不再使用带答案暗示的 `TP-*`、`FP-*`。
- Alert 与 `ground_truth` 分区保存；标签只进入指标计算，不传给 Agent。

当前冻结的 50 条 Judge-only、No-RAG 基线：

| 指标 | 结果 |
|---|---:|
| Accuracy | 72.00% |
| Precision | 91.30% |
| Recall | 84.00% |
| F1 | 87.50% |
| Macro-F1 | 78.63% |
| Coverage | 82.00% |
| 已决准确率 | 87.80% |

该结果使用攻击时间窗弱标签，只用于后续同口径对比，不等同于事件级最终准确率。

### 2. 标准数据集协议

- 新增统一评测数据加载器，兼容旧式内嵌标签和推荐的标签分离格式。
- 支持环境变量指定默认数据集。
- 支持页面列出、选择和上传标准评测 JSON。
- 上传文件限制为 25 MiB，文件名经过清理并附加内容哈希。
- 支持 10、20、50、100 或全部样本预算。
- 有正负样本时按标签均衡抽样，降低类别不平衡造成的指标误导。
- 数据集元信息保存标签依据、种子、上下文版本和风险提示。

## 二、受控 ReAct 执行层

### 1. 统一工具协议

新增以下抽象：

- `AgentTool`：统一异步工具入口；
- `ToolContext`：告警、样本和截止时间上下文，不包含评测标签；
- `ToolResult`：统一返回状态、证据、来源、耗时、重试次数和错误；
- `Evidence`：为每条可引用观测生成稳定 `EV-*` 编号；
- `ControlledToolExecutor`：统一处理参数校验、重复调用、超时和重试。

工具状态统一为：

- `found`
- `not_found`
- `timeout`
- `failed`
- `invalid_arguments`

其中 `not_found` 只代表当前数据源未找到记录，不再被错误解释为“安全”。

### 2. 执行护栏

新增可配置护栏：

- 最大工具步数；
- 单工具超时；
- 单样本全局超时；
- 工具失败重试；
- LLM 调用预算；
- 估算 Token 预算；
- 连续无证据退出阈值；
- 相同工具与参数的重复调用拦截。

模型客户端也使用全局超时作为兜底，防止中转服务或外部接口长期无响应。

### 3. 证据引用与实时轨迹

- ReAct 结论只能引用实际存在且可用的 `evidence_id`。
- 最终结果保存完整证据、引用列表、执行策略和退出原因。
- SSE 新增 Agent 内部事件：
  `sample_started → preprocess_completed → judge_completed → decision_updated → tool_started → tool_completed → disposition_completed → sample_completed`。
- 每个事件在推送前写入 SQLite；评测中断后，已完成样本及其内部轨迹仍可查看。
- 历史记录新增策略、模型、Prompt 版本、数据集元信息、初判指标和同轮 ReAct 对比。

### 4. Judge-only 与 ReAct 配对评测

- `judge_only`：每条样本只进行 Judge 调用，作为无工具、无 RAG 基线。
- `react`：运行完整多轮工具链。
- 同一次 ReAct 运行同时保存初判和最终判定，统计修正数、退化数和准确率净变化。
- 记录每条样本及整轮实验的 LLM 调用数、输入/输出 Token 和延迟。

## 三、CAM-LDS 多源证据 Pilot

- 新增 CAM-LDS 适配器，将同一攻击步骤内的 Wazuh 与 Suricata 告警聚合为关联案例。
- 接入真实端点 `audit/auth/syslog` 等日志。
- 接入 Suricata `fast.log` 网络检测证据，并明确标记其不是完整 NetFlow。
- AttackMate 仅用于独立 ground truth，不进入 Agent 输入或工具证据。
- 工具查询使用真实 hostname/IP，不再误用检测器管理地址。
- 端点日志优先返回 EXECVE、SYSCALL、命令、认证等高价值记录。
- ReAct 只允许调用案例真实具备的数据源，避免演示用 Mock 情报污染正式评测。
- Pilot 按防守侧可观测性排序并按场景轮询抽样，不读取 ground truth 做样本排序。

修复后的同样本 10 条 CAM-LDS ReAct 验证：

| 指标 | 结果 |
|---|---:|
| 同轮初判准确率 | 50.00% |
| ReAct 最终准确率 | 70.00% |
| 净变化 | +20 个百分点 |
| 修正 | 2 |
| 退化 | 0 |
| 攻击召回率 | 70.00% |
| 待查率 | 20.00% |
| 已决准确率 | 87.50% |

这批 CAM-LDS 样本全部来自受控攻击步骤，因此主要评价攻击召回和证据融合，
不能单独用于证明误报率或完整分类准确率。

## 四、指标与前端改进

- 修正“假阳被判待查仍计为 TN”的指标错误。
- 待查拆分为真实真阳待查和真实假阳待查。
- 新增 Coverage、Selective Accuracy、Macro-F1、Negative-F1。
- 混淆矩阵单独展示明确误判和两类待查。
- 评测页新增数据集选择、上传、样本预算和策略选择。
- 真实评测过程中实时显示最近的 Agent 节点和工具事件。
- 历史列表显示策略、模型、Prompt、Macro-F1、调用数和 Token。
- 样本明细显示完整 ReAct 流程、证据、调用数和 Token。

## 五、重点缺陷修复

### 第三方 OpenAI 兼容接口增强

- 在 `.env.example` 中补充官方/兼容接口 `base_url` 和 thinking 开关说明。
- 为 DeepSeek、Qwen 客户端增加请求超时兜底，并与 ReAct 全局时限保持一致。
- 本版本不会提交本机 `.env`、个人 API Key 或个人中转站地址。

### ReAct 准确率退化

- 移除 `analysis/reasoning` 的 300 字符限制，避免有效结构化响应因内容稍长而失败。
- 将 Judge 当前判定、置信度和理由传入 ReAct，避免每轮从头判断。
- 工具仍待执行时只保存候选判断，不再把临时“待查”提交为最终结果。
- 解析失败时继续执行剩余真实证据查询，不再直接中断工具链。
- 解析失败、超时或预算耗尽不再把已提交结论强制改为“待查”。
- 工具无记录、失败或不可用不能单独推翻现有攻击证据。

### 数据与评测安全

- Agent 输入移除标签、私有证据路径和内部定位字段。
- Mock 工具不再通过告警 ID 的 `TP/FP` 前缀读取答案。
- `.gitignore` 增加上传数据集、当前数据集选择、派生数据、历史数据库和向量库。
- `.env.example` 只包含空 Key 和官方默认地址，不包含个人中转站信息。

## 六、验证结果

- 后端完整测试：`78 passed`
- 最终相关回归测试：`36 passed`
- 新增数据适配、指标、评测历史、受控工具、图路由和解析容错测试。
- `git diff --check` 通过。

提交前仍应执行：

```powershell
cd backend
uv run pytest -q

cd ../frontend
npm.cmd run build
```

上述检查均不调用真实模型，不消耗 API Token。

## 七、已知限制与下一阶段

- AIT-ADS 当前是攻击时间窗弱标签，不是事件级精确标签。
- CAM-LDS 当前 Pilot 缺少同构的良性业务案例，不能独立评估误报率。
- Suricata `fast.log` 是网络检测告警，不是完整 NetFlow。
- RAG 尚未启用，当前实验配置固定记录 `rag_enabled=false`。
- 剩余待查样本中一部分确实缺少足够端点/网络证据，RAG 只能补充知识，不能伪造遥测。

下一阶段将在本版本上增加 MITRE ATT&CK、Sigma、CVE 和处置手册知识库，并保持
相同数据集、模型、温度和 Prompt 口径，执行 No-RAG 与 RAG 的同样本 A/B 对比。

## 建议提交信息

```text
feat: 建立可信评测基线并完善受控 ReAct 多源证据链
```
