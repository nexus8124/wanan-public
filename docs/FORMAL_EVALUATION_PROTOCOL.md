# 正式评测协议：AIT-ADS 可信 85% 与 ToN_IoT 工业外部验证

## 1. 结论口径

本项目使用两条互相独立、不能混算的评测线：

1. **AIT-ADS-EVENT-GOLD** 是正式主评测。它用于判断系统是否达到“可信 85%”。
2. **ToN_IoT-INDUSTRIAL** 是工业互联网外部验证。它用于验证网络流和 Modbus 遥测接入、工具路由与跨域泛化，不用于替代 AIT-ADS 的 85% 结论。

只有冻结的 AIT-ADS 测试集同时通过准确率、统计下界、Macro-F1、负类 F1 和覆盖率门槛，才允许对外表述“达到可信 85%”。开发集或验证集成绩、选择性准确率、ToN_IoT 成绩均不能替代该结论。

## 2. AIT-ADS 事件级正式评测集

### 2.1 数据来源与真值

- AIT-ADS 原始数据：<https://zenodo.org/records/8263181>
- 官方事件标签生成仓库：<https://github.com/ait-aecid/alert-data-set>
- 固定版本：`ce927ddaeaa674f6909e1de676fa7dc293e393bd`
- `alerts_csv.zip` SHA-256：`2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3`

正式二分类标签要求时间标签和事件标签一致：

- 真阳：处于攻击时间窗，且存在由 Wazuh/AMiner 原始日志匹配或 Suricata 五元组时间匹配得到的事件标签。
- 假阳：处于 `false_positive` 时间窗，且没有事件标签。
- 冲突：时间标签和事件标签不一致，全部排除。

全量扫描 2,655,821 条官方记录；排除 91,755 条冲突记录，其中“攻击时间窗但无事件”19,543 条，“攻击窗外却有事件”72,212 条。案例化之前符合一致性规则的记录为 2,564,066 条。

### 2.2 案例去重和拆分

案例键为：

```text
(scenario, detector, rule_name, host, ip, 1-minute bucket)
```

它把同一检测器在同一资产、同一规则、同一分钟内产生的告警风暴合并为一个案例。共去除 2,434,129 条重复案例记录。

拆分按场景隔离，固定种子为 `20260819`：

| 集合 | 场景 | 真阳 | 假阳 | 总数 | 用途 |
|---|---|---:|---:|---:|---|
| development | fox、shaw、wardbeck | 300 | 300 | 600 | Prompt、规则和流程开发 |
| validation | santos、wheeler | 100 | 100 | 200 | 阈值选择和预验收 |
| test_frozen | harrison、russellmitchell、wilson | 500 | 500 | 1000 | 一次性正式验收 |

正类采用攻击事件类型分层轮转抽样，并限制单一事件类型不超过正类的 60%。测试集在正式验收前不得用于 Prompt 修改、阈值选择或错误案例迭代。

### 2.3 防泄漏与真实证据

- `alerts` 中不含 `label`、事件标签或时间标签。
- `ground_truth` 与 Agent 输入分离，评测器只在推理结束后读取。
- 每个案例通过不透明 `_evidence_ref` 关联独立证据文件。
- 证据文件只包含官方检测器记录和标签无关的前后 300 秒邻域统计。
- Wazuh/AMiner 作为主机侧检测记录；Suricata 作为网络告警。没有完整 NetFlow 时，工具必须明确说明，不能把网络告警称为 NetFlow。
- `待查` 是模型预测，不是真值类别，在总准确率中计错。

### 2.4 可信 85% 门槛

冻结测试集 1000 条必须同时满足：

| 指标 | 门槛 |
|---|---:|
| 总准确率 | ≥ 0.88 |
| 总准确率 Wilson 95% 置信下界 | ≥ 0.85 |
| Macro-F1 | ≥ 0.85 |
| 假阳类 F1 | ≥ 0.85 |
| 覆盖率（非待查比例） | ≥ 0.90 |

将点估计门槛设为 88% 是为了让 1000 条样本的 Wilson 95% 下界能够超过 85%。验收报告必须同时给出混淆矩阵、待查数、覆盖率、Wilson 下界、模型名、温度、Prompt 版本、代码提交和数据文件 SHA-256。

### 2.5 构造与运行

```bash
cd backend
uv run python -m app.data.catalog prepare-ait-event-gold

# 开发集调试
uv run python -m app.eval.run \
  --dataset ../data/processed/ait_ads_event_gold/ait_ads_event_gold_development.json \
  --strategy multi_agent

# 验证集预验收
uv run python -m app.eval.run \
  --dataset ../data/processed/ait_ads_event_gold/ait_ads_event_gold_validation.json \
  --strategy multi_agent

# 冻结测试集：最终版本才运行
uv run python -m app.eval.run \
  --dataset ../data/processed/ait_ads_event_gold/ait_ads_event_gold_test_frozen.json \
  --strategy multi_agent
```

## 3. ToN_IoT 工业互联网多源外部验证

### 3.1 数据来源

官方项目页：<https://research.unsw.edu.au/projects/toniot-datasets>。本项目使用固定提交的公开镜像，并对文件做 SHA-256 校验：

| 模态 | 文件 | 行数 | 固定版本 | SHA-256 |
|---|---|---:|---|---|
| 网络 | `train_test_network.csv` | 211,043 | `LalitKJ/Network-Intrusion-Detection@45152c3e` | `3019999cb8a94172c2d24bdaa5cec64ffa308768ae3835938b786eb42657405d` |
| 工业遥测 | `IoT_Modbus.csv` | 287,194 | `SHVleV9CYWkK/IoT-anomaly-detection@770a7d74` | `1cdb245661db3f15be52c3e8aeba5b1a3af37b8eed3f9132a7f1a03d8111aa16` |

UNSW 官方说明允许永久免费的学术研究使用；商业使用需要联系数据集作者取得许可，并应引用官方论文。

### 3.2 冻结外部验证集

构造结果共 2,000 条：

| 模态 | 真阳 | 假阳 | 总数 |
|---|---:|---:|---:|
| 网络流 | 500 | 500 | 1000 |
| Modbus 遥测 | 500 | 500 | 1000 |

正类按攻击类型轮转分层；样本覆盖 backdoor、DDoS、DoS、injection、MITM、password、ransomware、scanning 和 XSS。完全相同的可见源记录被去重；二进制标签和攻击类型只保存在 `ground_truth` 中。

网络 Train_Test 文件没有时间戳，因此本项目为满足统一 Alert schema 仅生成“保持源行顺序”的合成时间。这个时间不能用于攻击时序、跨源关联或延迟分析。网络记录与 Modbus 记录也不能被描述成同一事件的两份独立旁证。

### 3.3 工具接入

- 网络样本：`inspect_alert_context` + `fetch_network_flows`，返回该条真实 Zeek/Argus 特征记录。
- Modbus 样本：`inspect_alert_context` + `fetch_endpoint_logs`，返回该条真实设备遥测，并明确它不是独立 EDR 日志。
- ToN_IoT 正式样本不会回退到演示 Mock 威胁情报或 Mock 历史告警。
- 多智能体协调器根据告警和 `evidence_capabilities` 自主生成计划；每次工具观测后动态重规划，且只执行通过能力、权限、目标、去重和预算校验的任务。

构造和运行：

```bash
cd backend
uv run python -m app.data.catalog prepare-ton-iot
uv run python -m app.eval.run \
  --dataset ../data/processed/ton_iot_industrial/ton_iot_industrial_external_validation.json \
  --strategy multi_agent
```

ToN_IoT 报告标题建议使用“工业互联网网络流与 Modbus 遥测双模态外部验证”，不要写成“跨源事件级关联评测”。

## 4. 推荐发布表述

通过 AIT 冻结门槛后：

> 本系统在场景隔离、事件/时间标签一致的 1000 条 AIT-ADS 冻结案例上，总准确率、Wilson 95% 下界、Macro-F1、负类 F1 和覆盖率同时通过可信 85% 门槛；并在 2000 条 ToN_IoT 网络流与 Modbus 遥测冻结记录上完成工业互联网双模态外部验证。

未通过或尚未运行冻结测试时：

> 已完成可信 85% 的正式评测基础设施和冻结测试集构造；当前结果尚不足以宣称模型达到 85%。
