# AIT-ADS 第一阶段评测基线

已完成的 50 条 Judge-only 正式基线见
[AIT-ADS-50 Judge-only No-RAG Baseline v1](experiments/AIT_ADS_50_JUDGE_ONLY_BASELINE_V1.md)。

本项目支持将 AIT Alert Data Set（AIT-ADS）的 Wazuh、Suricata、AMiner JSONL
告警转换为统一 `Alert`，并生成可复现、类别均衡的小型评测集。

## 数据与真值边界

- 数据来源：<https://zenodo.org/records/8263181>
- DOI：`10.5281/zenodo.8263181`
- 许可证：CC BY 4.0
- 原始数据不复制进仓库，派生数据默认写入被 Git 忽略的 `data/processed/`。
- `labels.csv` 只标记攻击阶段的开始/结束时间，所以当前真值为
  `time_window_weak`（攻击时间窗弱标签），不是精确的事件因果标签。
- 如需精确 `event_label`，还要下载 AIT-LDSv2/AIT-NDS，并按官方脚本把原始日志行或
  NetFlow 与告警匹配。当前代码不会用规则名或告警文本猜测精确标签。

## 为什么标签不会泄漏

生成文件采用两个独立区域：

```json
{
  "alerts": [{"alert_id": "UUID", "description": "..."}],
  "ground_truth": {
    "UUID": {"label": "真阳", "attack_phase": "network_scans"}
  }
}
```

评测加载器先拆分两者，只把无 `label` 的 `Alert` 传给 Agent。告警 ID 使用稳定 UUID，
不会再出现 `TP-001`、`FP-001` 这类携带答案的前缀。

Mock ReAct 工具也不再通过告警 ID 或标签决定返回攻击/正常证据。适配器会进行第二遍
流式扫描，为每个入选告警保存前后 5 分钟内的事件数、同规则次数、常见源 IP 和少量
邻近事件。该上下文只来自原始检测器日志，不读取 `labels.csv`，因此能够恢复扫描/暴破等
频率证据，同时不会把真值泄漏给 Agent。AIT-ADS 的 ReAct 流程优先读取这份上下文。

## 生成 400 条试验集

在 `backend` 目录运行（按本机目录调整路径）：

```powershell
uv run python -m app.data.ait_ads `
  --source "D:\path\to\dataset\ait_ads" `
  --labels "D:\path\to\dataset\labels.csv" `
  --per-class 200
```

默认输出：

```text
data/processed/ait_ads_eval.json
```

抽样使用固定种子，并按场景、检测器和攻击阶段分层，避免样本全部被高频 `dirb` 告警占据。
随后会再次流式读取原始文件生成无标签邻近上下文，因此首次生成需要几分钟；重新执行同一
命令会得到相同样本。

## 启用 AIT-ADS 评测集

在项目根目录 `.env` 添加：

```dotenv
EVAL_DATASET_PATH=data/processed/ait_ads_eval.json
```

也可以启动前后端后，直接在“批量评测”页面的数据集下拉框中选择生成的 AIT-ADS
数据集。页面选择会保存在本机 `data/active_eval_dataset.json`，优先于 `.env`，重启后仍然有效。

页面还支持上传不超过 25 MiB 的标准评测 `.json`：

- 旧格式：告警数组中的每条记录包含 `label`；
- 推荐格式：顶层分别包含 `alerts` 和独立的 `ground_truth`；
- AIT-ADS 的原始 JSONL 不是标准评测 JSON，需要先运行本页前面的适配命令。

上传文件保存在被 Git 忽略的 `data/uploaded/`，文件名会经过清理并附加内容哈希，
不会覆盖源码或被 Git 提交。

随后可先做不消耗 Token 的链路检查：

```powershell
cd backend
uv run python -m app.eval.run --mock --no-save
```

Mock 结果只验证数据加载、Agent、指标和历史保存链路，不能代表业务准确率。

确认链路正常后运行真实基线（会调用配置的模型并消耗 Token）：

```powershell
uv run python -m app.eval.run --strategy judge_only --limit 50 --no-save
```

网页可直接选择 10/20/50/100/全部样本预算；命令行使用 `--limit`。子集会按真阳/假阳
均衡抽取，标签只用于评测采样，不会传给 Agent。建议先跑 10–20 条，再逐步扩大。

第一阶段基线必须选择 `Judge-only（无工具基线）`：每条样本只调用一次模型，不进入
ReAct，也不调用 RAG/查询工具。历史记录会保存策略、模型、温度、Prompt 版本、数据集
种子与上下文版本，并累计模型调用数和 API 返回的 Token 用量。若中转 API 不返回 usage，
Token 会显示为 0，但调用次数仍会记录。

第二阶段对比时再选择 `完整 ReAct（多轮调用）`。这样可以分别回答“模型自身效果”和
“工具壳带来的增益/成本”，避免把两者混成一个基线。

ReAct 最多调用 3 个工具，并阻止相同参数的重复调用。这个限制控制无效循环成本，但一条
低置信样本仍可能产生多轮模型请求，历史页面应同时观察平均延迟、待查率和覆盖率。

报告至少同时记录 Accuracy、正类 F1、Macro-F1、Coverage、待查分布、平均延迟、LLM
调用数和 Token。正类 F1 只衡量真阳类别；当假阳被判为待查时它可能仍为 100%，因此
不能脱离 Macro-F1 和 Coverage 单独汇报。

## 当前基线的解释

AIT-ADS 告警发生在攻击时间窗内时记为“真阳”，窗外记为“假阳”。攻击时间窗内仍可能
混有与攻击无关的正常告警，因此这一阶段的指标应该标注为“弱标签基线”。它适合发现明显
泛化问题、验证多源适配和对比后续 RAG/ReAct 改动，但不能替代人工复核或事件级真值实验。
