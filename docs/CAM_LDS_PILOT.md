# CAM-LDS 多源证据 Pilot

## 目标

CAM-LDS Pilot 用于验证 ReAct 是否能通过真实的检测告警、主机日志和网络告警完成证据融合。它不替代 AIT-ADS 的真阳/假阳基线。

当前接入的数据源：

- Wazuh `alerts.json` 与 Suricata `fast.log`：聚合成一个攻击步骤级关联案例，并供 `inspect_alert_context` 查询；不再用任意单条告警代表整个步骤。
- 主机 `audit.log`、`auth.log`、`syslog` 等：供 `fetch_endpoint_logs` 查询。
- Suricata `fast.log`：同时供 `fetch_network_flows` 返回按真实通信 IP 匹配的网络检测证据。
- AttackMate `attackmate.json`：只用于 ground truth，不进入 Agent 或工具证据。

`manifestations_filtered` 不包含完整 NetFlow/eve.json，因此当前网络工具会明确返回 `netflow_available=false`，不能将 Suricata 告警描述为完整流量基线。

## 生成 Pilot

在 `backend` 目录运行：

```powershell
uv run python -m app.data.cam_lds `
  --source "D:\学习资料\挑战杯\dataset\manifestations_filtered" `
  --max-cases 40
```

默认生成：

- `data/processed/cam_lds_pilot.json`：Alert 与独立 ground truth。
- `data/processed/cam_lds_evidence/pilot-20260722/`：不含标签的工具证据库。

这两个目录已经被 `.gitignore` 忽略，不会提交原始数据、本机路径或生成结果。

## 页面运行

重启后端后打开“批量评测”，数据集列表中选择 `CAM-LDS correlated attack-step pilot v2`。

建议先运行：

1. `Judge-only`：记录只看同一时间窗内关联告警集合时的攻击召回率。
2. `完整 ReAct`：查询检测器上下文，并按 `recommended_queries` 获取所有实际存在的端点/网络证据源。
3. 比较召回率、待查率、证据引用、Token 和延迟。

## 结果解释

当前 Pilot 40 条均来自受控攻击步骤，不能单独计算有意义的误报率或精确率。重点指标应是：

- 攻击召回率；
- 待查比例；
- 工具成功率；
- 可用证据引用率；
- Judge → ReAct 的修正与退化；
- 每条样本的 Token 和延迟。

后续应加入具有同构主机/网络证据的正常业务案例，再计算完整 Accuracy、Precision、Recall 和 F1。不要直接把 AIT-ADS 假阳与 CAM-LDS 真阳拼接后宣称是最终准确率，因为模型可能利用两个数据集的格式差异识别来源。

## 无标签泄漏约束

- Alert ID 使用确定性 UUID，不含 TP/FP、场景号或技术号。
- Agent 看不到证据文件路径和 evidence reference。
- 工具证据库不写入 label、AttackMate 命令、scenario、technique。
- `techniques/` 与 `sequences/` 目录不作为输入，避免重复和技术编号泄漏。
- Wazuh 自身产生的 MITRE 映射属于检测器原生字段，允许作为告警证据，但与 AttackMate ground truth 分开保存。

## v2 评测有效性修复

- 评测单位从“步骤目录中任意一条高等级告警”改为“受控攻击步骤关联案例”。
- detector events 按完全不读取 ground truth 的信号评分聚合，保留多检测器一致性和重复频率。
- Pilot 按防守侧可观测性排序后再按场景轮询抽样，避免随机抽中只有普通 PAM/协议噪声的案例。
- 端点日志不再截取每个文件开头，而是优先返回 EXECVE、SYSCALL、命令、认证等高价值记录。
- 没有 IP 映射的主机使用真实 hostname 查询，不再猜测检测器管理 IP。
- CAM-LDS ReAct 只允许调用现有真实证据能力，不再调用 Mock 威胁情报或历史告警。

## 同样本配对验证

本地同时生成了 `cam_lds_paired_legacy10_v2.json`，对应首次 v1 评测使用的相同 10 个 AttackMate 步骤。页面显示名为 `CAM-LDS paired legacy-10 attack-step v2`。

先在这个配对集上重新运行 Judge-only 和 ReAct。由于底层攻击步骤不变，和旧结果的差异主要来自：关联案例构建、日志排序、查询目标及能力路由修复。再运行 40 条主 Pilot，用于观察按防守侧可观测性选择后的整体攻击召回率。
