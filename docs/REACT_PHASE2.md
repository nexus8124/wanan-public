# 第二阶段：受控 ReAct 执行层

本阶段把原先“LLM 直接选择 Python 函数”的演示循环，改造成可约束、可追溯、可中断恢复的 Agent 执行层。原工具业务函数仍保留在 `backend/app/agent/tools.py`，外部由统一协议包装。

## 统一协议

- `AgentTool.execute(arguments, context)`：所有工具共享的异步入口。
- `ToolContext`：只携带告警、运行/样本标识和截止时间，不包含评测标签。
- `ToolResult`：固定返回 `status / evidence / source / latency_ms / attempts / error`。
- `Evidence`：每条观测都有稳定 `evidence_id`、来源、时间、摘要、置信度和原始数据。
- `Evidence.usable`：只有 `found` 观测可用于结论引用；无记录/失败结果只保留作审计。

工具状态只有：

- `found`：返回了可使用的观测；
- `not_found`：当前数据源没有记录，不等于安全；
- `timeout`：超过单工具或全局剩余时间；
- `failed`：工具内部异常；
- `invalid_arguments`：未知工具、缺少必填参数或重复调用。

## 执行护栏

默认值可在根目录 `.env` 中覆盖：

| 配置 | 默认值 | 作用 |
|---|---:|---|
| `REACT_MAX_STEPS` | 3 | 单样本最多工具轮数 |
| `REACT_TOOL_TIMEOUT_S` | 10 | 单工具超时 |
| `REACT_GLOBAL_TIMEOUT_S` | 120 | 单样本全局截止时间 |
| `REACT_TOOL_RETRIES` | 1 | 异常/超时后的最大重试次数 |
| `REACT_MAX_LLM_CALLS` | 5 | Judge + ReAct 决策调用预算 |
| `REACT_MAX_ESTIMATED_TOKENS` | 30000 | 运行中跨 Provider 的估算预算 |
| `REACT_MAX_NO_EVIDENCE` | 2 | 连续无有效证据后的受控退出阈值 |

真实 Token 用量仍由 LangChain 回调精确写入评测结果；运行中的 Token 上限采用字符数保守估算，因此报告同时保留“估算预算”和“真实用量”。每次模型请求同时接收当前全局预算的剩余秒数，客户端以此中止超时请求。浏览器中止后，不再启动下一条样本；已经完成的样本与 Agent 事件不会丢失。

## 证据与退出语义

- 威胁情报未命中现在返回 `not_found` 和 `malicious=null`，不再错误表达为“干净 IP”。
- AIT-ADS 未包含独立 EDR、NetFlow、实时情报和历史告警库；这些工具现在明确返回数据源不可用，不再把同一检测器时间窗重复包装成多源证据，也不会使用演示夹具污染正式评测。
- ReAct 输出新增 `cited_evidence`，只能引用证据列表中存在的 `EV-*` 编号。
- 最终结果保留全部 `evidence`、引用列表、是否有证据支撑以及执行预算/退出原因。
- 达到时间、LLM 调用、Token 或无证据上限时，Agent 受控退出为“待查”，交给人工复核。

## 实时事件与历史

批量评测新增 `agent_event` SSE，事件顺序包括：

`sample_started → preprocess_completed → judge_completed → decision_updated → tool_started → tool_completed → disposition_completed → sample_completed`

每个事件在推送前写入 SQLite 的 `eval_events` 表。历史详情 API 同时返回 `details` 和 `events`，所以评测中断前的样本结果与内部轨迹均可恢复。前端批量评测页会实时显示最近的 Agent 轨迹，样本详情继续展示完整 ReAct 工具证据。

## 同轮配对评测

完整 ReAct 运行会同时保存每条样本的 `initial_judgment` 和最终判定，并输出：

- 初始 Judge 准确率与最终 ReAct 准确率；
- 修正数、退化数、改变但仍错误数；
- 净修正数和准确率百分点变化。

该指标使用同一次请求链路，避免把两次独立模型运行的随机波动误认为 ReAct 收益。独立的 `judge_only` 运行仍用于整体成本基线，但判断 ReAct 是否有效应优先看同轮配对结果。

## 验证

```powershell
cd backend
uv run pytest -q

cd ../frontend
npm run build
```

这些验证使用 Mock 和本地工具，不调用真实模型。完成本阶段后，应使用第一阶段固定的 50 条样本分别运行 `judge_only` 与 `react`，比较准确率、Macro-F1、覆盖率、实际 Token、LLM 调用数和延迟；不要用不同样本集做横向结论。
