# XH-202614 · AI+安全大模型平台的智能体研究

> 本次正式评测与 ToN_IoT 接入的完整中文说明：[README_UPDATE_20260819_CN.md](README_UPDATE_20260819_CN.md)

> **挑战杯揭榜挂帅** · 发榜单位：深信服科技 · 截止 2026.09.05
> 核心场景：**SOC 告警误报剔除**｜核心技术：LangGraph + DeepSeek + RAG + ReAct + Multi-Agent

一个 LangGraph 状态机图，分层递进覆盖赛题基础/进阶/挑战三层任务：

| 任务                           | 节点                                     | 进度  |
| ------------------------------ | ---------------------------------------- | ----- |
| 🥉 基础（70 分）告警研判 Agent | preprocess → judge → output            | ✅    |
| 🥈 进阶（20 分）RAG 知识增强   | judge → selective RAG → guarded refine | ✅ v2 |
| 🥇 挑战（10 分）ReAct 自主闭环 | react_loop → disposition                | ✅    |

---

## 当前状态：可信评测基线 + 受控 ReAct + 选择性 RAG + 多智能体协同

> **正式准确率口径（2026-08-19）**：原有 50 条演示集 100% 仅是工程回归结果，不能作为正式准确率。现在以场景隔离的 `AIT-ADS-EVENT-GOLD` 冻结测试集为主评测；只有总准确率 ≥88%、Wilson 95% 下界 ≥85%、Macro-F1/假阳类 F1 ≥85%、覆盖率 ≥90% 同时成立，才可声明“可信 85%”。本次只完成数据与代码接入，不调用真实模型。

### ✅ 已完成

- **AIT-ADS 正式事件级评测**：
  - 扫描 2,655,821 条官方事件/时间标签，排除 91,755 条冲突记录
  - 以场景、检测器、规则、资产和一分钟桶聚合告警风暴，避免逐告警重复计分
  - 场景隔离的 development 600 / validation 200 / frozen test 1000
  - 真值与 Agent 输入分离；1800 个案例均可通过不透明引用查询标签无关的官方检测器证据
  - 评测器内置可信 85% 组合门槛和 Wilson 95% 置信下界
- **ToN_IoT 工业互联网双模态外部验证**：
  - 接入 211,043 条网络流与 287,194 条 Modbus 遥测原始记录
  - 生成 2,000 条冻结外部验证集，网络/Modbus 各 1000，模态内真阳/假阳各 500
  - 网络流和 Modbus 工具返回真实源记录，正式样本不会回退到演示 Mock 证据
  - 明确网络 Train_Test 文件无时间戳，只验证双模态覆盖和跨域泛化，不伪称跨源时间关联

- **Week 1 基础设施**：脚手架 + LLM 工厂 + Hello World + 数据 schema
- **Week 2-3 MVP 核心链路**：preprocess + judge + CoT + 评测 + API
- **Week 5 挑战任务 ReAct 闭环**：
  - 8 个工具（6 数据查询 Mock + 2 处置建议）
  - `react_decide` 节点：LLM 自主决定调哪个工具（Prompt 驱动，绕开 function_calling 不稳定）
  - `tool_executor` 节点：执行工具、收集证据
  - `disposition` 节点：真阳→封禁+隔离工单，假阳→加白，待查→升级人工
  - 循环终止三重保护：业务停止 / 置信度阈值 / 步数硬上限
- **第三阶段选择性 RAG v2**：
  - SQLite FTS5 + 本地稠密向量的混合检索，离线可运行
  - 内置 20 条高频 ATT&CK 技术与 19 条 SOC 研判手册，覆盖 17 类当前数据集行为域
  - 支持导入 MITRE ATT&CK STIX、Sigma YAML 与按需查询 NVD CVE
  - `KB-*` 知识与 `EV-*` 事件证据分离，引用编号经过校验
  - 先产出 No-RAG 初判，对待查/低置信及低特异性高置信真阳进行严格行为域检索
  - 引用门控和防退化保护避免无关知识把已决样本改成待查
  - 知识库版本不一致时自动补建，并提供不含标签的离线检索覆盖审计
  - 页面支持三种策略分别组合 No-RAG / RAG 的六组实验
- **第四阶段多智能体协同**：
  - 新增独立 `multi_agent` 评测策略，与 `judge_only`、`react` 保持同口径对照
  - 协调器维护任务账本与进度账本，按数据源选择上下文、端点和网络智能体
  - 工具按智能体最小权限固定归属，验证智能体只融合已取得的 `EV-*` 证据
  - 三种策略均可分别组合 No-RAG / 选择性 RAG，并记录同轮修正与退化

### 📊 真实 DeepSeek V4 + ReAct 评测结果（50 条样本）

```
=== 评测结果 ===
样本数: 50
混淆矩阵: TP=25 FP=0 FN=0 TN=25
准确率 (accuracy): 1.0000   ← ReAct 把 MVP 的 1 条待查也救回来了
精确率 (precision): 1.0000
召回率 (recall):    1.0000
F1 分数:            1.0000
平均延迟: 3.084s    ← 含 ReAct 多轮 LLM 调用，仍 < 4s
待查数: 0
```

**能力跃迁**：MVP 阶段 1 条"待查"告警，ReAct 接入后通过自主调工具（端点日志→威胁情报→网络流量）拉回正确判定，准确率 98% → **100%**。

### 🎯 ReAct 闭环演示（核心差异化）

低置信告警（judge 判待查 0.55）→ ReAct 3 步自主调查 → 最终真阳 0.90：

```
步1: fetch_endpoint_logs(10.20.33.51) → 发现 Word 启动编码 PowerShell（钓鱼宏特征）
步2: check_threat_intel(198.51.100.42) → 查域名信誉
步3: fetch_network_flows(10.20.33.51) → 信标行为 + 数据外传（C2 特征）
→ 置信度演变: 0.30 → 0.80 → 0.75 → 0.90
→ 处置: 封禁 198.51.100.42 + 隔离 10.20.33.51（生成工单，不执行）
```

### 🔧 DeepSeek V4 适配要点（踩坑记录）

1. **模型名**：用 `deepseek-v4-flash`（V4 主力）。`deepseek-chat` / `deepseek-reasoner` 已于 2026/07/24 弃用。
2. **关闭 thinking 模式**：V4 默认开 thinking，与 `tool_choice` 冲突会报错。研判 Prompt 已含 5 步 CoT，无需模型内部再 think，在 `get_llm()` 里通过 `extra_body={"thinking": {"type": "disabled"}}` 关闭。
3. **结构化输出用 `method="json_mode"`**：
   - `json_schema` → 报错 `response_format type unavailable`
   - `function_calling` → V4 极不稳定，66% 请求不触发 tool call
   - `json_mode` → 稳定可靠（response_format=json_object + Pydantic 解析）

### 🚧 下一步

- 在最终模型、Prompt 和阈值锁定后运行一次 AIT-ADS 冻结测试集正式验收
- 将 ToN_IoT 作为独立工业外部验证报告，不与 AIT-ADS 指标混算
- 选取官方 Sigma 规则子集并完成规则质量、许可证和重复项审计
- Week 6 工程化：Docker 部署、日志、红队样本
- Week 5-6 前端：CoTViewer / ToolCallTrace 可视化（评委视觉记忆点）
- Week 7 文档：设计/开发/测试/总结四份文档 + 3 分钟演示视频

---

## 快速开始

### 1. 环境要求

- Python 3.11（`>=3.11,<3.13`）
- [uv](https://docs.astral.sh/uv/) 0.11+
- Node.js 18+（前端开发/构建用）
- DeepSeek API Key（[申请地址](https://platform.deepseek.com/)）

### 2. 安装

```bash
cd backend
uv sync                     # 装后端依赖
cp ../.env.example ../.env  # 复制环境模板
# 编辑 .env，填入 DEEPSEEK_API_KEY=sk-...

cd ../frontend
npm install                 # 装前端依赖（首次）
```

### 3. 一键启动（推荐）

```bash
# 在项目根目录
python launcher.py
```

启动后打开 **http://127.0.0.1:15173** 即可看到前端。端口：

- 前端 `15173`（Vite dev server）
- 后端 `18000`（FastAPI + Swagger 文档在 `/docs`）

`Ctrl+C` 一次性停止所有服务。

### 4. 手动启动（调试用）

```bash
# 终端 1：后端
cd backend && uv run uvicorn app.main:app --reload --port 18000

# 终端 2：前端（改代码自动刷新）
cd frontend && npm run dev
```

### 5. 交付模式（评委用，无需 node）

```bash
cd frontend && npm run build        # 先构建静态文件（产物在 frontend/dist/）
cd ../backend && uv run uvicorn app.main:app --port 8000
# 浏览器打开 http://localhost:8000 即看到完整前端
```

### 6. 其他命令

```bash
# 数据加载（10 条种子样本）
cd backend && uv run python -m app.data.loader

# 生成评测数据集（50 条）
uv run python -m app.data.generator

# 构造正式 AIT-ADS 事件级三段评测集
uv run python -m app.data.catalog prepare-ait-event-gold

# 构造 ToN_IoT 网络 + Modbus 冻结外部验证集
uv run python -m app.data.catalog prepare-ton-iot

# 跑真实模型评测（会消耗所选模型的 Token）
uv run python -m app.eval.run

# 构建/检查 RAG；增加 --rag 运行 RAG 对照组
uv run python -m app.rag.cli build
uv run python -m app.rag.cli status
uv run python -m app.rag.cli audit
uv run python -m app.eval.run --strategy judge_only --rag --limit 50

# 三种独立策略；每种都可追加 --rag
uv run python -m app.eval.run --strategy judge_only --limit 50
uv run python -m app.eval.run --strategy react --limit 50
uv run python -m app.eval.run --strategy multi_agent --limit 50

# 跑测试
uv run pytest -v
```

阶段文档：

- [正式评测协议：AIT-ADS 可信 85% 与 ToN_IoT 工业外部验证](docs/FORMAL_EVALUATION_PROTOCOL.md)
- [AIT-ADS 第一阶段评测基线](docs/AIT_ADS_BASELINE.md)
- [第二阶段 ReAct 受控执行说明](docs/REACT_PHASE2.md)
- [第三阶段安全知识 RAG 与 A/B 实验](docs/RAG_PHASE3.md)
- [AIT-ADS-20 选择性 RAG 校准实验 v3](docs/experiments/AIT_ADS_20_RAG_SELECTIVE_CALIBRATION_V3.md)
- [CAM-LDS 多源证据 Pilot](docs/CAM_LDS_PILOT.md)
- [zzb 分支阶段版本优化说明（2026-07-23）](docs/RELEASE_NOTES_ZZB_20260723.md)
- [zzb 分支第三阶段 RAG 版本说明（2026-07-27）](docs/RELEASE_NOTES_ZZB_RAG_V3_20260727.md)

---

## 目录结构

```
XH-202614-security-agent/
├── README.md
├── .env.example
├── .gitignore
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py              # FastAPI 入口
│   │   ├── api/                 # 路由（Week 2 填 alerts.py）
│   │   ├── agent/               # ⭐ LangGraph 核心
│   │   │   ├── graph.py
│   │   │   ├── nodes.py
│   │   │   └── state.py
│   │   ├── rag/                 # 知识增强（Week 4）
│   │   ├── models/
│   │   │   ├── llm.py           # ⭐ LLM 抽象工厂
│   │   │   └── schemas.py       # Alert 数据模型
│   │   ├── data/
│   │   │   ├── loader.py
│   │   │   └── datasets/        # 样本数据
│   │   ├── eval/                # 评测（Week 2-3）
│   │   └── core/
│   │       ├── config.py        # Settings
│   │       └── logging.py
│   └── tests/
└── docs/                        # 评分必看（Week 7 四份文档）
```

---

## 任务对齐表

本项目的每个任务都对应赛题原文要求，详见 `../项目执行方案.md`。

| 赛题原文要求                                 | 对应实现                                                                              |
| -------------------------------------------- | ------------------------------------------------------------------------------------- |
| "基于深信服 AI 安全平台的智能体"             | `models/llm.py` LLM 抽象工厂 + `sangfor` 适配接口                                 |
| "开发解决……的智能体（Agent）"              | `agent/graph.py` LangGraph 状态机                                                   |
| "调用各类安全工具（如防火墙封禁、EDR 隔离）" | Week 5 工具集`agent/tools.py`（含 `suggest_block_ip` / `suggest_isolate_host`） |
| "展示完整的思维链推理过程"                   | Week 2 CoT Prompt + Week 5 前端 CoTViewer                                             |
| "利用 RAG 技术，解决幻觉问题"                | Week 4`rag/` 模块                                                                   |

---

## 文档

- 项目执行方案：`../项目执行方案.md`
- 方案展示（HTML）：`../方案展示.html`
- 赛题原文：`../XH-202614_AI+安全大模型平台的智能体研究.pdf`
