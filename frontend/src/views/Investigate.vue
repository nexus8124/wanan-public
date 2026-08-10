<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { streamJudgeAlert } from '../api/client'
import {
  loadModelSelection,
  selectedModel,
  selectedProvider,
} from '../modelSelection'
import type { StreamEvent } from '../env'
import JudgmentBadge from '../components/JudgmentBadge.vue'
import ConfidenceGauge from '../components/ConfidenceGauge.vue'
import CoTTimeline from '../components/CoTTimeline.vue'
import ToolCard from '../components/ToolCard.vue'
import DispositionCard from '../components/DispositionCard.vue'
import AgentProcessMap from '../components/AgentProcessMap.vue'
import MultiAgentFlow from '../components/MultiAgentFlow.vue'

// 预置示例告警：常用 4 个常驻 + 其余收起
const presetsCommon = [
  {
    name: '钓鱼 C2 外连',
    desc: 'Word 启动 PowerShell 外连 4444',
    color: 'border-red',
    data: {
      alert_id: 'DEMO-TP1', timestamp: '2026-07-18T02:13:44Z', source: 'edr', severity: 'high',
      src_ip: '10.20.33.51', dst_ip: '185.220.101.34', src_port: 49832, dst_port: 4444, protocol: 'TCP',
      rule_name: 'Suspicious reverse shell to known C2',
      description: 'powershell.exe 由 WINWORD.EXE 启动外连 185.220.101.34:4444，疑似钓鱼宏落地后的命令控制阶段',
    },
  },
  {
    name: '模糊告警（触发 ReAct）',
    desc: 'powershell 外连未知 IP，证据不足',
    color: 'border-yellow',
    data: {
      alert_id: 'DEMO-REACT', timestamp: '2026-07-18T14:00:00Z', source: 'ndr', severity: 'medium',
      src_ip: '10.20.33.51', dst_ip: '198.51.100.42', src_port: 49832, dst_port: 8080, protocol: 'TCP',
      rule_name: 'Anomalous powershell outbound',
      description: '检测到 powershell 外连未知公网 IP，端口 8080，无明确攻击载荷',
    },
  },
  {
    name: 'SQL 注入',
    desc: 'WAF 命中 SQLi 规则',
    color: 'border-orange',
    data: {
      alert_id: 'DEMO-TP4', timestamp: '2026-07-18T05:18:39Z', source: 'waf', severity: 'high',
      src_ip: '203.0.113.77', dst_ip: '10.10.20.5', src_port: 51888, dst_port: 443, protocol: 'HTTPS',
      rule_name: 'SQL injection in login form',
      description: 'WAF 命中 SQL injection 规则，login 参数含 UNION SELECT + sleep(5)，单 IP 5 分钟触发 42 次',
    },
  },
  {
    name: '健康检查（假阳）',
    desc: '运维定时监控误报',
    color: 'border-green',
    data: {
      alert_id: 'DEMO-FP1', timestamp: '2026-07-18T01:00:12Z', source: 'ids', severity: 'low',
      src_ip: '10.20.30.5', dst_ip: '10.20.40.7', src_port: 51230, dst_port: 22, protocol: 'TCP',
      rule_name: 'Possible port scan',
      description: '运维主机 health check 脚本 nightly monitor，对域控固定端口健康检查',
    },
  },
]
const presetsMore = [
  {
    name: '内网横向移动',
    desc: 'PsExec 访问域控 ADMIN$',
    color: 'border-red',
    data: {
      alert_id: 'DEMO-TP2', timestamp: '2026-07-18T03:42:11Z', source: 'ndr', severity: 'high',
      src_ip: '10.20.33.51', dst_ip: '10.20.40.7', src_port: 51322, dst_port: 445, protocol: 'SMB',
      rule_name: 'Lateral movement via SMB admin share',
      description: '财务主机 10.20.33.51 尝试访问域控 10.20.40.7 的 ADMIN$ 共享，伴随 PsExec 特征流量，疑似权限提升后的横向扩散',
    },
  },
  {
    name: '编码 PowerShell（LOLBin）',
    desc: 'regsvr32 远程加载恶意脚本',
    color: 'border-red',
    data: {
      alert_id: 'DEMO-TP3', timestamp: '2026-07-18T04:05:22Z', source: 'edr', severity: 'high',
      src_ip: '10.20.31.18', dst_ip: null, src_port: null, dst_port: null, protocol: null,
      rule_name: 'PowerShell encoded command execution',
      description: '检出编码 PowerShell 命令：regsvr32 通过 regsvr32.exe /s /u /i:http://... 调用远程脚本（spearphish 后的 LOLBin 执行）',
    },
  },
  {
    name: 'LDAP 暴力破解',
    desc: '3 分钟 1284 次登录尝试',
    color: 'border-orange',
    data: {
      alert_id: 'DEMO-TP5', timestamp: '2026-07-18T06:51:03Z', source: 'siem', severity: 'medium',
      src_ip: '10.20.35.99', dst_ip: '10.20.40.7', src_port: null, dst_port: 389, protocol: 'LDAP',
      rule_name: 'LDAP brute force against domain controller',
      description: '域控 LDAP 暴力破解：主机 10.20.35.99 在 3 分钟内尝试 1284 次登录，覆盖多个域账号，命中率 0.3%',
    },
  },
  {
    name: 'GitHub 外连（假阳）',
    desc: '开发主机访问 CDN 节点',
    color: 'border-green',
    data: {
      alert_id: 'DEMO-FP2', timestamp: '2026-07-18T02:30:45Z', source: 'ndr', severity: 'low',
      src_ip: '10.20.33.200', dst_ip: '140.82.112.4', src_port: 49811, dst_port: 443, protocol: 'HTTPS',
      rule_name: 'Unusual outbound HTTPS to foreign IP',
      description: '外连境外 IP 140.82.112.4:443。核查为开发主机访问 github.com 的 CDN 节点（AS36459 GitHub），属日常代码拉取行为',
    },
  },
  {
    name: 'CDN 回源（假阳）',
    desc: '缓存刷新正常任务',
    color: 'border-green',
    data: {
      alert_id: 'DEMO-FP3', timestamp: '2026-07-18T03:15:00Z', source: 'ids', severity: 'info',
      src_ip: '10.20.40.15', dst_ip: '10.20.40.7', src_port: 50231, dst_port: 443, protocol: 'HTTPS',
      rule_name: 'CDN origin pull traffic',
      description: 'CDN 回源流量告警：源站 10.20.40.15 收到来自 CDN 节点的批量回源请求，属正常缓存刷新任务，匹配 cron job cdn-refresh',
    },
  },
  {
    name: '备份脚本 PowerShell（假阳）',
    desc: '签名的定时备份任务',
    color: 'border-green',
    data: {
      alert_id: 'DEMO-FP5', timestamp: '2026-07-18T05:30:00Z', source: 'edr', severity: 'low',
      src_ip: '10.20.35.10', dst_ip: null, src_port: null, dst_port: null, protocol: null,
      rule_name: 'Suspicious PowerShell invocation',
      description: '检出 powershell.exe 执行。核查为备份脚本 dbbackup.ps1 的常规调用，命令行明文、签名验证通过、每日定时执行',
    },
  },
]
const showMore = ref(false)

// 表单状态
const alertJson = ref('')
// 流式状态
const streaming = ref(false)
const errorMsg = ref('')
const abortCtrl = ref<AbortController | null>(null)
const ragEnabled = ref(false)
const multiAgentEnabled = ref(false)

onMounted(() => {
  loadModelSelection().catch((error) => {
    errorMsg.value = error instanceof Error ? error.message : String(error)
  })
})

// 累积的状态（流式过程中逐步更新）
const trace = reactive({
  currentNode: '',          // 当前正在跑的节点
  judgment: '' as string,    // 当前判定
  confidence: 0,             // 当前置信度
  cotTrace: [] as string[],  // CoT 步骤
  reactSteps: [] as any[],   // ReAct 工具调用
  multiAgentSteps: [] as any[],
  taskLedger: {} as Record<string, any>,
  progressLedger: {} as Record<string, any>,
  toolsCalled: [] as string[],
  knowledgeHits: [] as any[],
  citedKnowledge: [] as string[],
  disposition: null as any,
  evidence: [] as any[],
  citedEvidence: [] as string[],
  visitedNodes: [] as string[],
  confidenceHistory: [] as Array<{ node: string; value: number }>,
  reason: '',
  done: false,
})

function loadPreset(p: { name: string; desc: string; color: string; data: Record<string, any> }) {
  alertJson.value = JSON.stringify(p.data, null, 2)
  resetTrace()
}

function resetTrace() {
  trace.currentNode = ''
  trace.judgment = ''
  trace.confidence = 0
  trace.cotTrace = []
  trace.reactSteps = []
  trace.multiAgentSteps = []
  trace.taskLedger = {}
  trace.progressLedger = {}
  trace.toolsCalled = []
  trace.knowledgeHits = []
  trace.citedKnowledge = []
  trace.disposition = null
  trace.evidence = []
  trace.citedEvidence = []
  trace.visitedNodes = []
  trace.confidenceHistory = []
  trace.reason = ''
  trace.done = false
  errorMsg.value = ''
}

function handleEvent(ev: StreamEvent) {
  trace.currentNode = ev.node
  if (!trace.visitedNodes.includes(ev.node)) trace.visitedNodes.push(ev.node)
  const u = ev.update
  // 各节点产出的字段按顺序累积
  if (u.confidence !== undefined) {
    trace.confidence = Number(u.confidence)
    const latest = trace.confidenceHistory[trace.confidenceHistory.length - 1]
    if (!latest || latest.node !== ev.node || latest.value !== trace.confidence) {
      trace.confidenceHistory.push({ node: ev.node, value: trace.confidence })
    }
  }
  if (u.judgment !== undefined) trace.judgment = u.judgment
  if (u.reason !== undefined) trace.reason = u.reason
  if (u.cot_trace !== undefined) trace.cotTrace = u.cot_trace
  if (u.tools_called !== undefined) trace.toolsCalled = u.tools_called
  if (u.knowledge_hits !== undefined) trace.knowledgeHits = u.knowledge_hits
  if (u.cited_knowledge !== undefined) trace.citedKnowledge = u.cited_knowledge
  if (u.react_steps !== undefined) trace.reactSteps = u.react_steps
  if (u.multi_agent_steps !== undefined) trace.multiAgentSteps = u.multi_agent_steps
  if (u.task_ledger !== undefined) trace.taskLedger = u.task_ledger
  if (u.progress_ledger !== undefined) trace.progressLedger = u.progress_ledger
  if (u.disposition !== undefined) trace.disposition = u.disposition
  if (u.evidence !== undefined) trace.evidence = u.evidence
  if (u.cited_evidence !== undefined) trace.citedEvidence = u.cited_evidence
}

async function startStream() {
  let alertData: Record<string, any>
  try {
    alertData = JSON.parse(alertJson.value)
  } catch {
    errorMsg.value = '告警 JSON 格式错误，请检查'
    return
  }

  resetTrace()
  streaming.value = true
  abortCtrl.value = new AbortController()

  try {
    await streamJudgeAlert(
      alertData,
      {
        onEvent: handleEvent,
        onError: (msg) => { errorMsg.value = msg },
        onDone: () => { trace.done = true },
      },
      abortCtrl.value.signal,
      ragEnabled.value,
      multiAgentEnabled.value,
      selectedProvider.value,
      selectedModel.value,
    )
  } catch (e: any) {
    if (e.name !== 'AbortError') {
      errorMsg.value = e.message || String(e)
    }
  } finally {
    streaming.value = false
    trace.done = true
  }
}

function stopStream() {
  abortCtrl.value?.abort()
  streaming.value = false
}

// 当前进行中的 ReAct 步骤（最后一条）
const activeReactStep = computed(() => {
  if (!streaming.value || trace.reactSteps.length === 0) return undefined
  // 最后一条且当前节点是 tool_executor 时算 active
  return trace.currentNode === 'tool_executor' ? trace.reactSteps[trace.reactSteps.length - 1] : undefined
})

// 是否在 ReAct 阶段
const inReactPhase = computed(() =>
  ['react_decide', 'tool_executor'].includes(trace.currentNode)
)

const inMultiAgentPhase = computed(() =>
  ['multi_agent_plan', 'multi_agent_worker', 'multi_agent_verify'].includes(trace.currentNode)
)

const totalToolSteps = computed(() => (
  multiAgentEnabled.value ? trace.multiAgentSteps.length : trace.reactSteps.length
))

const participatingAgentCount = computed(() => new Set(
  trace.multiAgentSteps.map((step) => step.agent).filter(Boolean),
).size)

const evidenceCount = computed(() => {
  const directEvidence = trace.evidence.length
  const toolEvidence = trace.reactSteps.reduce(
    (total, step) => total + (Array.isArray(step.result?.evidence) ? step.result.evidence.length : 0),
    0,
  )
  const multiAgentEvidence = trace.multiAgentSteps.reduce(
    (total, step) => total + (Array.isArray(step.result?.evidence) ? step.result.evidence.length : 0),
    0,
  )
  return Math.max(directEvidence, toolEvidence, multiAgentEvidence)
})
</script>

<template>
  <div class="grid grid-cols-12 gap-5">
    <!-- 左：告警输入 -->
    <div class="col-span-12 lg:col-span-3 space-y-4">
      <div class="card p-5">
        <h3 class="font-bold text-sm mb-3 flex items-center gap-2">
          <span>📥</span> 告警输入
        </h3>

        <!-- 示例按钮 -->
        <div class="text-[10px] text-text-mute mb-2">一键加载示例</div>
        <div class="grid grid-cols-1 gap-2">
          <button
            v-for="p in presetsCommon"
            :key="p.name"
            @click="loadPreset(p)"
            class="text-left p-2 rounded-lg border bg-bg-2 hover:bg-card-hover transition-all"
            :class="p.color"
          >
            <div class="text-xs font-semibold text-text">{{ p.name }}</div>
            <div class="text-[10px] text-text-dim mt-0.5">{{ p.desc }}</div>
          </button>
        </div>

        <!-- 展开更多示例 -->
        <button
          v-if="!showMore"
          @click="showMore = true"
          class="mt-2 text-[10px] text-cyan hover:text-cyan-dim transition-colors"
        >
          更多示例 ▾
        </button>
        <div v-if="showMore" class="grid grid-cols-1 gap-2 mt-2">
          <button
            v-for="p in presetsMore"
            :key="p.name"
            @click="loadPreset(p)"
            class="text-left p-2 rounded-lg border bg-bg-2 hover:bg-card-hover transition-all"
            :class="p.color"
          >
            <div class="text-xs font-semibold text-text">{{ p.name }}</div>
            <div class="text-[10px] text-text-dim mt-0.5">{{ p.desc }}</div>
          </button>
          <button
            @click="showMore = false"
            class="text-[10px] text-text-mute hover:text-text-dim transition-colors text-center py-1"
          >
            收起 ▴
          </button>
        </div>

        <!-- JSON 编辑 -->
        <div class="text-[10px] text-text-mute mb-1">告警 JSON（可编辑）</div>
        <textarea
          v-model="alertJson"
          rows="14"
          class="w-full bg-bg border border-border rounded-lg p-3 text-xs font-mono text-text focus:border-cyan focus:outline-none resize-none"
          placeholder='点击上方示例加载，或粘贴告警 JSON...'
        ></textarea>

        <label class="mt-3 flex items-center justify-between rounded-lg border border-border bg-bg px-3 py-2 text-xs">
          <span>
            <b class="text-text">安全知识 RAG</b>
            <span class="block text-[10px] text-text-mute">仅对低置信初判检索并后融合</span>
          </span>
          <input
            v-model="ragEnabled"
            type="checkbox"
            :disabled="streaming"
            class="h-4 w-4 accent-cyan"
          />
        </label>

        <label class="mt-2 flex items-center justify-between rounded-lg border border-border bg-bg px-3 py-2 text-xs">
          <span>
            <b class="text-text">多智能体研判</b>
            <span class="block text-[10px] text-text-mute">按上下文、端点和网络证据源协同调查</span>
          </span>
          <input
            v-model="multiAgentEnabled"
            type="checkbox"
            :disabled="streaming"
            class="h-4 w-4 accent-purple"
          />
        </label>

        <div v-if="multiAgentEnabled" class="mt-2 rounded-md border border-purple/30 bg-purple/5 px-3 py-2 text-[10px] text-text-mute">
          多智能体与单智能体 ReAct 为独立策略；开启后由协调器分配专业智能体，可与 RAG 同时使用。
        </div>

        <button
          @click="streaming ? stopStream() : startStream()"
          :disabled="!alertJson && !streaming"
          class="mt-3 w-full py-2.5 rounded-lg font-bold transition-all"
          :class="streaming
            ? 'bg-red/20 text-red border border-red/40 hover:bg-red/30'
            : 'bg-gradient-to-r from-cyan to-purple text-bg hover:opacity-90'"
        >
          {{ streaming ? '⏹ 中止研判' : '🚀 开始研判' }}
        </button>
      </div>
    </div>

    <!-- 中：实时研判过程（核心） -->
    <div class="col-span-12 lg:col-span-6">
      <div class="card p-5 min-h-[600px]">
        <div class="flex items-center justify-between mb-4">
          <h3 class="font-bold text-sm flex items-center gap-2">
            <span>🧠</span> 实时研判过程
          </h3>
          <div v-if="streaming" class="chip border-cyan text-cyan">
            <span class="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse-dot"></span>
            {{ trace.currentNode || '启动中' }}
          </div>
          <div v-else-if="trace.done" class="chip border-green text-green">✓ 完成</div>
        </div>

        <!-- 错误 -->
        <div v-if="errorMsg" class="p-3 rounded-lg bg-red/10 border border-red/40 text-sm text-red">
          ⚠ {{ errorMsg }}
        </div>

        <!-- Agent 执行拓扑始终可见，运行时实时点亮节点 -->
        <section v-if="trace.currentNode || streaming || trace.done" class="mb-5">
          <div class="section-title mb-3 flex items-center justify-between gap-3">
            <span>00 · Agent 执行拓扑</span>
            <span class="normal-case tracking-normal text-[9px] text-text-mute">LIVE ORCHESTRATION MAP</span>
          </div>
          <AgentProcessMap
            :current-node="trace.currentNode"
            :visited-nodes="trace.visitedNodes"
            :confidence-history="trace.confidenceHistory"
            :streaming="streaming"
            :done="trace.done"
            :rag-enabled="ragEnabled"
            :multi-agent-enabled="multiAgentEnabled"
            :judgment="trace.judgment"
            :knowledge-count="trace.knowledgeHits.length"
            :tool-count="totalToolSteps"
            :evidence-count="evidenceCount"
          />
        </section>

        <!-- 空状态 -->
        <div
          v-if="!trace.currentNode && !streaming && !trace.done && !errorMsg"
          class="min-h-[500px] flex flex-col items-center justify-center text-center text-text-mute"
        >
          <div class="text-sm text-text-dim">选择左侧告警示例或粘贴告警 JSON，然后开始研判</div>
          <div class="text-xs mt-2">研判开始后，思维链、多智能体协作与证据调用将在这里实时展示</div>
        </div>

        <!-- 流式内容 -->
        <div v-if="trace.currentNode" class="space-y-5">
          <section v-if="trace.knowledgeHits.length">
            <div class="section-title mb-3">01 · RAG 安全知识</div>
            <div class="space-y-2">
              <div
                v-for="hit in trace.knowledgeHits"
                :key="hit.knowledge_id"
                class="rounded-lg border border-border bg-bg p-3"
              >
                <div class="flex items-center justify-between gap-3">
                  <code class="text-[10px] text-cyan">{{ hit.knowledge_id }}</code>
                  <span class="text-[10px] text-text-mute">相关度 {{ Math.round(hit.score * 100) }}%</span>
                </div>
                <div class="mt-1 text-xs font-semibold text-text">{{ hit.title }}</div>
              </div>
            </div>
            <div class="mt-2 text-[10px] text-text-mute">
              KB 知识用于解释技术和调查条件，不代表当前事件已经发生。
            </div>
          </section>

          <!-- judge 节点输出 -->
          <section v-if="trace.cotTrace.length || trace.currentNode === 'judge'">
            <div class="section-title mb-3 flex items-center justify-between gap-3">
              <span>02 · 可解释推理图</span>
              <span class="normal-case tracking-normal text-[9px] text-text-mute">REASONING EVIDENCE BOARD</span>
            </div>
            <CoTTimeline :steps="trace.cotTrace" :streaming="streaming && trace.currentNode === 'judge'" />
          </section>

          <!-- 多智能体阶段 -->
          <section v-if="multiAgentEnabled && (inMultiAgentPhase || trace.multiAgentSteps.length || Object.keys(trace.progressLedger).length)">
            <div class="section-title mb-3 flex items-center gap-2">
              <span>03 · 多智能体调查轨迹</span>
              <span v-if="inMultiAgentPhase" class="text-purple normal-case tracking-normal text-[10px]">协同取证中...</span>
              <span v-else class="text-text-mute normal-case tracking-normal text-[10px]">({{ trace.multiAgentSteps.length }} 次调用)</span>
            </div>
            <MultiAgentFlow
              :steps="trace.multiAgentSteps"
              :ledger="trace.progressLedger"
              :evidence="trace.evidence"
              :knowledge-hits="trace.knowledgeHits"
              :cited-evidence="trace.citedEvidence"
              :judgment="trace.judgment"
              :confidence="trace.confidence"
            />
          </section>

          <!-- ReAct 阶段 -->
          <section v-if="!multiAgentEnabled && (inReactPhase || trace.reactSteps.length)">
            <div class="section-title mb-3 flex items-center gap-2">
              <span>03 · ReAct 工具调查</span>
              <span v-if="inReactPhase" class="text-pink normal-case tracking-normal text-[10px]">自主调查中...</span>
              <span v-else class="text-text-mute normal-case tracking-normal text-[10px]">({{ trace.reactSteps.length }} 步)</span>
            </div>
            <div class="space-y-3">
              <ToolCard
                v-for="rs in trace.reactSteps"
                :key="rs.step"
                :step="rs"
                :active="activeReactStep && rs.step === activeReactStep.step"
              />
              <!-- 正在决策中占位 -->
              <div v-if="streaming && trace.currentNode === 'react_decide'" class="text-xs text-text-mute italic px-2 py-2">
                <span class="animate-pulse-dot inline-block">●</span> Agent 正在分析证据、决定下一步...
              </div>
            </div>
          </section>

          <!-- 处置 -->
          <section v-if="trace.disposition">
            <div class="section-title mb-3">04 · 处置闭环</div>
            <DispositionCard :disposition="trace.disposition" />
          </section>
        </div>
      </div>
    </div>

    <!-- 右：最终结果 -->
    <div class="col-span-12 lg:col-span-3 space-y-4">
      <!-- 判定 + 置信度 -->
      <div class="card p-5">
        <h3 class="font-bold text-sm mb-4 flex items-center gap-2">
          <span>📊</span> 最终结果
        </h3>

        <div class="flex justify-center mb-3">
          <ConfidenceGauge :confidence="trace.confidence" :size="140" />
        </div>

        <div class="text-center mb-3">
          <div class="text-[10px] text-text-mute mb-1">判定</div>
          <JudgmentBadge v-if="trace.judgment" :judgment="trace.judgment" size="lg" />
          <span v-else class="text-text-mute text-sm italic">等待研判...</span>
        </div>

        <div v-if="trace.reason" class="text-xs text-text-dim leading-relaxed p-3 rounded-lg bg-bg-2 border border-border">
          {{ trace.reason }}
        </div>
      </div>

      <!-- 多智能体摘要 -->
      <div v-if="trace.multiAgentSteps.length" class="card p-5">
        <h3 class="font-bold text-sm mb-3 flex items-center gap-2">
          <span>🧩</span> 多智能体协同统计
        </h3>
        <div class="space-y-2 text-xs">
          <div class="flex justify-between">
            <span class="text-text-dim">参与智能体</span>
            <span class="font-mono text-purple">{{ participatingAgentCount }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-dim">工具调用</span>
            <span class="font-mono text-cyan">{{ trace.multiAgentSteps.length }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-dim">有效证据</span>
            <span class="font-mono text-green">{{ evidenceCount }}</span>
          </div>
        </div>
      </div>

      <!-- ReAct 摘要 -->
      <div v-if="trace.reactSteps.length" class="card p-5">
        <h3 class="font-bold text-sm mb-3 flex items-center gap-2">
          <span>🔧</span> 工具调用统计
        </h3>
        <div class="space-y-2">
          <div class="flex justify-between text-xs">
            <span class="text-text-dim">调用步数</span>
            <span class="font-mono text-cyan">{{ trace.reactSteps.length }}</span>
          </div>
          <div class="flex justify-between text-xs">
            <span class="text-text-dim">不同工具</span>
            <span class="font-mono text-purple">{{ trace.toolsCalled.length }}</span>
          </div>
          <div class="pt-2 border-t border-border">
            <div class="text-[10px] text-text-mute mb-1">工具列表</div>
            <div class="flex flex-wrap gap-1">
              <code
                v-for="t in trace.toolsCalled"
                :key="t"
                class="text-[10px] px-1.5 py-0.5 rounded bg-bg-2 text-green border border-border"
              >{{ t }}</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
