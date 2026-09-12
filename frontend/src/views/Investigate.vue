<script setup lang="ts">
import { computed, ref, reactive, onMounted } from 'vue'
import { PhBrain, PhCheck, PhDownloadSimple, PhPlay, PhStop, PhWarning } from '@phosphor-icons/vue'
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
    color: 'border-pink',
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
    color: 'border-pink',
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
  responseExecution: {} as Record<string, any>,
  evidence: [] as any[],
  citedEvidence: [] as string[],
  visitedNodes: [] as string[],
  reason: '',
  done: false,
})

// 工作区是否已有轨迹可展示(进入研判或已结束)
const traceActive = computed(() => Boolean(trace.currentNode || streaming.value || trace.done))

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
  trace.responseExecution = {}
  trace.evidence = []
  trace.citedEvidence = []
  trace.visitedNodes = []
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
  if (u.response_execution !== undefined) trace.responseExecution = u.response_execution
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

// JSON 编辑器内 Ctrl/Cmd + Enter 快速开始/中止
function runShortcut() {
  if (streaming.value) stopStream()
  else if (alertJson.value) startStream()
}

</script>

<template>
  <div class="inv-page page-enter">
    <!-- 页面头:与概览页同一指挥头区语言,压缩高度 -->
    <header class="inv-command">
      <div class="inv-eyebrow">ALERT ADJUDICATION WORKSPACE</div>
      <h2>告警研判工作区</h2>
      <p>加载示例告警或粘贴 JSON，实时观察研判管线、思维链、多智能体协同与处置闭环</p>
    </header>

    <div class="inv-layout">
    <!-- 左:告警收件箱(示例 + JSON + 开关 + 启动) -->
    <aside class="inv-inbox">
      <div class="card p-5">
        <h3 class="font-bold text-base mb-3 flex items-center gap-2">
          <PhDownloadSimple :size="18" weight="bold" class="text-cyan" aria-hidden="true" /> 告警输入
        </h3>

        <!-- 示例按钮 -->
        <div class="text-[11px] text-text-mute mb-2">一键加载示例</div>
        <div class="grid grid-cols-1 gap-2">
          <button
            v-for="p in presetsCommon"
            :key="p.name"
            @click="loadPreset(p)"
            class="text-left p-2 rounded-none border bg-bg-2 hover:bg-card-hover hover:border-text transition-all"
            :class="p.color"
          >
            <div class="text-sm font-semibold text-text">{{ p.name }}</div>
            <div class="text-[11px] text-text-dim mt-0.5">{{ p.desc }}</div>
          </button>
        </div>

        <!-- 展开更多示例 -->
        <button
          v-if="!showMore"
          @click="showMore = true"
          class="mt-2 text-[11px] text-cyan hover:text-cyan-dim transition-colors"
        >
          更多示例 ▾
        </button>
        <div v-if="showMore" class="grid grid-cols-1 gap-2 mt-2">
          <button
            v-for="p in presetsMore"
            :key="p.name"
            @click="loadPreset(p)"
            class="text-left p-2 rounded-none border bg-bg-2 hover:bg-card-hover hover:border-text transition-all"
            :class="p.color"
          >
            <div class="text-sm font-semibold text-text">{{ p.name }}</div>
            <div class="text-[11px] text-text-dim mt-0.5">{{ p.desc }}</div>
          </button>
          <button
            @click="showMore = false"
            class="text-[11px] text-text-mute hover:text-text-dim transition-colors text-center py-1"
          >
            收起 ▴
          </button>
        </div>

        <!-- JSON 编辑 -->
        <div class="mt-3 mb-1 flex items-center justify-between gap-2">
          <div class="text-[11px] text-text-mute">告警 JSON（可编辑）</div>
          <div class="text-[10px] text-text-mute font-mono">Ctrl + Enter 快速研判</div>
        </div>
        <textarea
          v-model="alertJson"
          rows="12"
          class="w-full bg-card border border-border rounded-none p-3 text-[13px] font-mono text-text focus:border-text focus:outline-none resize-none"
          placeholder='点击上方示例加载，或粘贴告警 JSON...'
          @keydown.ctrl.enter.prevent="runShortcut"
          @keydown.meta.enter.prevent="runShortcut"
        ></textarea>

        <label class="mt-3 flex items-center justify-between rounded-none border border-border bg-card px-3 py-2 text-xs">
          <span>
            <b class="text-text">安全知识 RAG</b>
            <span class="block text-[11px] text-text-mute">仅对低置信初判检索并后融合</span>
          </span>
          <input
            v-model="ragEnabled"
            type="checkbox"
            :disabled="streaming"
            class="h-4 w-4 accent-cyan"
          />
        </label>

        <label class="mt-2 flex items-center justify-between rounded-none border border-border bg-card px-3 py-2 text-xs">
          <span>
            <b class="text-text">多智能体研判</b>
            <span class="block text-[11px] text-text-mute">自主规划并按新证据动态重规划</span>
          </span>
          <input
            v-model="multiAgentEnabled"
            type="checkbox"
            :disabled="streaming"
            class="h-4 w-4 accent-purple"
          />
        </label>

        <div v-if="multiAgentEnabled" class="mt-2 rounded-none border border-purple/30 bg-purple/5 px-3 py-2 text-[11px] text-text-mute">
          开启后进入多智能体 ReAct 闭环：协调器自主制定计划，专业智能体取证，每次观测后重新决定下一步；可与 RAG 同时使用。
        </div>

        <button
          @click="streaming ? stopStream() : startStream()"
          :disabled="!alertJson && !streaming"
          class="mt-3 w-full py-2.5 rounded-none font-bold transition-all inline-flex items-center justify-center gap-1.5"
          :class="streaming
            ? 'bg-red/10 text-red border border-red/40 hover:bg-red/20'
            : 'bg-cyan text-on-accent border border-cyan hover:bg-text hover:text-bg hover:border-text'"
        >
          <PhStop v-if="streaming" :size="14" weight="fill" aria-hidden="true" />
          <PhPlay v-else :size="14" weight="fill" aria-hidden="true" />
          {{ streaming ? '中止研判' : '开始研判' }}
        </button>
      </div>
    </aside>

    <!-- 右:研判工作区(判定条 + 编号分区) -->
    <div class="inv-workspace">
      <!-- 判定条:置信度仪表 + 结论 + 实时状态与计数 -->
      <section v-if="traceActive" class="ws-verdict">
        <div class="verdict-gauge">
          <ConfidenceGauge :confidence="trace.confidence" :size="104" />
        </div>

        <div class="verdict-main">
          <div class="verdict-head">
            <JudgmentBadge v-if="trace.judgment" :judgment="trace.judgment" size="lg" />
            <span v-else class="verdict-pending">研判中…</span>
            <div v-if="streaming" class="chip border-cyan text-cyan">
              <span class="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse-dot"></span>
              {{ trace.currentNode || '启动中' }}
            </div>
            <div v-else-if="trace.done" class="chip border-green text-green">
              <PhCheck :size="13" weight="bold" aria-hidden="true" /> 完成
            </div>
          </div>
          <p v-if="trace.reason" class="verdict-reason">{{ trace.reason }}</p>
          <div class="verdict-chips">
            <span class="chip border-cyan text-cyan" v-if="ragEnabled">RAG 知识增强</span>
            <span class="chip border-purple text-purple" v-if="multiAgentEnabled">多智能体协同</span>
          </div>
        </div>

        <div class="verdict-stats">
          <div class="vstat">
            <b>{{ trace.cotTrace.length }}</b>
            <small>推理步骤</small>
          </div>
          <div class="vstat">
            <b>{{ trace.toolsCalled.length }}</b>
            <small>工具调用</small>
          </div>
          <div class="vstat">
            <b>{{ trace.citedEvidence.length }}</b>
            <small>引用证据</small>
          </div>
        </div>
      </section>

      <!-- 错误 -->
      <div v-if="errorMsg" role="alert" class="ws-error">
        <PhWarning :size="16" weight="bold" aria-hidden="true" /> {{ errorMsg }}
      </div>

      <!-- 01 研判管线 -->
      <section v-if="traceActive && !errorMsg" class="ws-section">
        <header class="ws-head">
          <span class="ws-index">01</span>
          <div class="ws-copy"><b>研判管线</b><small>LIVE PIPELINE</small></div>
          <span class="ws-note">{{ streaming ? '节点状态随流式事件实时推进' : '本次运行经过的节点' }}</span>
        </header>
        <AgentProcessMap
          :current-node="trace.currentNode"
          :visited-nodes="trace.visitedNodes"
          :streaming="streaming"
          :done="trace.done"
          :rag-enabled="ragEnabled"
          :multi-agent-enabled="multiAgentEnabled"
        />
      </section>

      <!-- 02 可解释研判链 -->
      <section v-if="traceActive && !errorMsg && trace.cotTrace.length" class="ws-section">
        <header class="ws-head">
          <span class="ws-index">02</span>
          <div class="ws-copy"><b>可解释研判链</b><small>EVIDENCE CHAIN</small></div>
          <span class="ws-note">点击节点查看该步依据</span>
        </header>
        <CoTTimeline :steps="trace.cotTrace" :streaming="streaming && trace.currentNode === 'judge'" />
      </section>

      <!-- 03 调查轨迹:多智能体 或 ReAct -->
      <section
        v-if="traceActive && !errorMsg && multiAgentEnabled && (trace.multiAgentSteps.length || Object.keys(trace.progressLedger).length)"
        class="ws-section"
      >
        <header class="ws-head">
          <span class="ws-index">03</span>
          <div class="ws-copy"><b>多智能体调查轨迹</b><small>MULTI-AGENT TRACE</small></div>
          <span class="ws-note">{{ streaming ? '正在接收智能体调度与证据返回' : '可点击智能体、工具与证据节点查看详情' }}</span>
        </header>
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

      <section v-else-if="traceActive && !errorMsg && trace.reactSteps.length" class="ws-section">
        <header class="ws-head">
          <span class="ws-index">03</span>
          <div class="ws-copy"><b>ReAct 工具调查轨迹</b><small>REACT TRACE</small></div>
          <span class="ws-note">按执行顺序展示每一步受控工具调用</span>
        </header>
        <div class="ws-tool-grid">
          <ToolCard
            v-for="rs in trace.reactSteps"
            :key="rs.step"
            :step="rs"
            :active="streaming && trace.currentNode === 'tool_executor' && rs === trace.reactSteps[trace.reactSteps.length - 1]"
          />
        </div>
      </section>

      <!-- 04 处置闭环 -->
      <section v-if="traceActive && !errorMsg && trace.disposition" class="ws-section">
        <header class="ws-head">
          <span class="ws-index">04</span>
          <div class="ws-copy"><b>处置闭环</b><small>RESPONSE LOOP</small></div>
          <span class="ws-note">动作执行后独立验证生效，失败有界重试并可回滚</span>
        </header>
        <DispositionCard
          :disposition="trace.disposition"
          :response-execution="trace.responseExecution"
        />
      </section>

      <!-- 空状态指引:以流程预告填充工作区,而非大片空白 -->
      <div v-if="!traceActive && !errorMsg" class="ws-guide">
        <div class="guide-head">
          <PhBrain :size="22" weight="bold" class="guide-head-icon" aria-hidden="true" />
          <div>
            <b>等待研判输入</b>
            <span>选择左侧告警示例或粘贴 JSON，点击「开始研判」后，以下内容将在这里实时展开</span>
          </div>
        </div>
        <div class="guide-grid">
          <div class="guide-card">
            <span>01</span>
            <b>研判管线</b>
            <small>七个节点的实时推进状态，RAG 知识增强与多智能体按需启用</small>
          </div>
          <div class="guide-card">
            <span>02</span>
            <b>可解释研判链</b>
            <small>五类证据汇入最终判定的交互式关系图，点击节点可查看依据</small>
          </div>
          <div class="guide-card">
            <span>03</span>
            <b>调查轨迹</b>
            <small>ReAct 受控工具调用，或多智能体协同取证与动态重规划</small>
          </div>
          <div class="guide-card">
            <span>04</span>
            <b>处置闭环</b>
            <small>处置工单执行、效果独立观测，失败有界重试并可补偿回滚</small>
          </div>
        </div>
        <div class="guide-tip">左侧可开启「安全知识 RAG」与「多智能体研判」，两者可叠加；JSON 编辑器内 Ctrl + Enter 快速开始</div>
      </div>
    </div>
    </div>
  </div>
</template>

<style scoped>
/* 页面容器:标题头 + 工作区 */
.inv-page { min-width: 0; display: flex; flex-direction: column; gap: 14px; }
/* 页面头:与概览页指挥头区同语言(眉标 + 大标题 + 一句说明) */
.inv-command { padding: 2px 0 12px; border-bottom: 1px solid rgb(var(--text)); }
.inv-eyebrow { margin-bottom: 8px; color: rgb(var(--cyan)); font: 700 11px/1.2 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .22em; }
.inv-command h2 { margin: 0; font-size: 26px; font-weight: 800; letter-spacing: -0.03em; color: rgb(var(--text)); }
.inv-command p { margin: 7px 0 0; color: rgb(var(--text-dim)); font-size: 13px; max-width: 60ch; }

/* 工作区布局:左收件箱 + 右工作区 */
.inv-layout { display: grid; grid-template-columns: minmax(280px, 3fr) minmax(0, 9fr); gap: 16px; align-items: start; }
.inv-inbox { min-width: 0; display: flex; flex-direction: column; gap: 16px; }
.inv-workspace { min-width: 0; display: flex; flex-direction: column; gap: 16px; }

/* 判定条:仪表 + 结论 + 计数,细线分栏的连续条 */
.ws-verdict { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; border: 1px solid rgb(var(--border)); background: rgb(var(--card)); }
.verdict-gauge { display: grid; place-items: center; padding: 14px 22px; border-right: 1px solid rgb(var(--border)); }
.verdict-main { min-width: 0; padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; }
.verdict-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.verdict-pending { color: rgb(var(--text-mute)); font-size: 15px; font-style: italic; }
.verdict-reason { margin: 0; color: rgb(var(--text-dim)); font-size: 13.5px; line-height: 1.7; }
.verdict-chips { display: flex; gap: 8px; flex-wrap: wrap; }
.verdict-stats { display: grid; grid-template-columns: repeat(3, minmax(74px, 1fr)); border-left: 1px solid rgb(var(--border)); }
.vstat { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px; padding: 12px 14px; }
.vstat + .vstat { border-left: 1px solid rgb(var(--border)); }
.vstat b { color: rgb(var(--text)); font: 700 22px/1 'JetBrains Mono', ui-monospace, monospace; }
.vstat small { color: rgb(var(--text-mute)); font-size: 10.5px; }

/* 错误条 */
.ws-error { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border: 1px solid rgb(var(--red) / .4); background: rgb(var(--red) / .05); color: rgb(var(--red)); font-size: 13.5px; }

/* 编号分区头 */
.ws-head { display: flex; align-items: center; gap: 12px; padding: 13px 16px; border: 1px solid rgb(var(--border)); border-bottom: 0; background: rgb(var(--bg)); }
.ws-index { width: 30px; height: 30px; display: grid; place-items: center; border: 1px solid rgb(var(--text)); background: rgb(var(--text)); color: rgb(var(--bg)); font: 700 12px 'JetBrains Mono', ui-monospace, monospace; flex: 0 0 auto; }
.ws-copy { min-width: 0; }
.ws-copy b { display: block; color: rgb(var(--text)); font-size: 14.5px; font-weight: 800; letter-spacing: -0.01em; }
.ws-copy small { display: block; margin-top: 2px; color: rgb(var(--text-mute)); font: 9px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .14em; }
.ws-note { margin-left: auto; color: rgb(var(--text-mute)); font-size: 11px; text-align: right; }
.ws-section { min-width: 0; }
/* 分区体:内容组件自带边框,与头部拼接 */
.ws-section > :deep(.process-map),
.ws-section > :deep(.reasoning-graph-shell),
.ws-section > :deep(.agent-flow),
.ws-section > .card { border-top: 0; }
.ws-tool-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; border: 1px solid rgb(var(--border)); border-top: 0; background: rgb(var(--bg-2) / .4); padding: 14px; }

/* 空状态:以流程预告卡片填充工作区 */
.ws-guide { display: flex; flex-direction: column; gap: 13px; padding: 18px; border: 1px dashed rgb(var(--border-light)); }
.guide-head { display: flex; align-items: center; gap: 12px; }
.guide-head-icon { flex: 0 0 auto; color: rgb(var(--cyan)); opacity: .8; }
.guide-head b { display: block; color: rgb(var(--text-dim)); font-size: 15px; }
.guide-head span { display: block; margin-top: 3px; color: rgb(var(--text-mute)); font-size: 12.5px; }
.guide-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.guide-card { padding: 14px 16px; border: 1px solid rgb(var(--border)); background: rgb(var(--card)); }
.guide-card > span { display: inline-grid; place-items: center; min-width: 26px; height: 26px; padding: 0 4px; border: 1px solid rgb(var(--text)); background: rgb(var(--text)); color: rgb(var(--bg)); font: 700 11px 'JetBrains Mono', ui-monospace, monospace; }
.guide-card b { display: block; margin-top: 10px; color: rgb(var(--text)); font-size: 14px; font-weight: 700; }
.guide-card small { display: block; margin-top: 5px; color: rgb(var(--text-mute)); font-size: 12px; line-height: 1.7; }
.guide-tip { padding: 10px 12px; border-left: 2px solid rgb(var(--cyan)); background: rgb(var(--cyan) / .05); color: rgb(var(--text-dim)); font-size: 12px; }

@media (max-width: 1240px) {
  .inv-layout { grid-template-columns: 1fr; }
  .ws-tool-grid { grid-template-columns: 1fr; }
}
@media (max-width: 820px) {
  .ws-verdict { grid-template-columns: 1fr; }
  .verdict-gauge { border-right: 0; border-bottom: 1px solid rgb(var(--border)); }
  .verdict-stats { grid-template-columns: repeat(3, 1fr); border-left: 0; border-top: 1px solid rgb(var(--border)); }
  .ws-note { display: none; }
}
@media (max-width: 640px) {
  .inv-command h2 { font-size: 22px; }
  .inv-command p { font-size: 13px; }
  .guide-grid { grid-template-columns: 1fr; }
}
</style>
