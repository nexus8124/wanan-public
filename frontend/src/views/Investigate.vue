<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
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
            <span class="block text-[10px] text-text-mute">自主规划并按新证据动态重规划</span>
          </span>
          <input
            v-model="multiAgentEnabled"
            type="checkbox"
            :disabled="streaming"
            class="h-4 w-4 accent-purple"
          />
        </label>

        <div v-if="multiAgentEnabled" class="mt-2 rounded-md border border-purple/30 bg-purple/5 px-3 py-2 text-[10px] text-text-mute">
          开启后进入多智能体 ReAct 闭环：协调器自主制定计划，专业智能体取证，每次观测后重新决定下一步；可与 RAG 同时使用。
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

    <!-- 右侧主工作区：顶部进度与结果，底部实时展开研判轨迹 -->
    <div class="col-span-12 lg:col-span-9 grid grid-cols-12 gap-5 items-start">
    <!-- 实时进度与最终结果合并为一个全宽总览组件 -->
    <div class="col-span-12">
      <div class="card p-5 min-h-[300px]">
        <div class="flex items-center justify-between mb-4">
          <h3 class="font-bold text-sm flex items-center gap-2">
            <span>🧠</span> 实时研判总览
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

        <div
          v-if="trace.currentNode || streaming || trace.done"
          class="grid grid-cols-12 gap-5 items-stretch"
        >
          <!-- 左侧：横向实时进度 -->
          <section class="col-span-12 xl:col-span-9">
            <div class="section-title mb-3 flex items-center justify-between gap-3">
              <span>研判进度</span>
              <span class="normal-case tracking-normal text-[9px] text-text-mute">LIVE PROGRESS</span>
            </div>
            <AgentProcessMap
              :current-node="trace.currentNode"
              :visited-nodes="trace.visitedNodes"
              :streaming="streaming"
              :done="trace.done"
              :rag-enabled="ragEnabled"
              :multi-agent-enabled="multiAgentEnabled"
            />
          </section>

          <!-- 右侧：同一卡片内的最终结果 -->
          <section class="col-span-12 xl:col-span-3 border-t xl:border-t-0 xl:border-l border-border pt-5 xl:pt-0 xl:pl-5 flex flex-col">
            <div class="section-title mb-2">最终结果</div>
            <div class="flex justify-center">
              <ConfidenceGauge :confidence="trace.confidence" :size="112" />
            </div>
            <div class="text-center -mt-1 mb-3">
              <JudgmentBadge v-if="trace.judgment" :judgment="trace.judgment" size="lg" />
              <span v-else class="text-text-mute text-sm italic">研判中...</span>
            </div>
            <div
              v-if="trace.reason"
              class="mt-auto text-xs text-text-dim leading-relaxed p-3 rounded-lg bg-bg-2 border border-border"
            >
              {{ trace.reason }}
            </div>
          </section>
        </div>

        <!-- 空状态 -->
        <div
          v-if="!trace.currentNode && !streaming && !trace.done && !errorMsg"
          class="min-h-[220px] flex flex-col items-center justify-center text-center text-text-mute"
        >
          <div class="text-sm text-text-dim">选择左侧告警示例或粘贴告警 JSON，然后开始研判</div>
          <div class="text-xs mt-2">研判开始后，思维链、多智能体协作与证据调用将在这里实时展示</div>
        </div>

      </div>
    </div>

    <!-- 研判开始后，紧跟进度区实时展示思维链与多智能体过程 -->
    <section
      v-if="trace.currentNode && !errorMsg"
      class="col-span-12 card p-6 space-y-6"
    >
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <div class="section-title">研判过程可视化</div>
          <div class="mt-1 text-xs text-text-mute">
            {{ streaming
              ? '正在实时接收模型推理、智能体调度、工具调用与证据返回'
              : '本次告警分析已完成，可点击智能体、工具与证据节点查看详细内容' }}
          </div>
        </div>
        <div class="flex flex-wrap gap-2 text-xs">
          <span class="chip border-purple text-purple" v-if="multiAgentEnabled">多智能体协同</span>
          <span class="chip border-cyan text-cyan" v-if="ragEnabled">RAG 知识增强</span>
          <span class="chip border-green text-green">{{ trace.judgment || '待查' }}</span>
        </div>
      </div>

      <section v-if="trace.cotTrace.length">
        <div class="section-title mb-3">01 · 可解释研判链</div>
        <CoTTimeline :steps="trace.cotTrace" :streaming="streaming && trace.currentNode === 'judge'" />
      </section>

      <section
        v-if="multiAgentEnabled && (trace.multiAgentSteps.length || Object.keys(trace.progressLedger).length)"
      >
        <div class="section-title mb-3">02 · 多智能体调查轨迹</div>
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

      <section v-else-if="trace.reactSteps.length">
        <div class="section-title mb-3">02 · ReAct 工具调查轨迹</div>
        <div class="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <ToolCard
            v-for="rs in trace.reactSteps"
            :key="rs.step"
            :step="rs"
            :active="streaming && trace.currentNode === 'tool_executor' && rs === trace.reactSteps[trace.reactSteps.length - 1]"
          />
        </div>
      </section>

      <section v-if="trace.disposition">
        <div class="section-title mb-3">03 · 处置闭环</div>
        <DispositionCard :disposition="trace.disposition" />
      </section>
    </section>
    </div>
  </div>
</template>
