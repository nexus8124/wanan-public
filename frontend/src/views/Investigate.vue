<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { streamJudgeAlert } from '../api/client'
import type { StreamEvent } from '../env'
import JudgmentBadge from '../components/JudgmentBadge.vue'
import ConfidenceGauge from '../components/ConfidenceGauge.vue'
import CoTTimeline from '../components/CoTTimeline.vue'
import ToolCard from '../components/ToolCard.vue'
import DispositionCard from '../components/DispositionCard.vue'

// 预置示例告警（一键加载，覆盖不同判定场景）
const presets = [
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
      alert_id: 'DEMO-TP2', timestamp: '2026-07-18T05:18:39Z', source: 'waf', severity: 'high',
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

// 表单状态
const alertJson = ref('')
// 流式状态
const streaming = ref(false)
const errorMsg = ref('')
const abortCtrl = ref<AbortController | null>(null)
const ragEnabled = ref(false)

// 累积的状态（流式过程中逐步更新）
const trace = reactive({
  currentNode: '',          // 当前正在跑的节点
  judgment: '' as string,    // 当前判定
  confidence: 0,             // 当前置信度
  cotTrace: [] as string[],  // CoT 步骤
  reactSteps: [] as any[],   // ReAct 工具调用
  toolsCalled: [] as string[],
  knowledgeHits: [] as any[],
  citedKnowledge: [] as string[],
  disposition: null as any,
  reason: '',
  done: false,
})

function loadPreset(p: typeof presets[0]) {
  alertJson.value = JSON.stringify(p.data, null, 2)
  resetTrace()
}

function resetTrace() {
  trace.currentNode = ''
  trace.judgment = ''
  trace.confidence = 0
  trace.cotTrace = []
  trace.reactSteps = []
  trace.toolsCalled = []
  trace.knowledgeHits = []
  trace.citedKnowledge = []
  trace.disposition = null
  trace.reason = ''
  trace.done = false
  errorMsg.value = ''
}

function handleEvent(ev: StreamEvent) {
  trace.currentNode = ev.node
  const u = ev.update
  // 各节点产出的字段按顺序累积
  if (u.confidence !== undefined) trace.confidence = u.confidence
  if (u.judgment !== undefined) trace.judgment = u.judgment
  if (u.reason !== undefined) trace.reason = u.reason
  if (u.cot_trace !== undefined) trace.cotTrace = u.cot_trace
  if (u.tools_called !== undefined) trace.toolsCalled = u.tools_called
  if (u.knowledge_hits !== undefined) trace.knowledgeHits = u.knowledge_hits
  if (u.cited_knowledge !== undefined) trace.citedKnowledge = u.cited_knowledge
  if (u.react_steps !== undefined) trace.reactSteps = u.react_steps
  if (u.disposition !== undefined) trace.disposition = u.disposition
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
        <div class="grid grid-cols-1 gap-2 mb-4">
          <button
            v-for="p in presets"
            :key="p.name"
            @click="loadPreset(p)"
            class="text-left p-2 rounded-lg border bg-bg-2 hover:bg-card-hover transition-all"
            :class="p.color"
          >
            <div class="text-xs font-semibold text-text">{{ p.name }}</div>
            <div class="text-[10px] text-text-dim mt-0.5">{{ p.desc }}</div>
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

        <!-- 空状态 -->
        <div v-if="!trace.currentNode && !errorMsg" class="flex flex-col items-center justify-center py-20 text-text-mute">
          <div class="text-5xl mb-3 opacity-40">🤖</div>
          <div class="text-sm">点击左侧"开始研判"，观看 Agent 实时思考过程</div>
          <div class="text-xs mt-1">SSE 流式推送：judge → 选择性 RAG → ReAct → 处置闭环</div>
        </div>

        <!-- 错误 -->
        <div v-if="errorMsg" class="p-3 rounded-lg bg-red/10 border border-red/40 text-sm text-red">
          ⚠ {{ errorMsg }}
        </div>

        <!-- 流式内容 -->
        <div v-if="trace.currentNode" class="space-y-5">
          <section v-if="trace.knowledgeHits.length">
            <div class="section-title mb-3">00 · RAG 安全知识</div>
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
            <div class="section-title mb-3">01 · CoT 思维链（节点3）</div>
            <CoTTimeline :steps="trace.cotTrace" :streaming="streaming && trace.currentNode === 'judge'" />
          </section>

          <!-- ReAct 阶段 -->
          <section v-if="inReactPhase || trace.reactSteps.length">
            <div class="section-title mb-3 flex items-center gap-2">
              <span>02 · ReAct 工具调用</span>
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
            <div class="section-title mb-3">03 · 处置闭环</div>
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
