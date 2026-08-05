<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  streamRunEval,
  listEvalHistory,
  getEvalHistory,
  deleteEvalHistory,
  listEvalDatasets,
  selectEvalDataset,
  uploadEvalDataset,
  type EvalDatasetInfo,
} from '../api/client'
import StatCard from '../components/StatCard.vue'
import JudgmentBadge from '../components/JudgmentBadge.vue'
import ConfidenceGauge from '../components/ConfidenceGauge.vue'
import CoTTimeline from '../components/CoTTimeline.vue'
import ToolCard from '../components/ToolCard.vue'
import DispositionCard from '../components/DispositionCard.vue'

const loading = ref(false)
const errorMsg = ref('')
const result = ref<any>(null)
const progress = ref({ completed: 0, total: 50 })
const abortCtrl = ref<AbortController | null>(null)
const selectedDetail = ref<any | null>(null)
const historyRuns = ref<any[]>([])
const historyLoading = ref(false)
const activeRunId = ref('')
const viewingRunId = ref('')
const datasets = ref<EvalDatasetInfo[]>([])
const selectedDatasetId = ref('')
const datasetBusy = ref(false)
const uploadInput = ref<HTMLInputElement | null>(null)
const evalLimit = ref(20)
const evalStrategy = ref<'judge_only' | 'react'>('judge_only')
const ragEnabled = ref(false)
const liveAgentEvents = ref<any[]>([])

const eventLabels: Record<string, string> = {
  sample_started: '开始处理样本',
  preprocess_completed: '预处理完成',
  knowledge_retrieved: '安全知识检索完成',
  knowledge_refined: '安全知识后融合完成',
  judge_completed: '初步研判完成',
  decision_updated: 'ReAct 决策更新',
  tool_started: '开始调用工具',
  tool_completed: '工具返回证据',
  disposition_completed: '处置建议生成',
  sample_completed: '样本流程完成',
}

const metrics = computed(() => result.value?.metrics || null)
const details = computed(() => result.value?.details || [])
const activeDataset = computed(() =>
  datasets.value.find((item) => item.id === selectedDatasetId.value) || null,
)

async function loadHistory() {
  historyLoading.value = true
  try {
    const data = await listEvalHistory()
    historyRuns.value = data.runs
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    historyLoading.value = false
  }
}

async function loadDatasets() {
  datasetBusy.value = true
  try {
    const data = await listEvalDatasets()
    datasets.value = data.datasets
    selectedDatasetId.value = data.active_id
    const selected = datasets.value.find((item) => item.id === data.active_id)
    progress.value.total = selected?.count || progress.value.total
    if (data.errors?.length) {
      console.warn('部分数据集校验失败:', data.errors)
    }
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    datasetBusy.value = false
  }
}

onMounted(() => {
  loadHistory()
  loadDatasets()
})

async function changeDataset(event: Event) {
  const datasetId = (event.target as HTMLSelectElement).value
  if (!datasetId || datasetId === selectedDatasetId.value) return
  datasetBusy.value = true
  errorMsg.value = ''
  try {
    const selected = await selectEvalDataset(datasetId)
    selectedDatasetId.value = selected.id
    datasets.value = datasets.value.map((item) => ({
      ...item,
      active: item.id === selected.id,
    }))
    result.value = null
    selectedDetail.value = null
    viewingRunId.value = ''
    progress.value = { completed: 0, total: selected.count }
  } catch (e: any) {
    errorMsg.value = e.message
    await loadDatasets()
  } finally {
    datasetBusy.value = false
  }
}

function openUploadDialog() {
  uploadInput.value?.click()
}

async function handleDatasetUpload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  input.value = ''
  if (!file.name.toLowerCase().endsWith('.json')) {
    errorMsg.value = '只支持标准评测 JSON 文件；AIT 原始 JSONL 请先运行后端适配器。'
    return
  }
  if (file.size > 25 * 1024 * 1024) {
    errorMsg.value = '上传文件不能超过 25 MiB。'
    return
  }
  datasetBusy.value = true
  errorMsg.value = ''
  try {
    const uploaded = await uploadEvalDataset(file)
    await loadDatasets()
    selectedDatasetId.value = uploaded.id
    progress.value = { completed: 0, total: uploaded.count }
    result.value = null
    viewingRunId.value = ''
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    datasetBusy.value = false
  }
}

async function startEval(useMock: boolean) {
  const datasetCount = activeDataset.value?.count || progress.value.total
  const requestedLimit = evalLimit.value > 0 ? Math.min(evalLimit.value, datasetCount) : null
  const sampleCount = requestedLimit || datasetCount
  const strategyText = evalStrategy.value === 'judge_only' ? '单次 Judge 基线' : '完整 ReAct'
  const ragText = ragEnabled.value ? '启用 RAG' : '不启用 RAG'
  if (!useMock && !confirm(`将以“${strategyText} + ${ragText}”对 ${sampleCount} 条均衡样本调用真实模型并消耗 Token，确认继续？`)) {
    return
  }
  loading.value = true
  errorMsg.value = ''
  result.value = null
  selectedDetail.value = null
  viewingRunId.value = ''
  activeRunId.value = ''
  liveAgentEvents.value = []
  progress.value = { completed: 0, total: sampleCount }
  abortCtrl.value = new AbortController()
  try {
    await streamRunEval(
      useMock,
      requestedLimit,
      evalStrategy.value,
      ragEnabled.value,
      {
        onStart: (data) => {
          activeRunId.value = data.run_id
          progress.value.total = data.total || progress.value.total
          loadHistory()
        },
        onAgentEvent: (data) => {
          liveAgentEvents.value = [...liveAgentEvents.value.slice(-99), data]
        },
        onProgress: (data) => {
          progress.value = {
            completed: data.completed,
            total: data.total,
          }
          const currentDetails = result.value?.details || []
          result.value = {
            mode: useMock ? 'mock' : 'deepseek',
            strategy: evalStrategy.value,
            experiment_config: data.experiment_config,
            metrics: data.metrics,
            initial_metrics: data.initial_metrics,
            paired_react: data.paired_react,
            paired_rag: data.paired_rag,
            details: [...currentDetails, data.detail],
          }
          const history = historyRuns.value.find((item) => item.id === data.run_id)
          if (history) {
            history.completed = data.completed
            history.metrics = data.metrics
          }
        },
        onComplete: (finalResult) => {
          result.value = finalResult
          progress.value = {
            completed: finalResult.metrics?.n || progress.value.completed,
            total: progress.value.total,
          }
          activeRunId.value = ''
          loadHistory()
        },
        onError: (message) => {
          errorMsg.value = message
          activeRunId.value = ''
          loadHistory()
        },
      },
      abortCtrl.value.signal,
    )
  } catch (e: any) {
    if (e.name !== 'AbortError') errorMsg.value = e.message
  } finally {
    loading.value = false
    abortCtrl.value = null
  }
}

function stopEval() {
  abortCtrl.value?.abort()
  loading.value = false
}

async function viewHistory(run: any) {
  try {
    const saved = await getEvalHistory(run.id)
    result.value = {
      mode: saved.mode,
      strategy: saved.strategy,
      experiment_config: saved.experiment_config,
      dataset: saved.dataset,
      metrics: saved.metrics,
      initial_metrics: saved.initial_metrics,
      paired_react: saved.paired_react,
      paired_rag: saved.paired_rag,
      details: saved.details,
    }
    progress.value = { completed: saved.completed, total: saved.total }
    viewingRunId.value = saved.id
    selectedDetail.value = null
    liveAgentEvents.value = saved.events || []
  } catch (e: any) {
    errorMsg.value = e.message
  }
}

async function removeHistory(run: any) {
  if (!confirm(`确认删除评测记录 ${run.id.slice(0, 8)}？`)) return
  try {
    await deleteEvalHistory(run.id)
    if (viewingRunId.value === run.id) {
      result.value = null
      viewingRunId.value = ''
    }
    await loadHistory()
  } catch (e: any) {
    errorMsg.value = e.message
  }
}

function formatTime(value: string): string {
  return value ? new Date(value).toLocaleString() : '-'
}

const statusText: Record<string, string> = {
  running: '运行中',
  completed: '已完成',
  interrupted: '已中断',
  failed: '失败',
}

function statusClass(status: string): string {
  if (status === 'completed') return 'border-green/40 text-green bg-green/5'
  if (status === 'running') return 'border-cyan/40 text-cyan bg-cyan/5'
  if (status === 'interrupted') return 'border-yellow/40 text-yellow bg-yellow/5'
  return 'border-red/40 text-red bg-red/5'
}

function openDetail(detail: any) {
  selectedDetail.value = detail
}

const progressPercent = computed(() => {
  if (!progress.value.total) return 0
  return Math.round(progress.value.completed / progress.value.total * 100)
})
</script>

<template>
  <div class="space-y-5">
    <!-- 控制栏 -->
    <div class="card p-5">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 class="font-bold text-sm flex items-center gap-2 mb-1">
            <span>📊</span> 批量评测
          </h3>
          <p class="text-xs text-text-dim">
            在 {{ activeDataset?.count || progress.total }} 条标注样本上运行完整 Agent，输出准确率/精确率/召回率/F1
          </p>
        </div>
        <div class="flex gap-2">
          <button
            @click="startEval(true)"
            :disabled="loading || datasetBusy || !activeDataset"
            class="px-4 py-2 rounded-lg text-sm font-bold transition-all"
            :class="loading
              ? 'bg-bg-2 text-text-mute'
              : 'bg-bg-2 border border-cyan/40 text-cyan hover:bg-cyan/10'"
          >
            🧪 Mock 评测（不耗 token）
          </button>
          <button
            @click="startEval(false)"
            :disabled="loading || datasetBusy || !activeDataset"
            class="px-4 py-2 rounded-lg text-sm font-bold transition-all"
            :class="loading
              ? 'bg-bg-2 text-text-mute'
              : 'bg-gradient-to-r from-cyan to-purple text-bg hover:opacity-90'"
          >
            🚀 真实评测（消耗 token）
          </button>
          <button
            v-if="loading"
            @click="stopEval"
            class="px-4 py-2 rounded-lg text-sm font-bold bg-red/10 border border-red/40 text-red hover:bg-red/20"
          >
            ⏹ 停止评测
          </button>
        </div>
      </div>

      <div class="mt-5 pt-4 border-t border-border flex flex-wrap items-end gap-3">
        <label class="min-w-[280px] flex-1 max-w-xl">
          <span class="block text-[10px] uppercase tracking-wider text-text-mute mb-2">评测数据集</span>
          <select
            :value="selectedDatasetId"
            @change="changeDataset"
            :disabled="loading || datasetBusy"
            class="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-xs text-text focus:border-cyan outline-none disabled:opacity-50"
          >
            <option v-for="item in datasets" :key="item.id" :value="item.id">
              {{ item.name }}（{{ item.count }} 条）
            </option>
          </select>
        </label>

        <button
          @click="openUploadDialog"
          :disabled="loading || datasetBusy"
          class="px-4 py-2.5 rounded-lg border border-border text-xs text-text-dim hover:border-cyan hover:text-cyan disabled:opacity-50"
        >
          {{ datasetBusy ? '处理中...' : '上传评测 JSON' }}
        </button>
        <input
          ref="uploadInput"
          type="file"
          accept=".json,application/json"
          class="hidden"
          @change="handleDatasetUpload"
        />

        <label class="min-w-[150px]">
          <span class="block text-[10px] uppercase tracking-wider text-text-mute mb-2">本次样本预算</span>
          <select
            v-model.number="evalLimit"
            :disabled="loading || datasetBusy"
            class="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-xs text-text focus:border-cyan outline-none disabled:opacity-50"
          >
            <option :value="10">10 条（快速验证）</option>
            <option :value="20">20 条（推荐）</option>
            <option :value="50">50 条</option>
            <option :value="100">100 条</option>
            <option :value="0">全部样本</option>
          </select>
        </label>

        <label class="min-w-[210px]">
          <span class="block text-[10px] uppercase tracking-wider text-text-mute mb-2">评测策略</span>
          <select
            v-model="evalStrategy"
            :disabled="loading || datasetBusy"
            class="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-xs text-text focus:border-cyan outline-none disabled:opacity-50"
          >
            <option value="judge_only">Judge-only（无工具基线）</option>
            <option value="react">完整 ReAct（多轮调用）</option>
          </select>
        </label>

        <label class="min-w-[180px]">
          <span class="block text-[10px] uppercase tracking-wider text-text-mute mb-2">知识增强</span>
          <select
            v-model="ragEnabled"
            :disabled="loading || datasetBusy"
            class="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-xs text-text focus:border-cyan outline-none disabled:opacity-50"
          >
            <option :value="false">No-RAG 基线</option>
            <option :value="true">选择性安全知识 RAG</option>
          </select>
        </label>

        <div v-if="activeDataset" class="w-full flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-text-mute">
          <span>真阳 {{ activeDataset.labels?.['真阳'] || 0 }}</span>
          <span>假阳 {{ activeDataset.labels?.['假阳'] || 0 }}</span>
          <span>标签：{{ activeDataset.label_basis }}</span>
          <span v-if="activeDataset.label_basis === 'time_window_weak'" class="text-yellow">
            攻击时间窗弱标签
          </span>
          <span v-if="activeDataset.label_warning" class="truncate max-w-2xl" :title="activeDataset.label_warning">
            {{ activeDataset.label_warning }}
          </span>
        </div>
        <div class="w-full text-[10px] text-text-mute">
          RAG 先保留无知识初判，对待查、低置信及低特异性高置信真阳进行严格检索与后融合；高置信假阳和强攻击证据样本会跳过。标签不会传给 Agent。
        </div>
      </div>
    </div>

    <!-- 持久化评测历史 -->
    <div class="card overflow-hidden">
      <div class="p-5 border-b border-border flex items-center justify-between gap-3">
        <div>
          <h3 class="font-bold text-sm flex items-center gap-2"><span>🗂️</span> 评测历史</h3>
          <div class="text-[10px] text-text-mute mt-1">结果保存在本机 SQLite，中断前已完成的样本也可恢复</div>
        </div>
        <button
          @click="loadHistory"
          :disabled="historyLoading"
          class="px-3 py-1.5 rounded-lg border border-border text-xs text-text-dim hover:border-cyan hover:text-cyan"
        >{{ historyLoading ? '刷新中...' : '↻ 刷新' }}</button>
      </div>

      <div v-if="historyRuns.length" class="divide-y divide-border">
        <div
          v-for="run in historyRuns"
          :key="run.id"
          class="p-4 hover:bg-bg-2/60 transition-colors"
          :class="viewingRunId === run.id ? 'bg-cyan/5' : ''"
        >
          <div class="flex flex-wrap items-center gap-3">
            <code class="font-mono text-xs text-cyan">{{ run.id.slice(0, 8) }}</code>
            <span class="chip text-[10px]" :class="statusClass(run.status)">{{ statusText[run.status] || run.status }}</span>
            <span class="text-xs" :class="run.mode === 'mock' ? 'text-purple' : 'text-pink'">
              {{ run.mode === 'mock' ? 'Mock' : '真实模型' }}
            </span>
            <span class="chip text-[10px] text-text-dim">
              {{ run.strategy === 'judge_only' ? 'Judge-only' : 'ReAct' }}
            </span>
            <span class="text-[10px] text-text-mute">{{ formatTime(run.started_at) }}</span>
            <span v-if="run.experiment_config?.model" class="text-[10px] text-text-mute font-mono">
              {{ run.experiment_config.model }} · {{ run.experiment_config.prompt_version }}
            </span>
            <span class="ml-auto text-xs font-mono text-text-dim">{{ run.completed }} / {{ run.total }}</span>
          </div>

          <div class="h-1.5 rounded-full bg-bg mt-3 overflow-hidden">
            <div
              class="h-full rounded-full bg-gradient-to-r from-cyan to-purple"
              :style="{ width: (run.total ? run.completed / run.total * 100 : 0) + '%' }"
            ></div>
          </div>

          <div class="flex flex-wrap items-center gap-4 mt-3">
            <template v-if="run.metrics">
              <span class="text-[10px] text-text-mute">准确率 <b class="text-green">{{ (run.metrics.accuracy * 100).toFixed(1) }}%</b></span>
              <span class="text-[10px] text-text-mute">F1 <b class="text-cyan">{{ (run.metrics.f1 * 100).toFixed(1) }}</b></span>
              <span class="text-[10px] text-text-mute">Macro-F1 <b class="text-purple">{{ ((run.metrics.macro_f1 ?? run.metrics.f1) * 100).toFixed(1) }}</b></span>
              <span class="text-[10px] text-text-mute">调用 <b class="text-text-dim">{{ run.metrics.llm_calls ?? '-' }}</b></span>
              <span class="text-[10px] text-text-mute">Token <b class="text-text-dim">{{ run.metrics.total_tokens ?? '-' }}</b></span>
              <span class="text-[10px] text-text-mute">平均延迟 <b class="text-text-dim">{{ run.metrics.avg_latency_s.toFixed(2) }}s</b></span>
            </template>
            <span v-if="run.error" class="text-[10px] text-yellow truncate max-w-md" :title="run.error">{{ run.error }}</span>
            <div class="ml-auto flex gap-2">
              <button
                @click="viewHistory(run)"
                class="px-3 py-1.5 rounded-lg border border-cyan/40 text-xs text-cyan hover:bg-cyan/10"
              >查看 {{ run.completed }} 条结果</button>
              <button
                @click="removeHistory(run)"
                :disabled="run.status === 'running'"
                class="px-3 py-1.5 rounded-lg border border-red/30 text-xs text-red disabled:opacity-30 hover:bg-red/10"
              >删除</button>
            </div>
          </div>
        </div>
      </div>
      <div v-else class="p-8 text-center text-xs text-text-mute">
        {{ historyLoading ? '正在读取历史...' : '暂无评测历史，运行一次评测后会自动保存' }}
      </div>
    </div>

    <!-- 错误 -->
    <div v-if="errorMsg" class="p-4 rounded-lg bg-red/10 border border-red/40 text-red">
      ⚠ {{ errorMsg }}
    </div>

    <!-- 加载中 -->
    <div v-if="loading" class="card p-10 text-center">
      <div class="animate-pulse-dot text-cyan text-3xl mb-3">●</div>
      <div class="text-sm text-text-dim">
        评测进行中：{{ progress.completed }} / {{ progress.total }}（{{ progressPercent }}%）
      </div>
      <div class="max-w-xl h-2 mx-auto mt-4 rounded-full bg-bg-2 overflow-hidden">
        <div
          class="h-full bg-gradient-to-r from-cyan to-purple rounded-full transition-all duration-300"
          :style="{ width: progressPercent + '%' }"
        ></div>
      </div>
      <div v-if="details.length" class="text-xs text-text-mute mt-3">
        最近完成：{{ details[details.length - 1].alert_id }} ·
        {{ details[details.length - 1].pred }} ·
        {{ (details[details.length - 1].confidence * 100).toFixed(0) }}%
      </div>
      <div
        v-if="liveAgentEvents.length"
        class="max-w-3xl mx-auto mt-5 text-left border border-border rounded-lg bg-bg-1/70 overflow-hidden"
      >
        <div class="px-4 py-2 border-b border-border text-xs text-text-dim flex justify-between">
          <span>实时 Agent 轨迹</span>
          <span class="font-mono">{{ liveAgentEvents.length }} events</span>
        </div>
        <div class="max-h-52 overflow-y-auto divide-y divide-border/60">
          <div
            v-for="event in liveAgentEvents.slice(-8)"
            :key="`${event.event_seq}-${event.type}`"
            class="px-4 py-2 text-xs flex gap-3"
          >
            <span class="font-mono text-cyan shrink-0">{{ event.sample_index || '-' }}/{{ event.sample_total || progress.total }}</span>
            <span class="text-text w-32 shrink-0">{{ eventLabels[event.type] || event.type }}</span>
            <span class="text-text-mute truncate">
              {{ event.alert_id }}
              <template v-if="event.tool"> · {{ event.tool }}</template>
              <template v-else-if="event.data?.next_action?.tool"> · {{ event.data.next_action.tool }}</template>
              <template v-else-if="event.data?.judgment"> · {{ event.data.judgment }} {{ Math.round((event.data.confidence || 0) * 100) }}%</template>
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- 结果 -->
    <template v-if="metrics">
      <div class="card px-4 py-3 flex flex-wrap items-center gap-4 text-xs text-text-dim">
        <span>策略：<b class="text-cyan">{{ result?.strategy === 'judge_only' ? 'Judge-only 无工具基线' : '完整 ReAct' }}</b></span>
        <span>模型：<b class="font-mono text-text">{{ result?.experiment_config?.model || '-' }}</b></span>
        <span>Prompt：<b class="font-mono text-text">{{ result?.experiment_config?.prompt_version || '-' }}</b></span>
        <span>RAG：<b class="text-text">{{ result?.experiment_config?.rag_enabled ? '选择性后融合' : '关闭' }}</b></span>
      </div>
      <div
        v-if="result?.experiment_config?.rag_enabled && result?.paired_rag"
        class="card px-5 py-4 grid grid-cols-2 md:grid-cols-6 gap-4 text-xs"
      >
        <div><div class="text-text-mute">无 RAG 初判</div><div class="text-lg font-bold text-text">{{ (result.paired_rag.initial_accuracy * 100).toFixed(1) }}%</div></div>
        <div><div class="text-text-mute">RAG 后融合</div><div class="text-lg font-bold text-cyan">{{ (result.paired_rag.final_accuracy * 100).toFixed(1) }}%</div></div>
        <div><div class="text-text-mute">RAG 净变化</div><div class="text-lg font-bold" :class="result.paired_rag.accuracy_delta >= 0 ? 'text-green' : 'text-red'">{{ result.paired_rag.accuracy_delta >= 0 ? '+' : '' }}{{ (result.paired_rag.accuracy_delta * 100).toFixed(1) }} pp</div></div>
        <div><div class="text-text-mute">触发 / 采纳</div><div class="text-lg font-bold text-purple">{{ result.paired_rag.triggered }} / {{ result.paired_rag.refinement_accepted }}</div></div>
        <div><div class="text-text-mute">修正 / 退化</div><div class="text-lg font-bold"><span class="text-green">{{ result.paired_rag.fixes }}</span> / <span class="text-red">{{ result.paired_rag.regressions }}</span></div></div>
        <div><div class="text-text-mute">后融合失败</div><div class="text-lg font-bold" :class="result.paired_rag.refinement_errors ? 'text-red' : 'text-green'">{{ result.paired_rag.refinement_errors }}</div></div>
      </div>
      <div
        v-if="result?.strategy === 'react' && result?.paired_react"
        class="card px-5 py-4 grid grid-cols-2 md:grid-cols-6 gap-4 text-xs"
      >
        <div><div class="text-text-mute">{{ result?.experiment_config?.rag_enabled ? 'RAG 后判定' : '同轮初判' }}</div><div class="text-lg font-bold text-text">{{ (result.paired_react.initial_accuracy * 100).toFixed(1) }}%</div></div>
        <div><div class="text-text-mute">ReAct 最终</div><div class="text-lg font-bold text-cyan">{{ (result.paired_react.final_accuracy * 100).toFixed(1) }}%</div></div>
        <div><div class="text-text-mute">净变化</div><div class="text-lg font-bold" :class="result.paired_react.accuracy_delta >= 0 ? 'text-green' : 'text-red'">{{ result.paired_react.accuracy_delta >= 0 ? '+' : '' }}{{ (result.paired_react.accuracy_delta * 100).toFixed(1) }} pp</div></div>
        <div><div class="text-text-mute">修正</div><div class="text-lg font-bold text-green">{{ result.paired_react.fixes }}</div></div>
        <div><div class="text-text-mute">退化</div><div class="text-lg font-bold text-red">{{ result.paired_react.regressions }}</div></div>
        <div><div class="text-text-mute">改变但仍错</div><div class="text-lg font-bold text-yellow">{{ result.paired_react.changed_wrong }}</div></div>
      </div>
      <!-- 指标卡 -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="样本数" :value="metrics.n" color="cyan" />
        <StatCard label="准确率 (Accuracy)" :value="(metrics.accuracy * 100).toFixed(1) + '%'" color="green" />
        <StatCard label="精确率 (Precision)" :value="(metrics.precision * 100).toFixed(1) + '%'" color="purple" />
        <StatCard label="召回率 (Recall)" :value="(metrics.recall * 100).toFixed(1) + '%'" color="pink" />
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Macro-F1" :value="((metrics.macro_f1 ?? metrics.f1) * 100).toFixed(1)" color="purple" />
        <StatCard label="覆盖率" :value="(metrics.coverage * 100).toFixed(1) + '%'" color="cyan" />
        <StatCard label="LLM 调用" :value="metrics.llm_calls ?? 0" color="pink" />
        <StatCard label="Token" :value="metrics.total_tokens ?? 0" color="green" />
      </div>

      <!-- F1 + 混淆矩阵 -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div class="card p-6 lg:col-span-1">
          <div class="text-xs text-text-dim mb-1">F1 分数</div>
          <div class="text-5xl font-black gradient-text-cyan">{{ (metrics.f1 * 100).toFixed(1) }}</div>
          <div class="text-xs text-text-mute mt-1">F1 = 2·P·R / (P+R)</div>
          <div class="mt-4 pt-4 border-t border-border text-xs space-y-1">
            <div class="flex justify-between">
              <span class="text-text-dim">平均延迟</span>
              <span class="font-mono text-cyan">{{ metrics.avg_latency_s.toFixed(2) }}s</span>
            </div>
            <div class="flex justify-between">
              <span class="text-text-dim">待查数</span>
              <span class="font-mono text-yellow">{{ metrics.unknown_count }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-text-dim">平均调用/样本</span>
              <span class="font-mono text-text-dim">{{ (metrics.avg_llm_calls_per_sample ?? 0).toFixed(2) }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-text-dim">平均 Token/样本</span>
              <span class="font-mono text-text-dim">{{ (metrics.avg_tokens_per_sample ?? 0).toFixed(0) }}</span>
            </div>
          </div>
        </div>

        <!-- 混淆矩阵 -->
        <div class="card p-6 lg:col-span-2">
          <h3 class="font-bold text-sm mb-4">混淆矩阵</h3>
          <div class="grid grid-cols-4 gap-2 text-center text-xs">
            <div></div>
            <div class="text-text-dim pb-2">预测：真阳</div>
            <div class="text-text-dim pb-2">预测：假阳</div>
            <div class="text-text-dim pb-2">预测：待查</div>

            <div class="text-text-dim pr-2 flex items-center">真实：真阳</div>
            <div class="p-4 rounded-lg bg-green/10 border border-green/30">
              <div class="text-2xl font-black text-green">{{ metrics.confusion_matrix.tp }}</div>
              <div class="text-[10px] text-text-mute mt-1">TP（正确识别攻击）</div>
            </div>
            <div class="p-4 rounded-lg bg-red/10 border border-red/30">
              <div class="text-2xl font-black text-red">{{ metrics.confusion_matrix.explicit_fn ?? metrics.confusion_matrix.fn }}</div>
              <div class="text-[10px] text-text-mute mt-1">真阳误判为假阳</div>
            </div>
            <div class="p-4 rounded-lg bg-yellow/10 border border-yellow/30">
              <div class="text-2xl font-black text-yellow">{{ metrics.confusion_matrix.abstain_positive ?? 0 }}</div>
              <div class="text-[10px] text-text-mute mt-1">真阳待查</div>
            </div>

            <div class="text-text-dim pr-2 flex items-center">真实：假阳</div>
            <div class="p-4 rounded-lg bg-orange/10 border border-orange/30">
              <div class="text-2xl font-black text-orange">{{ metrics.confusion_matrix.fp }}</div>
              <div class="text-[10px] text-text-mute mt-1">FP（误报，正常判成攻击）</div>
            </div>
            <div class="p-4 rounded-lg bg-cyan/10 border border-cyan/30">
              <div class="text-2xl font-black text-cyan">{{ metrics.confusion_matrix.tn }}</div>
              <div class="text-[10px] text-text-mute mt-1">TN（正确识别误报）</div>
            </div>
            <div class="p-4 rounded-lg bg-yellow/10 border border-yellow/30">
              <div class="text-2xl font-black text-yellow">{{ metrics.confusion_matrix.abstain_negative ?? 0 }}</div>
              <div class="text-[10px] text-text-mute mt-1">假阳待查</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 明细表 -->
      <div class="card overflow-hidden">
        <div class="p-5 border-b border-border flex items-center justify-between gap-3">
          <h3 class="font-bold text-sm flex items-center gap-2">
            <span>📋</span> 样本明细（{{ details.length }} 条）
          </h3>
          <span class="text-[10px] text-text-mute">点击任意样本查看完整研判流程</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-xs">
            <thead>
              <tr class="bg-bg-2 text-text-mute">
                <th class="px-4 py-3 text-left font-medium">告警 ID</th>
                <th class="px-4 py-3 text-left font-medium">真实标签</th>
                <th class="px-4 py-3 text-left font-medium">预测</th>
                <th class="px-4 py-3 text-left font-medium">置信度</th>
                <th class="px-4 py-3 text-left font-medium">延迟</th>
                <th class="px-4 py-3 text-left font-medium">调用/Token</th>
                <th class="px-4 py-3 text-left font-medium">结果</th>
                <th class="px-4 py-3 text-left font-medium">理由</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(d, i) in details"
                :key="d.alert_id"
                @click="openDetail(d)"
                class="border-t border-border hover:bg-bg-2 transition-colors cursor-pointer"
                :class="i % 2 === 1 ? 'bg-bg/30' : ''"
                title="点击查看完整研判流程"
              >
                <td class="px-4 py-2.5"><code class="font-mono text-cyan">{{ d.alert_id }}</code></td>
                <td class="px-4 py-2.5">
                  <JudgmentBadge :judgment="d.label" size="sm" />
                </td>
                <td class="px-4 py-2.5">
                  <JudgmentBadge :judgment="d.pred" size="sm" />
                </td>
                <td class="px-4 py-2.5 font-mono text-text-dim">{{ (d.confidence * 100).toFixed(0) }}%</td>
                <td class="px-4 py-2.5 font-mono text-text-mute">{{ d.latency_s.toFixed(2) }}s</td>
                <td class="px-4 py-2.5 font-mono text-text-mute">
                  {{ d.llm_calls ?? '-' }} / {{ d.token_usage?.total_tokens ?? '-' }}
                </td>
                <td class="px-4 py-2.5">
                  <span :class="d.correct ? 'text-green' : 'text-red'" class="font-bold">
                    {{ d.correct ? '✓' : '✗' }}
                  </span>
                </td>
                <td class="px-4 py-2.5 text-text-dim max-w-xs truncate" :title="d.reason">
                  {{ d.reason }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- 空状态 -->
    <div v-if="!metrics && !loading && !errorMsg" class="card p-16 text-center">
      <div class="text-5xl mb-3 opacity-40">📊</div>
      <div class="text-sm text-text-dim mb-1">尚未运行评测</div>
      <div class="text-xs text-text-mute">点击上方按钮开始（推荐先用 Mock 模式验证链路）</div>
    </div>

    <!-- 已完成样本的完整研判流程；仅展示本次已有结果，不会重复调用模型。 -->
    <div
      v-if="selectedDetail"
      class="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-start justify-center p-4 md:p-8 overflow-y-auto"
      @click.self="selectedDetail = null"
    >
      <div class="card w-full max-w-5xl p-6 my-auto">
        <div class="flex items-start justify-between gap-4 mb-6">
          <div>
            <div class="text-[10px] text-text-mute mb-1">评测样本研判流程</div>
            <h2 class="text-xl font-bold font-mono text-cyan">{{ selectedDetail.alert_id }}</h2>
            <div class="text-xs text-text-dim mt-1">{{ selectedDetail.alert?.rule_name }}</div>
          </div>
          <button
            @click="selectedDetail = null"
            class="w-9 h-9 rounded-lg border border-border text-text-dim hover:text-text hover:border-cyan"
          >✕</button>
        </div>

        <div v-if="selectedDetail.agent_result" class="space-y-6">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="card p-4 flex items-center justify-center">
              <ConfidenceGauge :confidence="selectedDetail.agent_result.confidence" :size="120" />
            </div>
            <div class="card p-4 md:col-span-2">
              <div class="flex flex-wrap items-center gap-3 mb-3">
                <JudgmentBadge :judgment="selectedDetail.agent_result.judgment" size="lg" />
                <span :class="selectedDetail.correct ? 'text-green' : 'text-red'" class="text-xs font-bold">
                  {{ selectedDetail.correct ? '✓ 与标签一致' : '✗ 与标签不一致' }}
                </span>
                <span class="text-xs text-text-mute">真实标签：{{ selectedDetail.label }}</span>
              </div>
              <div class="text-sm text-text-dim leading-relaxed">{{ selectedDetail.agent_result.reason }}</div>
              <div class="text-xs text-text-mute mt-3">
                耗时 {{ selectedDetail.latency_s.toFixed(2) }}s ·
                {{ selectedDetail.agent_result.react_used ? '进入过 ReAct' : '高置信直接处置' }}
              </div>
            </div>
          </div>

          <section v-if="selectedDetail.agent_result.cot_trace?.length">
            <div class="section-title mb-3">01 · CoT 思维链</div>
            <CoTTimeline :steps="selectedDetail.agent_result.cot_trace" :streaming="false" />
          </section>

          <section v-if="selectedDetail.agent_result.retrieval_trace?.strategy">
            <div class="section-title mb-3">RAG · 检索知识与引用</div>
            <div class="card p-3 mb-3 text-[10px] text-text-mute flex flex-wrap gap-x-5 gap-y-2">
              <span>策略：选择性后融合</span>
              <span>是否触发：{{ selectedDetail.agent_result.rag_attempted ? '是' : '否' }}</span>
              <span>召回：{{ selectedDetail.agent_result.knowledge_hits?.length || 0 }} 条</span>
              <span>
                融合：{{
                  selectedDetail.agent_result.rag_refinement?.accepted
                    ? '已采纳'
                    : (selectedDetail.agent_result.rag_refinement?.attempted ? '未采纳' : '未执行')
                }}
              </span>
              <span v-if="selectedDetail.agent_result.retrieval_trace?.skipped_reason">
                跳过原因：{{ selectedDetail.agent_result.retrieval_trace.skipped_reason }}
              </span>
              <span v-if="selectedDetail.agent_result.rag_refinement?.reason">
                融合原因：{{ selectedDetail.agent_result.rag_refinement.reason }}
              </span>
              <span v-if="selectedDetail.agent_result.rag_refinement?.parse_mode">
                解析路径：{{ selectedDetail.agent_result.rag_refinement.parse_mode }}
              </span>
              <span v-if="selectedDetail.agent_result.rag_refinement?.attempts">
                请求次数：{{ selectedDetail.agent_result.rag_refinement.attempts }}
              </span>
            </div>
            <div
              v-if="selectedDetail.agent_result.rag_refinement?.diagnostics?.length"
              class="mb-3 rounded-lg border border-red/30 bg-red/5 p-3 text-[10px] text-red"
            >
              {{ selectedDetail.agent_result.rag_refinement.diagnostics.join(' · ') }}
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div
                v-for="hit in selectedDetail.agent_result.knowledge_hits"
                :key="hit.knowledge_id"
                class="card p-4"
              >
                <div class="flex items-center justify-between gap-3">
                  <code class="text-[10px] text-cyan">{{ hit.knowledge_id }}</code>
                  <span class="text-[10px] text-text-mute">{{ Math.round(hit.score * 100) }}%</span>
                </div>
                <div class="mt-2 text-xs font-semibold">{{ hit.title }}</div>
                <div class="mt-2 text-[10px] text-text-mute line-clamp-3">{{ hit.content }}</div>
              </div>
            </div>
            <div class="mt-2 text-[10px] text-text-mute">
              本次实际引用：{{ selectedDetail.agent_result.cited_knowledge?.join(', ') || '无' }}
            </div>
          </section>

          <section v-if="selectedDetail.agent_result.react_steps?.length">
            <div class="section-title mb-3">02 · ReAct 工具调用</div>
            <div class="space-y-3">
              <ToolCard
                v-for="step in selectedDetail.agent_result.react_steps"
                :key="step.step"
                :step="step"
                :active="false"
              />
            </div>
          </section>

          <section v-if="selectedDetail.agent_result.disposition">
            <div class="section-title mb-3">03 · 处置闭环</div>
            <DispositionCard :disposition="selectedDetail.agent_result.disposition" />
          </section>

          <details class="card p-4">
            <summary class="text-xs font-bold text-text-dim cursor-pointer">查看原始告警与归一化特征</summary>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <pre class="text-[10px] text-text-dim bg-bg rounded-lg p-3 overflow-auto">{{ JSON.stringify(selectedDetail.alert, null, 2) }}</pre>
              <pre class="text-[10px] text-text-dim bg-bg rounded-lg p-3 overflow-auto">{{ JSON.stringify(selectedDetail.agent_result.features, null, 2) }}</pre>
            </div>
          </details>
        </div>

        <div v-else class="p-5 rounded-lg bg-red/10 border border-red/40 text-sm text-red">
          该样本调用失败，没有可展示的完整Agent流程。{{ selectedDetail.reason }}
        </div>
      </div>
    </div>
  </div>
</template>
