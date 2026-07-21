<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { streamRunEval, listEvalHistory, getEvalHistory, deleteEvalHistory } from '../api/client'
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

const metrics = computed(() => result.value?.metrics || null)
const details = computed(() => result.value?.details || [])

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

onMounted(loadHistory)

async function startEval(useMock: boolean) {
  if (!useMock && !confirm('真实评测会消耗约 5-10 万 token（DeepSeek V4），确认继续？')) {
    return
  }
  loading.value = true
  errorMsg.value = ''
  result.value = null
  selectedDetail.value = null
  viewingRunId.value = ''
  activeRunId.value = ''
  progress.value = { completed: 0, total: 50 }
  abortCtrl.value = new AbortController()
  try {
    await streamRunEval(
      useMock,
      {
        onStart: (data) => {
          activeRunId.value = data.run_id
          progress.value.total = data.total || progress.value.total
          loadHistory()
        },
        onProgress: (data) => {
          progress.value = {
            completed: data.completed,
            total: data.total,
          }
          const currentDetails = result.value?.details || []
          result.value = {
            mode: useMock ? 'mock' : 'deepseek',
            metrics: data.metrics,
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
      dataset: saved.dataset,
      metrics: saved.metrics,
      details: saved.details,
    }
    progress.value = { completed: saved.completed, total: saved.total }
    viewingRunId.value = saved.id
    selectedDetail.value = null
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
            在 50 条标注样本上跑完整 Agent，输出准确率/精确率/召回率/F1
          </p>
        </div>
        <div class="flex gap-2">
          <button
            @click="startEval(true)"
            :disabled="loading"
            class="px-4 py-2 rounded-lg text-sm font-bold transition-all"
            :class="loading
              ? 'bg-bg-2 text-text-mute'
              : 'bg-bg-2 border border-cyan/40 text-cyan hover:bg-cyan/10'"
          >
            🧪 Mock 评测（不耗 token）
          </button>
          <button
            @click="startEval(false)"
            :disabled="loading"
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
            <span class="text-[10px] text-text-mute">{{ formatTime(run.started_at) }}</span>
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
    </div>

    <!-- 结果 -->
    <template v-if="metrics">
      <!-- 指标卡 -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="样本数" :value="metrics.n" color="cyan" />
        <StatCard label="准确率 (Accuracy)" :value="(metrics.accuracy * 100).toFixed(1) + '%'" color="green" />
        <StatCard label="精确率 (Precision)" :value="(metrics.precision * 100).toFixed(1) + '%'" color="purple" />
        <StatCard label="召回率 (Recall)" :value="(metrics.recall * 100).toFixed(1) + '%'" color="pink" />
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
          </div>
        </div>

        <!-- 混淆矩阵 -->
        <div class="card p-6 lg:col-span-2">
          <h3 class="font-bold text-sm mb-4">混淆矩阵</h3>
          <div class="grid grid-cols-3 gap-2 text-center text-xs">
            <div></div>
            <div class="text-text-dim pb-2">预测：真阳</div>
            <div class="text-text-dim pb-2">预测：假阳</div>

            <div class="text-text-dim pr-2 flex items-center">真实：真阳</div>
            <div class="p-4 rounded-lg bg-green/10 border border-green/30">
              <div class="text-2xl font-black text-green">{{ metrics.confusion_matrix.tp }}</div>
              <div class="text-[10px] text-text-mute mt-1">TP（正确识别攻击）</div>
            </div>
            <div class="p-4 rounded-lg bg-red/10 border border-red/30">
              <div class="text-2xl font-black text-red">{{ metrics.confusion_matrix.fn }}</div>
              <div class="text-[10px] text-text-mute mt-1">FN（漏报攻击）</div>
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
