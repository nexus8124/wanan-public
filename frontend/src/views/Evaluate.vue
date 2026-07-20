<script setup lang="ts">
import { ref, computed } from 'vue'
import { runEval } from '../api/client'
import StatCard from '../components/StatCard.vue'
import JudgmentBadge from '../components/JudgmentBadge.vue'

const loading = ref(false)
const errorMsg = ref('')
const result = ref<any>(null)

const metrics = computed(() => result.value?.metrics || null)
const details = computed(() => result.value?.details || [])

async function startEval(useMock: boolean) {
  if (!useMock && !confirm('真实评测会消耗约 5-10 万 token（DeepSeek V4），确认继续？')) {
    return
  }
  loading.value = true
  errorMsg.value = ''
  result.value = null
  try {
    result.value = await runEval(useMock)
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    loading.value = false
  }
}
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
        </div>
      </div>
    </div>

    <!-- 错误 -->
    <div v-if="errorMsg" class="p-4 rounded-lg bg-red/10 border border-red/40 text-red">
      ⚠ {{ errorMsg }}
    </div>

    <!-- 加载中 -->
    <div v-if="loading" class="card p-10 text-center">
      <div class="animate-pulse-dot text-cyan text-3xl mb-3">●</div>
      <div class="text-sm text-text-dim">评测进行中，约需 2-5 分钟（每条告警含多轮 LLM 调用）...</div>
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
        <h3 class="font-bold text-sm p-5 border-b border-border flex items-center gap-2">
          <span>📋</span> 样本明细（{{ details.length }} 条）
        </h3>
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
                class="border-t border-border hover:bg-bg-2 transition-colors"
                :class="i % 2 === 1 ? 'bg-bg/30' : ''"
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
  </div>
</template>
