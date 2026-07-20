<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getStats } from '../api/client'
import type { Stats } from '../env'
import StatCard from '../components/StatCard.vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const stats = ref<Stats | null>(null)
const loading = ref(true)
const errorMsg = ref('')

onMounted(async () => {
  try {
    stats.value = await getStats()
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    loading.value = false
  }
})

// 计算 source 最大值用于柱状图
function maxSource(s: Stats): number {
  return Math.max(...Object.values(s.by_source), 1)
}

// label 颜色
const labelColors: Record<string, string> = {
  '真阳': 'bg-red',
  '假阳': 'bg-green',
  '待查': 'bg-yellow',
  '未标注': 'bg-text-mute',
}

const sourceLabels: Record<string, string> = {
  edr: 'EDR 端点',
  ids: 'IDS 入侵检测',
  waf: 'WAF Web 应用防火墙',
  siem: 'SIEM 日志',
  ndr: 'NDR 网络检测',
  firewall: '防火墙',
}

function goInvestigate() {
  router.push('/investigate')
}
</script>

<template>
  <div v-if="loading" class="text-center py-20 text-text-dim">
    <div class="animate-pulse-dot text-cyan text-3xl mb-3">●</div>
    加载数据大屏...
  </div>

  <div v-else-if="errorMsg" class="p-4 rounded-lg bg-red/10 border border-red/40 text-red">
    ⚠ {{ errorMsg }}
  </div>

  <div v-else-if="stats" class="space-y-6">
    <!-- 顶部数字卡 -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard label="数据集样本总数" :value="stats.total" hint="含真阳/假阳标注" color="cyan" />
      <StatCard label="真实攻击（真阳）" :value="stats.by_label['真阳'] || 0" hint="涵盖多种攻击手法" color="red" />
      <StatCard label="误报样本（假阳）" :value="stats.by_label['假阳'] || 0" hint="用于验证识别能力" color="green" />
      <StatCard label="ATT&CK 战术覆盖" :value="stats.attack_types.length" hint="MITRE 战术编号" color="purple" />
    </div>

    <!-- 中部图表 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <!-- 左：标签分布饼图（用 conic-gradient） -->
      <div class="card p-6">
        <h3 class="font-bold text-sm mb-4 flex items-center gap-2">
          <span>🎯</span> 标签分布
        </h3>
        <div class="flex items-center gap-8">
          <div class="relative">
            <div
              class="w-40 h-40 rounded-full"
              :style="{
                background: `conic-gradient(
                  #f87171 0% ${(stats.by_label['真阳'] || 0) / stats.total * 100}%,
                  #34d399 ${(stats.by_label['真阳'] || 0) / stats.total * 100}% ${(stats.by_label['真阳'] || 0 + stats.by_label['假阳'] || 0) / stats.total * 100}%,
                  #fbbf24 ${(stats.by_label['真阳'] || 0 + stats.by_label['假阳'] || 0) / stats.total * 100}% 100%
                )`
              }"
            ></div>
            <div class="absolute inset-4 rounded-full bg-card flex flex-col items-center justify-center">
              <div class="text-2xl font-black gradient-text-cyan">{{ stats.total }}</div>
              <div class="text-[10px] text-text-mute">样本</div>
            </div>
          </div>
          <div class="space-y-2 flex-1">
            <div v-for="cnt, lbl in stats.by_label" :key="lbl" class="flex items-center gap-2 text-sm">
              <span class="w-3 h-3 rounded" :class="labelColors[lbl] || 'bg-text-mute'"></span>
              <span class="text-text-dim">{{ lbl }}</span>
              <span class="ml-auto font-mono font-bold text-text">{{ cnt }}</span>
              <span class="text-xs text-text-mute">({{ (cnt / stats.total * 100).toFixed(0) }}%)</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右：按数据源分布 -->
      <div class="card p-6">
        <h3 class="font-bold text-sm mb-4 flex items-center gap-2">
          <span>📡</span> 数据源分布
        </h3>
        <div class="space-y-3">
          <div v-for="cnt, src in stats.by_source" :key="src">
            <div class="flex items-center justify-between text-xs mb-1">
              <span class="text-text-dim">{{ sourceLabels[src] || src }}</span>
              <span class="font-mono text-cyan">{{ cnt }}</span>
            </div>
            <div class="h-2 rounded-full bg-bg-2 overflow-hidden">
              <div
                class="h-full bg-gradient-to-r from-cyan to-purple rounded-full transition-all"
                :style="{ width: (cnt / maxSource(stats) * 100) + '%' }"
              ></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ATT&CK 战术覆盖 -->
    <div class="card p-6">
      <h3 class="font-bold text-sm mb-4 flex items-center gap-2">
        <span>⚔️</span> ATT&CK 战术覆盖
        <span class="ml-2 text-[10px] text-text-mute normal-case font-normal">点击任意战术进入研判演示</span>
      </h3>
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
        <button
          v-for="at in stats.attack_types"
          :key="at.id"
          @click="goInvestigate"
          class="text-left p-3 rounded-lg border border-border bg-bg-2 hover:border-cyan hover:bg-cyan/5 transition-all"
        >
          <code class="text-xs font-mono font-bold text-pink">{{ at.id }}</code>
          <div class="text-[10px] text-text-dim mt-1">出现 {{ at.count }} 次</div>
        </button>
      </div>
    </div>

    <!-- CTA -->
    <div class="card p-6 relative overflow-hidden">
      <div class="absolute inset-0 bg-gradient-to-br from-cyan/10 via-purple/5 to-pink/10"></div>
      <div class="relative flex items-center justify-between">
        <div>
          <div class="text-lg font-bold mb-1">想看 Agent 如何研判一条告警？</div>
          <div class="text-sm text-text-dim">实时展示 CoT 思维链 + ReAct 自主调查 + 处置闭环</div>
        </div>
        <button
          @click="goInvestigate"
          class="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan to-purple text-bg font-bold hover:opacity-90"
        >
          进入研判演示 →
        </button>
      </div>
    </div>
  </div>
</template>
