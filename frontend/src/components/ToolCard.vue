<script setup lang="ts">
import type { ReactStep } from '../env'

const props = defineProps<{
  step: ReactStep
  active?: boolean // 是否当前进行中
}>()

// 工具图标映射
const toolIcons: Record<string, string> = {
  fetch_endpoint_logs: '🖥️',
  fetch_network_flows: '🌐',
  check_threat_intel: '📡',
  query_similar_alerts: '🔍',
  search_attck_technique: '🎯',
  lookup_cve: '🐛',
  suggest_block_ip: '🚫',
  suggest_isolate_host: '🔒',
}

function icon(tool: string): string {
  return toolIcons[tool] || '🔧'
}

function rawData(result: Record<string, any>): Record<string, any> {
  return result.evidence?.[0]?.data || result
}

// 从 result 提取关键证据
function keyEvidence(result: Record<string, any>): string[] {
  result = rawData(result)
  const out: string[] = []
  if (result.suspicious_processes?.length) {
    for (const p of result.suspicious_processes) {
      out.push(`${p.name} (PID ${p.pid}) ← parent: ${p.parent}`)
    }
  }
  if (result.anomalies?.length) {
    for (const a of result.anomalies) {
      out.push(`${a.type}: ${a.desc}`)
    }
  }
  if (result.malicious) {
    out.push(`命中威胁情报：${(result.tags || []).join(', ')}`)
  }
  if (result.first_seen !== undefined) {
    out.push(result.first_seen ? '近 30 天首次出现' : `历史出现 ${result.history_count_30d} 次`)
  }
  if (result.matches?.length) {
    for (const m of result.matches.slice(0, 3)) {
      out.push(`${m.id || m.cve_id || '?'}: ${m.name || m.product || ''}`)
    }
  }
  return out
}
</script>

<template>
  <div
    class="rounded-xl border p-4 stream-item transition-all"
    :class="active
      ? 'border-cyan bg-cyan/5 shadow-[0_0_30px_-8px_rgba(0,217,255,0.4)]'
      : 'border-border-light bg-bg-2'"
  >
    <!-- 头部：步数 + 工具名 -->
    <div class="flex items-center gap-2 mb-2">
      <span class="w-6 h-6 rounded-full bg-purple/20 text-purple flex items-center justify-center text-xs font-bold font-mono">
        {{ step.step }}
      </span>
      <span class="text-lg">{{ icon(step.tool) }}</span>
      <code class="text-sm font-mono font-semibold text-cyan">{{ step.tool }}</code>
      <span v-if="active" class="ml-auto chip border-cyan text-cyan text-[10px]">
        <span class="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse-dot"></span>
        进行中
      </span>
    </div>

    <!-- 输入参数 -->
    <div class="text-xs text-text-mute font-mono mb-2">
      <span class="text-text-dim">输入:</span>
      <span v-for="(v, k) in step.args" :key="k" class="ml-2">
        <span class="text-purple">{{ k }}</span>=<span class="text-green">"{{ v }}"</span>
      </span>
    </div>

    <!-- 关键证据 -->
    <div v-if="keyEvidence(step.result).length" class="border-t border-border pt-2 mt-2">
      <div class="text-[10px] text-text-dim mb-1">📋 关键证据</div>
      <ul class="space-y-1">
        <li
          v-for="(ev, i) in keyEvidence(step.result)"
          :key="i"
          class="text-xs text-text font-mono leading-relaxed"
        >
          <span class="text-cyan">•</span> {{ ev }}
        </li>
      </ul>
    </div>

    <!-- 结论 verdict -->
    <div class="mt-2 flex flex-wrap gap-2 text-[10px] font-mono">
      <span class="chip border-border-light text-text-dim">{{ step.result.status || 'legacy' }}</span>
      <span v-if="step.result.latency_ms !== undefined" class="chip border-border-light text-text-mute">{{ step.result.latency_ms }}ms</span>
      <span v-for="ev in step.result.evidence || []" :key="ev.evidence_id" class="chip border-cyan/40 text-cyan">{{ ev.evidence_id }}</span>
    </div>

    <div v-if="step.result.summary || rawData(step.result).verdict" class="mt-2 text-xs px-2 py-1.5 rounded bg-bg border-l-2 border-cyan">
      <span class="text-text-dim">判定：</span>
      <span class="text-text">{{ step.result.summary || rawData(step.result).verdict }}</span>
    </div>
  </div>
</template>
