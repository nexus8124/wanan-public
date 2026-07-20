<script setup lang="ts">
import type { Disposition } from '../env'

defineProps<{
  disposition: Disposition
}>()

const actionLabels: Record<string, string> = {
  block_and_isolate: '封禁 + 隔离',
  block_ip: '封禁 IP',
  isolate_host: '隔离主机',
  whitelist: '加白名单',
  escalate_human: '升级人工',
  monitor: '持续监控',
}

const severityColors: Record<string, string> = {
  critical: 'text-red border-red/40',
  high: 'text-orange border-orange/40',
  medium: 'text-yellow border-yellow/40',
  low: 'text-cyan border-cyan/40',
  info: 'text-text-dim border-border',
}
</script>

<template>
  <div class="card p-5">
    <div class="flex items-center justify-between mb-3">
      <h3 class="font-bold text-sm flex items-center gap-2">
        <span>🛡️</span> 处置建议
      </h3>
      <span
        class="chip text-[10px]"
        :class="severityColors[disposition.severity]"
      >
        {{ disposition.severity.toUpperCase() }}
      </span>
    </div>

    <!-- 动作 -->
    <div class="flex items-center gap-2 mb-3">
      <span class="text-xs text-text-dim">动作：</span>
      <span class="font-bold text-cyan">{{ actionLabels[disposition.action] || disposition.action }}</span>
    </div>

    <!-- 总结 -->
    <p class="text-sm text-text-dim leading-relaxed mb-3">{{ disposition.summary }}</p>

    <!-- 工单 -->
    <div v-if="disposition.tickets.length" class="space-y-2">
      <div class="text-[10px] text-text-mute font-mono mb-1">生成工单（未执行，待人工确认）</div>
      <div
        v-for="t in disposition.tickets"
        :key="t.ticket_id"
        class="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-bg-2 border border-border-light"
      >
        <div class="min-w-0">
          <code class="text-xs font-mono text-cyan">{{ t.ticket_id }}</code>
          <div class="text-xs text-text-dim mt-0.5">
            {{ t.action }} → <span class="text-pink font-mono">{{ t.target }}</span>
          </div>
        </div>
        <span class="chip text-[10px] border-yellow text-yellow shrink-0">
          ⏸ 待执行
        </span>
      </div>
    </div>

    <!-- 无工单 -->
    <div v-else class="text-xs text-text-mute italic">
      （此判定无需生成处置工单）
    </div>
  </div>
</template>
