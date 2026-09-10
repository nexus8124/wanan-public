<script setup lang="ts">
import type { Disposition } from '../env'

const props = defineProps<{
  disposition: Disposition
  responseExecution?: Record<string, any>
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

const responseLabels: Record<string, string> = {
  awaiting_observation: '等待效果验证',
  retry_required: '反馈后重试',
  rollback_required: '准备补偿回滚',
  contained: '已执行并验证生效',
  rolled_back: '执行不完整，已安全回滚',
  manual_required: '自动处置失败，人工接管',
  skipped: '未触发自动执行',
}

function actionResult(ticketId: string): Record<string, any> | undefined {
  return props.responseExecution?.actions?.find(
    (item: Record<string, any>) => item.action_id === ticketId,
  )
}

function actionStatus(ticketId: string): string {
  const item = actionResult(ticketId)
  if (item?.verified) return '✓ 已验证生效'
  if (item?.rollback?.rolled_back) return '↩ 已回滚'
  if (item?.executed) return '◌ 已执行待验证'
  if (item?.status === 'failed' || item?.status === 'rejected') return '⚠ 执行失败'
  return '⏳ 已规划'
}

function actionStatusClass(ticketId: string): string {
  const item = actionResult(ticketId)
  if (item?.verified) return 'border-green text-green'
  if (item?.rollback?.rolled_back) return 'border-yellow text-yellow'
  if (item?.status === 'failed' || item?.status === 'rejected') return 'border-red text-red'
  return 'border-cyan text-cyan'
}
</script>

<template>
  <div class="card p-5">
    <div class="flex items-center justify-between mb-3">
      <h3 class="font-bold text-sm flex items-center gap-2">
        <span>🛡️</span> 自主处置闭环
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

    <div
      v-if="responseExecution?.status"
      class="mb-3 rounded-lg border border-cyan/30 bg-cyan/5 px-3 py-2 text-xs"
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <b class="text-cyan">{{ responseLabels[responseExecution.status] || responseExecution.status }}</b>
        <span class="font-mono text-[10px] text-text-mute">
          {{ responseExecution.mode }} · 尝试 {{ responseExecution.attempt || 0 }}/{{ responseExecution.max_attempts || 0 }}
        </span>
      </div>
      <p class="mt-1 text-text-dim">{{ responseExecution.reason }}</p>
    </div>

    <!-- 工单 -->
    <div v-if="disposition.tickets.length" class="space-y-2">
      <div class="text-[10px] text-text-mute font-mono mb-1">处置动作与效果观测</div>
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
        <span
          class="chip text-[10px] shrink-0"
          :class="actionStatusClass(t.ticket_id)"
        >
          {{ actionStatus(t.ticket_id) }}
        </span>
      </div>
    </div>

    <!-- 无工单 -->
    <div v-else class="text-xs text-text-mute italic">
      （此判定无需生成处置工单）
    </div>
  </div>
</template>
