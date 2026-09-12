<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  confidence: number // 0-1
  size?: number
}>()

const size = props.size || 120
const radius = size / 2 - 8
const circumference = Math.PI * radius // 半圆周长

const percent = computed(() => Math.max(0, Math.min(1, props.confidence)))
// 0→红, 0.5→黄, 1→绿(引用主题令牌,随亮暗自适应;三段式,不留橙色区段)
const color = computed(() => {
  const p = percent.value
  if (p >= 0.85) return 'rgb(var(--green))'
  if (p >= 0.5) return 'rgb(var(--yellow))'
  return 'rgb(var(--red))'
})
const dashOffset = computed(() => circumference * (1 - percent.value))
</script>

<template>
  <div class="flex flex-col items-center">
    <svg :width="size" :height="size / 2 + 8" :viewBox="`0 0 ${size} ${size / 2 + 8}`">
      <!-- 背景半圆 -->
      <path
        :d="`M 8 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 8} ${size / 2}`"
        fill="none"
        stroke="rgb(var(--glow-track))"
        :stroke-width="8"
        stroke-linecap="round"
      />
      <!-- 进度半圆(0% 时不渲染,避免圆头线帽留下残影点) -->
      <path
        v-if="percent > 0"
        :d="`M 8 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 8} ${size / 2}`"
        fill="none"
        :stroke="color"
        :stroke-width="8"
        stroke-linecap="round"
        :stroke-dasharray="circumference"
        :stroke-dashoffset="dashOffset"
        style="transition: stroke-dashoffset 0.6s ease, stroke 0.3s"
      />
      <!-- 数值 -->
      <text
        :x="size / 2"
        :y="size / 2 - 4"
        text-anchor="middle"
        class="font-mono font-bold"
        :fill="color"
        :font-size="size / 5"
      >
        {{ (percent * 100).toFixed(0) }}%
      </text>
    </svg>
    <div class="text-sm font-medium text-text-dim mt-1">置信度</div>
  </div>
</template>
