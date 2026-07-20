<script setup lang="ts">
// CoT 思维链时间线：把字符串数组渲染成竖向时间线
defineProps<{
  steps: string[]
  // 是否正在流式（影响动画）
  streaming?: boolean
}>()
</script>

<template>
  <div v-if="steps.length === 0" class="text-text-mute text-sm italic py-4">
    （等待 Agent 推理...）
  </div>
  <ol v-else class="relative space-y-4">
    <!-- 竖线 -->
    <div class="absolute left-[7px] top-2 bottom-2 w-0.5 bg-gradient-to-b from-cyan via-purple to-border"></div>
    <li
      v-for="(step, i) in steps"
      :key="i"
      class="relative pl-7 stream-item"
    >
      <!-- 圆点 -->
      <span
        class="absolute left-0 top-1 w-4 h-4 rounded-full border-2 flex items-center justify-center"
        :class="i === steps.length - 1 && streaming
          ? 'border-cyan bg-cyan/20 shadow-[0_0_12px_rgba(0,217,255,0.6)]'
          : 'border-cyan bg-bg'"
      >
        <span v-if="i === steps.length - 1 && streaming" class="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse-dot"></span>
      </span>
      <div class="text-[10px] text-text-mute font-mono mb-0.5">第 {{ i + 1 }} 步</div>
      <div class="text-sm text-text leading-relaxed">{{ step }}</div>
    </li>
  </ol>
</template>
