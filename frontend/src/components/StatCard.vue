<script setup lang="ts">
defineProps<{
  label: string
  value: string | number
  hint?: string
  color?: 'cyan' | 'purple' | 'pink' | 'green' | 'yellow' | 'red'
}>()

const colorMap = {
  cyan: 'text-cyan',
  purple: 'text-purple',
  pink: 'text-pink',
  green: 'text-green',
  yellow: 'text-yellow',
  red: 'text-red',
}
</script>

<template>
  <div class="card p-5">
    <div class="text-xs text-text-dim mb-2">{{ label }}</div>
    <div class="text-3xl font-black" :class="colorMap[color || 'cyan']">{{ value }}</div>
    <div v-if="hint" class="text-xs text-text-mute mt-1">{{ hint }}</div>
  </div>
</template>
