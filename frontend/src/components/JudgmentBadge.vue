<script setup lang="ts">
defineProps<{
  judgment: '真阳' | '假阳' | '待查' | string
  size?: 'sm' | 'md' | 'lg'
}>()

const sizeMap = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-3 py-1',
  lg: 'text-base px-4 py-1.5',
}
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full font-bold border"
    :class="[
      sizeMap[size || 'md'],
      judgment === '真阳' && 'bg-red/10 text-red border-red/40',
      judgment === '假阳' && 'bg-green/10 text-green border-green/40',
      judgment === '待查' && 'bg-yellow/10 text-yellow border-yellow/40',
    ]"
  >
    <span v-if="judgment === '真阳'">⚠</span>
    <span v-else-if="judgment === '假阳'">✓</span>
    <span v-else>?</span>
    {{ judgment }}
  </span>
</template>
