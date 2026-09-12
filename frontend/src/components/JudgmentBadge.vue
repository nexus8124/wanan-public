<script setup lang="ts">
import { PhCheck, PhQuestion, PhWarning } from '@phosphor-icons/vue'

defineProps<{
  judgment: '真阳' | '假阳' | '待查' | string
  size?: 'sm' | 'md' | 'lg'
}>()

const sizeMap = {
  sm: 'text-[13px] px-2.5 py-1',
  md: 'text-sm px-3.5 py-1.5',
  lg: 'text-lg px-4 py-2',
}
const iconSizeMap = { sm: 13, md: 15, lg: 18 }
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-none font-bold border"
    :class="[
      sizeMap[size || 'md'],
      judgment === '真阳' && 'bg-red/10 text-red border-red/40',
      judgment === '假阳' && 'bg-green/10 text-green border-green/40',
      judgment === '待查' && 'bg-yellow/10 text-yellow border-yellow/40',
    ]"
  >
    <PhWarning v-if="judgment === '真阳'" :size="iconSizeMap[size || 'md']" weight="bold" aria-hidden="true" />
    <PhCheck v-else-if="judgment === '假阳'" :size="iconSizeMap[size || 'md']" weight="bold" aria-hidden="true" />
    <PhQuestion v-else :size="iconSizeMap[size || 'md']" weight="bold" aria-hidden="true" />
    {{ judgment }}
  </span>
</template>
