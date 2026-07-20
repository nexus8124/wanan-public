<script setup lang="ts">
import { RouterView, RouterLink, useRoute } from 'vue-router'
import { computed } from 'vue'

const route = useRoute()
const pageTitle = computed(() => (route.meta.title as string) || '安全智能体')
</script>

<template>
  <div class="min-h-screen flex flex-col">
    <!-- 顶部导航 -->
    <nav class="sticky top-0 z-50 backdrop-blur-xl bg-bg/80 border-b border-border">
      <div class="max-w-[1400px] mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan to-purple flex items-center justify-center font-black text-bg text-sm">
            AI
          </div>
          <div>
            <div class="font-bold text-sm">XH-202614</div>
            <div class="text-[10px] text-text-mute font-mono">SECURITY AGENT · 挑战杯</div>
          </div>
        </div>
        <div class="flex items-center gap-7">
          <RouterLink to="/" class="nav-link">数据大屏</RouterLink>
          <RouterLink to="/investigate" class="nav-link">告警研判</RouterLink>
          <RouterLink to="/evaluate" class="nav-link">批量评测</RouterLink>
        </div>
        <div class="chip border-cyan text-cyan">
          <span class="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse-dot"></span>
          DeepSeek V4
        </div>
      </div>
    </nav>

    <!-- 主体 -->
    <main class="flex-1 max-w-[1400px] mx-auto w-full px-6 py-8">
      <div class="mb-6">
        <h1 class="text-2xl font-bold">{{ pageTitle }}</h1>
      </div>
      <RouterView />
    </main>

    <!-- 页脚 -->
    <footer class="border-t border-border mt-10">
      <div class="max-w-[1400px] mx-auto px-6 py-6 text-xs text-text-mute flex flex-wrap items-center justify-between gap-3">
        <span class="font-mono">XH-202614 · AI+安全大模型平台的智能体研究</span>
        <span>挑战杯揭榜挂帅 · 发榜单位：深信服科技 · 截止 2026.09.05</span>
      </div>
    </footer>
  </div>
</template>
