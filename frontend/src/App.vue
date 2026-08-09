<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterLink, RouterView } from 'vue-router'
import {
  loadModelSelection,
  modelProfiles,
  modelsLoading,
  selectedModelKey,
  selectModelKey,
} from './modelSelection'

onMounted(() => {
  loadModelSelection().catch((error) => console.warn('load model catalog failed:', error))
})

function changeGlobalModel(event: Event) {
  selectModelKey((event.target as HTMLSelectElement).value)
}
</script>

<template>
  <div class="app-shell">
    <nav class="topbar">
      <div class="topbar-inner">
        <RouterLink to="/" class="brand">
          <span class="brand-mark">
            <i class="brand-ring"></i>
            <i class="brand-line"></i>
          </span>
          <span class="brand-copy">
            <b>安全告警研判平台</b>
            <small>SECURITY ALERT ANALYSIS</small>
          </span>
        </RouterLink>

        <div class="primary-nav">
          <RouterLink to="/" class="nav-item"><small>01</small><span>概览</span></RouterLink>
          <RouterLink to="/investigate" class="nav-item"><small>02</small><span>告警研判</span></RouterLink>
          <RouterLink to="/evaluate" class="nav-item"><small>03</small><span>模型评测</span></RouterLink>
        </div>

        <label class="model-status">
          <span></span>
          <div>
            <small>MODEL</small>
            <select
              :value="selectedModelKey"
              :disabled="modelsLoading || !modelProfiles.length"
              aria-label="全局模型"
              @change="changeGlobalModel"
            >
              <optgroup
                v-for="profile in modelProfiles"
                :key="profile.provider"
                :label="profile.display_name"
              >
                <option
                  v-for="model in profile.models"
                  :key="`${profile.provider}::${model.id}`"
                  :value="`${profile.provider}::${model.id}`"
                  :disabled="!profile.configured"
                >
                  {{ model.label }}{{ profile.configured ? '' : '（未配置）' }}
                </option>
              </optgroup>
            </select>
          </div>
        </label>
      </div>
    </nav>

    <main class="app-main">
      <RouterView />
    </main>

    <footer class="app-footer">
      <span>XH-202614 · AI+安全大模型平台的智能体研究</span>
      <span>挑战杯揭榜挂帅 · 深信服科技</span>
    </footer>
  </div>
</template>

<style scoped>
.app-shell { min-height: 100vh; display: flex; flex-direction: column; background: #090e16; }
.topbar { position: sticky; top: 0; z-index: 50; border-bottom: 1px solid #263143; background: rgba(9,14,22,.96); backdrop-filter: blur(18px); }
.topbar-inner { width: min(1480px, 100%); min-height: 68px; margin: 0 auto; padding: 0 22px; display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 24px; }
.brand { min-width: 0; display: inline-flex; align-items: center; gap: 12px; text-decoration: none; }
.brand-mark { position: relative; width: 38px; height: 38px; flex: 0 0 auto; border: 1px solid #31518a; border-radius: 6px; background: #0e1725; }
.brand-ring { position: absolute; width: 13px; height: 13px; left: 10px; top: 9px; border: 1px solid #5d8fe8; border-radius: 50%; }
.brand-ring::after { content: ''; position: absolute; width: 4px; height: 4px; left: 4px; top: 4px; border-radius: 50%; background: #df6a73; box-shadow: 0 0 8px #df6a73; }
.brand-line { position: absolute; width: 11px; height: 1px; left: 21px; top: 23px; background: #5d8fe8; transform: rotate(45deg); transform-origin: left center; }
.brand-copy b, .brand-copy small { display: block; white-space: nowrap; }
.brand-copy b { color: #edf3fc; font-size: 13px; font-weight: 760; }
.brand-copy small { margin-top: 3px; color: #6284b5; font: 8px/1 ui-monospace, monospace; letter-spacing: .19em; }
.primary-nav { align-self: stretch; display: flex; align-items: stretch; gap: 8px; }
.nav-item { position: relative; min-width: 86px; padding: 0 12px; display: flex; align-items: center; justify-content: center; gap: 7px; color: #8392a9; font-size: 12px; text-decoration: none; }
.nav-item small { color: #50627c; font: 8px ui-monospace, monospace; }
.nav-item:hover { color: #c2d0e2; }
.nav-item.router-link-active { color: #e7effb; }
.nav-item.router-link-active small { color: #6d94d8; }
.nav-item.router-link-active::after { content: ''; position: absolute; left: 12px; right: 12px; bottom: 0; height: 2px; background: #6796e9; box-shadow: 0 -4px 12px rgba(103,150,233,.2); }
.model-status { justify-self: end; min-width: 170px; padding: 7px 10px; display: flex; align-items: center; gap: 8px; border: 1px solid #233044; border-radius: 6px; background: #0e1622; }
.model-status > span { width: 6px; height: 6px; border-radius: 50%; background: #60c49b; box-shadow: 0 0 8px rgba(96,196,155,.5); }
.model-status > div { min-width: 0; flex: 1; }
.model-status small { display: block; }
.model-status small { color: #526d91; font: 7px ui-monospace, monospace; letter-spacing: .08em; }
.model-status select { width: 100%; margin-top: 1px; padding: 0; border: 0; outline: 0; background: transparent; color: #9cb1ce; font: 9px ui-monospace, monospace; cursor: pointer; }
.model-status select:disabled { cursor: wait; opacity: .65; }
.model-status option, .model-status optgroup { color: #dce7f7; background: #0e1622; }
.app-main { width: min(1480px, 100%); flex: 1; margin: 0 auto; padding: 27px 22px 34px; }
.app-footer { width: min(1480px, 100%); margin: 0 auto; padding: 18px 22px 24px; display: flex; justify-content: space-between; gap: 18px; border-top: 1px solid #1b2635; color: #46566c; font: 9px ui-monospace, monospace; }

@media (max-width: 760px) {
  .topbar-inner { min-height: 110px; grid-template-columns: 1fr auto; grid-template-rows: 60px 49px; gap: 0 12px; padding: 0 14px; }
  .primary-nav { grid-column: 1 / -1; grid-row: 2; justify-content: center; border-top: 1px solid #1b2635; }
  .nav-item { min-width: 0; flex: 1; padding: 0 5px; }
  .brand-copy b { font-size: 12px; }
  .model-status { min-width: 132px; padding: 7px 9px; }
  .app-main { padding: 20px 14px 28px; }
  .app-footer { padding: 16px 14px; flex-direction: column; }
}
</style>
