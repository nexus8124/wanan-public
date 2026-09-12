<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink, RouterView } from 'vue-router'
import {
  loadModelSelection,
  modelProfiles,
  modelsLoading,
  selectedModelKey,
  selectModelKey,
} from './modelSelection'
import { applyThemeMode, loadThemeMode, persistThemeMode, type ThemeMode } from './theme'

const themeMode = ref<ThemeMode>('system')
const themeOptions: { value: ThemeMode; label: string; title: string }[] = [
  { value: 'system', label: '自动', title: '跟随系统' },
  { value: 'light', label: '亮', title: '亮色模式' },
  { value: 'dark', label: '暗', title: '暗色模式' },
]

function setThemeMode(mode: ThemeMode) {
  themeMode.value = mode
  applyThemeMode(mode)
  persistThemeMode(mode)
}

onMounted(() => {
  themeMode.value = loadThemeMode()
  loadModelSelection().catch((error) => console.warn('load model catalog failed:', error))
})

function changeGlobalModel(event: Event) {
  selectModelKey((event.target as HTMLSelectElement).value)
}
</script>

<template>
  <div class="app-shell">
    <!-- 键盘用户跳过导航直达主内容 -->
    <a class="skip-link" href="#app-main">跳到主内容</a>

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
          <RouterLink to="/models" class="nav-item"><small>04</small><span>模型配置</span></RouterLink>
        </div>

        <div class="topbar-tools">
          <div class="theme-switch" role="radiogroup" aria-label="界面主题">
            <button
              v-for="option in themeOptions"
              :key="option.value"
              type="button"
              role="radio"
              :aria-checked="themeMode === option.value"
              :title="option.title"
              :class="{ active: themeMode === option.value }"
              @click="setThemeMode(option.value)"
            >
              {{ option.label }}
            </button>
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
            <RouterLink to="/models" class="model-config-link" title="配置厂商与模型" aria-label="打开模型配置页">
              <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M6.5 1h3l.4 2 1.7 1 1.9-.7 1.5 2.6-1.5 1.4v2l1.5 1.4-1.5 2.6-1.9-.7-1.7 1-.4 2h-3l-.4-2-1.7-1-1.9.7L1 11.7l1.5-1.4v-2L1 6.9l1.5-2.6 1.9.7 1.7-1 .4-2Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/>
                <circle cx="8" cy="8" r="2.2" stroke="currentColor" stroke-width="1.3"/>
              </svg>
            </RouterLink>
          </label>
        </div>
      </div>
    </nav>

    <main id="app-main" class="app-main" tabindex="-1">
      <!-- 不用 <Transition>:懒加载路由组件 + out-in 组合下进场插入不可靠,
           页面入场动效由各视图根元素的 .page-enter CSS 动画承担 -->
      <RouterView />
    </main>

    <footer class="app-statusbar">
      <span>XH-202614 · AI+安全大模型平台的智能体研究</span>
      <span class="sb-sep" aria-hidden="true"></span>
      <span>挑战杯揭榜挂帅 · 深信服科技</span>
      <span class="sb-fill"></span>
      <span>SECURITY ALERT ANALYSIS CONSOLE</span>
    </footer>
  </div>
</template>

<style scoped>
.app-shell { min-height: 100vh; display: flex; flex-direction: column; background: rgb(var(--bg)); }
/* 跳转主内容链接:仅键盘聚焦时可见 */
.skip-link { position: fixed; top: -52px; left: 16px; z-index: 100; padding: 10px 14px; border: 1px solid rgb(var(--text)); background: rgb(var(--text)); color: rgb(var(--bg)); font-size: 13px; font-weight: 600; text-decoration: none; transition: top .2s ease; }
.skip-link:focus-visible { top: 12px; }
.app-main:focus { outline: none; }
.topbar { position: sticky; top: 0; z-index: 50; border-bottom: 1px solid rgb(var(--text)); background: rgb(var(--bg) / .92); backdrop-filter: blur(12px); }
.topbar-inner { width: min(1720px, 100%); min-height: 62px; margin: 0 auto; padding: 0 22px; display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 24px; }
.brand { min-width: 0; display: inline-flex; align-items: center; gap: 12px; text-decoration: none; }
.brand-mark { position: relative; width: 38px; height: 38px; flex: 0 0 auto; border: 1px solid rgb(var(--text)); border-radius: 0; background: rgb(var(--cyan)); }
.brand-ring { position: absolute; width: 13px; height: 13px; left: 10px; top: 9px; border: 1px solid #ffffff; border-radius: 50%; }
.brand-ring::after { content: ''; position: absolute; width: 4px; height: 4px; left: 4px; top: 4px; border-radius: 50%; background: #ffffff; }
.brand-line { position: absolute; width: 11px; height: 1px; left: 21px; top: 23px; background: #ffffff; transform: rotate(45deg); transform-origin: left center; }
.brand-copy b, .brand-copy small { display: block; white-space: nowrap; }
.brand-copy b { color: rgb(var(--text)); font-size: 14.5px; font-weight: 800; letter-spacing: -0.01em; }
.brand-copy small { margin-top: 4px; color: rgb(var(--text-mute)); font: 9px/1 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .19em; }
.primary-nav { align-self: stretch; display: flex; align-items: stretch; gap: 8px; }
.nav-item { position: relative; min-width: 92px; padding: 0 12px; display: flex; align-items: center; justify-content: center; gap: 8px; color: rgb(var(--text-dim)); font-size: 14px; font-weight: 600; text-decoration: none; transition: color .2s ease; }
.nav-item small { color: rgb(var(--text-mute)); font: 9px 'JetBrains Mono', ui-monospace, monospace; transition: color .2s ease; }
.nav-item:hover { color: rgb(var(--text)); }
.nav-item.router-link-active { color: rgb(var(--text)); }
.nav-item.router-link-active small { color: rgb(var(--cyan)); }
.nav-item.router-link-active::after { content: ''; position: absolute; left: 12px; right: 12px; bottom: 0; height: 2px; background: rgb(var(--text)); }

.topbar-tools { justify-self: end; display: flex; align-items: center; gap: 10px; }
/* 主题三态分段控件:终端式小标签,非日月开关 */
.theme-switch { display: inline-flex; border: 1px solid rgb(var(--border-light)); background: rgb(var(--card)); }
.theme-switch button { padding: 6px 9px; border: 0; background: transparent; color: rgb(var(--text-mute)); font: 500 10.5px 'JetBrains Mono', ui-monospace, monospace; cursor: pointer; transition: color .2s ease, background .2s ease; }
.theme-switch button + button { border-left: 1px solid rgb(var(--border-light)); }
.theme-switch button:hover { color: rgb(var(--text)); }
.theme-switch button.active { color: rgb(var(--cyan)); background: rgb(var(--cyan) / .08); }

.model-status { min-width: 170px; padding: 7px 10px; display: flex; align-items: center; gap: 8px; border: 1px solid rgb(var(--border-light)); border-radius: 0; background: rgb(var(--card)); transition: border-color .2s ease; }
.model-status:hover { border-color: rgb(var(--text)); }
.model-status > span { width: 6px; height: 6px; border-radius: 50%; background: rgb(var(--green)); }
.model-status > div { min-width: 0; flex: 1; }
.model-status small { display: block; }
.model-status small { color: rgb(var(--text-mute)); font: 8.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; }
.model-status select { width: 100%; margin-top: 2px; padding: 0; border: 0; outline: 0; background: transparent; color: rgb(var(--text)); font: 600 11px 'JetBrains Mono', ui-monospace, monospace; cursor: pointer; }
.model-status select:disabled { cursor: wait; opacity: .65; }
/* 顶栏模型选择器旁的配置入口齿轮 */
.model-config-link { flex: 0 0 auto; display: grid; place-items: center; width: 26px; height: 26px; border: 1px solid transparent; color: rgb(var(--text-mute)); transition: color .2s ease, border-color .2s ease; }
.model-config-link:hover { color: rgb(var(--cyan)); border-color: rgb(var(--border-light)); }
.model-config-link.router-link-active { color: rgb(var(--cyan)); border-color: rgb(var(--cyan) / .5); }
/* 原生下拉弹层颜色交由 color-scheme 自动适配,不强制 */
.app-main { width: min(1720px, 100%); flex: 1; margin: 0 auto; padding: 20px 22px 34px; }
/* 终端式底部状态条:sticky 贴底,滚动时保持可见 */
.app-statusbar { position: sticky; bottom: 0; z-index: 40; display: flex; align-items: center; gap: 12px; padding: 8px 22px; border-top: 1px solid rgb(var(--border)); background: rgb(var(--bg) / .94); backdrop-filter: blur(10px); color: rgb(var(--text-mute)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .04em; }
.sb-sep { width: 1px; height: 10px; background: rgb(var(--border-light)); }
.sb-fill { flex: 1; }

@media (max-width: 760px) {
  .topbar-inner { min-height: 110px; grid-template-columns: 1fr auto; grid-template-rows: 60px 49px; gap: 0 12px; padding: 0 14px; }
  .primary-nav { grid-column: 1 / -1; grid-row: 2; justify-content: center; border-top: 1px solid rgb(var(--border-light)); }
  .nav-item { min-width: 0; flex: 1; padding: 0 5px; }
  .brand-copy b { font-size: 12px; }
  .topbar-tools { gap: 8px; }
  .theme-switch button { padding: 6px 7px; }
  .model-status { min-width: 128px; padding: 7px 9px; }
  .app-main { padding: 20px 14px 32px; }
  .app-statusbar { padding: 7px 14px; gap: 8px; }
  .app-statusbar > span:last-child { display: none; }
}
</style>
