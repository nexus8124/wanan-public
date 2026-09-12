<script setup lang="ts">
// 站内确认对话框:取代原生 confirm(),与终端风 UI 同语言。
// 内置 Esc 关闭、打开时聚焦确认键、关闭后归还焦点、背景滚动锁定。
import { nextTick, onBeforeUnmount, ref, useId, watch } from 'vue'
import { PhRocket, PhTrash } from '@phosphor-icons/vue'

const props = withDefaults(
  defineProps<{
    open: boolean
    title?: string
    body?: string
    confirmLabel?: string
    cancelLabel?: string
    tone?: 'accent' | 'danger'
  }>(),
  { title: '', body: '', confirmLabel: '确认', cancelLabel: '取消', tone: 'accent' },
)

const emit = defineEmits<{ confirm: []; cancel: [] }>()

const titleId = useId()
const confirmBtn = ref<HTMLButtonElement | null>(null)
let lastFocus: HTMLElement | null = null

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.stopPropagation()
    emit('cancel')
  }
}

function release() {
  document.removeEventListener('keydown', onKeydown, true)
  if (document.body.style.overflow === 'hidden') document.body.style.overflow = ''
}

watch(
  () => props.open,
  (open) => {
    if (open) {
      lastFocus = document.activeElement as HTMLElement | null
      document.addEventListener('keydown', onKeydown, true)
      document.body.style.overflow = 'hidden'
      nextTick(() => confirmBtn.value?.focus())
    } else {
      release()
      lastFocus?.focus?.()
      lastFocus = null
    }
  },
)

onBeforeUnmount(release)
</script>

<template>
  <Teleport to="body">
    <Transition name="confirm">
      <div v-if="open" class="confirm-mask" @click.self="emit('cancel')">
        <div class="confirm-box" role="alertdialog" aria-modal="true" :aria-labelledby="titleId">
          <div class="confirm-head">
            <span class="confirm-mark" :class="tone">
              <PhTrash v-if="tone === 'danger'" :size="19" weight="bold" aria-hidden="true" />
              <PhRocket v-else :size="19" weight="bold" aria-hidden="true" />
            </span>
            <b :id="titleId">{{ title }}</b>
          </div>
          <p class="confirm-body">{{ body }}</p>
          <div class="confirm-actions">
            <button type="button" class="confirm-cancel" @click="emit('cancel')">
              {{ cancelLabel }}
            </button>
            <button
              ref="confirmBtn"
              type="button"
              class="confirm-ok"
              :class="tone"
              @click="emit('confirm')"
            >
              {{ confirmLabel }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.confirm-mask { position: fixed; inset: 0; z-index: 110; display: grid; place-items: center; padding: 20px; background: rgb(var(--overlay) / .7); backdrop-filter: blur(3px); }
.confirm-box { width: min(440px, 100%); padding: 20px 22px; border: 1px solid rgb(var(--text)); background: rgb(var(--card)); box-shadow: 8px 8px 0 0 rgb(var(--text) / .9); }
.confirm-head { display: flex; align-items: center; gap: 12px; }
.confirm-head b { color: rgb(var(--text)); font-size: 16.5px; font-weight: 800; letter-spacing: -0.01em; }
.confirm-mark { width: 40px; height: 40px; flex: 0 0 auto; display: grid; place-items: center; border: 1px solid currentColor; }
.confirm-mark.accent { color: rgb(var(--cyan)); background: rgb(var(--cyan) / .08); }
.confirm-mark.danger { color: rgb(var(--red)); background: rgb(var(--red) / .08); }
.confirm-body { margin: 14px 0 18px; color: rgb(var(--text-dim)); font-size: 13.5px; line-height: 1.75; }
.confirm-actions { display: flex; justify-content: flex-end; gap: 10px; }
.confirm-cancel { padding: 9px 14px; border: 1px solid rgb(var(--border-light)); background: rgb(var(--card)); color: rgb(var(--text-dim)); font-size: 13px; font-weight: 600; transition: color .2s ease, border-color .2s ease; }
.confirm-cancel:hover { border-color: rgb(var(--text)); color: rgb(var(--text)); }
.confirm-ok { padding: 9px 16px; border: 1px solid rgb(var(--cyan)); background: rgb(var(--cyan)); color: rgb(var(--on-accent)); font-size: 13px; font-weight: 700; white-space: nowrap; transition: background .2s ease, color .2s ease, border-color .2s ease; }
.confirm-ok:hover { background: rgb(var(--text)); border-color: rgb(var(--text)); color: rgb(var(--bg)); }
.confirm-ok.danger { border-color: rgb(var(--red)); background: transparent; color: rgb(var(--red)); }
.confirm-ok.danger:hover { background: rgb(var(--red)); border-color: rgb(var(--red)); color: #ffffff; }

.confirm-enter-active, .confirm-leave-active { transition: opacity .18s ease; }
.confirm-enter-active .confirm-box { transition: transform .18s ease; }
.confirm-enter-from, .confirm-leave-to { opacity: 0; }
.confirm-enter-from .confirm-box { transform: translateY(8px); }
</style>
