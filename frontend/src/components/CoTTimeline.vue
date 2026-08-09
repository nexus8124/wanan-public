<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  steps: string[]
  streaming?: boolean
}>()

const stepMeta = [
  { code: 'NET', fallback: '流量特征', tone: 'blue' },
  { code: 'INT', fallback: '行为意图', tone: 'purple' },
  { code: 'CTX', fallback: '关联上下文', tone: 'cyan' },
  { code: 'HIS', fallback: '历史模式', tone: 'amber' },
  { code: 'DEC', fallback: '综合判定', tone: 'green' },
]

const visualSteps = computed(() => props.steps.map((step, index) => {
  const colon = step.search(/[：:]/)
  const meta = stepMeta[index] || { code: `S${index + 1}`, fallback: `推理步骤 ${index + 1}`, tone: 'blue' }
  return {
    index: index + 1,
    code: meta.code,
    tone: meta.tone,
    title: colon > 0 ? step.slice(0, colon).trim() : meta.fallback,
    detail: colon > 0 ? step.slice(colon + 1).trim() : step,
  }
}))
</script>

<template>
  <div v-if="steps.length === 0" class="reasoning-empty">
    <span></span>
    Agent 正在生成可解释研判链路
  </div>
  <div v-else class="reasoning-board">
    <article
      v-for="(step, index) in visualSteps"
      :key="index"
      class="reasoning-card stream-item"
      :class="[`tone-${step.tone}`, { final: index === visualSteps.length - 1, active: index === visualSteps.length - 1 && streaming }]"
    >
      <div class="reasoning-code">
        <span>{{ step.code }}</span>
        <i>{{ String(step.index).padStart(2, '0') }}</i>
      </div>
      <div class="reasoning-copy">
        <div><b>{{ step.title }}</b><small>REASONING STEP {{ step.index }}</small></div>
        <p>{{ step.detail }}</p>
      </div>
      <span v-if="index < visualSteps.length - 1" class="reasoning-arrow">↘</span>
      <span v-else class="reasoning-result">VERDICT</span>
    </article>
  </div>
</template>

<style scoped>
.reasoning-empty { min-height: 84px; display: flex; align-items: center; justify-content: center; gap: 9px; border: 1px dashed #2a394e; border-radius: 7px; color: #52647c; font-size: 10px; }
.reasoning-empty span { width: 6px; height: 6px; border-radius: 50%; background: #6399ee; box-shadow: 0 0 9px #6399ee; animation: pulse 1.5s infinite; }
.reasoning-board { display: grid; grid-template-columns: 1fr 1fr; gap: 9px; }
.reasoning-card { --tone: #669df0; position: relative; min-width: 0; min-height: 116px; display: grid; grid-template-columns: 48px 1fr; gap: 12px; padding: 13px; border: 1px solid #29384d; border-radius: 7px; background: linear-gradient(135deg, color-mix(in srgb, var(--tone) 5%, #0c131e), #0c131e 62%); overflow: hidden; }
.reasoning-card::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--tone); opacity: .75; }
.reasoning-card.final { grid-column: 1 / -1; min-height: 102px; background: linear-gradient(100deg, color-mix(in srgb, var(--tone) 8%, #0c131e), #0c131e 55%); }
.reasoning-card.active { border-color: color-mix(in srgb, var(--tone) 62%, #29384d); box-shadow: 0 0 20px color-mix(in srgb, var(--tone) 10%, transparent); }
.tone-blue { --tone: #669df0; }
.tone-purple { --tone: #9b87df; }
.tone-cyan { --tone: #56b7cd; }
.tone-amber { --tone: #d5a954; }
.tone-green { --tone: #5fc49b; }
.reasoning-code { width: 48px; height: 48px; display: grid; place-items: center; align-content: center; border: 1px solid color-mix(in srgb, var(--tone) 42%, #29384d); border-radius: 6px; background: color-mix(in srgb, var(--tone) 7%, #0a111a); }
.reasoning-code span { color: var(--tone); font: 700 9px ui-monospace, monospace; letter-spacing: .06em; }
.reasoning-code i { margin-top: 3px; color: #4f6179; font: normal 7px ui-monospace, monospace; }
.reasoning-copy { min-width: 0; }
.reasoning-copy > div { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.reasoning-copy b { color: #c6d3e3; font-size: 11px; }
.reasoning-copy small { color: #465a75; font: 6px ui-monospace, monospace; letter-spacing: .08em; white-space: nowrap; }
.reasoning-copy p { margin: 9px 0 0; color: #8899af; font-size: 11px; line-height: 1.7; }
.reasoning-arrow { position: absolute; right: 8px; bottom: 5px; color: color-mix(in srgb, var(--tone) 55%, #405068); font-size: 12px; }
.reasoning-result { position: absolute; right: 10px; bottom: 7px; color: color-mix(in srgb, var(--tone) 52%, #405068); font: 7px ui-monospace, monospace; letter-spacing: .1em; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
@media (max-width: 680px) {
  .reasoning-board { grid-template-columns: 1fr; }
  .reasoning-card.final { grid-column: auto; }
}
</style>
