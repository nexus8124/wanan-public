<script setup lang="ts">
import { computed, ref, watch } from 'vue'

const props = defineProps<{
  steps: string[]
  streaming?: boolean
}>()

interface ReasoningNode {
  index: number
  code: string
  tone: string
  title: string
  detail: string
  role: string
}

interface ReasoningEdge {
  from: number
  to: number
  path: string
}

const stepMeta = [
  { code: 'NET', fallback: '流量特征', tone: 'blue', role: '网络事实' },
  { code: 'INT', fallback: '行为意图', tone: 'purple', role: '意图推断' },
  { code: 'CTX', fallback: '关联上下文', tone: 'cyan', role: '上下文证据' },
  { code: 'HIS', fallback: '历史模式', tone: 'amber', role: '基线对照' },
  { code: 'DEC', fallback: '综合判定', tone: 'green', role: '证据融合' },
]

const selectedIndex = ref(0)
const overview = ref(true)

const visualSteps = computed<ReasoningNode[]>(() => props.steps.map((step, index) => {
  const colon = step.search(/[：:]/)
  const meta = stepMeta[index] || {
    code: `S${index + 1}`,
    fallback: `推理步骤 ${index + 1}`,
    tone: 'blue',
    role: '补充证据',
  }
  return {
    index,
    code: meta.code,
    tone: meta.tone,
    role: meta.role,
    title: colon > 0 ? step.slice(0, colon).trim() : meta.fallback,
    detail: colon > 0 ? step.slice(colon + 1).trim() : step,
  }
}))

// 五类证据不是简单流水线：流量先支持意图判断，上下文和历史模式
// 与意图判断共同汇入最终结论。
const graphEdges = computed<ReasoningEdge[]>(() => {
  const count = visualSteps.value.length
  if (count >= 5) {
    return [
      { from: 0, to: 1, path: 'M 285 100 C 330 100, 345 100, 390 100' },
      { from: 1, to: 4, path: 'M 615 100 C 705 100, 675 260, 745 260' },
      { from: 2, to: 4, path: 'M 285 260 C 445 260, 585 260, 745 260' },
      { from: 3, to: 4, path: 'M 285 420 C 520 420, 625 350, 745 290' },
    ]
  }
  return Array.from({ length: Math.max(0, count - 1) }, (_, index) => ({
    from: index,
    to: index + 1,
    path: `M ${180 + index * 160} 260 L ${300 + index * 160} 260`,
  }))
})

const selectedNode = computed(() => visualSteps.value[selectedIndex.value] || visualSteps.value[0])
const selectedIncoming = computed(() => graphEdges.value.filter((edge) => edge.to === selectedIndex.value))

watch(() => props.steps.length, (length, previousLength) => {
  if (!length) {
    selectedIndex.value = 0
    return
  }
  if (props.streaming && length > (previousLength ?? 0)) selectedIndex.value = length - 1
  else if (selectedIndex.value >= length) selectedIndex.value = length - 1
}, { immediate: true })

function selectNode(index: number) {
  selectedIndex.value = index
  overview.value = false
}

function edgeClass(edge: ReasoningEdge) {
  const selected = selectedIndex.value
  const active = overview.value || edge.to === selected || (selected === 4 && edge.to === 4)
  return {
    active,
    streaming: props.streaming && edge.to === visualSteps.value.length - 1,
  }
}

function nodeStatus(index: number): string {
  if (props.streaming && index === visualSteps.value.length - 1) return '正在分析'
  if (index === visualSteps.value.length - 1) return '最终融合'
  return '证据已提取'
}
</script>

<template>
  <div v-if="steps.length === 0" class="reasoning-empty">
    <span></span>
    Agent 正在生成可解释研判链路
  </div>

  <div v-else class="reasoning-graph-shell">
    <div class="graph-toolbar">
      <div>
        <small>EVIDENCE RELATION GRAPH</small>
        <b>交互式研判证据图</b>
      </div>
      <div class="graph-actions">
        <button
          type="button"
          :class="{ active: overview }"
          @click="overview = true"
        >
          全链路
        </button>
        <span>点击节点查看依据</span>
      </div>
    </div>

    <div class="graph-canvas" :class="{ focused: !overview }">
      <svg class="graph-links" viewBox="0 0 1000 520" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <marker id="reasoning-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" />
          </marker>
          <filter id="reasoning-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <path
          v-for="edge in graphEdges"
          :key="`${edge.from}-${edge.to}`"
          :d="edge.path"
          class="graph-link"
          :class="edgeClass(edge)"
          marker-end="url(#reasoning-arrow)"
        />
      </svg>

      <button
        v-for="(step, index) in visualSteps"
        :key="`${step.code}-${index}`"
        type="button"
        class="graph-node"
        :class="[
          `node-${Math.min(index, 4)}`,
          `tone-${step.tone}`,
          { selected: !overview && selectedIndex === index, muted: !overview && selectedIndex !== index, live: streaming && index === visualSteps.length - 1 },
        ]"
        :aria-pressed="!overview && selectedIndex === index"
        @click="selectNode(index)"
      >
        <span class="node-code"><i></i>{{ step.code }}</span>
        <span class="node-role">{{ step.role }}</span>
        <strong>{{ step.title }}</strong>
        <span class="node-preview">{{ step.detail }}</span>
        <span class="node-status">{{ nodeStatus(index) }}</span>
      </button>
    </div>

    <div class="graph-detail" :class="`tone-${selectedNode?.tone || 'blue'}`">
      <div class="detail-index">
        <span>{{ selectedNode?.code }}</span>
        <small>{{ String((selectedNode?.index || 0) + 1).padStart(2, '0') }}</small>
      </div>
      <div class="detail-copy">
        <div class="detail-title">
          <div><small>SELECTED EVIDENCE</small><b>{{ selectedNode?.title }}</b></div>
          <span v-if="selectedIncoming.length">汇入 {{ selectedIncoming.length }} 条证据链</span>
          <span v-else>起始证据节点</span>
        </div>
        <p>{{ selectedNode?.detail }}</p>
      </div>
      <div class="step-switcher" aria-label="切换研判节点">
        <button
          v-for="(step, index) in visualSteps"
          :key="`switch-${step.code}`"
          type="button"
          :class="{ active: selectedIndex === index }"
          :title="step.title"
          @click="selectNode(index)"
        >{{ index + 1 }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.reasoning-empty { min-height: 84px; display: flex; align-items: center; justify-content: center; gap: 9px; border: 1px dashed rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); font-size: 13px; }
.reasoning-empty span { width: 6px; height: 6px; border-radius: 50%; background: rgb(var(--cyan)); animation: pulse 1.5s infinite; }
.reasoning-graph-shell { border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--card)); overflow: hidden; }
.graph-toolbar { min-height: 56px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 11px 15px; border-bottom: 1px solid rgb(var(--border)); background: rgb(var(--bg)); }
.graph-toolbar small, .graph-toolbar b { display: block; }
.graph-toolbar small { color: rgb(var(--text-mute)); font: 9px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .12em; }
.graph-toolbar b { margin-top: 3px; color: rgb(var(--text)); font-size: 13.5px; }
.graph-actions { display: flex; align-items: center; gap: 9px; color: rgb(var(--text-mute)); font-size: 10.5px; }
.graph-actions button { padding: 5px 9px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); background: rgb(var(--card)); transition: .2s ease; }
.graph-actions button:hover, .graph-actions button.active { border-color: rgb(var(--text)); color: rgb(var(--text)); background: rgb(var(--text)); }
.graph-actions button.active { color: rgb(var(--bg)); }
.graph-canvas { position: relative; min-height: 430px; background-image: linear-gradient(rgb(var(--grid-line) / .4) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--grid-line) / .4) 1px, transparent 1px); background-size: 28px 28px; overflow: hidden; }
.graph-links { position: absolute; inset: 0; width: 100%; height: 100%; z-index: 1; overflow: visible; }
.graph-link { fill: none; stroke: rgb(var(--border-light)); stroke-width: 2; vector-effect: non-scaling-stroke; opacity: .55; transition: opacity .25s ease, stroke .25s ease; }
.graph-link.active { stroke: rgb(var(--text)); opacity: 1; }
.graph-link.streaming { stroke: rgb(var(--cyan)); stroke-dasharray: 8 8; animation: route 1.1s linear infinite; }
.graph-links marker path { fill: rgb(var(--text)); }
.graph-node { --tone: rgb(var(--cyan)); position: absolute; z-index: 2; width: 24%; min-height: 118px; padding: 12px 13px 24px; border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--card)); text-align: left; box-shadow: none; transition: transform .22s ease, opacity .22s ease, border-color .22s ease, box-shadow .22s ease; }
.graph-node:hover, .graph-node:focus-visible { z-index: 4; transform: translateY(-3px); border-color: var(--tone); outline: none; box-shadow: 4px 4px 0 0 rgb(var(--text) / .9); }
.graph-node.selected { z-index: 4; transform: translateY(-3px); border-color: var(--tone); box-shadow: 4px 4px 0 0 var(--tone); }
.graph-node.muted { opacity: .42; }
.graph-node.live { animation: liveNode 1.8s ease-in-out infinite; }
.node-0 { left: 4%; top: 7%; }
.node-1 { left: 39%; top: 7%; }
.node-2 { left: 4%; top: 38%; }
.node-3 { left: 4%; top: 69%; }
.node-4 { right: 3%; top: 38%; }
.node-code { display: inline-flex; align-items: center; gap: 6px; color: var(--tone); font: 700 10px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; }
.node-code i { width: 6px; height: 6px; border-radius: 50%; background: var(--tone); }
.node-role { float: right; color: rgb(var(--text-mute)); font-size: 10.5px; }
.graph-node strong, .node-preview, .node-status { display: block; }
.graph-node strong { margin-top: 10px; color: rgb(var(--text)); font-size: 13.5px; }
.node-preview { height: 33px; margin-top: 7px; overflow: hidden; color: rgb(var(--text-mute)); font-size: 12px; line-height: 1.75; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }
.node-status { position: absolute; left: 13px; bottom: 8px; color: var(--tone); font-size: 9.5px; }
.tone-blue { --tone: rgb(var(--cyan)); }
.tone-purple { --tone: rgb(var(--purple)); }
.tone-cyan { --tone: rgb(var(--teal)); }
.tone-amber { --tone: rgb(var(--yellow)); }
.tone-green { --tone: rgb(var(--green)); }
.graph-detail { --tone: rgb(var(--cyan)); position: relative; display: grid; grid-template-columns: 54px 1fr auto; gap: 13px; align-items: start; min-height: 118px; padding: 15px; border-top: 1px solid rgb(var(--border)); background: rgb(var(--bg)); }
.detail-index { width: 50px; height: 50px; display: grid; place-items: center; align-content: center; border: 1px solid var(--tone); border-radius: 0; background: rgb(var(--card)); }
.detail-index span { color: var(--tone); font: 700 11px 'JetBrains Mono', ui-monospace, monospace; }
.detail-index small { margin-top: 3px; color: rgb(var(--text-mute)); font: 9px 'JetBrains Mono', ui-monospace, monospace; }
.detail-copy { min-width: 0; }
.detail-title { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.detail-title small, .detail-title b { display: block; }
.detail-title small { color: rgb(var(--text-mute)); font: 9px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .1em; }
.detail-title b { margin-top: 3px; color: rgb(var(--text)); font-size: 13.5px; }
.detail-title > span { padding: 4px 7px; border: 1px solid var(--tone); border-radius: 0; color: var(--tone); font-size: 9.5px; white-space: nowrap; }
.detail-copy p { margin: 10px 0 0; color: rgb(var(--text-mute)); font-size: 13px; line-height: 1.75; }
.step-switcher { display: flex; gap: 5px; padding-top: 2px; }
.step-switcher button { width: 24px; height: 24px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); background: rgb(var(--card)); font: 10px 'JetBrains Mono', ui-monospace, monospace; }
.step-switcher button:hover, .step-switcher button.active { border-color: rgb(var(--text)); color: rgb(var(--text)); background: rgb(var(--text)); }
.step-switcher button.active { color: rgb(var(--bg)); }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
@keyframes route { to { stroke-dashoffset: -32; } }
@keyframes liveNode { 0%,100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--tone) 0%, transparent); } 50% { box-shadow: 0 0 0 5px color-mix(in srgb, var(--tone) 10%, transparent); } }
@media (max-width: 720px) {
  .graph-toolbar { align-items: flex-start; }
  .graph-actions span { display: none; }
  .graph-canvas { min-height: auto; padding: 16px; }
  .graph-links { display: none; }
  .graph-node { position: relative; left: auto !important; right: auto !important; top: auto !important; width: 100%; min-height: 96px; margin-bottom: 22px; }
  .graph-node:not(:last-of-type)::after { content: '↓'; position: absolute; left: 50%; bottom: -21px; color: rgb(var(--text-mute)); font-size: 13px; }
  .graph-detail { grid-template-columns: 48px 1fr; }
  .step-switcher { grid-column: 1 / -1; justify-content: flex-end; }
}
</style>
