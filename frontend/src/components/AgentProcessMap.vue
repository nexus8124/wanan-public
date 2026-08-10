<script setup lang="ts">
import { computed } from 'vue'

interface ConfidencePoint {
  node: string
  value: number
}

interface FlowNode {
  key: string
  code: string
  title: string
  subtitle: string
  aliases: string[]
}

const props = defineProps<{
  currentNode: string
  visitedNodes: string[]
  confidenceHistory: ConfidencePoint[]
  streaming: boolean
  done: boolean
  ragEnabled: boolean
  judgment: string
  knowledgeCount: number
  toolCount: number
  evidenceCount: number
}>()

const flowNodes: FlowNode[] = [
  { key: 'preprocess', code: '01', title: '特征解析', subtitle: 'PREPROCESS', aliases: ['preprocess'] },
  { key: 'judge', code: '02', title: '模型初判', subtitle: 'JUDGE', aliases: ['judge'] },
  { key: 'rag', code: '03', title: '知识增强', subtitle: 'RAG', aliases: ['rag_retrieve', 'rag_refine'] },
  { key: 'react', code: '04', title: '自主调查', subtitle: 'REACT', aliases: ['react_decide', 'tool_executor'] },
  { key: 'disposition', code: '05', title: '处置决策', subtitle: 'DISPOSITION', aliases: ['disposition'] },
  { key: 'output', code: '06', title: '结果输出', subtitle: 'OUTPUT', aliases: ['output'] },
]

function nodeState(node: FlowNode): 'pending' | 'active' | 'complete' | 'skipped' {
  if (node.key === 'rag' && !props.ragEnabled) return 'skipped'
  if (node.aliases.includes(props.currentNode) && props.streaming) return 'active'
  if (node.aliases.some((name) => props.visitedNodes.includes(name))) return 'complete'
  if (props.done && props.visitedNodes.length) return 'skipped'
  return 'pending'
}

function edgeState(index: number): string {
  const source = nodeState(flowNodes[index])
  const target = nodeState(flowNodes[index + 1])
  if (source === 'complete' && ['complete', 'active', 'skipped'].includes(target)) return 'complete'
  if (source === 'active' || target === 'active') return 'active'
  return 'pending'
}

const chartPoints = computed(() => {
  const values = props.confidenceHistory.slice(-8)
  return values.map((item, index) => {
    const x = values.length === 1 ? 150 : 16 + (index * 268) / (values.length - 1)
    const y = 70 - Math.max(0, Math.min(1, item.value)) * 52
    return { ...item, x, y }
  })
})

const polyline = computed(() => chartPoints.value.map((point) => `${point.x},${point.y}`).join(' '))
const latestConfidence = computed(() => (
  props.confidenceHistory[props.confidenceHistory.length - 1]?.value ?? 0
))

const currentLabel = computed(() => {
  for (const node of flowNodes) {
    if (node.aliases.includes(props.currentNode)) return node.title
  }
  return props.done ? '研判完成' : '等待启动'
})

function judgmentClass(): string {
  if (props.judgment === '真阳') return 'danger'
  if (props.judgment === '假阳') return 'success'
  if (props.judgment === '待查') return 'warning'
  return 'neutral'
}
</script>

<template>
  <div class="process-map">
    <div class="flow-lane">
      <template v-for="(node, index) in flowNodes" :key="node.key">
        <div class="flow-node" :class="nodeState(node)">
          <div class="node-orbit"><span>{{ node.code }}</span><i></i></div>
          <div class="node-copy">
            <small>{{ node.subtitle }}</small>
            <b>{{ node.title }}</b>
          </div>
          <span class="node-state">
            {{ nodeState(node) === 'complete' ? '已完成' : nodeState(node) === 'active' ? '处理中' : nodeState(node) === 'skipped' ? '已跳过' : '等待' }}
          </span>
        </div>
        <div v-if="index < flowNodes.length - 1" class="flow-edge" :class="edgeState(index)">
          <i></i><span>›</span>
        </div>
      </template>
    </div>

    <div class="process-insights">
      <section class="confidence-panel">
        <div class="insight-head">
          <div><small>CONFIDENCE EVOLUTION</small><b>置信度演进</b></div>
          <strong>{{ Math.round(latestConfidence * 100) }}%</strong>
        </div>
        <svg viewBox="0 0 300 82" preserveAspectRatio="none" aria-label="置信度变化曲线">
          <line x1="16" y1="18" x2="284" y2="18" class="guide"></line>
          <line x1="16" y1="44" x2="284" y2="44" class="guide"></line>
          <line x1="16" y1="70" x2="284" y2="70" class="axis"></line>
          <polyline v-if="chartPoints.length > 1" :points="polyline" class="confidence-line"></polyline>
          <g v-for="(point, index) in chartPoints" :key="`${point.node}-${index}`">
            <circle :cx="point.x" :cy="point.y" r="3.5" class="confidence-dot"></circle>
          </g>
        </svg>
        <div v-if="confidenceHistory.length" class="chart-labels">
          <span>{{ confidenceHistory[0].node }}</span>
          <span>{{ confidenceHistory[confidenceHistory.length - 1]?.node }}</span>
        </div>
        <div v-else class="chart-empty">研判开始后生成动态曲线</div>
      </section>

      <section class="signal-panel">
        <div class="insight-head">
          <div><small>INVESTIGATION SIGNALS</small><b>调查信号</b></div>
          <span class="current-stage"><i :class="{ live: streaming }"></i>{{ currentLabel }}</span>
        </div>
        <div class="signal-grid">
          <div><span>KB</span><b>{{ knowledgeCount }}</b><small>知识命中</small></div>
          <div><span>TL</span><b>{{ toolCount }}</b><small>工具调用</small></div>
          <div><span>EV</span><b>{{ evidenceCount }}</b><small>事件证据</small></div>
          <div class="verdict" :class="judgmentClass()"><span>结果</span><b>{{ judgment || '--' }}</b><small>当前判定</small></div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.process-map { border: 1px solid #27364b; border-radius: 8px; background: #0c131e; overflow: hidden; }
.flow-lane { min-height: 122px; padding: 18px 14px; display: flex; align-items: center; overflow-x: auto; background: radial-gradient(circle at 50% 0, rgba(83,133,218,.07), transparent 52%); }
.flow-node { position: relative; min-width: 66px; display: flex; flex-direction: column; align-items: center; text-align: center; opacity: .46; transition: opacity .3s ease, transform .3s ease; }
.node-orbit { position: relative; width: 38px; height: 38px; display: grid; place-items: center; border: 1px solid #34445b; border-radius: 50%; background: #101a28; color: #61738c; font: 700 9px ui-monospace, monospace; }
.node-orbit::before { content: ''; position: absolute; inset: 5px; border: 1px dashed #2d3c51; border-radius: 50%; }
.node-orbit span { position: relative; z-index: 1; }
.node-orbit i { position: absolute; width: 5px; height: 5px; top: -3px; left: 16px; border-radius: 50%; background: #415168; }
.node-copy { margin-top: 9px; }
.node-copy small, .node-copy b { display: block; }
.node-copy small { color: #526680; font: 7px ui-monospace, monospace; letter-spacing: .08em; }
.node-copy b { margin-top: 3px; color: #8a9ab0; font-size: 10px; }
.node-state { margin-top: 4px; color: #4e6078; font-size: 8px; }
.flow-node.active, .flow-node.complete { opacity: 1; }
.flow-node.active { transform: translateY(-2px); }
.flow-node.active .node-orbit { border-color: #5d93ed; color: #84aff7; box-shadow: 0 0 0 5px rgba(93,147,237,.07), 0 0 22px rgba(93,147,237,.18); }
.flow-node.active .node-orbit i { background: #69a0ff; box-shadow: 0 0 9px #69a0ff; animation: orbitPulse 1.4s infinite; }
.flow-node.active .node-copy b, .flow-node.active .node-state { color: #8eb8ff; }
.flow-node.complete .node-orbit { border-color: #4eaa8b; color: #65c59f; background: rgba(61,130,108,.1); }
.flow-node.complete .node-orbit i { background: #5fc49b; box-shadow: 0 0 8px rgba(95,196,155,.7); }
.flow-node.complete .node-copy b { color: #b5c7d8; }
.flow-node.complete .node-state { color: #58b490; }
.flow-node.skipped { opacity: .28; }
.flow-node.skipped .node-orbit { border-style: dashed; }
.flow-edge { position: relative; min-width: 11px; flex: 1 1 22px; height: 14px; margin: 0 -2px 38px; color: #35455c; }
.flow-edge i { position: absolute; left: 0; right: 6px; top: 7px; height: 1px; background: #2c3a4e; }
.flow-edge span { position: absolute; right: 0; top: -2px; font-size: 18px; }
.flow-edge.complete i { background: linear-gradient(90deg, #4dad8c, #557faa); }
.flow-edge.complete { color: #5f8ec3; }
.flow-edge.active i { background: linear-gradient(90deg, #4dad8c, #6598ef); box-shadow: 0 0 7px rgba(101,152,239,.35); }
.flow-edge.active { color: #6598ef; }

.process-insights { display: grid; grid-template-columns: .9fr 1.1fr; border-top: 1px solid #27364b; }
.confidence-panel, .signal-panel { min-width: 0; padding: 14px 16px; }
.confidence-panel { border-right: 1px solid #27364b; }
.insight-head { min-height: 30px; display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.insight-head small, .insight-head b { display: block; }
.insight-head small { color: #4d678c; font: 7px ui-monospace, monospace; letter-spacing: .09em; }
.insight-head b { margin-top: 3px; color: #aebed2; font-size: 10px; }
.insight-head strong { color: #79a7f6; font: 700 20px ui-monospace, monospace; }
.confidence-panel svg { width: 100%; height: 76px; margin-top: 5px; overflow: visible; }
.guide { stroke: #1d2a3b; stroke-width: 1; stroke-dasharray: 3 4; }
.axis { stroke: #334158; stroke-width: 1; }
.confidence-line { fill: none; stroke: #69a0f4; stroke-width: 2; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(105,160,244,.45)); }
.confidence-dot { fill: #0c131e; stroke: #69a0f4; stroke-width: 2; vector-effect: non-scaling-stroke; }
.chart-labels { display: flex; justify-content: space-between; margin-top: -6px; color: #4e6078; font: 7px ui-monospace, monospace; text-transform: uppercase; }
.chart-empty { height: 15px; margin-top: -5px; color: #405168; font-size: 8px; text-align: center; }
.current-stage { display: inline-flex; align-items: center; gap: 5px; color: #71849e; font-size: 8px; }
.current-stage i { width: 5px; height: 5px; border-radius: 50%; background: #526177; }
.current-stage i.live { background: #65a0ff; box-shadow: 0 0 8px #65a0ff; animation: pulse 1.5s infinite; }
.signal-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 14px; }
.signal-grid > div { min-width: 0; padding: 11px 8px; border: 1px solid #26354a; border-radius: 6px; background: #0a111b; text-align: center; }
.signal-grid span, .signal-grid b, .signal-grid small { display: block; }
.signal-grid span { color: #48658c; font: 7px ui-monospace, monospace; }
.signal-grid b { margin: 7px 0 4px; color: #d2deed; font: 700 17px ui-monospace, monospace; white-space: nowrap; }
.signal-grid small { color: #52637a; font-size: 8px; white-space: nowrap; }
.signal-grid .verdict.danger b { color: #e6767e; }
.signal-grid .verdict.success b { color: #65c59f; }
.signal-grid .verdict.warning b { color: #dcb35e; }

@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
@keyframes orbitPulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.5); } }
@media (max-width: 720px) {
  .flow-node { min-width: 66px; }
  .process-insights { grid-template-columns: 1fr; }
  .confidence-panel { border-right: 0; border-bottom: 1px solid #27364b; }
}
</style>
