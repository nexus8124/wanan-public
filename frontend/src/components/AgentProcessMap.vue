<script setup lang="ts">
import { computed } from 'vue'

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
  streaming: boolean
  done: boolean
  ragEnabled: boolean
  multiAgentEnabled: boolean
}>()

const flowNodes = computed<FlowNode[]>(() => [
  { key: 'preprocess', code: '01', title: '特征解析', subtitle: 'PREPROCESS', aliases: ['preprocess'] },
  { key: 'judge', code: '02', title: '模型初判', subtitle: 'JUDGE', aliases: ['judge'] },
  { key: 'rag', code: '03', title: '知识增强', subtitle: 'RAG', aliases: ['rag_retrieve', 'rag_refine'] },
  {
    key: 'investigate',
    code: '04',
    title: props.multiAgentEnabled ? '协同调查' : '自主调查',
    subtitle: props.multiAgentEnabled ? 'MULTI-AGENT' : 'REACT',
    aliases: props.multiAgentEnabled
      ? ['multi_agent_plan', 'multi_agent_worker', 'multi_agent_verify']
      : ['react_decide', 'tool_executor'],
  },
  { key: 'disposition', code: '05', title: '处置决策', subtitle: 'DISPOSITION', aliases: ['disposition'] },
  { key: 'output', code: '06', title: '结果输出', subtitle: 'OUTPUT', aliases: ['output'] },
])

function nodeState(node: FlowNode): 'pending' | 'active' | 'complete' | 'skipped' {
  if (node.key === 'rag' && !props.ragEnabled) return 'skipped'
  if (node.aliases.includes(props.currentNode) && props.streaming) return 'active'
  if (node.aliases.some((name) => props.visitedNodes.includes(name))) return 'complete'
  if (props.done && props.visitedNodes.length) return 'skipped'
  return 'pending'
}

function edgeState(index: number): string {
  const source = nodeState(flowNodes.value[index])
  const target = nodeState(flowNodes.value[index + 1])
  if (source === 'complete' && ['complete', 'active', 'skipped'].includes(target)) return 'complete'
  if (source === 'active' || target === 'active') return 'active'
  return 'pending'
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

@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
@keyframes orbitPulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.5); } }
@media (max-width: 720px) {
  .flow-node { min-width: 66px; }
}
</style>
