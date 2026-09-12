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
      ? ['multi_agent_plan', 'multi_agent_worker', 'multi_agent_replan', 'multi_agent_verify']
      : ['react_decide', 'tool_executor'],
  },
  { key: 'disposition', code: '05', title: '处置决策', subtitle: 'DISPOSITION', aliases: ['disposition'] },
  { key: 'response', code: '06', title: '执行与验证', subtitle: 'RESPONSE', aliases: ['response_execute', 'response_observe', 'response_rollback'] },
  { key: 'output', code: '07', title: '结果输出', subtitle: 'OUTPUT', aliases: ['output'] },
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
.process-map { border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--card)); overflow: hidden; }
.flow-lane { min-height: 122px; padding: 18px 14px; display: flex; align-items: center; overflow-x: auto; background: rgb(var(--card)); }
.flow-node { position: relative; min-width: 66px; display: flex; flex-direction: column; align-items: center; text-align: center; opacity: .42; transition: opacity .3s ease, transform .3s ease; }
.node-orbit { position: relative; width: 38px; height: 38px; display: grid; place-items: center; border: 1px solid rgb(var(--border-light)); border-radius: 50%; background: rgb(var(--bg)); color: rgb(var(--text-mute)); font: 700 11px 'JetBrains Mono', ui-monospace, monospace; }
.node-orbit::before { content: ''; position: absolute; inset: 5px; border: 1px dashed rgb(var(--border)); border-radius: 50%; }
.node-orbit span { position: relative; z-index: 1; }
.node-orbit i { position: absolute; width: 5px; height: 5px; top: -3px; left: 16px; border-radius: 50%; background: rgb(var(--text-mute)); }
.node-copy { margin-top: 9px; }
.node-copy small, .node-copy b { display: block; }
.node-copy small { color: rgb(var(--text-mute)); font: 9.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; }
.node-copy b { margin-top: 4px; color: rgb(var(--text)); font-size: 13px; font-weight: 700; }
.node-state { margin-top: 5px; color: rgb(var(--text-mute)); font-size: 10.5px; }
.flow-node.active, .flow-node.complete { opacity: 1; }
.flow-node.active { transform: translateY(-2px); }
.flow-node.active .node-orbit { border-color: rgb(var(--cyan)); color: rgb(var(--cyan)); box-shadow: 0 0 0 4px rgb(var(--cyan) / .12); }
.flow-node.active .node-orbit i { background: rgb(var(--cyan)); animation: orbitPulse 1.4s infinite; }
.flow-node.active .node-copy b, .flow-node.active .node-state { color: rgb(var(--cyan)); }
.flow-node.complete .node-orbit { border-color: rgb(var(--text)); color: rgb(var(--bg)); background: rgb(var(--text)); }
.flow-node.complete .node-orbit span { color: rgb(var(--bg)); }
.flow-node.complete .node-orbit i { background: rgb(var(--bg)); }
.flow-node.complete .node-copy b { color: rgb(var(--text)); }
.flow-node.complete .node-state { color: rgb(var(--green)); }
.flow-node.skipped { opacity: .28; }
.flow-node.skipped .node-orbit { border-style: dashed; }
.flow-edge { position: relative; min-width: 11px; flex: 1 1 22px; height: 14px; margin: 0 -2px 38px; color: rgb(var(--text-mute)); }
.flow-edge i { position: absolute; left: 0; right: 6px; top: 7px; height: 1px; background: rgb(var(--border-light)); }
.flow-edge span { position: absolute; right: 0; top: -2px; font-size: 18px; }
.flow-edge.complete i { background: rgb(var(--text)); }
.flow-edge.complete { color: rgb(var(--text)); }
.flow-edge.active i { background: rgb(var(--cyan)); }
.flow-edge.active { color: rgb(var(--cyan)); }

@keyframes orbitPulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.5); } }
@media (max-width: 720px) {
  .flow-node { min-width: 66px; }
}
</style>
