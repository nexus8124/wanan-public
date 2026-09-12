<script setup lang="ts">
import type { Component } from 'vue'
import { computed, ref, watch } from 'vue'
import {
  PhBroadcast,
  PhCheck,
  PhCrosshair,
  PhGear,
  PhMagnifyingGlass,
  PhMonitor,
  PhNetwork,
  PhScan,
  PhStack,
} from '@phosphor-icons/vue'

interface AgentStep {
  step?: number
  agent?: string
  capability?: string
  tool?: string
  args?: Record<string, unknown>
  status?: string
  summary?: string
  purpose?: string
  knowledge_ids?: string[]
  result?: Record<string, any>
}

interface FlowSelection {
  key: string
  eyebrow: string
  title: string
  detail: string
  meta: string[]
  tone: string
}

interface IndexedStep {
  step: AgentStep
  index: number
}

interface AgentBranch {
  key: string
  agent: string
  capability: string
  steps: IndexedStep[]
}

const props = defineProps<{
  steps: AgentStep[]
  ledger?: Record<string, any>
  evidence?: Record<string, any>[]
  knowledgeHits?: Record<string, any>[]
  citedEvidence?: string[]
  judgment?: string
  confidence?: number
}>()

const selectedKey = ref('orchestrator')
const expandedBranch = ref<number | null>(null)
const expandedPanel = ref<'tool' | 'evidence'>('evidence')

const toolMeta: Record<string, { icon: Component; label: string }> = {
  rag_retrieve: { icon: PhMagnifyingGlass, label: '安全知识检索' },
  inspect_alert_context: { icon: PhScan, label: '检测器上下文' },
  fetch_endpoint_logs: { icon: PhMonitor, label: '端点日志取证' },
  fetch_network_flows: { icon: PhNetwork, label: '网络流量取证' },
  check_threat_intel: { icon: PhBroadcast, label: '威胁情报查询' },
  query_similar_alerts: { icon: PhStack, label: '相似告警检索' },
  search_attck_technique: { icon: PhCrosshair, label: 'ATT&CK 映射' },
}

function toolInfo(tool = '') {
  return toolMeta[tool] || { icon: PhGear, label: tool || '受控调查工具' }
}

function stepEvidence(step: AgentStep): Record<string, any>[] {
  return Array.isArray(step.result?.evidence) ? step.result!.evidence : []
}

function evidenceIds(step: AgentStep): string[] {
  const eventIds = stepEvidence(step).map((item) => item.evidence_id).filter(Boolean)
  const knowledgeIds = Array.isArray(step.knowledge_ids) ? step.knowledge_ids : []
  return [...knowledgeIds, ...eventIds]
}

function stepStatus(step: AgentStep): string {
  if (step.status === 'completed' || step.result?.success) return '已完成'
  if (step.status === 'failed' || step.result?.status === 'failed') return '失败'
  return step.status || step.result?.status || '已规划'
}

function evidenceLabel(step: AgentStep): string {
  const ids = evidenceIds(step)
  if (ids.length) return `${ids.length} 条证据`
  if (step.result?.success) return '工具已返回'
  return '无新增证据'
}

const plannedAgents = computed(() => props.ledger?.planned_agents || props.steps.map((step) => step.agent).filter(Boolean))
const completedAgents = computed(() => props.ledger?.completed_agents || [])
const agentBranches = computed<AgentBranch[]>(() => {
  const grouped = new Map<string, AgentBranch>()
  props.steps.forEach((step, index) => {
    const agent = step.agent || `agent_${index + 1}`
    let branch = grouped.get(agent)
    if (!branch) {
      branch = { key: agent, agent, capability: step.capability || '-', steps: [] }
      grouped.set(agent, branch)
    }
    branch.steps.push({ step, index })
  })
  return [...grouped.values()]
})
const branchLayoutClass = computed(() => {
  if (agentBranches.value.length <= 1) return 'layout-one'
  if (agentBranches.value.length === 2) return 'layout-two'
  return 'layout-many'
})
const pendingAgents = computed(() => plannedAgents.value.filter(
  (agent: string) => !props.steps.some((step) => step.agent === agent),
))
const totalEvidence = computed(() => {
  const ids = new Set<string>()
  props.steps.forEach((step) => evidenceIds(step).forEach((id) => ids.add(id)))
  props.evidence?.forEach((item) => item.evidence_id && ids.add(item.evidence_id))
  return ids.size
})

const selections = computed<FlowSelection[]>(() => {
  const items: FlowSelection[] = [{
    key: 'orchestrator', eyebrow: 'SOC ORCHESTRATOR', title: '任务编排与权限分配',
    detail: `协调器先自主规划调查任务；每次专业智能体返回观测后，再根据新证据和剩余预算决定继续、换路或进入验证。`,
    meta: [`计划：${plannedAgents.value.join(' → ') || '无额外任务'}`, `重规划：${props.ledger?.replan_count || 0} 次`, `状态：${props.ledger?.status || 'completed'}`], tone: 'blue',
  }]

  agentBranches.value.forEach((branch) => {
    items.push({
      key: `agent-${branch.key}`, eyebrow: 'SPECIALIST AGENT', title: branch.agent,
      detail: branch.steps[0]?.step.purpose || branch.steps[0]?.step.summary || `该智能体在本轮执行 ${branch.steps.length} 次受控工具调用。`,
      meta: [`能力：${branch.capability}`, `调用轮次：${branch.steps.length}`], tone: 'purple',
    })
    branch.steps.forEach(({ step, index }) => {
      const info = toolInfo(step.tool)
      const ids = evidenceIds(step)
      items.push({
        key: `tool-${index}`, eyebrow: 'CONTROLLED TOOL', title: step.tool || info.label,
        detail: step.result?.summary || step.summary || `${info.label} 已按受控参数执行。`,
        meta: [`参数：${JSON.stringify(step.args || {})}`, `延迟：${step.result?.latency_ms ?? '-'} ms`], tone: 'cyan',
      })
      items.push({
        key: `evidence-${index}`, eyebrow: 'VERIFIABLE EVIDENCE', title: ids.length ? ids.join(' · ') : evidenceLabel(step),
        detail: stepEvidence(step)[0]?.summary || step.summary || '该分支未生成可用于改变结论的新事件证据。',
        meta: [`证据状态：${ids.length ? '可验证' : '仅完成调用'}`, `来源：${stepEvidence(step)[0]?.source || step.capability || '-'}`], tone: 'green',
      })
    })
  })

  items.push({
    key: 'verifier', eyebrow: 'VERIFIER AGENT', title: `证据融合 · ${props.judgment || '待查'}`,
    detail: props.citedEvidence?.length
      ? `验证智能体仅引用有效 Evidence ID 形成最终结论：${props.citedEvidence.join('、')}。`
      : '验证智能体已检查各调查分支；没有新的有效事件证据时，不允许仅凭工具调用改变既有结论。',
    meta: [`置信度：${Math.round((props.confidence || 0) * 100)}%`, `引用证据：${props.citedEvidence?.length || 0}`], tone: 'amber',
  })
  return items
})

const selected = computed(() => selections.value.find((item) => item.key === selectedKey.value) || selections.value[0])

function openBranch(index: number, panel: 'tool' | 'evidence') {
  const key = `${panel}-${index}`
  selectedKey.value = key
  if (expandedBranch.value === index && expandedPanel.value === panel) {
    expandedBranch.value = null
    return
  }
  expandedBranch.value = index
  expandedPanel.value = panel
}

function knowledgeDetail(knowledgeId: string): Record<string, any> {
  return props.knowledgeHits?.find((item) => item.knowledge_id === knowledgeId) || { knowledge_id: knowledgeId }
}

function branchEvidence(step: AgentStep): Record<string, any>[] {
  const knowledge = (step.knowledge_ids || []).map(knowledgeDetail)
  return [...knowledge, ...stepEvidence(step)]
}

function evidencePreview(item: Record<string, any>): string {
  return item.content || item.summary || item.data?.verdict || item.data?.event || '该证据已被工具返回，但没有附加摘要。'
}

function evidenceFacts(item: Record<string, any>): string[] {
  const data = item.data || {}
  const temporal = data.temporal_context || {}
  const facts: string[] = []
  if (data.dataset) facts.push(`数据集 ${data.dataset}`)
  if (data.detector) facts.push(`检测器 ${data.detector}`)
  if (temporal.detector_event_count !== undefined) facts.push(`窗口事件 ${temporal.detector_event_count}`)
  if (temporal.same_rule_count !== undefined) facts.push(`同规则 ${temporal.same_rule_count}`)
  if (temporal.same_src_ip_count !== undefined) facts.push(`同源IP ${temporal.same_src_ip_count}`)
  if (item.score !== undefined) facts.push(`相关度 ${Math.round(item.score * 100)}%`)
  return facts
}

watch(() => props.steps.length, () => {
  if (!selections.value.some((item) => item.key === selectedKey.value)) selectedKey.value = 'orchestrator'
})
</script>

<template>
  <div class="agent-flow">
    <header class="flow-header">
      <div>
        <small>MULTI-AGENT INVESTIGATION GRAPH</small>
        <b>多智能体协同取证图</b>
      </div>
      <div class="flow-metrics">
        <span><i>{{ plannedAgents.length }}</i> 计划智能体</span>
        <span><i>{{ agentBranches.length }}</i> 参与智能体</span>
        <span><i>{{ steps.length }}</i> 工具调用</span>
        <span><i>{{ ledger?.replan_count || 0 }}</i> 自主重规划</span>
        <span><i>{{ totalEvidence }}</i> 证据对象</span>
      </div>
    </header>

    <div class="flow-stage">
      <button
        type="button"
        class="orchestrator-node"
        :class="{ selected: selectedKey === 'orchestrator' }"
        @click="selectedKey = 'orchestrator'"
      >
        <span class="node-emblem">SOC</span>
        <span><small>ORCHESTRATOR</small><b>调查任务编排器</b></span>
        <span class="node-state"><i></i>{{ ledger?.status || 'completed' }}</span>
      </button>

      <div class="down-route"><i></i><span>自主规划 → 观察反馈 → 动态重规划</span></div>

      <div class="branch-grid" :class="branchLayoutClass">
        <article
          v-for="(branch, branchIndex) in agentBranches"
          :key="branch.key"
          class="agent-branch"
          :class="{ expanded: branch.steps.some(({ index }) => expandedBranch === index) }"
        >
          <div class="branch-number">
            AGENT {{ String(branchIndex + 1).padStart(2, '0') }}
            <span>{{ branch.steps.length }} 轮调用</span>
          </div>
          <button
            type="button"
            class="branch-node agent-node"
            :class="{ selected: selectedKey === `agent-${branch.key}` }"
            @click="selectedKey = `agent-${branch.key}`"
          >
            <span class="agent-avatar">{{ branch.agent.slice(0, 2).toUpperCase() }}</span>
            <span class="branch-copy"><small>SPECIALIST AGENT</small><b>{{ branch.agent }}</b><em>{{ branch.capability }}</em></span>
            <span class="status-dot success"><i></i>{{ completedAgents.includes(branch.agent) ? '已完成' : stepStatus(branch.steps[branch.steps.length - 1].step) }}</span>
          </button>

          <div
            v-for="({ step, index }, roundIndex) in branch.steps"
            :key="`${step.step}-${step.tool}-${index}`"
            class="round-block"
          >
            <div class="round-divider"><i></i><span>ROUND {{ String(roundIndex + 1).padStart(2, '0') }}</span></div>

            <button
              type="button"
              class="branch-node tool-node"
              :class="{ selected: selectedKey === `tool-${index}` }"
              @click="openBranch(index, 'tool')"
            >
              <span class="tool-icon"><component :is="toolInfo(step.tool).icon" :size="20" weight="bold" aria-hidden="true" /></span>
              <span class="branch-copy"><small>CONTROLLED TOOL</small><b>{{ step.tool }}</b><em>{{ toolInfo(step.tool).label }}</em></span>
              <span class="tool-latency">{{ step.result?.latency_ms ?? '-' }} ms</span>
            </button>

            <div class="branch-arrow evidence-route"><span>返回</span><i></i></div>

            <button
              type="button"
              class="branch-node evidence-node"
              :class="{ selected: selectedKey === `evidence-${index}` }"
              @click="openBranch(index, 'evidence')"
            >
              <span class="evidence-mark">EV</span>
              <span class="branch-copy"><small>VERIFIABLE OUTPUT</small><b>{{ evidenceLabel(step) }}</b><em>{{ evidenceIds(step).slice(0, 2).join(' · ') || '无有效 Evidence ID' }}</em></span>
              <span class="evidence-count">{{ evidenceIds(step).length }}</span>
            </button>

            <div v-if="expandedBranch === index" class="branch-expansion">
              <div class="expansion-tabs">
                <button type="button" :class="{ active: expandedPanel === 'tool' }" @click="expandedPanel = 'tool'">工具执行详情</button>
                <button type="button" :class="{ active: expandedPanel === 'evidence' }" @click="expandedPanel = 'evidence'">对应证据 {{ evidenceIds(step).length }}</button>
                <button type="button" class="close-expansion" title="收起" @click="expandedBranch = null">×</button>
              </div>

              <div v-if="expandedPanel === 'tool'" class="tool-detail-panel">
                <div class="detail-tool-head">
                  <span class="tool-icon large"><component :is="toolInfo(step.tool).icon" :size="26" weight="bold" aria-hidden="true" /></span>
                  <div><small>CONTROLLED TOOL</small><b>{{ step.tool }}</b><em>{{ toolInfo(step.tool).label }}</em></div>
                  <span class="detail-status">{{ stepStatus(step) }}</span>
                </div>
                <div class="tool-detail-grid">
                  <div><small>调用参数</small><code>{{ JSON.stringify(step.args || {}, null, 2) }}</code></div>
                  <div><small>执行结果</small><p>{{ step.result?.summary || step.summary || '工具执行完成，未返回文字摘要。' }}</p></div>
                  <div><small>运行信息</small><p>状态 {{ step.result?.status || step.status || '-' }} · 尝试 {{ step.result?.attempts ?? '-' }} 次 · 延迟 {{ step.result?.latency_ms ?? '-' }} ms</p></div>
                </div>
              </div>

              <div v-else class="evidence-detail-list">
                <article v-for="item in branchEvidence(step)" :key="item.evidence_id || item.knowledge_id" class="evidence-detail-card">
                  <div class="evidence-detail-head">
                    <code>{{ item.evidence_id || item.knowledge_id }}</code>
                    <span>{{ item.evidence_id ? '事件证据' : '知识证据' }}</span>
                  </div>
                  <b>{{ item.title || item.kind || item.source || '可验证证据对象' }}</b>
                  <p>{{ evidencePreview(item) }}</p>
                  <div v-if="evidenceFacts(item).length" class="evidence-facts">
                    <span v-for="fact in evidenceFacts(item)" :key="fact">{{ fact }}</span>
                  </div>
                  <details v-if="item.data" class="raw-evidence">
                    <summary>查看结构化原始证据</summary>
                    <pre>{{ JSON.stringify(item.data, null, 2) }}</pre>
                  </details>
                </article>
                <div v-if="!branchEvidence(step).length" class="empty-evidence">该工具没有产生可展示的 Evidence ID。</div>
                </div>
            </div>
          </div>
        </article>
      </div>

      <div v-if="pendingAgents.length" class="pending-agents">
        <span>本轮有计划但未产生执行记录</span>
        <code v-for="agent in pendingAgents" :key="agent">{{ agent }}</code>
      </div>

      <div class="convergence"><i></i><span>证据汇聚与引用校验</span></div>

      <button
        type="button"
        class="verifier-node"
        :class="{ selected: selectedKey === 'verifier' }"
        @click="selectedKey = 'verifier'"
      >
        <span class="verifier-icon"><PhCheck :size="18" weight="bold" aria-hidden="true" /></span>
        <span><small>VERIFIER AGENT</small><b>证据融合验证器</b></span>
        <span class="verdict"><small>FINAL VERDICT</small><b>{{ judgment || '待查' }} · {{ Math.round((confidence || 0) * 100) }}%</b></span>
      </button>
    </div>

    <aside class="flow-inspector" :class="`tone-${selected?.tone || 'blue'}`">
      <div class="inspector-mark"><i></i></div>
      <div>
        <small>{{ selected?.eyebrow }}</small>
        <b>{{ selected?.title }}</b>
        <p>{{ selected?.detail }}</p>
      </div>
      <div class="inspector-meta">
        <span v-for="item in selected?.meta" :key="item">{{ item }}</span>
      </div>
    </aside>
  </div>
</template>

<style scoped>
/* 本地 tone 变量统一接入全局主题令牌,随亮暗自适应 */
.agent-flow { --blue: rgb(var(--cyan)); --cyan: rgb(var(--teal)); --purple: rgb(var(--purple)); --green: rgb(var(--green)); --amber: rgb(var(--yellow)); overflow: hidden; border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--card)); }
.flow-header { min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 13px 16px; border-bottom: 1px solid rgb(var(--border)); background: rgb(var(--bg)); }
.flow-header small, .flow-header b { display: block; }
.flow-header small { color: rgb(var(--text-mute)); font: 11px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .12em; }
.flow-header b { margin-top: 5px; color: rgb(var(--text)); font-size: 20px; font-weight: 800; letter-spacing: -0.01em; }
.flow-metrics { display: flex; gap: 7px; }
.flow-metrics span { padding: 7px 10px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); font-size: 13.5px; background: rgb(var(--card)); }
.flow-metrics i { color: rgb(var(--cyan)); font: normal 700 15px 'JetBrains Mono', ui-monospace, monospace; }
.flow-stage { padding: 22px 18px 18px; background-image: linear-gradient(rgb(var(--grid-line) / .4) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--grid-line) / .4) 1px, transparent 1px); background-size: 28px 28px; }
button { font: inherit; }
.orchestrator-node, .verifier-node { position: relative; width: min(760px, 92%); min-height: 78px; display: grid; grid-template-columns: 54px 1fr auto; align-items: center; gap: 14px; margin: 0 auto; padding: 12px 15px; border: 1px solid rgb(var(--text)); border-radius: 0; color: inherit; background: rgb(var(--card)); text-align: left; box-shadow: none; transition: .2s ease; }
.orchestrator-node:hover, .orchestrator-node.selected, .verifier-node:hover, .verifier-node.selected { transform: translateY(-2px); box-shadow: 4px 4px 0 0 rgb(var(--text)); }
.orchestrator-node.selected, .verifier-node.selected { box-shadow: 4px 4px 0 0 var(--blue); }
.verifier-node.selected { box-shadow: 4px 4px 0 0 var(--amber); }
.node-emblem, .verifier-icon { width: 43px; height: 43px; display: grid; place-items: center; border: 1px solid rgb(var(--text)); border-radius: 0; color: rgb(var(--bg)); background: rgb(var(--text)); font: 700 11px 'JetBrains Mono', ui-monospace, monospace; }
.orchestrator-node small, .orchestrator-node b, .verifier-node small, .verifier-node b { display: block; }
.orchestrator-node small, .verifier-node small { color: rgb(var(--text-mute)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .1em; }
.orchestrator-node b, .verifier-node b { margin-top: 5px; color: rgb(var(--text)); font-size: 17.5px; }
.node-state { display: flex; align-items: center; gap: 6px; color: rgb(var(--green)); font-size: 13px; }
.node-state i { width: 5px; height: 5px; border-radius: 50%; background: rgb(var(--green)); }
.down-route, .convergence { height: 55px; position: relative; display: grid; place-items: center; color: rgb(var(--text-mute)); font-size: 7px; }
.down-route i { position: absolute; top: 0; bottom: 12px; left: 50%; width: 1px; background: rgb(var(--text)); }
.down-route i::after { content: ''; position: absolute; bottom: -2px; left: -3px; width: 7px; height: 7px; border-right: 1px solid rgb(var(--text)); border-bottom: 1px solid rgb(var(--text)); transform: rotate(45deg); }
.down-route span, .convergence span { position: relative; padding: 3px 7px; border: 1px solid rgb(var(--border-light)); border-radius: 0; background: rgb(var(--card)); }
.branch-grid { width: min(1420px, 100%); display: grid; gap: 18px; margin: 0 auto; align-items: start; }
.branch-grid.layout-one { grid-template-columns: minmax(0, 920px); justify-content: center; }
.branch-grid.layout-two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.branch-grid.layout-many { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.agent-branch { position: relative; min-width: 0; padding: 16px; border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--card)); box-shadow: none; transition: border-color .2s ease; }
.agent-branch:hover { border-color: rgb(var(--text)); }
.agent-branch.expanded { grid-column: 1 / -1; border-color: rgb(var(--text)); box-shadow: 4px 4px 0 0 rgb(var(--text)); }
.branch-number { display: flex; justify-content: space-between; gap: 8px; margin-bottom: 11px; color: rgb(var(--text)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .1em; }
.branch-number span { color: rgb(var(--text-mute)); letter-spacing: 0; }
.branch-node { position: relative; width: 100%; min-height: 76px; display: grid; grid-template-columns: 46px 1fr auto; align-items: center; gap: 13px; padding: 11px 13px; border: 1px solid rgb(var(--border)); border-radius: 0; color: inherit; background: rgb(var(--card)); text-align: left; transition: .2s ease; }
.branch-node:hover, .branch-node.selected { transform: translateX(2px); border-color: var(--node-tone, rgb(var(--cyan))); box-shadow: none; }
.branch-node.selected { box-shadow: 3px 3px 0 0 var(--node-tone, rgb(var(--cyan))); }
.agent-node { --node-tone: var(--purple); }
.tool-node { --node-tone: var(--cyan); background: rgb(var(--bg)); }
.evidence-node { --node-tone: var(--green); background: rgb(var(--bg)); }
.agent-avatar, .tool-icon, .evidence-mark { width: 44px; height: 44px; display: grid; place-items: center; border: 1px solid var(--node-tone); border-radius: 0; color: var(--node-tone); background: rgb(var(--card)); font: 700 12.5px 'JetBrains Mono', ui-monospace, monospace; }
.tool-icon { font-size: 22px; }
.branch-copy { min-width: 0; }
.branch-copy small, .branch-copy b, .branch-copy em { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.branch-copy small { color: rgb(var(--text-mute)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .09em; }
.branch-copy b { margin-top: 5px; color: rgb(var(--text)); font: 700 17px 'JetBrains Mono', ui-monospace, monospace; }
.branch-copy em { margin-top: 4px; color: rgb(var(--text-mute)); font-size: 13.5px; font-style: normal; }
.status-dot { display: flex; align-items: center; gap: 5px; color: rgb(var(--text-mute)); font-size: 13px; }
.status-dot i { width: 5px; height: 5px; border-radius: 50%; background: rgb(var(--green)); }
.tool-latency, .evidence-count { color: rgb(var(--text-mute)); font: 11px 'JetBrains Mono', ui-monospace, monospace; }
.evidence-count { width: 22px; height: 22px; display: grid; place-items: center; border: 1px solid var(--green); border-radius: 0; color: var(--green); }
.round-block { position: relative; }
.round-block + .round-block { margin-top: 16px; padding-top: 4px; border-top: 1px dashed rgb(var(--border-light)); }
.round-divider { position: relative; height: 35px; display: grid; place-items: center; }
.round-divider i { position: absolute; inset-block: 0 7px; left: 50%; width: 1px; background: rgb(var(--text)); }
.round-divider i::after { content: ''; position: absolute; bottom: -1px; left: -3px; width: 7px; height: 7px; border-right: 1px solid rgb(var(--text)); border-bottom: 1px solid rgb(var(--text)); transform: rotate(45deg); }
.round-divider span { position: relative; padding: 3px 7px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text)); background: rgb(var(--card)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; }
.branch-expansion { margin-top: 14px; overflow: hidden; border: 1px solid rgb(var(--text)); border-radius: 0; background: rgb(var(--card)); animation: reveal .2s ease-out; }
.expansion-tabs { display: flex; gap: 5px; padding: 8px; border-bottom: 1px solid rgb(var(--border)); background: rgb(var(--bg)); }
.expansion-tabs button { padding: 7px 11px; border: 1px solid transparent; border-radius: 0; color: rgb(var(--text-mute)); background: transparent; font-size: 13px; }
.expansion-tabs button:hover, .expansion-tabs button.active { border-color: rgb(var(--text)); color: rgb(var(--text)); background: rgb(var(--card)); }
.expansion-tabs .close-expansion { margin-left: auto; color: rgb(var(--text-mute)); font-size: 17px; line-height: 1; }
.tool-detail-panel, .evidence-detail-list { padding: 15px; }
.detail-tool-head { display: grid; grid-template-columns: 54px 1fr auto; align-items: center; gap: 13px; }
.tool-icon.large { width: 52px; height: 52px; }
.detail-tool-head small, .detail-tool-head b, .detail-tool-head em { display: block; }
.detail-tool-head small { color: rgb(var(--text-mute)); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; }
.detail-tool-head b { margin-top: 4px; color: rgb(var(--text)); font: 700 16px 'JetBrains Mono', ui-monospace, monospace; }
.detail-tool-head em { margin-top: 3px; color: rgb(var(--text-mute)); font-size: 13px; font-style: normal; }
.detail-status { padding: 5px 8px; border: 1px solid rgb(var(--green)); border-radius: 0; color: rgb(var(--green)); font-size: 11.5px; }
.tool-detail-grid { display: grid; grid-template-columns: .8fr 1.2fr; gap: 9px; margin-top: 13px; }
.tool-detail-grid > div { padding: 11px; border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--bg)); }
.tool-detail-grid > div:last-child { grid-column: 1 / -1; }
.tool-detail-grid small { display: block; margin-bottom: 7px; color: rgb(var(--text-mute)); font-size: 10.5px; }
.tool-detail-grid code, .tool-detail-grid p { color: rgb(var(--text)); font: 12.5px/1.65 'JetBrains Mono', ui-monospace, monospace; white-space: pre-wrap; }
.evidence-detail-list { display: grid; gap: 10px; }
.evidence-detail-card { padding: 13px; border: 1px solid rgb(var(--border)); border-radius: 0; background: rgb(var(--bg)); }
.evidence-detail-card:hover { border-color: var(--green); }
.evidence-detail-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.evidence-detail-head code { color: rgb(var(--green)); font: 700 12.5px 'JetBrains Mono', ui-monospace, monospace; }
.evidence-detail-head span { color: rgb(var(--text-mute)); font-size: 10.5px; }
.evidence-detail-card > b { display: block; margin-top: 9px; color: rgb(var(--text)); font-size: 14.5px; }
.evidence-detail-card > p { margin: 7px 0 0; color: rgb(var(--text-mute)); font-size: 13.5px; line-height: 1.7; }
.evidence-facts { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.evidence-facts span { padding: 4px 7px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--green)); font-size: 11.5px; background: rgb(var(--card)); }
.raw-evidence { margin-top: 10px; border-top: 1px solid rgb(var(--border)); padding-top: 9px; }
.raw-evidence summary { color: rgb(var(--text-mute)); font-size: 11.5px; cursor: pointer; }
.raw-evidence pre { max-height: 280px; margin-top: 8px; overflow: auto; padding: 10px; border-radius: 0; color: rgb(var(--text)); background: rgb(var(--bg-2)); border: 1px solid rgb(var(--border)); font: 11.5px/1.55 'JetBrains Mono', ui-monospace, monospace; }
.empty-evidence { padding: 20px; color: rgb(var(--text-mute)); text-align: center; font-size: 13px; }
.pending-agents { width: min(1420px, 100%); display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin: 12px auto 0; padding: 10px 12px; border: 1px dashed rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); font-size: 11.5px; }
.pending-agents code { padding: 4px 7px; border-radius: 0; color: rgb(var(--purple)); background: rgb(var(--purple) / .07); border: 1px solid rgb(var(--purple) / .3); font-size: 11.5px; }
.branch-arrow { position: relative; height: 27px; display: grid; place-items: center; color: rgb(var(--text-mute)); font-size: 6px; }
.branch-arrow i { position: absolute; top: 0; bottom: 4px; left: 50%; width: 1px; background: rgb(var(--text)); }
.branch-arrow i::after { content: ''; position: absolute; bottom: -1px; left: -3px; width: 7px; height: 7px; border-right: 1px solid rgb(var(--text)); border-bottom: 1px solid rgb(var(--text)); transform: rotate(45deg); }
.branch-arrow span { position: relative; padding: 2px 5px; background: rgb(var(--card)); }
.convergence { margin-top: 3px; }
.convergence i { position: absolute; left: 15%; right: 15%; top: 12px; height: 24px; border: 1px solid rgb(var(--text-mute)); border-top: 0; border-radius: 0 0 9px 9px; }
.convergence i::after { content: ''; position: absolute; left: 50%; bottom: -8px; height: 8px; border-left: 1px solid rgb(var(--text)); }
.verifier-node { border-color: rgb(var(--text)); }
.verifier-node:hover, .verifier-node.selected { border-color: rgb(var(--text)); }
.verifier-icon { border-color: rgb(var(--yellow)); color: rgb(var(--yellow)); background: rgb(var(--card)); font-size: 17px; }
.verdict { text-align: right; }
.verdict b { color: rgb(var(--yellow)); font: 700 17px 'JetBrains Mono', ui-monospace, monospace; }
.flow-inspector { --tone: var(--blue); min-height: 118px; display: grid; grid-template-columns: 18px 1fr minmax(150px, auto); gap: 13px; align-items: start; padding: 15px 16px; border-top: 1px solid rgb(var(--border)); background: rgb(var(--bg)); }
.inspector-mark { position: relative; height: 100%; }
.inspector-mark::before { content: ''; position: absolute; left: 7px; top: 3px; bottom: 3px; width: 1px; background: linear-gradient(var(--tone), transparent); }
.inspector-mark i { position: absolute; left: 3px; top: 2px; width: 9px; height: 9px; border: 2px solid var(--tone); border-radius: 50%; }
.flow-inspector small, .flow-inspector b { display: block; }
.flow-inspector small { color: var(--tone); font: 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .1em; }
.flow-inspector b { margin-top: 5px; color: rgb(var(--text)); font-size: 17.5px; }
.flow-inspector p { margin: 9px 0 0; color: rgb(var(--text-mute)); font-size: 14.5px; line-height: 1.75; }
.inspector-meta { display: flex; flex-direction: column; gap: 6px; }
.inspector-meta span { padding: 6px 8px; border: 1px solid rgb(var(--border-light)); border-radius: 0; color: rgb(var(--text-mute)); font-size: 11.5px; background: rgb(var(--card)); white-space: nowrap; }
.branch-arrow span, .down-route span, .convergence span { font-size: 10.5px; }
.tool-detail-panel, .evidence-detail-list { scroll-margin-top: 18px; }
.agent-branch:has(.branch-expansion) { border-color: rgb(var(--text)); }
@keyframes reveal { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: translateY(0); } }
.tone-blue { --tone: var(--blue); }.tone-cyan { --tone: var(--cyan); }.tone-purple { --tone: var(--purple); }.tone-green { --tone: var(--green); }.tone-amber { --tone: var(--amber); }
@media (max-width: 820px) {
  .flow-header { align-items: flex-start; }
  .flow-metrics { flex-wrap: wrap; justify-content: flex-end; }
  .flow-inspector { grid-template-columns: 18px 1fr; }
  .inspector-meta { grid-column: 2; flex-direction: row; flex-wrap: wrap; }
  .branch-grid.layout-two, .branch-grid.layout-many { grid-template-columns: 1fr; }
}
@media (min-width: 821px) and (max-width: 1240px) {
  .branch-grid.layout-many { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 520px) {
  .flow-metrics { display: none; }
  .flow-stage { padding-inline: 10px; }
  .orchestrator-node, .verifier-node { width: 100%; grid-template-columns: 42px 1fr; }
  .node-state, .verdict { grid-column: 2; text-align: left; }
  .tool-detail-grid { grid-template-columns: 1fr; }
  .tool-detail-grid > div:last-child { grid-column: auto; }
}
</style>
