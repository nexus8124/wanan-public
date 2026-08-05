/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

// Agent 返回结果类型（与后端 schemas 对齐）
export interface AgentResult {
  alert_id: string
  judgment: '真阳' | '假阳' | '待查'
  confidence: number
  reason: string
  initial_judgment?: '真阳' | '假阳' | '待查'
  initial_confidence?: number
  initial_reason?: string
  cot_trace: string[]
  features: Record<string, any>
  react_used: boolean
  react_steps: ReactStep[]
  tools_called: string[]
  disposition: Disposition | null
  evidence?: Array<Record<string, any>>
  cited_evidence?: string[]
  evidence_grounded?: boolean
  rag_used?: boolean
  knowledge_hits?: Array<Record<string, any>>
  cited_knowledge?: string[]
  knowledge_grounded?: boolean
  retrieval_trace?: Record<string, any>
  execution?: Record<string, any>
}

export interface ReactStep {
  step: number
  tool: string
  args: Record<string, any>
  result: Record<string, any>
}

export interface Disposition {
  action: 'block_and_isolate' | 'block_ip' | 'isolate_host' | 'whitelist' | 'escalate_human' | 'monitor'
  summary: string
  tickets: Ticket[]
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
}

export interface Ticket {
  action: string
  target: string
  reason: string
  ticket_id: string
  executed: boolean
}

// SSE 流式事件
export interface StreamEvent {
  step: number
  node: string
  update: Record<string, any>
}

export interface Stats {
  dataset: string
  total: number
  by_label: Record<string, number>
  by_source: Record<string, number>
  by_severity: Record<string, number>
  attack_types: Array<{ id: string; count: number }>
}
