// 后端 API 封装
// dev 模式直接调后端绝对地址（绕过 vite proxy，避免 Windows 下 ECONNREFUSED）；
// 生产构建后同源（前端被 FastAPI 挂载），用相对路径。
import type { AgentResult, Stats, StreamEvent } from '../env'

// 判断是否 dev 模式：dev 时 import.meta.env.DEV 为 true
const DEV = (import.meta as any).env?.DEV
// dev 直连后端，prod 走相对路径（同源）
const API_BASE = DEV ? 'http://127.0.0.1:18000/api' : '/api'

// ---------- 同步接口 ----------

export async function judgeAlert(alert: Record<string, any>): Promise<AgentResult> {
  const res = await fetch(`${API_BASE}/alerts/judge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert),
  })
  if (!res.ok) {
    throw new Error(`judge failed: ${res.status} ${await res.text()}`)
  }
  return res.json()
}

export async function getSampleAlert(): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/alerts/sample`)
  return res.json()
}

export async function listSamples(): Promise<{ samples: Record<string, any>[]; count: number }> {
  const res = await fetch(`${API_BASE}/samples`)
  return res.json()
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/stats`)
  return res.json()
}

export async function runEval(mock = true): Promise<any> {
  const res = await fetch(`${API_BASE}/eval/run?mock=${mock}`, {
    method: 'POST',
  })
  if (!res.ok) {
    throw new Error(`eval failed: ${res.status} ${await res.text()}`)
  }
  return res.json()
}

export interface EvalStreamCallbacks {
  onStart?: (data: any) => void
  onAgentEvent?: (data: any) => void
  onProgress: (data: any) => void
  onComplete: (result: any) => void
  onError?: (err: string) => void
}

/** 流式批量评测：后端每完成一条样本就推送一次 progress 事件。 */
export async function streamRunEval(
  mock: boolean,
  limit: number | null,
  strategy: 'judge_only' | 'react',
  rag: boolean,
  callbacks: EvalStreamCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  const params = new URLSearchParams({
    mock: String(mock),
    strategy,
    rag: String(rag),
  })
  if (limit && limit > 0) params.set('limit', String(limit))
  const res = await fetch(`${API_BASE}/eval/run/stream?${params.toString()}`, {
    method: 'POST',
    headers: { Accept: 'text/event-stream' },
    signal,
  })

  if (!res.ok) {
    throw new Error(`eval stream failed: ${res.status} ${await res.text()}`)
  }

  const reader = res.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    buffer = buffer.replace(/\r\n/g, '\n')

    const parts = buffer.split('\n\n')
    buffer = parts.pop() || ''

    for (const part of parts) {
      let eventName = ''
      let dataStr = ''
      for (const line of part.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim()
        else if (line.startsWith('data:')) dataStr += line.slice(5).trim()
      }
      if (!dataStr) continue

      try {
        const data = JSON.parse(dataStr)
        if (eventName === 'start') callbacks.onStart?.(data)
        else if (eventName === 'agent_event') callbacks.onAgentEvent?.(data)
        else if (eventName === 'progress') callbacks.onProgress(data)
        else if (eventName === 'complete') callbacks.onComplete(data)
        else if (eventName === 'error') callbacks.onError?.(data.message || '未知错误')
      } catch (e) {
        console.warn('parse eval SSE failed:', dataStr, e)
      }
    }
  }
}

export async function listEvalHistory(limit = 50): Promise<{ runs: any[]; count: number }> {
  const res = await fetch(`${API_BASE}/eval/history?limit=${limit}`)
  if (!res.ok) throw new Error(`load eval history failed: ${res.status} ${await res.text()}`)
  return res.json()
}

export async function getEvalHistory(runId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/eval/history/${runId}`)
  if (!res.ok) throw new Error(`load eval history detail failed: ${res.status} ${await res.text()}`)
  return res.json()
}

export async function deleteEvalHistory(runId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/eval/history/${runId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`delete eval history failed: ${res.status} ${await res.text()}`)
}

export interface EvalDatasetInfo {
  id: string
  name: string
  filename: string
  count: number
  labels: Record<string, number>
  sources: Record<string, number>
  label_storage: string
  label_basis: string
  label_warning?: string | null
  source?: string | null
  active: boolean
}

export async function listEvalDatasets(): Promise<{
  datasets: EvalDatasetInfo[]
  active_id: string
  errors: { filename: string; error: string }[]
}> {
  const res = await fetch(`${API_BASE}/eval/datasets`)
  if (!res.ok) throw new Error(`load datasets failed: ${res.status} ${await res.text()}`)
  return res.json()
}

export async function selectEvalDataset(datasetId: string): Promise<EvalDatasetInfo> {
  const res = await fetch(`${API_BASE}/eval/datasets/select`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dataset_id: datasetId }),
  })
  if (!res.ok) throw new Error(`select dataset failed: ${res.status} ${await res.text()}`)
  const data = await res.json()
  return data.dataset
}

export async function uploadEvalDataset(file: File): Promise<EvalDatasetInfo> {
  const query = new URLSearchParams({ filename: file.name })
  const res = await fetch(`${API_BASE}/eval/datasets/upload?${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: file,
  })
  if (!res.ok) throw new Error(`upload dataset failed: ${res.status} ${await res.text()}`)
  const data = await res.json()
  return data.dataset
}

// ---------- SSE 流式接口 ----------
// EventSource 只支持 GET，用 fetch + ReadableStream 处理 POST SSE

export interface StreamCallbacks {
  onEvent: (event: StreamEvent) => void
  onError?: (err: string) => void
  onDone?: (totalSteps: number) => void
}

export async function streamJudgeAlert(
  alert: Record<string, any>,
  callbacks: StreamCallbacks,
  signal?: AbortSignal,
  rag = false,
): Promise<void> {
  const res = await fetch(`${API_BASE}/alerts/judge/stream?rag=${rag}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    body: JSON.stringify(alert),
    signal,
  })

  if (!res.ok) {
    throw new Error(`stream failed: ${res.status} ${await res.text()}`)
  }

  const reader = res.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  // 解析 SSE 格式：event: xxx\ndata: xxx\n\n
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    // EventSourceResponse 按 SSE 标准使用 CRLF（\r\n）换行。
    // 统一成 LF 后再分块，否则只查找 "\n\n" 会导致所有事件积压到流结束，
    // 页面只显示“完成”却收不到任何节点结果。
    buffer = buffer.replace(/\r\n/g, '\n')

    // 按空行分割事件块
    const parts = buffer.split('\n\n')
    buffer = parts.pop() || ''

    for (const part of parts) {
      const lines = part.split('\n')
      let eventName = ''
      let dataStr = ''
      for (const line of lines) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim()
        else if (line.startsWith('data:')) dataStr += line.slice(5).trim()
      }
      if (!dataStr) continue
      try {
        const data = JSON.parse(dataStr)
        if (eventName === 'error') {
          callbacks.onError?.(data.message || '未知错误')
        } else if (eventName === 'done') {
          callbacks.onDone?.(data.total_steps || 0)
        } else {
          // 普通节点事件
          callbacks.onEvent(data as StreamEvent)
        }
      } catch (e) {
        console.warn('parse SSE failed:', dataStr, e)
      }
    }
  }
}
