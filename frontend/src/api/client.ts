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
): Promise<void> {
  const res = await fetch(`${API_BASE}/alerts/judge/stream`, {
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
