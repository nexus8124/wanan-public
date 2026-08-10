<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getStats, subscribeStats } from '../api/client'
import type { Stats } from '../env'

const router = useRouter()
const stats = ref<Stats | null>(null)
const loading = ref(true)
const errorMsg = ref('')
const liveConnected = ref(false)
let closeStatsStream: (() => void) | null = null

const sourceLabels: Record<string, string> = {
  edr: 'EDR 端点检测',
  ids: 'IDS 入侵检测',
  waf: 'WAF 应用防护',
  siem: 'SIEM 日志',
  ndr: 'NDR 网络检测',
  firewall: '防火墙',
  unknown: '其他来源',
}

const judgmentMeta: Record<string, { color: string; dot: string; desc: string }> = {
  真阳: { color: 'var(--ops-danger)', dot: 'decision-danger', desc: '确认威胁，需响应处置' },
  假阳: { color: 'var(--ops-success)', dot: 'decision-success', desc: '已排除风险，无需处置' },
  待查: { color: 'var(--ops-warning)', dot: 'decision-warning', desc: '证据不足，等待复核' },
}

const decisionRows = computed(() => {
  if (!stats.value) return []
  return ['真阳', '假阳', '待查'].map((label) => ({
    label,
    count: stats.value?.by_judgment[label] || 0,
    ...judgmentMeta[label],
  }))
})

const maxSource = computed(() => {
  const values = Object.values(stats.value?.by_source || {})
  return Math.max(...values, 1)
})

function percentage(value: number, total: number): number {
  if (!total) return 0
  return Math.round((value / total) * 100)
}

function formatUpdatedAt(value: string | null): string {
  if (!value) return '等待首条研判记录'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(value))
}

function formatConfidence(value: number): string {
  return `${Math.round(value * 100)}%`
}

function goInvestigate() {
  router.push('/investigate')
}

async function loadStats() {
  try {
    stats.value = await getStats()
    errorMsg.value = ''
  } catch (error: any) {
    errorMsg.value = error.message || '运营统计加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadStats()
  closeStatsStream = subscribeStats(
    (snapshot) => {
      stats.value = snapshot
      liveConnected.value = true
      errorMsg.value = ''
    },
    () => {
      liveConnected.value = false
    },
  )
})

onBeforeUnmount(() => closeStatsStream?.())
</script>

<template>
  <div v-if="loading" class="ops-loading">
    <span class="ops-loading-dot"></span>
    正在汇总最新运营数据
  </div>

  <div v-else-if="errorMsg && !stats" class="ops-error">
    <span>运营统计暂时不可用</span>
    <button @click="loadStats">重新加载</button>
  </div>

  <div v-else-if="stats" class="ops-dashboard">
    <header class="ops-hero">
      <div>
        <div class="ops-eyebrow">SECURITY OPERATIONS WORKSPACE</div>
        <h2>安全运营态势总览</h2>
        <p>聚合所有已完成研判的最新结论，数据随新告警与误判记录实时更新</p>
      </div>
      <div class="ops-live" :class="{ connected: liveConnected }">
        <span class="ops-live-dot"></span>
        <div>
          <b>{{ liveConnected ? '实时同步中' : '正在连接' }}</b>
          <small>更新于 {{ formatUpdatedAt(stats.last_updated) }}</small>
        </div>
      </div>
    </header>

    <section class="ops-metric-grid">
      <article class="ops-metric metric-blue">
        <div class="metric-head"><span>累计告警</span><small>TOTAL ALERTS</small></div>
        <strong>{{ stats.total_alerts }}</strong>
        <p>按告警 ID 去重后的最新记录</p>
      </article>
      <article class="ops-metric metric-red">
        <div class="metric-head"><span>确认威胁</span><small>TRUE POSITIVE</small></div>
        <strong>{{ stats.confirmed_threats }}</strong>
        <p>需要响应或处置的真实攻击</p>
      </article>
      <article class="ops-metric metric-green">
        <div class="metric-head"><span>已排除风险</span><small>FALSE POSITIVE</small></div>
        <strong>{{ stats.dismissed_risks }}</strong>
        <p>已确认无需处置的误报告警</p>
      </article>
      <article class="ops-metric metric-amber">
        <div class="metric-head"><span>待人工复核</span><small>PENDING REVIEW</small></div>
        <strong>{{ stats.pending_review }}</strong>
        <p>当前证据不足，等待进一步研判</p>
      </article>
    </section>

    <section class="ops-grid ops-grid-main">
      <article class="ops-panel">
        <div class="ops-panel-head">
          <div><h3>研判结论</h3><p>全部已研判告警的最新结论分布</p></div>
          <small>DECISION DISTRIBUTION</small>
        </div>
        <div class="ops-panel-body decision-list">
          <div v-for="item in decisionRows" :key="item.label" class="decision-row">
            <div class="decision-label">
              <span class="decision-dot" :class="item.dot"></span>
              <span>{{ item.label }}</span>
              <small>{{ item.desc }}</small>
              <b>{{ item.count }}</b>
              <em>{{ percentage(item.count, stats.total_alerts) }}%</em>
            </div>
            <div class="ops-progress">
              <i :style="{ width: `${percentage(item.count, stats.total_alerts)}%`, background: item.color }"></i>
            </div>
          </div>
        </div>
      </article>

      <article class="ops-panel">
        <div class="ops-panel-head">
          <div><h3>数据源覆盖</h3><p>按检测器来源统计已处理告警数量</p></div>
          <small>SOURCE COVERAGE</small>
        </div>
        <div v-if="Object.keys(stats.by_source).length" class="ops-panel-body source-grid">
          <div v-for="(count, source) in stats.by_source" :key="source" class="source-row">
            <div><span>{{ sourceLabels[source] || source.toUpperCase() }}</span><b>{{ count }}</b></div>
            <div class="ops-progress source-progress"><i :style="{ width: `${count / maxSource * 100}%` }"></i></div>
          </div>
        </div>
        <div v-else class="ops-empty compact">暂无来源统计</div>
      </article>
    </section>

    <section class="ops-grid ops-grid-detail">
      <article class="ops-panel recent-panel">
        <div class="ops-panel-head">
          <div><h3>最新研判动态</h3><p>新告警与误判结果将自动加入此列表</p></div>
          <small>LIVE ACTIVITY</small>
        </div>
        <div v-if="stats.recent_events.length" class="recent-list">
          <div v-for="event in stats.recent_events" :key="`${event.alert_id}-${event.observed_at}`" class="recent-row">
            <div class="recent-status" :class="`status-${event.judgment}`"></div>
            <div class="recent-main">
              <div><code>{{ event.alert_id }}</code><span>{{ event.rule_name }}</span></div>
              <small>{{ sourceLabels[event.source] || event.source.toUpperCase() }} · {{ formatUpdatedAt(event.observed_at) }}</small>
            </div>
            <span v-if="event.correct === false" class="result-badge result-error">误判</span>
            <span v-else-if="event.judgment === '真阳'" class="result-badge result-danger">真阳</span>
            <span v-else-if="event.judgment === '假阳'" class="result-badge result-success">假阳</span>
            <span v-else class="result-badge result-warning">待查</span>
            <b class="recent-confidence">{{ formatConfidence(event.confidence) }}</b>
          </div>
        </div>
        <div v-else class="ops-empty">
          <div class="empty-radar"><i></i></div>
          <b>等待首条运营研判</b>
          <span>在“告警研判”或“模型评测”中完成分析后，这里会自动更新</span>
        </div>
      </article>
    </section>

    <section class="ops-cta">
      <div>
        <span class="ops-cta-icon">↗</span>
        <div><b>进入告警研判工作区</b><small>查看初判、知识检索、工具证据与处置建议的完整实时轨迹</small></div>
      </div>
      <button @click="goInvestigate">打开研判工作区 <span>→</span></button>
    </section>
  </div>
</template>

<style scoped>
.ops-dashboard {
  --ops-blue: #5f8ff1;
  --ops-danger: #e56b74;
  --ops-success: #5fc49b;
  --ops-warning: #d7aa54;
  --ops-panel: #111925;
  --ops-panel-deep: #0c121c;
  --ops-line: #253143;
  display: flex;
  flex-direction: column;
  gap: 22px;
  color: #dce6f5;
}

.ops-loading,
.ops-error {
  min-height: 320px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: #7f91aa;
}

.ops-error { flex-direction: column; }
.ops-error button { color: #79a4ff; border: 1px solid #35558d; padding: 8px 16px; border-radius: 6px; }
.ops-loading-dot { width: 8px; height: 8px; border-radius: 50%; background: #5f8ff1; box-shadow: 0 0 14px #5f8ff1; animation: pulse 1.5s infinite; }

.ops-hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  padding: 2px 0 20px;
  border-bottom: 1px solid var(--ops-line);
}
.ops-eyebrow { margin-bottom: 10px; color: #6592ed; font: 600 10px/1.2 ui-monospace, monospace; letter-spacing: .22em; }
.ops-hero h2 { margin: 0; font-size: 25px; font-weight: 760; letter-spacing: -.02em; color: #edf4ff; }
.ops-hero p { margin: 8px 0 0; color: #7487a3; font-size: 13px; }
.ops-live { display: flex; align-items: center; gap: 10px; min-width: 180px; padding: 10px 13px; border: 1px solid var(--ops-line); background: rgba(17,25,37,.72); border-radius: 7px; }
.ops-live-dot { width: 7px; height: 7px; border-radius: 50%; background: #78869b; }
.ops-live.connected .ops-live-dot { background: var(--ops-success); box-shadow: 0 0 10px rgba(95,196,155,.75); animation: pulse 2s infinite; }
.ops-live b, .ops-live small { display: block; }
.ops-live b { font-size: 11px; color: #bdcadc; }
.ops-live small { margin-top: 2px; font: 9px ui-monospace, monospace; color: #607087; }

.ops-metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
.ops-metric { position: relative; min-height: 116px; padding: 17px 18px; overflow: hidden; border: 1px solid var(--ops-line); border-radius: 8px; background: var(--ops-panel); }
.ops-metric::before { content: ''; position: absolute; inset: 0 auto 0 0; width: 2px; background: var(--metric-color); }
.ops-metric::after { content: ''; position: absolute; right: -34px; bottom: -54px; width: 120px; height: 120px; border-radius: 50%; background: radial-gradient(circle, color-mix(in srgb, var(--metric-color) 12%, transparent), transparent 68%); }
.metric-blue { --metric-color: var(--ops-blue); }
.metric-red { --metric-color: var(--ops-danger); }
.metric-green { --metric-color: var(--ops-success); }
.metric-amber { --metric-color: var(--ops-warning); }
.metric-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #8193ac; font-size: 11px; }
.metric-head small { color: #4d5d73; font: 8px ui-monospace, monospace; letter-spacing: .08em; }
.ops-metric strong { display: block; margin-top: 12px; color: #edf4ff; font: 700 27px/1 ui-monospace, monospace; }
.ops-metric p { margin: 10px 0 0; color: #53647c; font-size: 10px; }

.ops-grid { display: grid; gap: 16px; }
.ops-grid-main { grid-template-columns: .82fr 1.25fr; }
.ops-grid-detail { grid-template-columns: minmax(0, 1fr); }
.ops-panel { overflow: hidden; border: 1px solid var(--ops-line); border-radius: 8px; background: var(--ops-panel); }
.ops-panel-head { min-height: 72px; padding: 16px 18px; display: flex; justify-content: space-between; gap: 16px; border-bottom: 1px solid var(--ops-line); }
.ops-panel-head h3 { margin: 0; color: #e4edf9; font-size: 14px; font-weight: 700; }
.ops-panel-head p { margin: 6px 0 0; color: #667992; font-size: 11px; }
.ops-panel-head > small { color: #527099; font: 8px ui-monospace, monospace; letter-spacing: .08em; }
.ops-panel-body { padding: 18px; }

.decision-list { display: flex; flex-direction: column; gap: 18px; }
.decision-label { display: grid; grid-template-columns: auto auto 1fr auto 38px; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 11px; color: #9caac0; }
.decision-label small { color: #53647c; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.decision-label b { color: #dce7f6; font: 600 11px ui-monospace, monospace; }
.decision-label em { color: #687a93; font: normal 9px ui-monospace, monospace; text-align: right; }
.decision-dot { width: 7px; height: 7px; border-radius: 2px; }
.decision-danger { background: var(--ops-danger); }
.decision-success { background: var(--ops-success); }
.decision-warning { background: var(--ops-warning); }
.ops-progress { height: 6px; overflow: hidden; border-radius: 2px; background: #080e17; }
.ops-progress i { display: block; height: 100%; min-width: 0; border-radius: inherit; transition: width .5s ease; }

.source-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px 24px; align-content: start; }
.source-row > div:first-child { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 8px; color: #8fa0b9; font-size: 11px; }
.source-row b { color: #dce7f6; font: 600 11px ui-monospace, monospace; }
.source-progress i { background: var(--ops-blue); box-shadow: 0 0 8px rgba(95,143,241,.25); }

.recent-list { max-height: 366px; overflow: auto; }
.recent-row { min-height: 61px; display: grid; grid-template-columns: 3px minmax(0, 1fr) auto 46px; align-items: center; gap: 12px; padding: 10px 16px; border-bottom: 1px solid rgba(37,49,67,.75); }
.recent-row:last-child { border-bottom: 0; }
.recent-row:hover { background: rgba(93,136,205,.045); }
.recent-status { align-self: stretch; border-radius: 3px; background: #708098; }
.status-真阳 { background: var(--ops-danger); }
.status-假阳 { background: var(--ops-success); }
.status-待查 { background: var(--ops-warning); }
.recent-main { min-width: 0; }
.recent-main > div { display: flex; align-items: center; gap: 10px; min-width: 0; }
.recent-main code { color: #73a1ff; font: 10px ui-monospace, monospace; white-space: nowrap; }
.recent-main span { overflow: hidden; color: #aebdd0; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.recent-main small { display: block; margin-top: 5px; color: #53657d; font-size: 9px; }
.result-badge { min-width: 38px; padding: 3px 6px; border-radius: 4px; text-align: center; font-size: 9px; border: 1px solid; }
.result-danger, .result-error { color: #ee7d83; border-color: rgba(229,107,116,.35); background: rgba(229,107,116,.1); }
.result-success { color: #62cda2; border-color: rgba(95,196,155,.35); background: rgba(95,196,155,.1); }
.result-warning { color: #dcaf56; border-color: rgba(215,170,84,.35); background: rgba(215,170,84,.1); }
.recent-confidence { color: #879ab2; font: 10px ui-monospace, monospace; text-align: right; }

.ops-empty { min-height: 280px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; color: #60728b; text-align: center; }
.ops-empty.compact { min-height: 160px; }
.ops-empty b { color: #8395ad; font-size: 12px; }
.ops-empty span { max-width: 360px; font-size: 10px; }
.empty-radar { position: relative; width: 44px; height: 44px; margin-bottom: 4px; border: 1px solid #31425a; border-radius: 50%; }
.empty-radar::before, .empty-radar::after { content: ''; position: absolute; background: #31425a; }
.empty-radar::before { top: 50%; left: 5px; right: 5px; height: 1px; }
.empty-radar::after { left: 50%; top: 5px; bottom: 5px; width: 1px; }
.empty-radar i { position: absolute; inset: 7px; border: 1px solid #24344b; border-radius: 50%; }

.ops-cta { min-height: 78px; padding: 15px 17px; display: flex; align-items: center; justify-content: space-between; gap: 20px; border: 1px solid var(--ops-line); border-left: 2px solid var(--ops-blue); border-radius: 8px; background: linear-gradient(90deg, rgba(95,143,241,.05), var(--ops-panel) 26%); }
.ops-cta > div { display: flex; align-items: center; gap: 13px; }
.ops-cta-icon { width: 34px; height: 34px; display: grid; place-items: center; border: 1px solid #34548b; border-radius: 6px; color: #77a3ff; background: #0d1726; }
.ops-cta b, .ops-cta small { display: block; }
.ops-cta b { color: #e3edf9; font-size: 13px; }
.ops-cta small { margin-top: 5px; color: #667b96; font-size: 10px; }
.ops-cta button { padding: 10px 15px; border: 1px solid #5f8ff1; border-radius: 5px; color: #eef5ff; background: #4e7fdc; font-size: 11px; font-weight: 700; box-shadow: 0 4px 16px rgba(49,90,166,.22); }
.ops-cta button:hover { background: #5b8ceb; }
.ops-cta button span { margin-left: 6px; }

@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .45; } }

@media (max-width: 1024px) {
  .ops-metric-grid { grid-template-columns: repeat(2, 1fr); }
  .ops-grid-main, .ops-grid-detail { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .ops-hero { align-items: flex-start; flex-direction: column; }
  .ops-live { width: 100%; }
  .ops-metric-grid { grid-template-columns: 1fr; }
  .source-grid { grid-template-columns: 1fr; }
  .ops-panel-head > small { display: none; }
  .decision-label { grid-template-columns: auto auto 1fr auto; }
  .decision-label small { display: none; }
  .decision-label em { display: none; }
  .recent-row { grid-template-columns: 3px minmax(0, 1fr) auto; }
  .recent-confidence { display: none; }
  .ops-cta { align-items: stretch; flex-direction: column; }
  .ops-cta button { width: 100%; }
}
</style>
