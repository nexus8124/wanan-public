<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { PhArrowRight } from '@phosphor-icons/vue'
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

function formatClock(value: string | null): string {
  if (!value) return '--:--:--'
  return new Intl.DateTimeFormat('zh-CN', {
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
  <!-- 稳定单根容器:加载态→内容不能替换根元素,否则进场动画会重播 -->
  <div class="ops-view page-enter">
  <!-- 骨架屏:按最终布局占位,替代无信息量的圆点加载 -->
  <div v-if="loading" class="ops-skeleton" role="status" aria-label="正在加载运营数据">
    <div class="sk-head">
      <span class="sk-line" style="width: 210px; height: 11px"></span>
      <span class="sk-line" style="width: min(360px, 70%); height: 30px"></span>
    </div>
    <section class="ops-stat-rail">
      <div v-for="i in 4" :key="i" class="rail-cell">
        <span class="sk-line" style="width: 46%; height: 11px"></span>
        <span class="sk-line" style="width: 28%; height: 32px; margin-top: 16px"></span>
        <span class="sk-line" style="width: 72%; height: 10px; margin-top: 14px"></span>
      </div>
    </section>
    <section class="ops-main">
      <div class="ops-side">
        <div v-for="i in 2" :key="i" class="ops-panel">
          <div class="sk-panel-head">
            <span class="sk-line" style="width: 38%; height: 12px"></span>
            <span class="sk-line" style="width: 58%; height: 10px"></span>
          </div>
          <div class="ops-panel-body">
            <span
              v-for="n in 5"
              :key="n"
              class="sk-line"
              :style="{ width: `${92 - n * 7}%`, height: '11px', marginBottom: '12px' }"
            ></span>
          </div>
        </div>
      </div>
      <div class="ops-panel">
        <div class="sk-panel-head">
          <span class="sk-line" style="width: 30%; height: 12px"></span>
          <span class="sk-line" style="width: 52%; height: 10px"></span>
        </div>
        <div class="ops-panel-body">
          <span
            v-for="n in 7"
            :key="n"
            class="sk-line"
            :style="{ width: `${94 - (n % 3) * 7}%`, height: '13px', marginBottom: '13px' }"
          ></span>
        </div>
      </div>
    </section>
  </div>

  <div v-else-if="errorMsg && !stats" class="ops-error">
    <span>运营统计暂时不可用</span>
    <button @click="loadStats">重新加载</button>
  </div>

  <div v-else-if="stats" class="ops-dashboard">
    <!-- 指挥头区:标题块 + 实时状态与主操作 -->
    <header class="ops-command">
      <div class="ops-command-copy">
        <div class="ops-eyebrow">SECURITY OPERATIONS WORKSPACE</div>
        <h2>安全运营态势总览</h2>
        <p>聚合所有已完成研判的最新结论，数据随新告警与误判记录实时更新</p>
      </div>
      <div class="ops-command-tools">
        <div class="ops-live" :class="{ connected: liveConnected }">
          <span class="ops-live-dot"></span>
          <div>
            <b>{{ liveConnected ? '实时同步中' : '正在连接' }}</b>
            <small>更新于 {{ formatUpdatedAt(stats.last_updated) }}</small>
          </div>
        </div>
        <button class="ops-command-action" @click="goInvestigate">
          打开研判工作区
          <PhArrowRight :size="14" weight="bold" aria-hidden="true" />
        </button>
      </div>
    </header>

    <!-- 状态数据轨:单容器四格,细线分隔(取代卡片堆叠) -->
    <section class="ops-stat-rail">
      <article class="rail-cell metric-ink">
        <div class="rail-head"><span>累计告警</span><small>TOTAL ALERTS</small></div>
        <strong>{{ stats.total_alerts }}</strong>
        <p>按告警 ID 去重后的最新记录</p>
      </article>
      <article class="rail-cell metric-red">
        <div class="rail-head"><span>确认威胁</span><small>TRUE POSITIVE</small></div>
        <strong>{{ stats.confirmed_threats }}</strong>
        <p>需要响应或处置的真实攻击</p>
      </article>
      <article class="rail-cell metric-green">
        <div class="rail-head"><span>已排除风险</span><small>FALSE POSITIVE</small></div>
        <strong>{{ stats.dismissed_risks }}</strong>
        <p>已确认无需处置的误报告警</p>
      </article>
      <article class="rail-cell metric-amber">
        <div class="rail-head"><span>待人工复核</span><small>PENDING REVIEW</small></div>
        <strong>{{ stats.pending_review }}</strong>
        <p>当前证据不足，等待进一步研判</p>
      </article>
    </section>

    <!-- 主分区:左(结论分布 + 来源覆盖) 右(实时动态流) -->
    <section class="ops-main">
      <div class="ops-side">
        <article class="ops-panel">
          <div class="ops-panel-head">
            <div><h3>研判结论</h3><p>全部已研判告警的最新结论分布</p></div>
            <small>DECISION DISTRIBUTION</small>
          </div>
          <div class="ops-panel-body">
            <div v-if="stats.total_alerts" class="dist-bar" role="img" aria-label="研判结论占比">
              <i
                v-for="item in decisionRows"
                :key="item.label"
                :style="{ width: `${percentage(item.count, stats.total_alerts)}%`, background: item.color }"
              ></i>
            </div>
            <div class="dist-legend">
              <div v-for="item in decisionRows" :key="item.label" class="dist-row">
                <span class="decision-dot" :class="item.dot"></span>
                <div class="dist-copy">
                  <b>{{ item.label }}</b>
                  <small>{{ item.desc }}</small>
                </div>
                <b class="dist-count">{{ item.count }}</b>
                <em class="dist-pct">{{ percentage(item.count, stats.total_alerts) }}%</em>
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
              <div class="source-bar"><i :style="{ width: `${count / maxSource * 100}%` }"></i></div>
            </div>
          </div>
          <div v-else class="ops-empty compact">暂无来源统计</div>
        </article>
      </div>

      <article class="ops-panel ops-feed">
        <div class="ops-panel-head">
          <div><h3>最新研判动态</h3><p>新告警与误判结果将自动加入此流</p></div>
          <small class="feed-tag">LIVE FEED</small>
        </div>
        <div v-if="stats.recent_events.length" class="feed-list">
          <div v-for="event in stats.recent_events" :key="`${event.alert_id}-${event.observed_at}`" class="feed-row">
            <time class="feed-time">{{ formatClock(event.observed_at) }}</time>
            <div class="feed-status" :class="`status-${event.judgment}`"></div>
            <div class="feed-main">
              <div><code>{{ event.alert_id }}</code><span>{{ event.rule_name }}</span></div>
              <small>{{ sourceLabels[event.source] || event.source.toUpperCase() }}</small>
            </div>
            <span v-if="event.correct === false" class="result-badge result-error">误判</span>
            <span v-else-if="event.judgment === '真阳'" class="result-badge result-danger">真阳</span>
            <span v-else-if="event.judgment === '假阳'" class="result-badge result-success">假阳</span>
            <span v-else class="result-badge result-warning">待查</span>
            <b class="feed-confidence">{{ formatConfidence(event.confidence) }}</b>
          </div>
        </div>
        <div v-else class="ops-empty">
          <div class="empty-radar"><i></i></div>
          <b>等待首条运营研判</b>
          <span>在“告警研判”或“模型评测”中完成分析后，这里会自动更新</span>
        </div>
      </article>
    </section>
  </div>
  </div>
</template>

<style scoped>
.ops-view { min-width: 0; }
.ops-dashboard {
  --ops-blue: rgb(var(--cyan));
  --ops-danger: rgb(var(--red));
  --ops-success: rgb(var(--green));
  --ops-warning: rgb(var(--yellow));
  --ops-panel: rgb(var(--card));
  --ops-line: rgb(var(--border));
  display: flex;
  flex-direction: column;
  gap: 14px;
  color: rgb(var(--text));
}

.ops-error {
  min-height: 320px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: rgb(var(--text-mute));
}

.ops-error { flex-direction: column; }
.ops-error button { color: rgb(var(--text)); border: 1px solid rgb(var(--text)); padding: 8px 16px; border-radius: 0; background: rgb(var(--card)); }
.ops-error button:hover { background: rgb(var(--text)); color: rgb(var(--bg)); }

/* 骨架屏:复用最终布局的容器结构,只以微光占位条示意内容区域 */
.sk-line { display: block; background: linear-gradient(90deg, rgb(var(--bg-2)) 30%, rgb(var(--border-light) / .55) 50%, rgb(var(--bg-2)) 70%); background-size: 200% 100%; animation: shimmer 1.3s linear infinite; }
.sk-head { display: flex; flex-direction: column; gap: 12px; padding: 2px 0 14px; border-bottom: 1px solid rgb(var(--text)); }
.sk-panel-head { height: 72px; padding: 16px 20px; border-bottom: 1px solid var(--ops-line); display: flex; flex-direction: column; justify-content: center; gap: 9px; }
@keyframes shimmer { to { background-position: -200% 0; } }

/* 指挥头区 */
.ops-command {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  padding: 2px 0 14px;
  border-bottom: 1px solid rgb(var(--text));
}
.ops-eyebrow { margin-bottom: 9px; color: rgb(var(--cyan)); font: 700 11px/1.2 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .22em; }
.ops-command h2 { margin: 0; font-size: 32px; font-weight: 800; letter-spacing: -0.03em; color: rgb(var(--text)); }
.ops-command p { margin: 8px 0 0; color: rgb(var(--text-dim)); font-size: 13.5px; max-width: 56ch; }
.ops-command-tools { display: flex; align-items: center; gap: 10px; flex: 0 0 auto; }
.ops-live { display: flex; align-items: center; gap: 10px; min-width: 178px; padding: 9px 12px; border: 1px solid var(--ops-line); background: var(--ops-panel); border-radius: 0; }
.ops-live-dot { width: 7px; height: 7px; border-radius: 50%; background: rgb(var(--text-mute)); }
.ops-live.connected .ops-live-dot { background: var(--ops-success); animation: pulse 2s infinite; }
.ops-live b, .ops-live small { display: block; }
.ops-live b { font-size: 12.5px; font-weight: 700; color: rgb(var(--text)); }
.ops-live small { margin-top: 3px; font: 10.5px 'JetBrains Mono', ui-monospace, monospace; color: rgb(var(--text-mute)); }
/* 蓝底主操作按钮:亮主题配白字、暗主题配深字,对比度均 ≥4.5:1 */
.ops-command-action { display: inline-flex; align-items: center; gap: 7px; padding: 11px 16px; border: 1px solid rgb(var(--cyan)); border-radius: 0; color: rgb(var(--on-accent)); background: rgb(var(--cyan)); font-size: 13px; font-weight: 700; white-space: nowrap; transition: background .2s ease, color .2s ease, border-color .2s ease; }
.ops-command-action:hover { background: rgb(var(--text)); border-color: rgb(var(--text)); color: rgb(var(--bg)); }

/* 内容区错峰入场:头部→数据轨→面板,依次浮现 */
.ops-command, .ops-stat-rail, .ops-panel { animation: rise .45s cubic-bezier(.22, .61, .36, 1) backwards; }
.ops-stat-rail { animation-delay: 60ms; }
.ops-side .ops-panel:nth-child(1) { animation-delay: 120ms; }
.ops-feed { animation-delay: 100ms; }
.ops-side .ops-panel:nth-child(2) { animation-delay: 160ms; }
@keyframes rise { from { opacity: 0; transform: translateY(12px); } }

/* 状态数据轨:单容器 + 细线分格 */
.ops-stat-rail { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--ops-line); background: var(--ops-panel); }
.rail-cell { position: relative; min-height: 104px; padding: 14px 18px 12px; overflow: hidden; }
.rail-cell + .rail-cell { border-left: 1px solid var(--ops-line); }
.rail-cell::before { content: ''; position: absolute; inset: 0 auto 0 0; width: 2px; background: var(--metric-color, rgb(var(--text))); }
.metric-ink { --metric-color: rgb(var(--text)); }
.metric-red { --metric-color: var(--ops-danger); }
.metric-green { --metric-color: var(--ops-success); }
.metric-amber { --metric-color: var(--ops-warning); }
.rail-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; color: rgb(var(--text-dim)); font-size: 12.5px; font-weight: 600; }
.rail-head small { color: rgb(var(--text-mute)); font: 9.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; }
.rail-cell strong { display: block; margin-top: 9px; color: rgb(var(--text)); font: 800 30px/1 'JetBrains Mono', ui-monospace, monospace; letter-spacing: -0.03em; }
.rail-cell p { margin: 7px 0 0; color: rgb(var(--text-mute)); font-size: 11px; }

/* 主分区:左窄右宽非对称 */
.ops-main { display: grid; grid-template-columns: minmax(0, .92fr) minmax(0, 1.35fr); gap: 14px; align-items: start; }
.ops-side { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
.ops-panel { overflow: hidden; border: 1px solid var(--ops-line); border-radius: 0; background: var(--ops-panel); }
.ops-panel-head { padding: 12px 18px; display: flex; justify-content: space-between; gap: 16px; border-bottom: 1px solid var(--ops-line); }
.ops-panel-head h3 { margin: 0; color: rgb(var(--text)); font-size: 15px; font-weight: 800; letter-spacing: -0.01em; }
.ops-panel-head p { margin: 4px 0 0; color: rgb(var(--text-mute)); font-size: 12px; }
.ops-panel-head > small { color: rgb(var(--text-mute)); font: 9.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .08em; align-self: flex-start; padding-top: 3px; }
.ops-panel-body { padding: 14px 18px; }

/* 结论分布:分段占比条 + 图例行 */
.dist-bar { display: flex; height: 8px; margin-bottom: 12px; border: 1px solid rgb(var(--border)); }
.dist-bar i { display: block; height: 100%; min-width: 0; transition: width .5s ease; }
.dist-legend { display: flex; flex-direction: column; }
.dist-row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto 44px; align-items: center; gap: 10px; padding: 9px 0; }
.dist-row + .dist-row { border-top: 1px solid rgb(var(--border) / .55); }
.decision-dot { width: 8px; height: 8px; border-radius: 2px; }
.decision-danger { background: var(--ops-danger); }
.decision-success { background: var(--ops-success); }
.decision-warning { background: var(--ops-warning); }
.dist-copy { min-width: 0; }
.dist-copy b { display: block; color: rgb(var(--text)); font-size: 13.5px; font-weight: 700; }
.dist-copy small { display: block; margin-top: 2px; color: rgb(var(--text-mute)); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dist-count { color: rgb(var(--text)); font: 700 15px 'JetBrains Mono', ui-monospace, monospace; }
.dist-pct { color: rgb(var(--text-dim)); font: normal 11px 'JetBrains Mono', ui-monospace, monospace; text-align: right; }

/* 来源覆盖 */
.source-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 18px; align-content: start; }
.source-row > div:first-child { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 7px; color: rgb(var(--text)); font-size: 13px; font-weight: 600; }
.source-row b { color: rgb(var(--text)); font: 700 13px 'JetBrains Mono', ui-monospace, monospace; }
.source-bar { height: 3px; background: rgb(var(--bg-2)); }
.source-bar i { display: block; height: 100%; background: rgb(var(--text-dim)); }

/* 实时动态流:终端式行 */
.ops-feed { min-width: 0; }
.feed-tag { color: rgb(var(--cyan)) !important; }
.feed-list { max-height: 620px; overflow: auto; }
.feed-row { min-height: 52px; display: grid; grid-template-columns: 66px 3px minmax(0, 1fr) auto 54px; align-items: center; gap: 12px; padding: 9px 16px; border-bottom: 1px solid rgb(var(--border) / .55); }
.feed-row:last-child { border-bottom: 0; }
.feed-row:hover { background: rgb(var(--bg)); }
.feed-time { color: rgb(var(--text-mute)); font: 500 10.5px 'JetBrains Mono', ui-monospace, monospace; letter-spacing: .02em; }
.feed-status { align-self: stretch; border-radius: 0; background: rgb(var(--text-mute)); }
.status-真阳 { background: var(--ops-danger); }
.status-假阳 { background: var(--ops-success); }
.status-待查 { background: var(--ops-warning); }
.feed-main { min-width: 0; }
.feed-main > div { display: flex; align-items: center; gap: 10px; min-width: 0; }
.feed-main code { color: rgb(var(--cyan)); font: 700 11.5px 'JetBrains Mono', ui-monospace, monospace; white-space: nowrap; }
.feed-main span { overflow: hidden; color: rgb(var(--text)); font-size: 13px; font-weight: 500; text-overflow: ellipsis; white-space: nowrap; }
.feed-main small { display: block; margin-top: 4px; color: rgb(var(--text-mute)); font-size: 10.5px; }
.result-badge { min-width: 42px; padding: 4px 7px; border-radius: 0; text-align: center; font-size: 10.5px; font-weight: 600; border: 1px solid; }
.result-danger, .result-error { color: var(--ops-danger); border-color: rgb(var(--red) / .35); background: rgb(var(--red) / .06); }
.result-success { color: var(--ops-success); border-color: rgb(var(--green) / .35); background: rgb(var(--green) / .06); }
.result-warning { color: var(--ops-warning); border-color: rgb(var(--yellow) / .35); background: rgb(var(--yellow) / .06); }
.feed-confidence { color: rgb(var(--text-dim)); font: 600 11.5px 'JetBrains Mono', ui-monospace, monospace; text-align: right; }

.ops-empty { min-height: 180px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; color: rgb(var(--text-mute)); text-align: center; }
.ops-empty.compact { min-height: 110px; }
.ops-empty b { color: rgb(var(--text)); font-size: 14px; }
.ops-empty span { max-width: 380px; font-size: 12px; }
.empty-radar { position: relative; width: 44px; height: 44px; margin-bottom: 4px; border: 1px solid rgb(var(--border-light)); border-radius: 50%; }
.empty-radar::before, .empty-radar::after { content: ''; position: absolute; background: rgb(var(--border-light)); }
.empty-radar::before { top: 50%; left: 5px; right: 5px; height: 1px; }
.empty-radar::after { left: 50%; top: 5px; bottom: 5px; width: 1px; }
.empty-radar i { position: absolute; inset: 7px; border: 1px solid rgb(var(--border)); border-radius: 50%; }

@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .45; } }

@media (max-width: 1180px) {
  .ops-main { grid-template-columns: 1fr; }
}
@media (max-width: 1024px) {
  .ops-stat-rail { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .rail-cell:nth-child(3) { border-left: 0; }
  .rail-cell:nth-child(n + 3) { border-top: 1px solid var(--ops-line); }
}
@media (max-width: 640px) {
  .ops-command { align-items: flex-start; flex-direction: column; }
  .ops-command h2 { font-size: 26px; }
  .ops-command-tools { width: 100%; flex-direction: column; align-items: stretch; }
  .ops-live { width: 100%; }
  .ops-command-action { width: 100%; justify-content: center; }
  .ops-stat-rail { grid-template-columns: 1fr; }
  .rail-cell + .rail-cell { border-left: 0; border-top: 1px solid var(--ops-line); }
  .source-grid { grid-template-columns: 1fr; }
  .ops-panel-head > small { display: none; }
  .dist-copy small { display: none; }
  .feed-row { grid-template-columns: 3px minmax(0, 1fr) auto; }
  .feed-time, .feed-confidence { display: none; }
}
</style>
