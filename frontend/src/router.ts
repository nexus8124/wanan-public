import { createRouter, createWebHashHistory } from 'vue-router'

// 用 hash 路由：FastAPI 静态挂载时不需配 fallback，刷新不丢页面
const routes = [
  { path: '/', name: 'dashboard', component: () => import('./views/Dashboard.vue'), meta: { title: '数据大屏' } },
  { path: '/investigate', name: 'investigate', component: () => import('./views/Investigate.vue'), meta: { title: '告警研判' } },
  { path: '/evaluate', name: 'evaluate', component: () => import('./views/Evaluate.vue'), meta: { title: '模型评测' } },
  { path: '/models', name: 'modelSettings', component: () => import('./views/ModelSettings.vue'), meta: { title: '模型配置' } },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

// 导航后同步标签页标题,让浏览器历史/收藏带语义
const BASE_TITLE = 'XH-202614 · 安全智能体研判平台'
router.afterEach((to) => {
  const pageTitle = to.meta.title ? String(to.meta.title) : ''
  document.title = pageTitle ? `${pageTitle} · ${BASE_TITLE}` : BASE_TITLE
})

export default router
