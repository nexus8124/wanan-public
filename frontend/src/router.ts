import { createRouter, createWebHashHistory } from 'vue-router'

// 用 hash 路由：FastAPI 静态挂载时不需配 fallback，刷新不丢页面
const routes = [
  { path: '/', name: 'dashboard', component: () => import('./views/Dashboard.vue'), meta: { title: '数据大屏' } },
  { path: '/investigate', name: 'investigate', component: () => import('./views/Investigate.vue'), meta: { title: '告警研判' } },
  { path: '/evaluate', name: 'evaluate', component: () => import('./views/Evaluate.vue'), meta: { title: '批量评测' } },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

export default router
