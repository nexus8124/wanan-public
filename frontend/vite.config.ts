import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

// 端口固定写死（与 launcher.py 保持一致）。
// 不用环境变量：Windows 下 npm/vite 子进程传参不稳定。
const FRONTEND_PORT = 15173
const BACKEND_PORT = 18000

// 开发期：Vite dev server 把 /api 请求代理到 FastAPI
// 交付期：vite build → frontend/dist，由 FastAPI StaticFiles 挂载
export default defineConfig({
  // 生成相对路径，确保被 FastAPI 挂载时静态资源路径正确
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: FRONTEND_PORT,
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${BACKEND_PORT}`,
        changeOrigin: true,
        // SSE 流式接口需要禁用缓冲
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('Connection', 'keep-alive')
          })
        },
      },
    },
  },
  build: {
    outDir: 'dist',
  },
})
