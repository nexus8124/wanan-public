import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';
// 开发期：Vite dev server (5173) 把 /api 请求代理到 FastAPI (8000)
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
        port: 5173,
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
            },
        },
    },
    build: {
        outDir: 'dist',
    },
});
