"""FastAPI 应用入口。

赛题贴合：方案 B7，"确保可正常运行"。
路由：
    GET  /health               健康检查
    GET  /                     根信息
    POST /api/alerts/judge     同步研判单条告警
    POST /api/alerts/judge/stream  SSE 流式研判（评委可见实时思考）
    GET  /api/alerts/sample    取一条示例告警
    GET  /api/stats            数据大屏统计
    POST /api/eval/run         触发评测
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.alerts import router as alerts_router
from app.api.rag import router as rag_router
from app.api.stats import router as stats_router
from app.api.stream import router as stream_router
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.eval.history import mark_stale_runs_interrupted

# 启动时配置日志
setup_logging(level="INFO")
mark_stale_runs_interrupted()

settings = get_settings()

app = FastAPI(
    title="XH-202614 Security Agent",
    description="AI+安全大模型平台的智能体研究 · 告警误报剔除 Agent",
    version="0.1.0",
)

# 开发期 CORS：允许 Vite dev server (5173) 跨域访问后端 (8000)
# 交付期前端构建后挂载在同源，CORS 不再生效但保留无害
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载路由
app.include_router(alerts_router)
app.include_router(stream_router)
app.include_router(stats_router)
app.include_router(rag_router)


@app.get("/health")
def health() -> dict[str, str]:
    """健康检查端点。"""
    return {
        "status": "ok",
        "service": "xh-202614-security-agent",
        "env": settings.app_env,
        "llm_provider": settings.llm_provider,
    }


@app.get("/api")
def api_root() -> dict[str, str]:
    """API 根信息（不和静态前端 / 冲突）。"""
    return {
        "name": "XH-202614 Security Agent API",
        "docs": "/docs",
        "health": "/health",
        "judge": "POST /api/alerts/judge",
        "judge_stream": "POST /api/alerts/judge/stream",
    }


# ============================================================
# 交付期：挂载前端静态文件（Vite build 产物）
# 必须放在所有 API 路由注册之后，避免吞掉 /api/* 请求
# ============================================================

_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _FRONTEND_DIST.exists():
    from fastapi import Request
    from fastapi.responses import FileResponse

    # 静态资源（assets/、图片等）
    app.mount(
        "/assets",
        StaticFiles(directory=_FRONTEND_DIST / "assets"),
        name="assets",
    )

    # SPA fallback：所有非 /api、非 /assets 的 GET 请求都返回 index.html
    # 这样评委直接访问 /investigate 也能进（hash 路由主要用，但保留兼容）
    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str, request: Request):
        # 静态文件优先（如 favicon）
        candidate = _FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        # 否则返回 index.html（SPA 入口）
        return FileResponse(_FRONTEND_DIST / "index.html")
