#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XH-202614 一键启动脚本。

同时拉起后端 (FastAPI) + 前端 (Vite dev)，开发期用。
按 Ctrl+C 一次性停掉两个。

用法：
    python launcher.py            # 默认端口 18000 / 15173
    python launcher.py --no-build  # 跳过前端构建检查（更快）

端口选择（避开常用）：
    后端 18000   ← 避开 8000/8080/8888/9000/5000
    前端 15173   ← 避开 5173/3000/4200/8080

跨平台：Windows / macOS / Linux 通用。
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ============================================================
# 配置
# ============================================================

# 端口（选不常用的，避免和本地其他服务冲突）
BACKEND_PORT = 18000
FRONTEND_PORT = 15173

# 项目根目录（本脚本所在目录）
ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"
FRONTEND_DIR = ROOT / "frontend"


# ============================================================
# 工具函数
# ============================================================


def info(msg: str) -> None:
    print(f"\033[36m[i]\033[0m {msg}")


def ok(msg: str) -> None:
    print(f"\033[32m[+]\033[0m {msg}")


def warn(msg: str) -> None:
    print(f"\033[33m[!]\033[0m {msg}")


def err(msg: str) -> None:
    print(f"\033[31m[x]\033[0m {msg}", file=sys.stderr)


def is_windows() -> bool:
    return os.name == "nt"


def check_command(cmd: str) -> bool:
    """检查命令是否可用（PATH 中能找到）。"""
    from shutil import which
    return which(cmd) is not None


def port_in_use(port: int) -> bool:
    """检查端口是否被占用。"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ============================================================
# 启动前检查
# ============================================================


def preflight() -> bool:
    """启动前环境检查，失败返回 False。"""
    info("启动前环境检查...")

    # 1. 后端目录
    if not (BACKEND_DIR / "pyproject.toml").exists():
        err(f"后端目录不存在或缺少 pyproject.toml: {BACKEND_DIR}")
        return False

    # 2. 前端目录
    if not (FRONTEND_DIR / "package.json").exists():
        err(f"前端目录不存在或缺少 package.json: {FRONTEND_DIR}")
        return False

    # 3. uv 命令
    if not check_command("uv"):
        err("未找到 'uv' 命令。请先安装: https://docs.astral.sh/uv/")
        return False

    # 4. node / npm
    if not check_command("node") or not check_command("npm"):
        err("未找到 node/npm。请先安装 Node.js 18+: https://nodejs.org/")
        return False

    # 5. 前端依赖是否安装
    if not (FRONTEND_DIR / "node_modules").exists():
        warn("前端依赖未安装，正在执行 npm install...")
        try:
            subprocess.run(
                ["npm", "install"],
                cwd=FRONTEND_DIR,
                shell=is_windows(),
                check=True,
            )
            ok("前端依赖安装完成")
        except subprocess.CalledProcessError:
            err("npm install 失败")
            return False

    # 6. 端口冲突检查
    for port, name in [(BACKEND_PORT, "后端"), (FRONTEND_PORT, "前端")]:
        if port_in_use(port):
            err(
                f"端口 {port} 已被占用（{name}）。"
                f"请释放该端口或修改 launcher.py 顶部的端口配置。"
            )
            return False

    ok("环境检查通过")
    return True


# ============================================================
# 启动后端 / 前端
# ============================================================


def start_backend() -> subprocess.Popen:
    """启动 FastAPI 后端。

    host 用空字符串（监听所有接口，含 IPv4 + IPv6）。
    为什么不用 127.0.0.1：Node 18+ 的 vite proxy 走 happy-eyeballs 时
    会优先尝试 IPv6 ::1，若后端只绑 IPv4 会导致 ECONNREFUSED。
    监听所有接口可同时满足 IPv4/IPv6 客户端。
    """
    env = os.environ.copy()
    env["BACKEND_PORT"] = str(BACKEND_PORT)

    cmd = [
        "uv", "run", "uvicorn", "app.main:app",
        "--host", "0.0.0.0",   # 所有 IPv4 接口
        "--port", str(BACKEND_PORT),
        "--reload",  # 改后端代码自动重载
    ]
    info(f"启动后端: uvicorn --host 0.0.0.0 --port {BACKEND_PORT}")
    return subprocess.Popen(
        cmd,
        cwd=BACKEND_DIR,
        env=env,
        shell=is_windows(),
    )


def start_frontend() -> subprocess.Popen:
    """启动 Vite 前端 dev server。

    直接调本地 node_modules/.bin/vite，通过 --port 参数传端口。
    （不用 npm run dev，因为 Windows 下 npm 不稳定传递环境变量给 vite）
    """
    env = os.environ.copy()
    env["BACKEND_PORT"] = str(BACKEND_PORT)

    # 跨平台找到 vite 可执行文件
    bin_dir = FRONTEND_DIR / "node_modules" / ".bin"
    if is_windows():
        vite_cmd = str(bin_dir / "vite.cmd")
    else:
        vite_cmd = str(bin_dir / "vite")

    cmd = [
        vite_cmd,
        "--host", "127.0.0.1",   # 显式绑 IPv4，避免 localhost IPv6 问题
        "--port", str(FRONTEND_PORT),
        "--strictPort",
    ]
    info(f"启动前端: vite --host 127.0.0.1 --port {FRONTEND_PORT}")
    return subprocess.Popen(
        cmd,
        cwd=FRONTEND_DIR,
        env=env,
        shell=False,
    )


# ============================================================
# 健康检查
# ============================================================


def wait_for_backend(timeout: int = 30) -> bool:
    """等待后端 /health 接口可用。"""
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{BACKEND_PORT}/health", timeout=1
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


# ============================================================
# 主流程
# ============================================================


def main() -> int:
    print()
    print("  ╔════════════════════════════════════════════════════╗")
    print("  ║   XH-202614 安全智能体研判平台 · 一键启动         ║")
    print("  ╚════════════════════════════════════════════════════╝")
    print()

    if not preflight():
        return 1

    backend_proc = None
    frontend_proc = None

    # 注册信号处理：Ctrl+C 时把两个子进程都停掉
    def cleanup(*_):
        print()
        warn("正在停止所有服务...")
        for p, name in [(frontend_proc, "前端"), (backend_proc, "后端")]:
            if p and p.poll() is None:
                try:
                    if is_windows():
                        # Windows 下 kill 整个进程树
                        subprocess.run(
                            ["taskkill", "/PID", str(p.pid), "/F", "/T"],
                            capture_output=True,
                        )
                    else:
                        p.terminate()
                    info(f"已停止 {name} (PID {p.pid})")
                except Exception as e:
                    err(f"停止 {name} 失败: {e}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    if not is_windows():
        signal.signal(signal.SIGTERM, cleanup)

    # 启动后端
    backend_proc = start_backend()

    # 启动前端
    frontend_proc = start_frontend()

    # 等待后端就绪
    info(f"等待后端就绪 (http://127.0.0.1:{BACKEND_PORT}) ...")
    if wait_for_backend():
        ok(f"后端已就绪: http://127.0.0.1:{BACKEND_PORT}")
        ok(f"  API 文档:   http://127.0.0.1:{BACKEND_PORT}/docs")
    else:
        warn("后端 30 秒内未就绪，请检查上面的日志")

    print()
    print("  ┌──────────────────────────────────────────────────────┐")
    print("  │  🚀 打开浏览器访问前端：                            │")
    print(f"  │     http://127.0.0.1:{FRONTEND_PORT}                     │")
    print("  │                                                      │")
    print(f"  │  🔌 后端 API:     http://127.0.0.1:{BACKEND_PORT}           │")
    print(f"  │     Swagger 文档: http://127.0.0.1:{BACKEND_PORT}/docs      │")
    print("  │                                                      │")
    print("  │  📊 三个页面：                                        │")
    print("  │     /            数据大屏                            │")
    print("  │     /investigate 告警研判（核心，SSE 流式实时思考）  │")
    print("  │     /evaluate    批量评测（准确率/混淆矩阵）         │")
    print("  │                                                      │")
    print("  │  ⏹  按 Ctrl+C 停止所有服务                          │")
    print("  └──────────────────────────────────────────────────────┘")
    print()

    # 主循环：等待任一子进程退出
    try:
        while True:
            if backend_proc.poll() is not None:
                err("后端进程意外退出")
                break
            if frontend_proc.poll() is not None:
                err("前端进程意外退出")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
