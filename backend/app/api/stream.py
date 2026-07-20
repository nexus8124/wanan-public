"""SSE 流式研判接口。

把 LangGraph 的 graph.stream(stream_mode="updates") 转成 Server-Sent Events，
让前端能实时看到 Agent 每一步（judge → react_decide → tool_executor → disposition）。

赛题贴合：挑战任务"展示完整的思维链推理过程"——评委看到 Agent 实时思考过程。
"""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncGenerator

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from app.agent.graph import build_graph
from app.core.config import get_settings
from app.models.llm import get_llm
from app.models.schemas import Alert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["stream"])


def _safe_json(obj: Any) -> str:
    """序列化任意对象为 JSON，处理 datetime 等不可序列化类型。"""
    return json.dumps(obj, ensure_ascii=False, default=str)


async def _stream_graph(alert_dict: dict, use_mock: bool) -> AsyncGenerator[dict, None]:
    """把 LangGraph 同步 stream 包成 async generator（供 SSE）。"""
    import asyncio

    graph = build_graph(llm=get_llm(mock=use_mock))
    config = {"recursion_limit": 25}

    # 在线程池里跑同步 stream，避免阻塞事件循环
    queue: asyncio.Queue = asyncio.Queue()

    def _producer():
        try:
            for event in graph.stream(
                {"alert": alert_dict}, config=config, stream_mode="updates"
            ):
                queue.put_nowait(event)
        except Exception as e:
            queue.put_nowait({"__error__": str(e)})
        finally:
            queue.put_nowait(None)  # 结束信号

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _producer)

    sent_count = 0
    while True:
        item = await queue.get()
        if item is None:
            break
        if isinstance(item, dict) and "__error__" in item:
            yield {"event": "error", "data": _safe_json({"message": item["__error__"]})}
            break
        # 每个 event 是 {node_name: state_update}
        for node_name, update in item.items():
            if not isinstance(update, dict):
                continue
            sent_count += 1
            # 推一个 SSE 事件：event=node名, data=该节点产出的 state 更新
            payload = {
                "step": sent_count,
                "node": node_name,
                "update": update,
            }
            yield {"event": node_name, "data": _safe_json(payload)}

    # 完成信号
    yield {"event": "done", "data": _safe_json({"total_steps": sent_count})}


@router.post("/judge/stream")
async def judge_stream(alert: Alert):
    """SSE 流式研判接口。

    入参：Alert（与同步接口相同）
    返回：text/event-stream，每个节点完成推送一个事件：
        event: preprocess  data: {step, node, update}
        event: judge       data: {...}
        event: react_decide data: {...}    （可能多次）
        event: tool_executor data: {...}   （可能多次）
        event: disposition data: {...}
        event: output      data: {...}
        event: done        data: {total_steps}
        event: error       data: {message}  （出错时）
    """
    settings = get_settings()
    use_mock = not settings.deepseek_api_key
    if use_mock:
        logger.warning("DEEPSEEK_API_KEY 未配置，流式研判降级到 mock")

    # 隐藏 label，避免泄露给 Agent
    alert_dict = alert.model_dump(mode="json")
    alert_dict.pop("label", None)

    return EventSourceResponse(_stream_graph(alert_dict, use_mock))
