"""数据大屏统计 + 评测接口。

stats 接口聚合数据集统计（给首页大屏用）；
eval 接口复用 run.py 逻辑给评测页用。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from app.data.loader import DEFAULT_DATASET, load_alerts
from app.core.config import get_settings
from app.eval.dataset import (
    MAX_UPLOAD_BYTES,
    UPLOADED_DATASET_DIR,
    dataset_id_for_path,
    describe_eval_dataset,
    list_eval_datasets,
    load_eval_dataset,
    resolve_eval_dataset_path,
    safe_upload_filename,
    select_eval_dataset,
)
from app.models.llm import get_model_catalog
from app.operations import get_operations_snapshot, get_response_audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/models")
def get_models() -> dict:
    """Return selectable model metadata and key availability, never secrets."""
    return {"providers": get_model_catalog()}


class DatasetSelection(BaseModel):
    dataset_id: str


@router.get("/stats")
def get_stats() -> dict:
    """Return the latest deduplicated operational judgment statistics."""
    return get_operations_snapshot()


@router.get("/response/audit")
def response_audit(limit: int = 100) -> dict:
    """Return the persisted execute/verify/retry/rollback audit trail."""
    return get_response_audit(limit=limit)


async def _stream_stats(request: Request) -> AsyncGenerator[dict, None]:
    """Push a fresh dashboard snapshot whenever persisted judgments change."""
    last_revision: str | None = None
    while not await request.is_disconnected():
        try:
            snapshot = get_operations_snapshot()
            if snapshot["revision"] != last_revision:
                last_revision = snapshot["revision"]
                yield {
                    "event": "stats",
                    "data": json.dumps(snapshot, ensure_ascii=False, default=str),
                }
        except Exception as exc:
            logger.exception("operational stats stream failed: %s", exc)
            yield {
                "event": "error",
                "data": json.dumps(
                    {"message": "运营统计暂时不可用"}, ensure_ascii=False
                ),
            }
        await asyncio.sleep(1.5)


@router.get("/stats/stream")
async def stream_stats(request: Request) -> EventSourceResponse:
    """SSE stream used by the overview for near-real-time updates."""
    return EventSourceResponse(_stream_stats(request), ping=15)


@router.get("/samples")
def list_samples() -> dict:
    """返回示例告警列表（给前端"加载示例"用）。

    从 sample_alerts.json 取前 8 条（覆盖不同类型），去掉 label。
    """
    alerts = load_alerts(DEFAULT_DATASET)
    samples = []
    for a in alerts[:8]:
        d = a.model_dump(mode="json")
        d.pop("label", None)
        samples.append(d)
    return {"samples": samples, "count": len(samples)}


@router.post("/eval/run")
def run_eval_endpoint(
    request: Request,
    limit: int | None = None,
    strategy: str = "judge_only",
    rag: bool = False,
    provider: str | None = None,
    model: str | None = None,
) -> dict:
    """触发真实模型评测（会产生模型调用费用）。"""
    if "mock" in request.query_params:
        raise HTTPException(
            status_code=410,
            detail="Mock evaluation has been removed; refresh the frontend",
        )
    # 延迟导入，避免 main.py 启动时拉起整个评测模块
    from app.eval.run import run_eval

    if strategy not in {"judge_only", "react", "multi_agent"}:
        raise HTTPException(status_code=422, detail="invalid eval strategy")
    try:
        result = run_eval(
            dataset_path=None,
            save_results=False,
            max_samples=limit,
            strategy=strategy,  # type: ignore[arg-type]
            enable_rag=rag,
            provider=provider,
            model=model,
        )
        return result
    except Exception as e:
        logger.exception("eval run failed: %s", e)
        raise HTTPException(status_code=500, detail=f"eval failed: {e}")


async def _stream_eval(
    limit: int | None = None,
    strategy: str = "judge_only",
    rag: bool = False,
    provider: str | None = None,
    model: str | None = None,
    dataset_path_override: Path | None = None,
    run_id_override: str | None = None,
    initial_details: list[dict] | None = None,
) -> AsyncGenerator[dict, None]:
    """在线程池运行同步评测，并把逐样本进度转换成 SSE。"""
    from app.eval.history import create_run, finish_run, save_event, save_progress
    from app.eval.run import run_eval

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[tuple[str, dict] | None] = asyncio.Queue()
    stop_event = threading.Event()
    dataset_path = dataset_path_override or resolve_eval_dataset_path()
    loaded_dataset = load_eval_dataset(dataset_path)
    if limit is not None and limit < 1:
        raise HTTPException(status_code=422, detail="limit must be at least 1")
    if strategy not in {"judge_only", "react", "multi_agent"}:
        raise HTTPException(status_code=422, detail="invalid eval strategy")
    total = min(limit, len(loaded_dataset.samples)) if limit else len(loaded_dataset.samples)
    dataset_id = dataset_id_for_path(dataset_path)
    settings = get_settings()
    effective_provider = provider or settings.llm_provider
    mode = effective_provider
    initial_config = {
        "strategy": strategy,
        "rag_enabled": rag,
        "tools_enabled": strategy in {"react", "multi_agent"},
        "multi_agent_enabled": strategy == "multi_agent",
        "provider": effective_provider,
        "model": model,
        "requested_max_samples": limit,
    }
    run_id = run_id_override or create_run(
        mode=mode,
        strategy=strategy,
        dataset=str(dataset_path),
        total=total,
        experiment_config=initial_config,
    )

    def put_event(event: str, data: dict) -> None:
        # progress_callback 在工作线程中触发，必须线程安全地投递到事件循环。
        loop.call_soon_threadsafe(queue.put_nowait, (event, data))

    def producer() -> None:
        try:
            put_event(
                "start",
                {
                    "run_id": run_id,
                    "mode": mode,
                    "strategy": strategy,
                    "rag": rag,
                    "provider": effective_provider,
                    "model": model,
                    "resumed": run_id_override is not None,
                    "completed": len(initial_details or []),
                    "total": total,
                    "dataset_id": dataset_id,
                    "dataset": str(dataset_path),
                    "dataset_metadata": loaded_dataset.metadata,
                },
            )

            def handle_progress(data: dict) -> None:
                save_progress(run_id, data)
                put_event("progress", {**data, "run_id": run_id})

            def handle_agent_event(data: dict) -> None:
                event_seq = save_event(run_id, data)
                put_event(
                    "agent_event",
                    {**data, "run_id": run_id, "event_seq": event_seq},
                )

            result = run_eval(
                dataset_path=dataset_path,
                save_results=False,
                progress_callback=handle_progress,
                agent_event_callback=handle_agent_event,
                should_stop=stop_event.is_set,
                max_samples=limit,
                strategy=strategy,  # type: ignore[arg-type]
                enable_rag=rag,
                provider=provider,
                model=model,
                initial_details=initial_details,
            )
            was_stopped = stop_event.is_set()
            finish_run(
                run_id,
                status="interrupted" if was_stopped else "completed",
                metrics=result.get("metrics"),
                initial_metrics=result.get("initial_metrics"),
                paired_react=result.get("paired_react"),
                paired_multi_agent=result.get("paired_multi_agent"),
                paired_rag=result.get("paired_rag"),
                experiment_config=result.get("experiment_config"),
                error="用户中止或浏览器连接断开" if was_stopped else None,
            )
            if not was_stopped:
                put_event("complete", {**result, "run_id": run_id})
        except Exception as e:
            logger.exception("stream eval failed: %s", e)
            finish_run(run_id, status="failed", error=str(e))
            put_event("error", {"run_id": run_id, "message": f"eval failed: {e}"})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    loop.run_in_executor(None, producer)

    try:
        while True:
            item = await queue.get()
            if item is None:
                break
            event, data = item
            yield {
                "event": event,
                "data": json.dumps(data, ensure_ascii=False, default=str),
            }
    finally:
        # 浏览器中止或断开后，不再启动下一条样本；正在进行的模型请求会自然结束。
        stop_event.set()


@router.post("/eval/run/stream")
async def run_eval_stream_endpoint(
    request: Request,
    limit: int | None = None,
    strategy: str = "judge_only",
    rag: bool = False,
    provider: str | None = None,
    model: str | None = None,
) -> EventSourceResponse:
    """流式评测：逐条推送进度，完成后返回最终指标和全部明细。"""
    if "mock" in request.query_params:
        raise HTTPException(
            status_code=410,
            detail="Mock evaluation has been removed; refresh the frontend",
        )
    return EventSourceResponse(
        _stream_eval(limit, strategy, rag, provider, model)
    )


@router.post("/eval/history/{run_id}/resume")
async def resume_eval_history(run_id: str) -> EventSourceResponse:
    """Resume an interrupted run from its persisted deterministic prefix."""
    from app.eval.history import get_run, reopen_run

    saved = get_run(run_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="eval history not found")
    if saved["status"] == "running":
        raise HTTPException(status_code=409, detail="evaluation is already running")
    if saved["status"] == "completed" or saved["completed"] >= saved["total"]:
        raise HTTPException(status_code=409, detail="evaluation is already complete")

    config = saved.get("experiment_config") or {}
    if not config and not saved.get("details"):
        raise HTTPException(
            status_code=409,
            detail="run has no persisted experiment configuration; start a new run",
        )
    dataset_path = Path(saved["dataset"])
    if not dataset_path.exists():
        raise HTTPException(status_code=409, detail="original evaluation dataset is missing")
    if saved["mode"] == "mock" or config.get("provider") == "mock":
        raise HTTPException(
            status_code=409,
            detail="legacy mock evaluations can no longer be resumed",
        )

    state = reopen_run(run_id)
    if state != "resumed":
        raise HTTPException(status_code=409, detail=f"cannot resume run: {state}")

    provider = config.get("provider") or saved["mode"]
    model = config.get("model")
    return EventSourceResponse(
        _stream_eval(
            limit=int(saved["total"]),
            strategy=saved["strategy"],
            rag=bool(config.get("rag_enabled", False)),
            provider=provider,
            model=model,
            dataset_path_override=dataset_path,
            run_id_override=run_id,
            initial_details=saved.get("details") or [],
        )
    )


@router.get("/eval/datasets")
def get_eval_datasets() -> dict:
    """列出内置、适配器生成和用户上传的有效评测数据集。"""
    return list_eval_datasets()


@router.post("/eval/datasets/select")
def choose_eval_dataset(selection: DatasetSelection) -> dict:
    """切换后续统计与评测使用的数据集，并把选择持久化到本机。"""
    try:
        dataset = select_eval_dataset(selection.dataset_id)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"dataset": dataset}


@router.post("/eval/datasets/upload")
async def upload_eval_dataset(request: Request, filename: str) -> dict:
    """上传标准评测 JSON；请求体直接发送文件内容，不接收原始 AIT JSONL。"""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Dataset exceeds 25 MiB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    content_buffer = bytearray()
    async for chunk in request.stream():
        if len(content_buffer) + len(chunk) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Dataset exceeds 25 MiB limit")
        content_buffer.extend(chunk)
    content = bytes(content_buffer)
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded dataset is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Dataset exceeds 25 MiB limit")

    digest = hashlib.sha256(content).hexdigest()
    try:
        stored_name = safe_upload_filename(filename, digest)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    UPLOADED_DATASET_DIR.mkdir(parents=True, exist_ok=True)
    target = UPLOADED_DATASET_DIR / stored_name
    created = not target.exists()
    if created:
        target.write_bytes(content)

    try:
        descriptor = describe_eval_dataset(target)
        if descriptor["count"] < 1:
            raise ValueError("Dataset contains no labeled samples")
        descriptor = select_eval_dataset(f"uploaded:{stored_name}")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        if created:
            target.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid evaluation dataset: {exc}") from exc

    return {"dataset": descriptor, "sha256": digest, "created": created}


@router.get("/eval/history")
def list_eval_history(limit: int = 50) -> dict:
    """列出最近的评测历史，包括完成、中断和失败记录。"""
    from app.eval.history import list_runs

    runs = list_runs(limit=limit)
    return {"runs": runs, "count": len(runs)}


@router.get("/eval/history/{run_id}")
def get_eval_history(run_id: str) -> dict:
    """读取一次历史评测及其中已持久化的全部样本流程。"""
    from app.eval.history import get_run

    result = get_run(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="eval history not found")
    return result


@router.delete("/eval/history/{run_id}")
def delete_eval_history(run_id: str) -> dict:
    """删除已结束的历史评测；运行中的评测不可删除。"""
    from app.eval.history import delete_run

    status = delete_run(run_id)
    if status == "not_found":
        raise HTTPException(status_code=404, detail="eval history not found")
    if status == "running":
        raise HTTPException(status_code=409, detail="running eval cannot be deleted")
    return {"deleted": True, "run_id": run_id}
