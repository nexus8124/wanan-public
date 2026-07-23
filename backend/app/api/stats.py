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
from collections import Counter
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

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stats"])


class DatasetSelection(BaseModel):
    dataset_id: str


@router.get("/stats")
def get_stats() -> dict:
    """数据大屏统计接口。

    返回数据集的聚合统计：
        - total / by_label (真阳/假阳/待查)
        - by_source (edr/ids/waf/siem/ndr)
        - by_severity (high/medium/low/info)
        - attack_types (从 raw_payload.attck 聚合)
    """
    # 优先用 eval 数据集（50 条），不存在则用 sample（10 条）
    path = resolve_eval_dataset_path()
    try:
        dataset = load_eval_dataset(path)
        alerts = [sample.alert for sample in dataset.samples]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"load dataset failed: {e}")

    by_label = Counter(sample.label for sample in dataset.samples)
    by_source = Counter(a.source for a in alerts)
    by_severity = Counter(a.severity for a in alerts)

    # ATT&CK 战术聚合（从 raw_payload.attck 抽取）
    attack_types: list[dict] = []
    attck_counter: Counter = Counter()
    for a in alerts:
        attck = (a.raw_payload or {}).get("attck", [])
        if isinstance(attck, list):
            for tid in attck:
                attck_counter[tid] += 1
    # 把出现频次最高的战术排前面
    attack_types = [{"id": tid, "count": cnt} for tid, cnt in attck_counter.most_common(15)]

    return {
        "dataset": str(path.name),
        "total": len(alerts),
        "by_label": dict(by_label),
        "by_source": dict(by_source),
        "by_severity": dict(by_severity),
        "attack_types": attack_types,
    }


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
    mock: bool = True,
    limit: int | None = None,
    strategy: str = "judge_only",
) -> dict:
    """触发评测（给评测页用）。

    默认 mock=True（不耗 token，验证链路）。
    真实评测需要前端显式传 mock=false（会产生 token 费用）。
    """
    # 延迟导入，避免 main.py 启动时拉起整个评测模块
    from app.eval.run import run_eval

    if strategy not in {"judge_only", "react"}:
        raise HTTPException(status_code=422, detail="invalid eval strategy")
    try:
        result = run_eval(
            dataset_path=None,
            mock=mock,
            save_results=False,
            max_samples=limit,
            strategy=strategy,  # type: ignore[arg-type]
        )
        return result
    except Exception as e:
        logger.exception("eval run failed: %s", e)
        raise HTTPException(status_code=500, detail=f"eval failed: {e}")


async def _stream_eval(
    mock: bool,
    limit: int | None = None,
    strategy: str = "judge_only",
) -> AsyncGenerator[dict, None]:
    """在线程池运行同步评测，并把逐样本进度转换成 SSE。"""
    from app.eval.history import create_run, finish_run, save_event, save_progress
    from app.eval.run import run_eval

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[tuple[str, dict] | None] = asyncio.Queue()
    stop_event = threading.Event()
    dataset_path = resolve_eval_dataset_path()
    loaded_dataset = load_eval_dataset(dataset_path)
    if limit is not None and limit < 1:
        raise HTTPException(status_code=422, detail="limit must be at least 1")
    if strategy not in {"judge_only", "react"}:
        raise HTTPException(status_code=422, detail="invalid eval strategy")
    total = min(limit, len(loaded_dataset.samples)) if limit else len(loaded_dataset.samples)
    dataset_id = dataset_id_for_path(dataset_path)
    mode = "mock" if mock else get_settings().llm_provider
    run_id = create_run(
        mode=mode, strategy=strategy, dataset=str(dataset_path), total=total
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
                    "mock": mock,
                    "mode": mode,
                    "strategy": strategy,
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
                mock=mock,
                save_results=False,
                progress_callback=handle_progress,
                agent_event_callback=handle_agent_event,
                should_stop=stop_event.is_set,
                max_samples=limit,
                strategy=strategy,  # type: ignore[arg-type]
            )
            was_stopped = stop_event.is_set()
            finish_run(
                run_id,
                status="interrupted" if was_stopped else "completed",
                metrics=result.get("metrics"),
                initial_metrics=result.get("initial_metrics"),
                paired_react=result.get("paired_react"),
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
    mock: bool = True,
    limit: int | None = None,
    strategy: str = "judge_only",
) -> EventSourceResponse:
    """流式评测：逐条推送进度，完成后返回最终指标和全部明细。"""
    return EventSourceResponse(_stream_eval(mock, limit, strategy))


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
