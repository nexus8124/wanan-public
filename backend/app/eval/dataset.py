"""Evaluation dataset loading with ground truth kept outside Agent input."""

from __future__ import annotations

import json
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.core.config import PROJECT_ROOT, get_settings
from app.data.generator import EVAL_DATASET
from app.data.loader import DEFAULT_DATASET
from app.models.schemas import Alert


EvalLabel = Literal["真阳", "假阳"]

DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATASET_DIR = DATA_DIR / "processed"
UPLOADED_DATASET_DIR = DATA_DIR / "uploaded"
DATASET_SELECTION_FILE = DATA_DIR / "active_eval_dataset.json"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
_SELECTION_LOCK = threading.Lock()
_SAFE_FILENAME = re.compile(r"[^0-9A-Za-z._-]+")


@dataclass(frozen=True)
class EvalSample:
    alert: Alert
    label: EvalLabel
    truth_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LoadedEvalDataset:
    path: Path
    samples: list[EvalSample]
    metadata: dict[str, Any] = field(default_factory=dict)


def _path_from_dataset_id(dataset_id: str) -> Path | None:
    builtins = {
        "builtin:eval": EVAL_DATASET,
        "builtin:sample": DEFAULT_DATASET,
    }
    if dataset_id in builtins:
        return builtins[dataset_id].resolve()
    for prefix, directory in (
        ("processed:", PROCESSED_DATASET_DIR),
        ("uploaded:", UPLOADED_DATASET_DIR),
    ):
        if dataset_id.startswith(prefix):
            filename = dataset_id[len(prefix):]
            if not filename or Path(filename).name != filename or not filename.endswith(".json"):
                return None
            candidate = (directory / filename).resolve()
            if candidate.parent != directory.resolve():
                return None
            return candidate
    return None


def _read_selected_dataset_id() -> str | None:
    try:
        data = json.loads(DATASET_SELECTION_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    value = data.get("dataset_id") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def resolve_eval_dataset_path(path: str | Path | None = None) -> Path:
    """Resolve explicit, configured, or built-in evaluation dataset path."""
    if path:
        return Path(path).expanduser().resolve()

    selected_id = _read_selected_dataset_id()
    if selected_id:
        selected_path = _path_from_dataset_id(selected_id)
        if selected_path and selected_path.exists():
            return selected_path

    configured = get_settings().eval_dataset_path.strip()
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            configured_path = PROJECT_ROOT / configured_path
        return configured_path.resolve()

    return EVAL_DATASET if EVAL_DATASET.exists() else DEFAULT_DATASET


def _parse_truth_entry(alert_id: str, entry: Any) -> tuple[EvalLabel, dict[str, Any]]:
    if isinstance(entry, str):
        label = entry
        metadata: dict[str, Any] = {}
    elif isinstance(entry, dict):
        label = entry.get("label")
        metadata = {key: value for key, value in entry.items() if key != "label"}
    else:
        raise ValueError(f"ground_truth[{alert_id!r}] must be a string or object")

    if label not in {"真阳", "假阳"}:
        raise ValueError(f"ground_truth[{alert_id!r}] has unsupported label: {label!r}")
    return label, metadata  # type: ignore[return-value]


def load_eval_dataset(path: str | Path | None = None) -> LoadedEvalDataset:
    """Load legacy embedded labels or the leakage-safe separated format.

    Preferred format::

        {
          "metadata": {...},
          "alerts": [{... no label ...}],
          "ground_truth": {"alert-uuid": {"label": "真阳", ...}}
        }

    The ground-truth object is never copied into ``Alert`` or passed to the Agent.
    """
    dataset_path = resolve_eval_dataset_path(path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    with dataset_path.open(encoding="utf-8") as dataset_file:
        data = json.load(dataset_file)

    metadata: dict[str, Any] = {}
    samples: list[EvalSample] = []

    if isinstance(data, dict) and "ground_truth" in data:
        alerts_data = data.get("alerts")
        truth = data.get("ground_truth")
        if not isinstance(alerts_data, list) or not isinstance(truth, dict):
            raise ValueError("Separated dataset requires list 'alerts' and object 'ground_truth'")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}

        seen_ids: set[str] = set()
        for item in alerts_data:
            alert = Alert.model_validate(item)
            if alert.label is not None:
                raise ValueError(
                    f"Alert {alert.alert_id!r} embeds a label in a separated dataset"
                )
            if alert.alert_id in seen_ids:
                raise ValueError(f"Duplicate alert_id: {alert.alert_id}")
            seen_ids.add(alert.alert_id)
            if alert.alert_id not in truth:
                raise ValueError(f"Missing ground truth for alert: {alert.alert_id}")
            label, truth_metadata = _parse_truth_entry(alert.alert_id, truth[alert.alert_id])
            samples.append(EvalSample(alert, label, truth_metadata))

        orphan_truth = set(truth) - seen_ids
        if orphan_truth:
            example = sorted(orphan_truth)[0]
            raise ValueError(f"Ground truth references missing alert: {example}")
    else:
        alerts_data = data.get("alerts") if isinstance(data, dict) else data
        if not isinstance(alerts_data, list):
            raise ValueError("Dataset must be a list or contain an 'alerts' list")
        if isinstance(data, dict) and isinstance(data.get("metadata"), dict):
            metadata = data["metadata"]
        metadata = {"label_storage": "legacy_embedded", **metadata}
        for item in alerts_data:
            alert = Alert.model_validate(item)
            if alert.label in {"真阳", "假阳"}:
                label: EvalLabel = alert.label
                clean = alert.model_dump(mode="python")
                clean.pop("label", None)
                samples.append(EvalSample(Alert.model_validate(clean), label))

    return LoadedEvalDataset(dataset_path, samples, metadata)


def dataset_id_for_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    if resolved == EVAL_DATASET.resolve():
        return "builtin:eval"
    if resolved == DEFAULT_DATASET.resolve():
        return "builtin:sample"
    for prefix, directory in (
        ("processed", PROCESSED_DATASET_DIR),
        ("uploaded", UPLOADED_DATASET_DIR),
    ):
        try:
            relative = resolved.relative_to(directory.resolve())
        except ValueError:
            continue
        if len(relative.parts) == 1:
            return f"{prefix}:{relative.name}"
    return f"configured:{resolved.name}"


def describe_eval_dataset(path: str | Path) -> dict[str, Any]:
    dataset = load_eval_dataset(path)
    labels = Counter(sample.label for sample in dataset.samples)
    sources = Counter(sample.alert.source for sample in dataset.samples)
    metadata = dataset.metadata
    return {
        "id": dataset_id_for_path(dataset.path),
        "name": str(metadata.get("name") or dataset.path.stem),
        "filename": dataset.path.name,
        "count": len(dataset.samples),
        "labels": dict(labels),
        "sources": dict(sources),
        "label_storage": metadata.get("label_storage", "legacy_embedded"),
        "label_basis": metadata.get("label_basis", "embedded_label"),
        "label_warning": metadata.get("label_warning"),
        "source": metadata.get("source"),
    }


def list_eval_datasets() -> dict[str, Any]:
    """List valid built-in, generated, and uploaded evaluation datasets."""
    paths: list[Path] = [EVAL_DATASET, DEFAULT_DATASET]
    for directory in (PROCESSED_DATASET_DIR, UPLOADED_DATASET_DIR):
        if directory.exists():
            paths.extend(sorted(directory.glob("*.json")))

    active_path = resolve_eval_dataset_path()
    if active_path.exists() and active_path not in paths:
        paths.append(active_path)

    descriptors: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        try:
            descriptors.append(describe_eval_dataset(resolved))
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            errors.append({"filename": path.name, "error": str(exc)})

    active_id = dataset_id_for_path(active_path)
    for descriptor in descriptors:
        descriptor["active"] = descriptor["id"] == active_id
    return {"datasets": descriptors, "active_id": active_id, "errors": errors}


def select_eval_dataset(dataset_id: str) -> dict[str, Any]:
    path = _path_from_dataset_id(dataset_id)
    if path is None or not path.exists():
        raise ValueError(f"Unknown evaluation dataset: {dataset_id}")
    descriptor = describe_eval_dataset(path)
    if descriptor["count"] < 1:
        raise ValueError("Evaluation dataset contains no labeled samples")

    with _SELECTION_LOCK:
        DATASET_SELECTION_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = DATASET_SELECTION_FILE.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"dataset_id": dataset_id}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(DATASET_SELECTION_FILE)
    descriptor["active"] = True
    return descriptor


def safe_upload_filename(original_name: str, digest: str) -> str:
    base = Path(original_name).name
    if not base.lower().endswith(".json"):
        raise ValueError("Only .json evaluation datasets are supported")
    stem = _SAFE_FILENAME.sub("-", Path(base).stem).strip("-._") or "dataset"
    return f"{stem[:60]}-{digest[:10]}.json"
