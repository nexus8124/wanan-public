"""Reproducible downloads and local preparation for evaluation/RAG corpora.

Raw archives and generated indexes live under ``data/raw`` and ``data/processed``;
both are ignored by Git. The committed catalog is the provenance record, while
the checksum check prevents a partial or silently changed download from entering
an evaluation run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from app.core.config import PROJECT_ROOT


CATALOG_PATH = Path(__file__).with_name("source_catalog.json")


def load_catalog() -> dict[str, dict[str, Any]]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _inside_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    root = PROJECT_ROOT.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"catalog path escapes project root: {path}")
    return resolved


def _artifact_path(artifact: dict[str, Any]) -> Path:
    return _inside_root(PROJECT_ROOT / artifact["path"])


def _checksum(path: Path, specification: str) -> str:
    algorithm, expected = specification.split(":", 1)
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest().lower()
    if actual != expected.lower():
        raise ValueError(f"checksum mismatch for {path.name}: {actual} != {expected}")
    return f"{algorithm}:{actual}"


def verify_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    path = _artifact_path(artifact)
    if not path.exists():
        return {"name": artifact["name"], "path": str(path), "present": False}
    if artifact.get("size") is not None and path.stat().st_size != artifact["size"]:
        return {
            "name": artifact["name"],
            "path": str(path),
            "present": False,
            "error": f"size {path.stat().st_size} != {artifact['size']}",
        }
    try:
        checksum = _checksum(path, artifact["checksum"])
    except (OSError, ValueError) as exc:
        return {"name": artifact["name"], "path": str(path), "present": False, "error": str(exc)}
    result: dict[str, Any] = {
        "name": artifact["name"],
        "path": str(path),
        "present": True,
        "checksum": checksum,
    }
    if artifact.get("content_checksum") and artifact.get("content_path"):
        content_path = _inside_root(PROJECT_ROOT / artifact["content_path"])
        if content_path.exists():
            try:
                result["content_checksum"] = _checksum(
                    content_path, artifact["content_checksum"]
                )
            except (OSError, ValueError) as exc:
                result["present"] = False
                result["error"] = str(exc)
    return result


def _verify_content_artifact(artifact: dict[str, Any]) -> str | None:
    if not artifact.get("content_checksum") or not artifact.get("content_path"):
        return None
    return _checksum(
        _inside_root(PROJECT_ROOT / artifact["content_path"]),
        artifact["content_checksum"],
    )


def _download(artifact: dict[str, Any], *, force: bool = False) -> Path:
    path = _artifact_path(artifact)
    current = verify_artifact(artifact)
    if current.get("present") and not force:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    if partial.exists():
        partial.unlink()
    request = urllib.request.Request(
        artifact["url"], headers={"User-Agent": "wanan-public-data-catalog/1"}
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            _checksum(partial, artifact["checksum"])
            os.replace(partial, path)
            return path
        except Exception as exc:  # pragma: no cover - network failures are environment-specific
            last_error = exc
            if partial.exists():
                partial.unlink()
            if attempt < 2:
                time.sleep(2**attempt)
    raise RuntimeError(f"download failed for {artifact['name']}: {last_error}")


def _safe_extract(archive: Path, target: Path, *, force: bool = False) -> Path:
    if target.exists() and any(target.iterdir()) and not force:
        return target
    if target.exists() and force:
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            destination = (target / member.filename).resolve()
            if destination != root and root not in destination.parents:
                raise ValueError(f"unsafe archive member: {member.filename}")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    return target


def fetch_source(source_id: str, *, force: bool = False) -> dict[str, Any]:
    catalog = load_catalog()
    if source_id not in catalog:
        raise ValueError(f"unknown source: {source_id}")
    source = catalog[source_id]
    artifacts = []
    for artifact in source.get("artifacts", []):
        path = _download(artifact, force=force)
        extracted = None
        content_checksum = None
        if artifact.get("extract_to"):
            extracted = str(_safe_extract(path, _inside_root(PROJECT_ROOT / artifact["extract_to"]), force=force))
            content_checksum = _verify_content_artifact(artifact)
        artifacts.append({
            **verify_artifact(artifact),
            "extracted_to": extracted,
            "content_checksum": content_checksum,
        })
    return {"id": source_id, "name": source["name"], "kind": source["kind"], "artifacts": artifacts}


def catalog_status() -> list[dict[str, Any]]:
    result = []
    for source_id, source in load_catalog().items():
        result.append({
            "id": source_id,
            "name": source["name"],
            "kind": source["kind"],
            "license": source["license"],
            "source": source["source"],
            "revision": source.get("revision"),
            "warning": source.get("warning"),
            "artifacts": [verify_artifact(item) for item in source.get("artifacts", [])],
        })
    return result


def _main() -> None:
    parser = argparse.ArgumentParser(description="Download and prepare local security datasets")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="show sources, licenses, and local cache status")
    fetch = subparsers.add_parser("fetch", help="download and verify a catalog source")
    fetch.add_argument("source", choices=sorted(load_catalog()))
    fetch.add_argument("--force", action="store_true")
    prepare = subparsers.add_parser("prepare-ait", help="build a balanced AIT-ADS evaluation JSON")
    prepare.add_argument("--per-class", type=int, default=1000)
    prepare.add_argument("--seed", type=int, default=20260805)
    prepare.add_argument("--output", default="data/processed/ait_ads_eval_2000.json")
    rag = subparsers.add_parser("build-rag", help="download and build the local RAG index")
    rag.add_argument("--force", action="store_true")
    rag.add_argument(
        "--include-nvd",
        action="store_true",
        help="also index the large NVD CVE annual feeds; CISA KEV is indexed by default",
    )
    args = parser.parse_args()
    if args.command == "list":
        result: Any = catalog_status()
    elif args.command == "fetch":
        result = fetch_source(args.source, force=args.force)
    elif args.command == "prepare-ait":
        fetch_source("ait-ads")
        from app.data.ait_ads import build_dataset
        result = build_dataset(
            PROJECT_ROOT / "data/raw/ait_ads/extracted",
            PROJECT_ROOT / "data/raw/ait_ads/labels.csv",
            PROJECT_ROOT / args.output,
            per_class=args.per_class,
            seed=args.seed,
        )
    else:
        fetch_source("mitre-attack", force=args.force)
        fetch_source("sigma", force=args.force)
        fetch_source("cisa-kev", force=args.force)
        if args.include_nvd:
            fetch_source("nvd-cve-2.0-recent", force=args.force)
        from app.rag.service import get_rag_service
        result = get_rag_service().bootstrap(
            sigma_path=PROJECT_ROOT / "data/raw/knowledge/sigma/extracted",
            attack_stix_path=PROJECT_ROOT / "data/raw/knowledge/mitre/enterprise-attack.json",
            cisa_kev_path=PROJECT_ROOT / "data/raw/knowledge/cisa/known_exploited_vulnerabilities_2026-08-04.json",
            nvd_feed_path=(
                PROJECT_ROOT / "data/raw/knowledge/nvd/extracted"
                if args.include_nvd
                else None
            ),
            corpus_revision=(
                "mitre:a6c366439edee3a87b79cf90dc0b93f5d7975956"
                "+sigma:226e0f811b44c0e023bbe6799762e29864ebdb92"
                "+cisa-kev:2026.08.04"
                + ("+nvd:2024-2026" if args.include_nvd else "")
            ),
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
