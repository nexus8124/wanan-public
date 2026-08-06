"""Exact-CVE NVD adapter.

NVD is queried only when an explicit CVE ID is present. Returned records are
converted into ordinary knowledge chunks and persisted by the main store, so a
benchmark can disable networking and still reuse a pinned local snapshot.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.rag.models import KnowledgeChunk


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in _CVE_RE.findall(text)))


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return str(descriptions[0].get("value") or "") if descriptions else ""


def _cvss_summary(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(key) or []
        if not records:
            continue
        data = records[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or records[0].get("baseSeverity")
        vector = data.get("vectorString")
        return f"CVSS={score} severity={severity} vector={vector}"
    return "CVSS=unknown"


def _references(cve: dict[str, Any], *, limit: int = 8) -> list[str]:
    return [
        str(item.get("url"))
        for item in (cve.get("references") or [])[:limit]
        if item.get("url")
    ]


def _weaknesses(cve: dict[str, Any]) -> list[str]:
    return [
        str(desc.get("value"))
        for weak in (cve.get("weaknesses") or [])
        for desc in (weak.get("description") or [])
        if desc.get("value")
    ]


def _nvd_chunk(cve: dict[str, Any]) -> KnowledgeChunk | None:
    cve_id = str(cve.get("id") or "").upper()
    if not _CVE_RE.fullmatch(cve_id):
        return None
    references = _references(cve)
    weaknesses = list(dict.fromkeys(_weaknesses(cve)))
    content = "\n".join(
        part
        for part in (
            _english_description(cve),
            _cvss_summary(cve.get("metrics") or {}),
            f"Weaknesses: {', '.join(weaknesses)}" if weaknesses else "",
            f"Published: {cve.get('published', '')}",
            f"Last modified: {cve.get('lastModified', '')}",
            "References:\n" + "\n".join(references) if references else "",
        )
        if part
    )
    return KnowledgeChunk(
        knowledge_id=f"KB-NVD-{cve_id}",
        source="nvd",
        title=cve_id,
        content=content,
        source_uri=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        version=str(cve.get("lastModified") or ""),
        metadata={
            "cve_id": cve_id,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "source_identifier": cve.get("sourceIdentifier"),
            "vuln_status": cve.get("vulnStatus"),
            "weaknesses": weaknesses,
            "references": references,
        },
    ).with_checksum()


def _load_nvd_payload(path: Path) -> dict[str, Any] | None:
    try:
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as bundle:
                json_names = [
                    name for name in bundle.namelist()
                    if name.lower().endswith(".json")
                ]
                if not json_names:
                    return None
                with bundle.open(sorted(json_names)[0]) as stream:
                    return json.load(io.TextIOWrapper(stream, encoding="utf-8"))
        return json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile):
        return None


def load_nvd_feeds(root: str | Path) -> list[KnowledgeChunk]:
    """Load NVD CVE 2.0 feed JSON or zip files into exact-CVE chunks."""

    root_path = Path(root)
    if not root_path.exists():
        return []
    candidates = (
        sorted(root_path.rglob("nvdcve-2.0-*.json"))
        + sorted(root_path.rglob("nvdcve-2.0-*.json.zip"))
        if root_path.is_dir()
        else [root_path]
    )
    chunks: list[KnowledgeChunk] = []
    seen: set[str] = set()
    for candidate in candidates:
        payload = _load_nvd_payload(candidate)
        if not isinstance(payload, dict):
            continue
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") if isinstance(item, dict) else None
            if not isinstance(cve, dict):
                continue
            chunk = _nvd_chunk(cve)
            if chunk is None or chunk.knowledge_id in seen:
                continue
            chunks.append(chunk)
            seen.add(chunk.knowledge_id)
    return chunks


def load_cisa_kev(path: str | Path) -> list[KnowledgeChunk]:
    """Load CISA Known Exploited Vulnerabilities catalog records."""

    source_path = Path(path)
    if not source_path.exists():
        return []
    try:
        payload = json.loads(source_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    chunks: list[KnowledgeChunk] = []
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").upper()
        if not _CVE_RE.fullmatch(cve_id):
            continue
        notes = str(item.get("notes") or "")
        references = [
            part.strip()
            for part in notes.split(";")
            if part.strip().startswith(("http://", "https://"))
        ]
        content = "\n".join(
            part
            for part in (
                f"CISA KEV: {cve_id} {item.get('vulnerabilityName', '')}",
                f"Vendor/Product: {item.get('vendorProject', '')} / {item.get('product', '')}",
                str(item.get("shortDescription") or ""),
                f"Date added: {item.get('dateAdded', '')}",
                f"Due date: {item.get('dueDate', '')}",
                f"Known ransomware campaign use: {item.get('knownRansomwareCampaignUse', '')}",
                f"Required action: {item.get('requiredAction', '')}",
                f"CWEs: {', '.join(str(cwe) for cwe in item.get('cwes') or [])}",
                "References:\n" + "\n".join(references) if references else "",
            )
            if part
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-CISA-KEV-{cve_id}",
                source="cisa_kev",
                title=f"{cve_id} {item.get('vulnerabilityName', '')}".strip(),
                content=content,
                source_uri=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                version=str(payload.get("catalogVersion") or item.get("dateAdded") or ""),
                metadata={
                    "cve_id": cve_id,
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                    "cwes": item.get("cwes") or [],
                    "references": references,
                },
            ).with_checksum()
        )
    return chunks


def fetch_nvd_cve(cve_id: str, *, timeout_s: float = 15.0) -> KnowledgeChunk | None:
    """Fetch one CVE from the official NVD 2.0 API."""
    cve_id = cve_id.upper()
    if not _CVE_RE.fullmatch(cve_id):
        return None
    url = f"{_NVD_API}?{urlencode({'cveId': cve_id})}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "XH-202614-security-agent-rag/1.0",
        },
    )
    with urlopen(request, timeout=timeout_s) as response:  # noqa: S310 - fixed host
        payload = json.loads(response.read().decode("utf-8"))
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") or {}
    return _nvd_chunk(cve)
