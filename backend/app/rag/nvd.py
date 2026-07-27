"""Exact-CVE NVD adapter.

NVD is queried only when an explicit CVE ID is present. Returned records are
converted into ordinary knowledge chunks and persisted by the main store, so a
benchmark can disable networking and still reuse a pinned local snapshot.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.rag.models import KnowledgeChunk


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in _CVE_RE.findall(text)))


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return str(descriptions[0].get("value") or "") if descriptions else ""


def _cvss_summary(metrics: dict) -> str:
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
    references = [
        str(item.get("url"))
        for item in (cve.get("references") or [])[:8]
        if item.get("url")
    ]
    weaknesses = [
        str(desc.get("value"))
        for weak in (cve.get("weaknesses") or [])
        for desc in (weak.get("description") or [])
        if desc.get("value")
    ]
    content = "\n".join(
        part
        for part in (
            _english_description(cve),
            _cvss_summary(cve.get("metrics") or {}),
            f"Weaknesses: {', '.join(dict.fromkeys(weaknesses))}"
            if weaknesses
            else "",
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
        metadata={"cve_id": cve_id, "references": references},
    )
