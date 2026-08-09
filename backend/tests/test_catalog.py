from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from app.data.catalog import _safe_extract, load_catalog
from app.rag.sources import (
    load_attack_groups,
    load_attack_malware,
    load_attack_mitigations,
    load_attack_stix,
    load_attack_tools,
)
from app.rag.nvd import load_cisa_kev, load_nvd_feeds


def test_catalog_has_pinned_sources_and_checksums():
    catalog = load_catalog()
    assert catalog["ait-ads"]["license"] == "CC-BY-4.0"
    assert catalog["mitre-attack"]["revision"]
    assert catalog["sigma"]["artifacts"][0]["checksum"].startswith("sha256:")
    assert catalog["cisa-kev"]["revision"] == "2026.08.04"
    assert catalog["nvd-cve-2.0-recent"]["artifacts"][0]["content_checksum"].startswith("sha256:")


def test_safe_extract_rejects_zip_slip(tmp_path: Path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../../outside.txt", "blocked")
    with pytest.raises(ValueError, match="unsafe archive"):
        _safe_extract(archive, tmp_path / "out")


def test_attack_bundle_loaders_share_one_stix_shape(tmp_path: Path):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        json.dumps(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": "PowerShell",
                        "modified": "2026-01-01T00:00:00Z",
                        "external_references": [{"external_id": "T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"}],
                        "kill_chain_phases": [{"phase_name": "execution"}],
                        "x_mitre_platforms": ["Windows"],
                        "description": "Execute commands.",
                    },
                    {
                        "type": "intrusion-set",
                        "name": "Example Group",
                        "external_references": [{"external_id": "G0001", "url": "https://attack.mitre.org/groups/G0001/"}],
                        "description": "Example.",
                    },
                    {
                        "type": "malware",
                        "name": "Example Malware",
                        "external_references": [{"external_id": "S0001", "url": "https://attack.mitre.org/software/S0001/"}],
                        "description": "Example.",
                    },
                    {
                        "type": "tool",
                        "name": "Example Tool",
                        "external_references": [{"external_id": "S0002", "url": "https://attack.mitre.org/software/S0002/"}],
                        "description": "Example.",
                    },
                    {
                        "type": "course-of-action",
                        "name": "Example Mitigation",
                        "external_references": [{"external_id": "M0001", "url": "https://attack.mitre.org/mitigations/M0001/"}],
                        "description": "Example.",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    assert len(load_attack_stix(bundle_path)) == 1
    assert len(load_attack_groups(bundle_path)) == 1
    assert len(load_attack_malware(bundle_path)) == 1
    assert len(load_attack_tools(bundle_path)) == 1
    assert len(load_attack_mitigations(bundle_path)) == 1


def test_cisa_kev_loader_builds_exploited_vulnerability_chunks(tmp_path: Path):
    catalog_path = tmp_path / "kev.json"
    catalog_path.write_text(
        json.dumps({
            "catalogVersion": "2026.08.04",
            "vulnerabilities": [{
                "cveID": "CVE-2026-12345",
                "vendorProject": "Example",
                "product": "Product",
                "vulnerabilityName": "Example exploited vulnerability",
                "dateAdded": "2026-08-04",
                "shortDescription": "Known exploited issue.",
                "requiredAction": "Patch.",
                "dueDate": "2026-08-07",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                "cwes": ["CWE-288"],
            }],
        }),
        encoding="utf-8",
    )
    chunks = load_cisa_kev(catalog_path)
    assert len(chunks) == 1
    assert chunks[0].knowledge_id == "KB-CISA-KEV-CVE-2026-12345"
    assert chunks[0].source == "cisa_kev"
    assert chunks[0].metadata["cwes"] == ["CWE-288"]


def test_nvd_feed_loader_builds_exact_cve_chunks(tmp_path: Path):
    feed_path = tmp_path / "nvdcve-2.0-2026.json"
    feed_path.write_text(
        json.dumps({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-23456",
                    "sourceIdentifier": "nvd@nist.gov",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Example CVE."}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"value": "CWE-79"}],
                    }],
                    "references": [{"url": "https://example.test/advisory"}],
                }
            }],
        }),
        encoding="utf-8",
    )
    chunks = load_nvd_feeds(tmp_path)
    assert len(chunks) == 1
    assert chunks[0].knowledge_id == "KB-NVD-CVE-2026-23456"
    assert chunks[0].source == "nvd"
    assert "CVSS=9.8" in chunks[0].content
