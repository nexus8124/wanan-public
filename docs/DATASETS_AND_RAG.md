# Evaluation and RAG Data

This project keeps raw corpora, generated evaluation JSON, and the SQLite RAG
index outside Git. The committed `backend/app/data/source_catalog.json` records
the source URL, pinned revision, license, expected size, and checksum. Use the
catalog CLI instead of downloading files into the repository.

## Sources

### AIT-ADS

AIT-ADS is the primary large evaluation corpus. It is published under CC BY 4.0
at <https://zenodo.org/records/8263181> (DOI `10.5281/zenodo.8263181`). The
adapter converts Wazuh and AMiner JSONL into the project `Alert` schema and
creates a balanced, deterministic sample. The official labels describe attack
time windows, so the result must be reported as a `time_window_weak` baseline;
it is not event-level ground truth.

```powershell
cd backend
uv run python -m app.data.catalog prepare-ait --per-class 1000 --output data/processed/ait_ads_eval_2000.json
```

The generated document stores alerts and `ground_truth` separately. Labels and
attack phases are used only for sampling/metrics and are never passed to the
Agent. The page will list the generated file automatically.

### CAM-LDS

CAM-LDS is a CC BY 4.0 multi-source evidence corpus at
<https://zenodo.org/records/18861762>. Its filtered archive is about 214 MB;
the complete record is about 7.4 GB. It is useful for a correlated attack-step
Pilot and ReAct evidence retrieval, but attack-only cases cannot provide a
meaningful false-positive rate. Download it only when that Pilot is needed:

```powershell
uv run python -m app.data.catalog fetch cam-lds-filtered
```

### RAG corpora

The default local RAG build combines the official MITRE ATT&CK Enterprise STIX
bundle (pinned revision `a6c3664`), SigmaHQ rules (pinned revision `226e0f8`),
and CISA Known Exploited Vulnerabilities. NVD CVE 2.0 annual feeds for
2024-2026 are downloaded and verified as an optional large local corpus. MITRE's
repository license requires its copyright designation to be retained; Sigma
rules are under Detection Rule License 1.1. The corpus is not checked into Git
and can be rebuilt with:

```powershell
uv run python -m app.data.catalog build-rag
uv run python -m app.rag.cli status
```

ATT&CK techniques, groups, malware, tools, and mitigations are loaded into the
same SQLite index. Sigma rules remain source-attributed chunks, so retrieval can
show the rule title and source URI without presenting a rule as ground truth.
CISA KEV adds high-signal context for vulnerabilities known to be exploited in
the wild. NVD adds broad CVE detail, CVSS, CWE, and reference metadata; the
router searches NVD only when the query contains an explicit `CVE-YYYY-NNNN`
identifier, so ordinary alert triage is not diluted by unrelated CVE matches.
Full NVD indexing is intentionally opt-in because it is much larger than the
rest of the RAG corpus:

```powershell
uv run python -m app.data.catalog build-rag --include-nvd
```

The NVD zip files are verified twice: the catalog pins the downloaded zip SHA-256
and also validates the extracted JSON SHA-256 published in each official `.meta`
file. The current local build uses:

- CISA KEV catalog `2026.08.04`, 1,660 vulnerabilities.
- NVD CVE 2.0 `2024`, `2025`, and `2026` annual feeds.

Splunk Attack Data (Apache-2.0) and OTRF Security Datasets (MIT) were reviewed as
additional top-project patterns: both separate raw telemetry from detection
metadata and require adapters for a project-specific alert schema. They are not
bundled by default because their records do not provide the balanced,
leakage-safe labels needed by this page.

## Reproducibility checklist

1. Run `uv run python -m app.data.catalog list` and keep the printed revisions and checksums with an experiment record.
2. Build the AIT-ADS set with a fixed `--seed`; do not mix its weak labels with CAM-LDS attack-only cases when reporting Accuracy or F1.
3. Run Judge-only before ReAct/RAG, then compare paired changes, coverage, latency, and token usage.
4. Review `git diff --cached --name-only` before pushing. `data/raw/`, `data/processed/`, `data/knowledge/`, and evaluation results are ignored by the repository.
