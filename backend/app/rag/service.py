"""RAG orchestration, query routing, context construction, and status."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.rag.embeddings import get_embedding_provider
from app.rag.models import RetrievalHit, RetrievalResult
from app.rag.nvd import extract_cve_ids, fetch_nvd_cve
from app.rag.sources import (
    builtin_attack_seed,
    load_attack_groups,
    load_attack_malware,
    load_attack_mitigations,
    load_attack_stix,
    load_attack_tools,
    load_playbooks,
    load_sigma_rules,
)
from app.rag.store import SQLiteKnowledgeStore


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
_ATTCK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

# Alert-time retrieval is intentionally conservative.  These profiles are not
# labels and never decide the verdict; they only prevent unrelated security
# domains from entering the prompt.
_BEHAVIOR_PROFILES: dict[str, dict[str, Any]] = {
    "mail_authentication": {
        "priority_keywords": (
            "dovecot", "imap-login", "pop3-login", "smtp-auth",
        ),
        "keywords": (
            "mail authentication", "mail login", "邮件认证", "邮件登录",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-MAIL-AUTH-001",
            "KB-PLAYBOOK-PB-AUTH-001",
            "KB-ATTCK-T1078",
            "KB-ATTCK-T1110.001",
        },
    },
    "tls_anomaly": {
        "priority_keywords": (
            "tls invalid handshake", "invalid handshake message",
            "tls invalid record", "invalid record type",
        ),
        "keywords": (
            "tls", "ssl", "handshake", "ja3", "ja4", "sni",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-TLS-ANOMALY-001",
            "KB-PLAYBOOK-PB-NETWORK-SCAN-001",
            "KB-ATTCK-T1595",
        },
    },
    "dns_anomaly": {
        "priority_keywords": (
            "dns domain", "dns query", "dns logs", "dns tunneling",
            "high entropy in dns", "observed dns query",
        ),
        "keywords": (
            "dns", "domain", ".biz tld", "nameserver", "高熵域名",
            "dns隧道", "域名查询",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-DNS-ANOMALY-001",
            "KB-PLAYBOOK-PB-EXTERNAL-IP-LOOKUP-001",
            "KB-ATTCK-T1071.004",
            "KB-ATTCK-T1027",
        },
    },
    "software_update": {
        "priority_keywords": (
            "clamav database update", "apt user-agent",
            "package management", "unattended-upgrades",
        ),
        "keywords": (
            "apt-get", "freshclam", "software update", "package manager",
            "repository", "病毒库更新", "软件更新", "软件仓库",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-SOFTWARE-UPDATE-001",
            "KB-ATTCK-T1105",
        },
    },
    "web_access_anomaly": {
        "priority_keywords": (
            "web server 400", "apache access", "forbidden file",
            "new request method", "new status code",
        ),
        "keywords": (
            "400 error", "403", "404", "accesslog", "user agent",
            "referer", "http method", "访问日志", "错误响应",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-WEB-ACCESS-001",
            "KB-PLAYBOOK-PB-WEB-ATTACK-001",
            "KB-PLAYBOOK-PB-NETWORK-SCAN-001",
            "KB-ATTCK-T1190",
            "KB-ATTCK-T1595",
        },
    },
    "anomaly_baseline": {
        "priority_keywords": (
            "new event type", "new parameter combination",
            "unusual occurrence frequencies", "deviates from average",
            "out of expected range",
        ),
        "keywords": (
            "aminer", "novelty", "baseline", "new characters",
            "frequency anomaly", "统计异常", "基线偏差",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-ANOMALY-BASELINE-001",
            "KB-ATTCK-T1027",
        },
    },
    "unix_session": {
        "priority_keywords": (
            "pam: login session", "user_auth", "user_acct", "user_end",
            "cred_acq", "cred_disp", "cred_refr",
        ),
        "keywords": (
            "pam", "audit logs", "session opened", "session closed",
            "unix login", "linux session",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-UNIX-SESSION-001",
            "KB-PLAYBOOK-PB-AUTH-001",
            "KB-ATTCK-T1078",
        },
    },
    "unix_privilege": {
        "priority_keywords": (
            "successful sudo to root", "first time user executed sudo",
            "changed uid",
        ),
        "keywords": (
            "sudo", "sudoers", "uid", "root executed", "提权",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-UNIX-PRIVILEGE-001",
            "KB-ATTCK-T1548.003",
            "KB-ATTCK-T1068",
        },
    },
    "service_lifecycle": {
        "priority_keywords": (
            "service_start", "service_stop", "systemd", "service creation",
        ),
        "keywords": (
            "execstart", "unit file", "daemon", "new service",
            "服务启动", "服务停止", "服务创建",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-SERVICE-LIFECYCLE-001",
            "KB-PLAYBOOK-PB-PERSISTENCE-001",
            "KB-ATTCK-T1543.002",
        },
    },
    "system_monitoring": {
        "priority_keywords": (
            "cpu value deviates", "cpu value out of expected range",
        ),
        "keywords": (
            "cpu", "monitoring logs", "resource usage", "performance",
            "系统监控", "资源占用",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-SYSTEM-MONITORING-001",
        },
    },
    "network_scan": {
        "priority_keywords": (
            "potential ssh scan", "insecure connection attempt (scan)",
            "multiple web server 400", "port scan",
        ),
        "keywords": (
            "ssh scan", "web scan", "scanner", "reconnaissance",
            "扫描", "探测", "枚举",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-NETWORK-SCAN-001",
            "KB-ATTCK-T1046",
            "KB-ATTCK-T1595",
        },
    },
    "executable_download": {
        "priority_keywords": (
            "elf file download", "python basehttp serverbanner",
            "curl user-agent to dotted quad",
        ),
        "keywords": (
            "executable download", "basehttpserver", "wget", "curl",
            "payload download", "文件下载", "可执行文件",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-EXECUTABLE-DOWNLOAD-001",
            "KB-ATTCK-T1105",
            "KB-ATTCK-T1204.002",
        },
    },
    "generic_ids": {
        "priority_keywords": (
            "suricata: ids event", "generic ids event",
        ),
        "keywords": (
            "ids event", "suricata signature", "flow_id", "network signature",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-GENERIC-IDS-001",
            "KB-PLAYBOOK-PB-NETWORK-001",
        },
    },
    "powershell": {
        "priority_keywords": (
            "encodedcommand", "encoded command", "downloadstring",
            "invoke-expression",
        ),
        "keywords": (
            "powershell", "pwsh", "iex ", "regsvr32",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-POWERSHELL-001",
            "KB-ATTCK-T1059.001",
            "KB-ATTCK-T1218.010",
        },
    },
    "web_attack": {
        "priority_keywords": (
            "sql injection", "sqli", "webshell", "command injection",
            "path traversal",
        ),
        "keywords": (
            "wordpress", "http", "https", "waf", "xss", "url", "uri",
            "get request", "post request", "网页", "网站", "注入", "路径遍历",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-WEB-ATTACK-001",
            "KB-ATTCK-T1190",
            "KB-ATTCK-T1071.001",
        },
    },
    "authentication": {
        "priority_keywords": (
            "brute force", "password guessing", "authentication failure",
        ),
        "keywords": (
            "authentication", "login", "logon", "ssh", "rdp",
            "vpn", "password", "credential", "pam_", "认证", "登录",
            "口令", "暴力破解", "暴破",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-AUTH-001",
            "KB-ATTCK-T1110.001",
            "KB-ATTCK-T1021.002",
            "KB-ATTCK-T1078",
        },
    },
    "network": {
        "priority_keywords": (
            "beacon", "command and control", "reverse shell",
        ),
        "keywords": (
            "c2", "netflow", "suricata", "outbound", "external ip", "隧道",
            "外联", "回连", "网络流量",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-NETWORK-001",
            "KB-PLAYBOOK-PB-GENERIC-IDS-001",
            "KB-ATTCK-T1071.001",
            "KB-ATTCK-T1041",
        },
    },
    "persistence": {
        "priority_keywords": (
            "scheduled task", "run key", "startup folder",
        ),
        "keywords": (
            "cron", "startup", "计划任务", "定时任务", "启动项",
            "持久化",
        ),
        "knowledge_ids": {
            "KB-PLAYBOOK-PB-PERSISTENCE-001",
            "KB-PLAYBOOK-PB-SERVICE-LIFECYCLE-001",
            "KB-ATTCK-T1053.003",
        },
    },
}

# These detector families are useful signals, but a rule hit alone is not
# specific enough to justify bypassing false-positive knowledge.  High
# confidence from the initial model therefore still receives one guarded
# calibration pass.  Strong execution/C2/exploitation profiles remain on the
# normal confidence gate.
WEAK_SIGNAL_CALIBRATION_PROFILES = frozenset({
    "mail_authentication",
    "tls_anomaly",
    "dns_anomaly",
    "software_update",
    "anomaly_baseline",
    "unix_session",
    "unix_privilege",
    "service_lifecycle",
    "system_monitoring",
    "generic_ids",
})


def _keyword_matches(text: str, keyword: str) -> bool:
    """Avoid short-token substring matches such as ``rdp`` in ``wordpress``."""
    normalized = keyword.strip().lower()
    if re.fullmatch(r"[a-z0-9_.-]{2,5}", normalized):
        return bool(re.search(
            rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])",
            text,
        ))
    return keyword.lower() in text


def _behavior_profiles(text: str) -> list[str]:
    lowered = text.lower()
    scored: list[tuple[str, int]] = []
    for name, profile in _BEHAVIOR_PROFILES.items():
        score = 3 * sum(
            1 for keyword in profile.get("priority_keywords", ())
            if _keyword_matches(lowered, keyword)
        ) + sum(
            1 for keyword in profile["keywords"]
            if _keyword_matches(lowered, keyword)
        )
        if score:
            scored.append((name, score))
    scored.sort(key=lambda item: (-item[1], item[0]))
    # Alert-time grounding uses only the strongest behavior domain. A generic
    # secondary signal such as "outbound" must not pull network knowledge into
    # an otherwise specific web/authentication investigation.
    return [name for name, _score in scored[:1]]


class RagService:
    def __init__(
        self,
        *,
        db_path: str | Path | None = None,
        embedding_provider: str | None = None,
        embedding_model: str | None = None,
        auto_bootstrap: bool = True,
    ):
        settings = get_settings()
        self.db_path = Path(db_path or settings.rag_db_path)
        self.embedding = get_embedding_provider(
            embedding_provider or settings.rag_embedding_provider,
            embedding_model or settings.rag_embedding_model,
        )
        self.store = SQLiteKnowledgeStore(self.db_path, self.embedding)
        self.auto_bootstrap = auto_bootstrap
        self._bootstrapped = False

    def bootstrap(
        self,
        *,
        playbook_path: str | Path | None = None,
        sigma_path: str | Path | None = None,
        attack_stix_path: str | Path | None = None,
    ) -> dict[str, Any]:
        settings = get_settings()
        chunks = builtin_attack_seed()
        playbooks = load_playbooks(
            playbook_path or settings.rag_playbook_path
        )
        chunks.extend(playbooks)
        sigma_root = str(sigma_path or settings.rag_sigma_path).strip()
        attack_root = str(attack_stix_path or settings.rag_attack_stix_path).strip()
        if sigma_root:
            chunks.extend(load_sigma_rules(sigma_root))
        if attack_root:
            chunks.extend(load_attack_stix(attack_root))
            chunks.extend(load_attack_groups(attack_root))
            chunks.extend(load_attack_malware(attack_root))
            chunks.extend(load_attack_tools(attack_root))
            chunks.extend(load_attack_mitigations(attack_root))
        indexed = self.store.upsert(chunks)
        self.store.set_metadata("corpus_version", settings.rag_corpus_version)
        self._bootstrapped = True
        return {
            "indexed": indexed,
            "counts": self.store.count_by_source(),
            "embedding_model": self.embedding.name,
            "db_path": str(self.db_path),
            "corpus_version": settings.rag_corpus_version,
        }

    def ensure_ready(self) -> None:
        if self._bootstrapped:
            return
        settings = get_settings()
        indexed_version = self.store.get_metadata("corpus_version")
        if self.auto_bootstrap and (
            not self.store.count_by_source()
            or indexed_version != settings.rag_corpus_version
        ):
            self.bootstrap()
        self._bootstrapped = True

    def status(self) -> dict[str, Any]:
        self.ensure_ready()
        counts = self.store.count_by_source()
        settings = get_settings()
        return {
            "enabled_by_default": settings.rag_enabled,
            "ready": bool(sum(counts.values())),
            "counts": counts,
            "total_chunks": sum(counts.values()),
            "embedding_model": self.embedding.name,
            "db_path": str(self.db_path),
            "corpus_version": settings.rag_corpus_version,
            "indexed_corpus_version": self.store.get_metadata("corpus_version"),
            "weak_signal_calibration": {
                "enabled": settings.rag_calibrate_weak_signals,
                "profiles": sorted(WEAK_SIGNAL_CALIBRATION_PROFILES),
            },
        }

    @staticmethod
    def build_alert_query(alert: dict[str, Any], features: dict[str, Any]) -> str:
        payload = alert.get("raw_payload") or {}
        parts: list[str] = [
            str(alert.get("rule_name") or ""),
            str(alert.get("description") or ""),
            str(alert.get("protocol") or ""),
            str(alert.get("dst_port") or ""),
            str(features.get("direction") or ""),
        ]
        # Include only bounded defender-visible fields. Private evidence locators
        # and labels must never become retrieval queries.
        for key in (
            "full_log",
            "event_original",
            "process_name",
            "command_line",
            "detector_events",
        ):
            value = payload.get(key)
            if value:
                rendered = json.dumps(value, ensure_ascii=False, default=str)
                parts.append(rendered[:2500])
        query = " ".join(part for part in parts if part).strip()
        return query[:6000]

    @staticmethod
    def route_sources(query: str) -> list[str]:
        sources = ["playbook", "sigma", "mitre_attack"]
        if _CVE_RE.search(query):
            sources.append("nvd")
        return sources

    def calibration_policy(
        self, alert: dict[str, Any], features: dict[str, Any]
    ) -> dict[str, Any]:
        """Return label-free policy for high-confidence weak detector signals."""
        query = self.build_alert_query(alert, features)
        profiles = _behavior_profiles(query)
        matched = [
            profile
            for profile in profiles
            if profile in WEAK_SIGNAL_CALIBRATION_PROFILES
        ]
        enabled = get_settings().rag_calibrate_weak_signals
        eligible = bool(enabled and matched)
        return {
            # The retrieve node combines profile eligibility with the initial
            # verdict. Only high-confidence true-positive claims can be
            # force-calibrated; pending/low-confidence samples already use the
            # normal selective gate.
            "eligible": eligible,
            "forced": False,
            "enabled": enabled,
            "profiles": matched,
            "reason": (
                "weak_signal_profile_eligible"
                if eligible
                else "disabled"
                if not enabled
                else "strong_or_unsupported_profile"
            ),
        }

    def search(
        self,
        query: str,
        *,
        sources: list[str] | None = None,
        top_k: int | None = None,
        min_score: float | None = None,
    ) -> RetrievalResult:
        self.ensure_ready()
        settings = get_settings()
        selected_sources = sources or self.route_sources(query)
        hits = self.store.search(
            query,
            sources=selected_sources,
            top_k=top_k or settings.rag_top_k,
            candidate_k=settings.rag_candidate_k,
        )
        threshold = settings.rag_min_score if min_score is None else min_score
        hits = [hit for hit in hits if hit.score >= threshold]
        context = self.format_context(
            hits, max_chars=settings.rag_max_context_chars
        )
        return RetrievalResult(
            query=query,
            sources=selected_sources,
            hits=hits,
            context=context,
            skipped_reason=None if hits else "no_relevant_knowledge",
            corpus_version=settings.rag_corpus_version,
            embedding_model=self.embedding.name,
        )

    def lookup_cve(self, query: str) -> RetrievalResult:
        """Resolve explicit CVE IDs, optionally refreshing them from NVD."""
        self.ensure_ready()
        settings = get_settings()
        cve_ids = extract_cve_ids(query)
        if cve_ids and settings.rag_nvd_online:
            fresh = []
            for cve_id in cve_ids[:5]:
                if self.store.get(f"KB-NVD-{cve_id}") is not None:
                    continue
                try:
                    chunk = fetch_nvd_cve(
                        cve_id, timeout_s=settings.rag_nvd_timeout_s
                    )
                except Exception:
                    chunk = None
                if chunk is not None:
                    fresh.append(chunk)
            if fresh:
                self.store.upsert(fresh)
        return self.search(
            query,
            sources=["nvd"],
            min_score=0.0 if cve_ids else None,
        )

    def retrieve_for_alert(
        self, alert: dict[str, Any], features: dict[str, Any]
    ) -> RetrievalResult:
        self.ensure_ready()
        query = self.build_alert_query(alert, features)
        settings = get_settings()
        if not query:
            return RetrievalResult(
                query="",
                skipped_reason="empty_query",
                corpus_version=settings.rag_corpus_version,
                embedding_model=self.embedding.name,
            )
        profiles = _behavior_profiles(query)
        exact_ids = {
            match.upper() for match in (_CVE_RE.findall(query) + _ATTCK_RE.findall(query))
        }
        if not profiles and not exact_ids:
            return RetrievalResult(
                query=query,
                sources=[],
                skipped_reason="unsupported_or_ambiguous_behavior",
                corpus_version=settings.rag_corpus_version,
                embedding_model=self.embedding.name,
                routing={"profiles": [], "strict": True},
            )

        selected_sources = self.route_sources(query)
        candidates = self.store.search(
            query,
            sources=selected_sources,
            top_k=max(settings.rag_candidate_k, 12),
            candidate_k=max(settings.rag_candidate_k, 20),
        )
        allowed_ids: set[str] = set()
        profile_terms: list[str] = []
        for profile_name in profiles:
            profile = _BEHAVIOR_PROFILES[profile_name]
            profile_kb_ids = set(profile.get("knowledge_ids", []))
            allowed_ids.update(profile_kb_ids)
            profile_terms.extend(profile.get("keywords", []))
        # Profile-specific playbooks may have near-zero dense-vector scores
        # because the corpus is Chinese while queries are often English.
        # Inject any missing playbooks from knowledge_ids so they survive
        # the top_k cutoff without cross-contaminating other domains.
        existing_ids = {hit.knowledge_id for hit in candidates}
        for profile_name in profiles:
            profile = _BEHAVIOR_PROFILES[profile_name]
            for kb_id in profile.get("knowledge_ids", []):
                if not kb_id.startswith("KB-PLAYBOOK-"):
                    continue
                if kb_id in existing_ids:
                    # Already in candidates - will be promoted below if it passes filtering
                    continue
                chunk = self.store.get(kb_id)
                if chunk is None:
                    continue
                candidates.append(
                    RetrievalHit(
                        knowledge_id=chunk.knowledge_id,
                        source=chunk.source,
                        title=chunk.title,
                        content=chunk.content,
                        score=1.0,
                        source_uri=chunk.source_uri,
                        exact_match=False,
                        injected=True,
                    )
                )
                existing_ids.add(kb_id)

        strict_hits = []
        for hit in candidates:
            explicit = hit.exact_match
            profile_match = hit.knowledge_id in allowed_ids
            sigma_match = (
                hit.source == "sigma"
                and hit.lexical_rank is not None
                and any(
                    _keyword_matches(
                        f"{hit.title} {hit.content}".lower(), term
                    )
                    for term in profile_terms
                )
            )
            if not (explicit or profile_match or sigma_match):
                continue
            # Profile-specific playbooks may have near-zero dense-vector scores
            # because the corpus is Chinese while queries are often English.
            # Promote them so they survive the top_k cutoff.
            if profile_match and hit.source == "playbook":
                hit.score = 1.0
            if not explicit and not hit.injected and hit.score < settings.rag_min_score:
                continue
            strict_hits.append(hit)
        # Playbooks contain the project's actual false-positive and response
        # criteria, so they are more useful than a list consisting only of
        # ATT&CK technique descriptions. Exact IDs remain the strongest signal.
        # Give playbooks a priority boost so they survive the top_k cutoff.
        strict_hits.sort(
            key=lambda hit: (
                not hit.exact_match,
                -(hit.score + (0.15 if hit.source == "playbook" else 0.0)),
                hit.knowledge_id,
            )
        )
        strict_hits = strict_hits[:settings.rag_top_k]

        context = self.format_context(
            strict_hits, max_chars=settings.rag_max_context_chars
        )
        return RetrievalResult(
            query=query,
            sources=selected_sources,
            hits=strict_hits,
            context=context,
            skipped_reason=None if strict_hits else "no_high_relevance_knowledge",
            corpus_version=settings.rag_corpus_version,
            embedding_model=self.embedding.name,
            routing={
                "profiles": profiles,
                "strict": True,
                "candidate_count": len(candidates),
                "allowed_knowledge_ids": sorted(allowed_ids),
            },
        )

    @staticmethod
    def format_context(hits, *, max_chars: int = 9000) -> str:
        if not hits:
            return ""
        header = (
            "以下内容是通用安全知识，只用于解释技术、检测规则、已知误报和处置方法；"
            "它不能证明当前告警中的行为真实发生。必须结合当前告警和遥测证据研判。\n"
        )
        sections = [header]
        for hit in hits:
            section = (
                f"[{hit.knowledge_id}] 来源={hit.source} 相关度={hit.score:.3f}\n"
                f"标题: {hit.title}\n"
                f"{hit.content[:2600]}\n"
                f"出处: {hit.source_uri or '(本地知识库)'}"
            )
            if sum(len(item) for item in sections) + len(section) > max_chars:
                break
            sections.append(section)
        return "\n\n".join(sections)


@lru_cache(maxsize=1)
def get_rag_service() -> RagService:
    return RagService()
