"""Deterministic retrieval coverage checks for the bundled SOC corpus."""

from __future__ import annotations

from typing import Any


# These are behavior descriptions, not evaluation samples or labels.  They
# protect retrieval coverage without leaking benchmark answers into the corpus.
RETRIEVAL_QUALITY_CASES: tuple[dict[str, Any], ...] = (
    {
        "name": "mail_authentication",
        "rule_name": "Dovecot Authentication Success",
        "description": "imap-login Login user method PLAIN TLS",
        "expected": "KB-PLAYBOOK-PB-MAIL-AUTH-001",
    },
    {
        "name": "tls_anomaly",
        "rule_name": "SURICATA TLS invalid handshake message",
        "description": "TLS invalid record traffic to an internal service",
        "expected": "KB-PLAYBOOK-PB-TLS-ANOMALY-001",
    },
    {
        "name": "dns_anomaly",
        "rule_name": "High entropy in DNS domain",
        "description": "Unusual occurrence frequencies of DNS query records",
        "expected": "KB-PLAYBOOK-PB-DNS-ANOMALY-001",
    },
    {
        "name": "software_update",
        "rule_name": "ClamAV database update",
        "description": "GNU/Linux APT User-Agent outbound package management",
        "expected": "KB-PLAYBOOK-PB-SOFTWARE-UPDATE-001",
    },
    {
        "name": "web_access_anomaly",
        "rule_name": "Web server 400 error code",
        "description": "Apache Access request returned 404 forbidden file",
        "expected": "KB-PLAYBOOK-PB-WEB-ACCESS-001",
    },
    {
        "name": "anomaly_baseline",
        "rule_name": "AMiner New event type",
        "description": "New parameter combination and unusual occurrence frequencies",
        "expected": "KB-PLAYBOOK-PB-ANOMALY-BASELINE-001",
    },
    {
        "name": "unix_session",
        "rule_name": "PAM: Login session opened",
        "description": "audit user_auth user_acct session lifecycle",
        "expected": "KB-PLAYBOOK-PB-UNIX-SESSION-001",
    },
    {
        "name": "unix_privilege",
        "rule_name": "Successful sudo to ROOT executed",
        "description": "First time user executed sudo and changed UID",
        "expected": "KB-PLAYBOOK-PB-UNIX-PRIVILEGE-001",
    },
    {
        "name": "service_lifecycle",
        "rule_name": "New service_start parameter combination",
        "description": "systemd service_stop unit file ExecStart",
        "expected": "KB-PLAYBOOK-PB-SERVICE-LIFECYCLE-001",
    },
    {
        "name": "system_monitoring",
        "rule_name": "CPU value deviates from average",
        "description": "CPU value out of expected range in monitoring logs",
        "expected": "KB-PLAYBOOK-PB-SYSTEM-MONITORING-001",
    },
    {
        "name": "network_scan",
        "rule_name": "ET SCAN Potential SSH Scan",
        "description": "Multiple targets and ports scanned by one source",
        "expected": "KB-PLAYBOOK-PB-NETWORK-SCAN-001",
    },
    {
        "name": "executable_download",
        "rule_name": "ELF file download Over HTTP",
        "description": "curl User-Agent to dotted quad Python BaseHTTP ServerBanner",
        "expected": "KB-PLAYBOOK-PB-EXECUTABLE-DOWNLOAD-001",
    },
    {
        "name": "generic_ids",
        "rule_name": "Suricata: IDS event",
        "description": "Generic IDS event without signature or payload",
        "expected": "KB-PLAYBOOK-PB-GENERIC-IDS-001",
    },
    {
        "name": "powershell",
        "rule_name": "Suspicious PowerShell EncodedCommand",
        "description": "PowerShell DownloadString launched by Office",
        "expected": "KB-PLAYBOOK-PB-POWERSHELL-001",
    },
    {
        "name": "web_attack",
        "rule_name": "SQL injection",
        "description": "WAF detected UNION SELECT in an HTTP parameter",
        "expected": "KB-PLAYBOOK-PB-WEB-ATTACK-001",
    },
    {
        "name": "network_c2",
        "rule_name": "Periodic C2 beacon",
        "description": "Reverse shell command and control outbound connection",
        "expected": "KB-PLAYBOOK-PB-NETWORK-001",
    },
    {
        "name": "persistence",
        "rule_name": "Suspicious scheduled task",
        "description": "Cron task and Run Key persistence",
        "expected": "KB-PLAYBOOK-PB-PERSISTENCE-001",
    },
)


def audit_retrieval(service) -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    for index, case in enumerate(RETRIEVAL_QUALITY_CASES, 1):
        retrieval = service.retrieve_for_alert(
            {
                "alert_id": f"rag-audit-{index}",
                "rule_name": case["rule_name"],
                "description": case["description"],
                "raw_payload": {},
            },
            {},
        )
        hit_ids = [hit.knowledge_id for hit in retrieval.hits]
        passed = case["expected"] in hit_ids
        details.append({
            "name": case["name"],
            "expected": case["expected"],
            "profiles": retrieval.routing.get("profiles", []),
            "hits": hit_ids,
            "passed": passed,
            "skipped_reason": retrieval.skipped_reason,
        })
    passed_count = sum(item["passed"] for item in details)
    total = len(details)
    return {
        "passed": passed_count,
        "total": total,
        "coverage": round(passed_count / total, 4) if total else 0.0,
        "details": details,
    }
