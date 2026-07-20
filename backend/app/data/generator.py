"""评测数据集生成器。

赛题贴合：方案 2.3 节 MVP 验收要求"50 条以上标注样本"。
把 sample_alerts.json 的 10 条手工样本作为种子，扩充到 50 条用于评测。

策略：
  - 保留 10 条种子样本（A4 已建）
  - 用模板变体生成 40 条新样本（真阳/假阳各 20）
  - 生成结果是确定的（不引入随机种子以外的不确定性），便于复现
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.data.loader import DEFAULT_DATASET

EVAL_DATASET = DEFAULT_DATASET.parent / "eval_alerts.json"

# ============================================================
# 真阳模板（攻击场景）—— 每个模板描述一种攻击家族
# ============================================================

TP_TEMPLATES: list[dict[str, Any]] = [
    {
        "source": "edr", "severity": "high", "protocol": "TCP",
        "rule_name": "Reverse shell to {dst_ip}",
        "description": "powershell.exe 由 WINWORD.EXE 启动外连 {dst_ip}:{dst_port}，疑似钓鱼宏落地后的命令控制",
        "keywords": ["powershell.exe", "外连", "钓鱼"],
    },
    {
        "source": "ndr", "severity": "high", "protocol": "SMB",
        "rule_name": "Lateral movement via SMB admin share",
        "description": "横向移动：{src_ip} 通过 PsExec 访问 {dst_ip} 的 ADMIN$ 共享，伴随权限提升",
        "keywords": ["横向移动", "psexec"],
    },
    {
        "source": "edr", "severity": "high", "protocol": None,
        "rule_name": "PowerShell encoded command",
        "description": "检出编码 PowerShell 命令，regsvr32 远程脚本下载执行，疑似 LOLBin 攻击",
        "keywords": ["regsvr32", "powershell.exe", "encoded"],
    },
    {
        "source": "waf", "severity": "high", "protocol": "HTTPS",
        "rule_name": "SQL injection attempt",
        "description": "WAF 命中 SQL injection 规则，载荷含 UNION SELECT + sleep，sql injection 单 IP 高频触发",
        "keywords": ["sql injection", "sqli"],
    },
    {
        "source": "siem", "severity": "medium", "protocol": "LDAP",
        "rule_name": "LDAP brute force",
        "description": "域控 LDAP brute force，单 IP 3 分钟内 1284 次登录尝试，暴破特征明显",
        "keywords": ["brute force", "暴力破解", "ldap brute"],
    },
    {
        "source": "ndr", "severity": "high", "protocol": "TCP",
        "rule_name": "Known C2 beacon",
        "description": "检出 C2 server 信标行为，{src_ip} 周期性外连 known c2 地址 {dst_ip}，beacon 间隔固定",
        "keywords": ["known c2", "c2 server"],
    },
    {
        "source": "ids", "severity": "high", "protocol": "TCP",
        "rule_name": "Phishing domain access",
        "description": "用户访问钓鱼域名（{dst_ip}），URL 匹配 phishing 特征库，疑似 phishing 落地",
        "keywords": ["钓鱼", "phishing"],
    },
    {
        "source": "edr", "severity": "high", "protocol": None,
        "rule_name": "Malicious script execution",
        "description": "检出 malicious 脚本执行，reverse shell 特征：bash -i >& /dev/tcp/{dst_ip}/{dst_port}",
        "keywords": ["malicious", "reverse shell"],
    },
    {
        "source": "firewall", "severity": "high", "protocol": "TCP",
        "rule_name": "C2 lateral movement detected",
        "description": "横向移动 + C2 混合：{src_ip} 横向移动到多台内网主机后外连 C2 server {dst_ip}",
        "keywords": ["横向移动", "c2 server"],
    },
    {
        "source": "ids", "severity": "high", "protocol": "HTTPS",
        "rule_name": "Encoded powershell sqli",
        "description": "复合攻击：sql injection 配合 powershell.exe encoded command 落地执行",
        "keywords": ["sqli", "powershell.exe", "encoded"],
    },
]

# ============================================================
# 假阳模板（误报场景）—— 每个模板描述一种正常业务模式
# ============================================================

FP_TEMPLATES: list[dict[str, Any]] = [
    {
        "source": "ids", "severity": "low", "protocol": "TCP",
        "rule_name": "Possible port scan",
        "description": "运维主机 health check 脚本 nightly monitor，对域控固定端口健康检查",
        "keywords": ["health check", "nightly", "监控", "健康检查"],
    },
    {
        "source": "ndr", "severity": "low", "protocol": "HTTPS",
        "rule_name": "CDN origin pull",
        "description": "CDN 回源流量，cron 定时任务 cdn-refresh，15 分钟固定周期刷新缓存",
        "keywords": ["cron", "定时", "cdn"],
    },
    {
        "source": "siem", "severity": "info", "protocol": "HTTPS",
        "rule_name": "Repetitive logins internal",
        "description": "可用性探针 availability probe，服务账号定时健康检查，每分钟固定 6 次成功登录",
        "keywords": ["可用性探针", "定时", "监控"],
    },
    {
        "source": "edr", "severity": "low", "protocol": None,
        "rule_name": "PowerShell invocation",
        "description": "签名验证通过的备份脚本 dbbackup.ps1，cron 每日定时执行，监控范畴",
        "keywords": ["签名验证通过", "定时", "监控"],
    },
    {
        "source": "ids", "severity": "info", "protocol": "TCP",
        "rule_name": "Health probe traffic",
        "description": "k8s liveness probe，health check 每 10 秒定时探测，监控用，可用性探针",
        "keywords": ["health check", "定时", "监控", "可用性探针"],
    },
    {
        "source": "ndr", "severity": "low", "protocol": "HTTPS",
        "rule_name": "Github git operations",
        "description": "开发主机拉取代码，访问 github CDN 节点，weekly 周期性的正常业务",
        "keywords": ["cdn", "定时"],
    },
    {
        "source": "siem", "severity": "info", "protocol": "TCP",
        "rule_name": "DB monitor heartbeat",
        "description": "DB 监控探针，health check 心跳，定时 1 秒间隔的可用性探针",
        "keywords": ["health check", "监控", "定时", "探针", "可用性探针"],
    },
    {
        "source": "edr", "severity": "low", "protocol": None,
        "rule_name": "Scheduled backup job",
        "description": "DBA 定时巡检脚本，cron 作业，监控数据库健康，签名验证通过",
        "keywords": ["定时", "监控", "签名验证通过", "cron"],
    },
    {
        "source": "ids", "severity": "info", "protocol": "TCP",
        "rule_name": "Load balancer health check",
        "description": "LB 健康检查，每 5 秒 availability probe，监控后端服务状态，可用性探针",
        "keywords": ["availability probe", "监控", "健康检查", "定时"],
    },
    {
        "source": "ndr", "severity": "low", "protocol": "HTTPS",
        "rule_name": "DNS resolver pool",
        "description": "CDN 边缘节点定时回源，cron 调度，监控任务触发",
        "keywords": ["cdn", "cron", "定时", "监控"],
    },
]

# IP / 端口池
# 注：保留 IP（10.x/192.0.2.x/203.0.113.x/198.51.100.x）严格区分内外网，
# 避免 LLM 因"目的 IP 是 TEST-NET 保留地址但标为内网"这种数据矛盾而判待查。
_INTERNAL_IPS = ["10.20.30.5", "10.20.33.51", "10.20.40.7", "10.20.35.10", "10.20.31.18"]
_EXTERNAL_IPS = [
    "185.220.101.34", "45.137.21.9", "91.219.236.7",
    "193.27.228.142", "146.70.124.55", "81.17.30.158",
]

# protocol ↔ port 的合理映射（避免"HTTPS 到 22 端口"这类矛盾）
_PROTOCOL_PORT: dict[str, list[int]] = {
    "TCP": [4444, 8080, 3389, 22],
    "HTTPS": [443],
    "HTTP": [80, 8080],
    "SMB": [445],
    "LDAP": [389],
    "RDP": [3389],
    "SSH": [22],
    "PostgreSQL": [5432],
    "MySQL": [3306],
    "Redis": [6379],
}


def _pick_ip(internal: bool, rng: random.Random) -> str:
    pool = _INTERNAL_IPS if internal else _EXTERNAL_IPS
    return rng.choice(pool)


def _gen_id(prefix: str, idx: int) -> str:
    return f"{prefix}-{idx:03d}"


def _expand_template(
    template: dict[str, Any], idx: int, label: str, rng: random.Random
) -> dict[str, Any]:
    """把模板填充成一条具体告警。"""
    is_tp = label == "真阳"
    src_ip = _pick_ip(internal=True, rng=rng)
    # 真阳 → 外网目的；假阳 → 内网目的（业务流量）
    dst_ip = _pick_ip(internal=(not is_tp and rng.random() < 0.8), rng=rng)

    # protocol 跟随模板；若模板没有就根据 label 选合适的协议
    proto = template.get("protocol")
    if proto is None:
        proto = rng.choice(["TCP", "HTTPS"]) if is_tp else rng.choice(["HTTPS", "TCP", "SSH"])
    proto = "TCP" if proto == "TCP" else proto
    # port 必须与 protocol 自洽
    dst_port = rng.choice(_PROTOCOL_PORT.get(proto, [443]))
    src_port = rng.randint(49152, 65535)
    ts = datetime(2026, 7, 18, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
    ts -= timedelta(minutes=idx)

    rule = template["rule_name"].format(dst_ip=dst_ip, src_ip=src_ip)
    desc = template["description"].format(dst_ip=dst_ip, src_ip=src_ip, dst_port=dst_port)

    return {
        "alert_id": _gen_id("EVTP" if is_tp else "EVFP", idx),
        "timestamp": ts.isoformat() + "Z",
        "source": template["source"],
        "severity": template["severity"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "rule_name": rule,
        "description": desc,
        "raw_payload": {},
        "label": label,
    }


def generate_eval_dataset(
    n_per_class: int = 20, seed: int = 202614
) -> list[dict[str, Any]]:
    """生成评测数据集。

    参数：
        n_per_class: 每类（真阳/假阳）生成多少条；默认 20 → 总 40 条
        seed: 随机种子，固定保证可复现
    """
    rng = random.Random(seed)
    out: list[dict[str, Any]] = []

    # 1) 先加载 10 条手工种子样本
    seeds = json.loads(DEFAULT_DATASET.read_text(encoding="utf-8"))["alerts"]
    out.extend(seeds)

    # 2) 模板变体：真阳/假阳各 n_per_class 条
    for i in range(n_per_class):
        tp_tpl = TP_TEMPLATES[i % len(TP_TEMPLATES)]
        fp_tpl = FP_TEMPLATES[i % len(FP_TEMPLATES)]
        out.append(_expand_template(tp_tpl, i + 1, "真阳", rng))
        out.append(_expand_template(fp_tpl, i + 1, "假阳", rng))

    return out


def _main() -> None:
    """命令行入口：python -m app.data.generator"""
    data = generate_eval_dataset()
    EVAL_DATASET.write_text(
        json.dumps({"alerts": data}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tp = sum(1 for a in data if a["label"] == "真阳")
    fp = sum(1 for a in data if a["label"] == "假阳")
    print(f"=== 生成评测数据集 ===")
    print(f"输出: {EVAL_DATASET.name}")
    print(f"总数: {len(data)} (真阳 {tp} / 假阳 {fp})")
    print(f"种子样本: 10，模板生成: {len(data) - 10}")


if __name__ == "__main__":
    _main()
