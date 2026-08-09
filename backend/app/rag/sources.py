"""Knowledge-source adapters for playbooks, Sigma, and ATT&CK STIX."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.rag.models import KnowledgeChunk


@lru_cache(maxsize=8)
def _load_stix_objects(path_text: str, signature: tuple[int, int]) -> tuple[dict[str, Any], ...]:
    """Parse a STIX file/directory once per file signature during a bootstrap."""
    source_path = Path(path_text)
    candidates = (
        sorted(source_path.rglob("*.json"))
        if source_path.is_dir()
        else [source_path]
    )
    objects: list[dict[str, Any]] = []
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("objects"), list):
            values = payload["objects"]
        elif isinstance(payload, list):
            values = payload
        else:
            values = [payload]
        objects.extend(item for item in values if isinstance(item, dict))
    return tuple(objects)


def _stix_objects(path: str | Path) -> tuple[dict[str, Any], ...]:
    source_path = Path(path)
    try:
        stat = source_path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return ()
    return _load_stix_objects(str(source_path.resolve()), signature)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{key}: {_as_text(item)}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(f"- {_as_text(item)}" for item in value)
    return str(value)


def _local_uri(root: Path, path: Path, scheme: str) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.name
    return f"{scheme}://{relative}"


def load_playbooks(root: str | Path) -> list[KnowledgeChunk]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    chunks: list[KnowledgeChunk] = []
    for path in sorted(root_path.rglob("*.y*ml")):
        for index, document in enumerate(yaml.safe_load_all(path.read_text("utf-8"))):
            if not isinstance(document, dict):
                continue
            playbook_id = str(document.get("id") or f"{path.stem}-{index + 1}")
            title = str(document.get("title") or playbook_id)
            if document.get("content"):
                sections = [_as_text(document["content"])]
            else:
                sections = [
                    f"适用告警:\n{_as_text(document.get('applies_to'))}",
                    f"所需证据:\n{_as_text(document.get('required_evidence'))}",
                    f"常见正常解释:\n{_as_text(document.get('benign_explanations'))}",
                    f"研判条件:\n{_as_text(document.get('decision'))}",
                    f"处置建议:\n{_as_text(document.get('response'))}",
                    _as_text(document.get("notes")),
                ]
            chunks.append(
                KnowledgeChunk(
                    knowledge_id=f"KB-PLAYBOOK-{playbook_id.upper()}",
                    source="playbook",
                    title=title,
                    content="\n\n".join(section for section in sections if section.strip()),
                    source_uri=_local_uri(root_path, path, "playbook"),
                    version=str(document.get("version") or "1"),
                    metadata={
                        "applies_to": document.get("applies_to") or [],
                        "tags": document.get("tags") or [],
                    },
                ).with_checksum()
            )
    return chunks


def load_sigma_rules(root: str | Path) -> list[KnowledgeChunk]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    chunks: list[KnowledgeChunk] = []
    for path in sorted(root_path.rglob("*.y*ml")):
        try:
            documents = list(yaml.safe_load_all(path.read_text("utf-8")))
        except (OSError, yaml.YAMLError):
            continue
        for index, rule in enumerate(documents):
            if not isinstance(rule, dict) or not rule.get("title"):
                continue
            rule_id = str(rule.get("id") or f"{path.stem}-{index + 1}")
            content = "\n".join(
                [
                    f"描述: {_as_text(rule.get('description'))}",
                    f"日志源: {_as_text(rule.get('logsource'))}",
                    f"检测逻辑: {_as_text(rule.get('detection'))}",
                    f"已知误报: {_as_text(rule.get('falsepositives'))}",
                    f"等级: {_as_text(rule.get('level'))}",
                    f"标签: {_as_text(rule.get('tags'))}",
                    f"参考: {_as_text(rule.get('references'))}",
                ]
            )
            chunks.append(
                KnowledgeChunk(
                    knowledge_id=f"KB-SIGMA-{rule_id.upper()}",
                    source="sigma",
                    title=str(rule["title"]),
                    content=content,
                    source_uri=_local_uri(root_path, path, "sigma"),
                    version=str(rule.get("modified") or rule.get("date") or ""),
                    metadata={
                        "rule_id": rule_id,
                        "status": rule.get("status"),
                        "level": rule.get("level"),
                        "logsource": rule.get("logsource") or {},
                        "tags": rule.get("tags") or [],
                    },
                ).with_checksum()
            )
    return chunks


def _external_id(obj: dict[str, Any]) -> str:
    for reference in obj.get("external_references") or []:
        external_id = reference.get("external_id")
        if external_id:
            return str(external_id)
    return str(obj.get("id") or "")


def load_attack_stix(path: str | Path) -> list[KnowledgeChunk]:
    """Load Enterprise ATT&CK attack-pattern objects from a STIX bundle."""

    source_path = Path(path)
    if not source_path.exists():
        return []
    chunks: list[KnowledgeChunk] = []
    for obj in _stix_objects(source_path):
        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        technique_id = _external_id(obj)
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
            continue
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases") or []
            if phase.get("phase_name")
        ]
        reference_url = next(
            (
                ref.get("url")
                for ref in obj.get("external_references") or []
                if ref.get("external_id") == technique_id and ref.get("url")
            ),
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        )
        content = "\n".join(
            [
                f"ATT&CK 技术: {technique_id} {obj.get('name', '')}",
                f"战术: {', '.join(tactics)}",
                f"平台: {', '.join(obj.get('x_mitre_platforms') or [])}",
                str(obj.get("description") or ""),
            ]
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-ATTCK-{technique_id}",
                source="mitre_attack",
                title=f"{technique_id} {obj.get('name', '')}".strip(),
                content=content,
                source_uri=str(reference_url),
                version=str(obj.get("modified") or obj.get("created") or ""),
                metadata={
                    "technique_id": technique_id,
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms") or [],
                    "stix_id": obj.get("id"),
                },
            ).with_checksum()
        )
    return chunks


def load_attack_groups(path: str | Path) -> list[KnowledgeChunk]:
    """Load MITRE ATT&CK intrusion-set (threat-actor group) objects from a STIX bundle."""
    source_path = Path(path)
    if not source_path.exists():
        return []
    objects = _stix_objects(source_path)
    chunks: list[KnowledgeChunk] = []
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or obj.get("type") != "intrusion-set"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        group_id = _external_id(obj) or str(obj.get("id", ""))
        name = str(obj.get("name", group_id))
        aliases = obj.get("aliases") or []
        description = str(obj.get("description") or "")
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases") or []
            if phase.get("phase_name")
        ]
        references = [
            str(ref.get("url"))
            for ref in obj.get("external_references") or []
            if ref.get("url")
        ]
        content = "\n".join(
            part
            for part in (
                f"威胁行为者: {name}",
                f"ID: {group_id}",
                f"别名: {', '.join(str(a) for a in aliases)}" if aliases else "",
                f"战术: {', '.join(tactics)}" if tactics else "",
                description,
                "参考:\n" + "\n".join(references) if references else "",
            )
            if part
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-ATTCK-GROUP-{group_id.upper()}",
                source="mitre_attack",
                title=name,
                content=content,
                source_uri=str(
                    next(
                        (ref.get("url") for ref in obj.get("external_references") or [] if ref.get("url")),
                        f"https://attack.mitre.org/groups/{group_id.replace('.', '/')}/",
                    )
                ),
                version=str(obj.get("modified") or obj.get("created") or ""),
                metadata={
                    "group_id": group_id,
                    "aliases": [str(a) for a in aliases],
                    "tactics": tactics,
                    "stix_id": obj.get("id"),
                },
            ).with_checksum()
        )
    return chunks


def load_attack_malware(path: str | Path) -> list[KnowledgeChunk]:
    """Load MITRE ATT&CK malware objects from a STIX bundle."""
    source_path = Path(path)
    if not source_path.exists():
        return []
    objects = _stix_objects(source_path)
    chunks: list[KnowledgeChunk] = []
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or obj.get("type") != "malware"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        malware_id = _external_id(obj) or str(obj.get("id", ""))
        name = str(obj.get("name", malware_id))
        malware_types = obj.get("malware_types") or []
        description = str(obj.get("description") or "")
        references = [
            str(ref.get("url"))
            for ref in obj.get("external_references") or []
            if ref.get("url")
        ]
        content = "\n".join(
            part
            for part in (
                f"恶意软件: {name}",
                f"ID: {malware_id}",
                f"类型: {', '.join(str(t) for t in malware_types)}" if malware_types else "",
                description,
                "参考:\n" + "\n".join(references) if references else "",
            )
            if part
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-ATTCK-MALWARE-{malware_id.upper()}",
                source="mitre_attack",
                title=name,
                content=content,
                source_uri=str(
                    next(
                        (ref.get("url") for ref in obj.get("external_references") or [] if ref.get("url")),
                        "",
                    )
                ),
                version=str(obj.get("modified") or obj.get("created") or ""),
                metadata={
                    "malware_id": malware_id,
                    "malware_types": [str(t) for t in malware_types],
                    "stix_id": obj.get("id"),
                },
            ).with_checksum()
        )
    return chunks


def load_attack_tools(path: str | Path) -> list[KnowledgeChunk]:
    """Load MITRE ATT&CK tool objects from a STIX bundle."""
    source_path = Path(path)
    if not source_path.exists():
        return []
    objects = _stix_objects(source_path)
    chunks: list[KnowledgeChunk] = []
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or obj.get("type") != "tool"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        tool_id = _external_id(obj) or str(obj.get("id", ""))
        name = str(obj.get("name", tool_id))
        tool_types = obj.get("tool_types") or []
        description = str(obj.get("description") or "")
        references = [
            str(ref.get("url"))
            for ref in obj.get("external_references") or []
            if ref.get("url")
        ]
        content = "\n".join(
            part
            for part in (
                f"工具: {name}",
                f"ID: {tool_id}",
                f"类型: {', '.join(str(t) for t in tool_types)}" if tool_types else "",
                description,
                "参考:\n" + "\n".join(references) if references else "",
            )
            if part
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-ATTCK-TOOL-{tool_id.upper()}",
                source="mitre_attack",
                title=name,
                content=content,
                source_uri=str(
                    next(
                        (ref.get("url") for ref in obj.get("external_references") or [] if ref.get("url")),
                        "",
                    )
                ),
                version=str(obj.get("modified") or obj.get("created") or ""),
                metadata={
                    "tool_id": tool_id,
                    "tool_types": [str(t) for t in tool_types],
                    "stix_id": obj.get("id"),
                },
            ).with_checksum()
        )
    return chunks


def load_attack_mitigations(path: str | Path) -> list[KnowledgeChunk]:
    """Load MITRE ATT&CK course-of-action (mitigation) objects from a STIX bundle."""
    source_path = Path(path)
    if not source_path.exists():
        return []
    objects = _stix_objects(source_path)
    chunks: list[KnowledgeChunk] = []
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or obj.get("type") != "course-of-action"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        mit_id = _external_id(obj) or str(obj.get("id", ""))
        name = str(obj.get("name", mit_id))
        description = str(obj.get("description") or "")
        references = [
            str(ref.get("url"))
            for ref in obj.get("external_references") or []
            if ref.get("url")
        ]
        content = "\n".join(
            part
            for part in (
                f"缓解措施: {name}",
                f"ID: {mit_id}",
                description,
                "参考:\n" + "\n".join(references) if references else "",
            )
            if part
        )
        chunks.append(
            KnowledgeChunk(
                knowledge_id=f"KB-ATTCK-MITIGATION-{mit_id.upper()}",
                source="mitre_attack",
                title=name,
                content=content,
                source_uri=str(
                    next(
                        (ref.get("url") for ref in obj.get("external_references") or [] if ref.get("url")),
                        "",
                    )
                ),
                version=str(obj.get("modified") or obj.get("created") or ""),
                metadata={
                    "mitigation_id": mit_id,
                    "stix_id": obj.get("id"),
                },
            ).with_checksum()
        )
    return chunks


def builtin_attack_seed() -> list[KnowledgeChunk]:
    """Small official-link seed so a fresh clone has a useful offline index."""

    rows = [
        (
            "T1059.001",
            "PowerShell",
            "execution",
            "PowerShell 可被用于执行命令、下载载荷和编码脚本。仅出现 PowerShell 名称不足以证明攻击，"
            "应结合父子进程、命令行、签名、用户和网络行为。",
        ),
        (
            "T1110.001",
            "Password Guessing",
            "credential-access",
            "密码猜测通常表现为同一来源在短时间内对多个账户或同一账户重复认证失败。"
            "单次失败登录、失效服务账号和配置错误脚本可能是正常原因。",
        ),
        (
            "T1021.002",
            "SMB/Windows Admin Shares",
            "lateral-movement",
            "SMB 管理共享可用于远程服务执行和横向移动。需要结合账户、源主机、服务创建、"
            "共享访问以及后续进程证据，合法运维工具也可能产生相似行为。",
        ),
        (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
            "针对公网应用的漏洞利用可能包含注入、路径遍历或远程代码执行特征。"
            "扫描器、WAF 测试和资产巡检也会触发相似规则。",
        ),
        (
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "攻击者可使用 HTTP/HTTPS 进行命令与控制。正常浏览、更新、CDN 和 API 流量十分常见，"
            "应结合域名信誉、周期性、进程归属和数据量判断。",
        ),
        (
            "T1218.010",
            "Regsvr32",
            "defense-evasion",
            "Regsvr32 可代理执行代码。远程 SCT、异常父进程和外连是较强风险信号，"
            "但软件安装、组件注册也可能是合法使用。",
        ),
        (
            "T1041",
            "Exfiltration Over C2 Channel",
            "exfiltration",
            "通过已有 C2 通道外传数据通常需要异常目标、数据量或编码载荷等证据，"
            "不能仅凭一次外连确定数据渗出。",
        ),
        (
            "T1566",
            "Phishing",
            "initial-access",
            "钓鱼常通过附件或链接诱导执行。Office 启动脚本解释器、下载器或异常外连"
            "可以增强攻击假设，单独的邮件或文档访问不是充分证据。",
        ),
        (
            "T1046",
            "Network Service Discovery",
            "discovery",
            "网络服务发现通常表现为短时间探测多个端口或主机。单次连接失败、"
            "健康检查和授权资产扫描不应直接定性为恶意扫描。",
        ),
        (
            "T1595",
            "Active Scanning",
            "reconnaissance",
            "外部主动扫描可能枚举公网服务、路径和漏洞。应区分未授权侦察、"
            "备案扫描器以及真正成功的漏洞利用，错误响应不代表入侵成功。",
        ),
        (
            "T1078",
            "Valid Accounts",
            "defense-evasion,persistence,privilege-escalation,initial-access",
            "攻击者可能使用有效账户登录。成功认证本身不是恶意证据；"
            "异常来源、失败后成功、越权操作和登录后行为才可增强失陷判断。",
        ),
        (
            "T1053.003",
            "Cron",
            "execution,persistence,privilege-escalation",
            "Cron 可用于周期执行和持久化，也广泛用于备份、监控和更新。"
            "必须核对任务内容、创建主体、文件路径和变更记录。",
        ),
        (
            "T1543.002",
            "Systemd Service",
            "persistence,privilege-escalation",
            "Systemd 服务可实现持久化。服务启停或参数首次出现不足以证明攻击，"
            "异常 unit、用户可写路径、未知二进制和无变更记录才是关键。",
        ),
        (
            "T1105",
            "Ingress Tool Transfer",
            "command-and-control",
            "攻击者可能把工具或载荷传入受害环境。下载 ELF/脚本需要结合来源、"
            "文件哈希、落地路径、后续执行和网络行为判断。",
        ),
        (
            "T1059.004",
            "Unix Shell",
            "execution",
            "Unix shell 可用于执行攻击命令，也用于正常管理与自动化。"
            "应结合调用主体、命令内容、TTY、父进程和后续影响。",
        ),
        (
            "T1548.003",
            "Sudo and Sudo Caching",
            "privilege-escalation,defense-evasion",
            "Sudo 可被用于提权，但成功 sudo/首次 sudo 也可能是合法维护。"
            "需核对原用户、目标命令、授权关系、时间和变更单。",
        ),
        (
            "T1068",
            "Exploitation for Privilege Escalation",
            "privilege-escalation",
            "提权漏洞利用应有崩溃、异常内核/进程行为或权限变化链条。"
            "单独的 UID 变化和管理员操作不足以证明漏洞利用。",
        ),
        (
            "T1027",
            "Obfuscated Files or Information",
            "defense-evasion",
            "编码、高熵和混淆可以隐藏恶意内容，但压缩包、令牌、CDN 和业务标识也可能高熵。"
            "必须解码内容并关联执行或通信证据。",
        ),
        (
            "T1204.002",
            "Malicious File",
            "execution",
            "恶意文件通常需要用户或进程触发执行。仅下载文件不足以证明执行，"
            "应确认文件类型、哈希、签名、父子进程和执行结果。",
        ),
        (
            "T1071.004",
            "DNS",
            "command-and-control",
            "DNS 可用于命令控制或隧道，但高熵、冷门 TLD 和新域名也常见于 CDN、"
            "更新和云服务。需要时序、编码、数据量和发起进程证据。",
        ),
    ]
    return [
        KnowledgeChunk(
            knowledge_id=f"KB-ATTCK-{technique_id}",
            source="mitre_attack",
            title=f"{technique_id} {name}",
            content=f"ATT&CK 技术: {technique_id} {name}\n战术: {tactic}\n{content}",
            source_uri=(
                "https://attack.mitre.org/techniques/"
                f"{technique_id.replace('.', '/')}/"
            ),
            version="offline-seed-v1",
            metadata={"technique_id": technique_id, "tactics": [tactic]},
        ).with_checksum()
        for technique_id, name, tactic, content in rows
    ]
