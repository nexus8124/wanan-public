"""Command-line management for the local security knowledge index."""

from __future__ import annotations

import argparse
import json

from app.rag.service import get_rag_service
from app.rag.quality import audit_retrieval


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage the local security RAG index")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build/update the local index")
    build.add_argument("--playbooks")
    build.add_argument("--sigma")
    build.add_argument("--attack-stix")
    build.add_argument("--attack-groups", dest="attack_groups",
                       help="path to MITRE ATT&CK STIX file for group loading")
    build.add_argument("--attack-malware", dest="attack_malware",
                       help="path to MITRE ATT&CK STIX file for malware loading")
    build.add_argument("--attack-tools", dest="attack_tools",
                       help="path to MITRE ATT&CK STIX file for tool loading")
    build.add_argument("--attack-mitigations", dest="attack_mitigations",
                       help="path to MITRE ATT&CK STIX file for mitigation loading")

    search = subparsers.add_parser("search", help="test hybrid retrieval")
    search.add_argument("query")
    search.add_argument("--source", action="append", dest="sources")
    search.add_argument("--top-k", type=int, default=5)

    subparsers.add_parser("status", help="show index status")
    subparsers.add_parser(
        "audit", help="run deterministic alert-to-knowledge coverage checks"
    )
    args = parser.parse_args()
    service = get_rag_service()

    if args.command == "build":
        # Attack STIX path also feeds groups/malware/tools/mitigations when
        # specific flags are not provided, keeping backward compatibility.
        attack_path = args.attack_stix
        result = service.bootstrap(
            playbook_path=args.playbooks,
            sigma_path=args.sigma,
            attack_stix_path=attack_path,
        )
        # If explicit per-type flags are given, reload those types too.
        extra_types = 0
        if args.attack_groups:
            extra_types += len(load_attack_groups(args.attack_groups))
        if args.attack_malware:
            extra_types += len(load_attack_malware(args.attack_malware))
        if args.attack_tools:
            extra_types += len(load_attack_tools(args.attack_tools))
        if args.attack_mitigations:
            extra_types += len(load_attack_mitigations(args.attack_mitigations))
        if extra_types:
            result["extra_types_indexed"] = extra_types
            result["counts"] = service.store.count_by_source()
            result["total_chunks"] = sum(result["counts"].values())
    elif args.command == "search":
        result = service.search(
            args.query, sources=args.sources, top_k=args.top_k
        ).model_dump(mode="json")
    elif args.command == "status":
        result = service.status()
    else:
        result = audit_retrieval(service)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "audit" and result["passed"] != result["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
