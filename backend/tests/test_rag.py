from __future__ import annotations

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from app.agent.graph import judge_alert
from app.agent.nodes import (
    _parse_judgment_text,
    _rag_refinement_acceptance,
    make_rag_refine_node,
    make_rag_retrieve_node,
)
from app.agent.prompts import build_rag_refine_prompt
from app.models.llm import get_llm
from app.rag.quality import RETRIEVAL_QUALITY_CASES, audit_retrieval
from app.rag.service import RagService


def _service(tmp_path):
    return RagService(
        db_path=tmp_path / "rag.sqlite3",
        embedding_provider="hashing",
        auto_bootstrap=True,
    )


def test_rag_bootstrap_and_exact_attack_lookup(tmp_path):
    service = _service(tmp_path)
    status = service.status()
    assert status["counts"]["mitre_attack"] >= 20
    assert status["counts"]["playbook"] >= 19
    assert status["indexed_corpus_version"] == status["corpus_version"]

    result = service.search(
        "T1059.001 PowerShell EncodedCommand",
        sources=["mitre_attack"],
        min_score=0.0,
    )
    assert result.hits
    assert result.hits[0].knowledge_id == "KB-ATTCK-T1059.001"
    assert result.hits[0].exact_match is True


def test_rag_query_does_not_leak_evaluation_label(tmp_path):
    service = _service(tmp_path)
    query = service.build_alert_query(
        {
            "alert_id": "opaque-id",
            "label": "真阳",
            "rule_name": "Suspicious PowerShell",
            "description": "encoded command",
            "raw_payload": {
                "_evidence_ref": "private",
                "label": "假阳",
                "full_log": "PowerShell EncodedCommand",
            },
        },
        {"direction": "外连（内→外）"},
    )
    assert "真阳" not in query
    assert "假阳" not in query
    assert "private" not in query
    assert "PowerShell" in query


def test_graph_high_confidence_initial_judgment_skips_rag(tmp_path):
    service = _service(tmp_path)
    alert = {
        "alert_id": "RAG-DEMO-1",
        "timestamp": "2026-07-25T10:00:00Z",
        "source": "edr",
        "severity": "high",
        "src_ip": "10.20.1.10",
        "dst_ip": "203.0.113.8",
        "dst_port": 4444,
        "protocol": "TCP",
        "rule_name": "Suspicious PowerShell EncodedCommand",
        "description": "PowerShell encoded command followed by outbound C2",
        "raw_payload": {},
    }
    result = judge_alert(
        alert,
        llm=get_llm(mock=True),
        enable_react=False,
        enable_rag=True,
        rag_service=service,
    )
    assert result["rag_attempted"] is False
    assert result["rag_used"] is False
    assert result["knowledge_hits"] == []
    assert (
        result["retrieval_trace"]["skipped_reason"]
        == "high_confidence_initial_judgment"
    )
    assert result["judgment"] == result["initial_judgment"]
    assert result["evidence"] == []


def test_high_confidence_weak_signal_forces_guarded_rag_calibration(tmp_path):
    service = _service(tmp_path)
    node = make_rag_retrieve_node(service)
    result = node({
        "alert": {
            "alert_id": "RAG-WEAK-DNS",
            "rule_name": "ET INFO Observed DNS Query to .biz TLD",
            "description": "A workstation repeatedly queried one .biz domain",
            "protocol": "DNS",
            "dst_port": 53,
            "raw_payload": {},
        },
        "normalized_features": {"direction": "内网到外网"},
        "judgment": "真阳",
        "confidence": 0.95,
    })
    assert result["rag_attempted"] is True
    assert result["rag_used"] is True
    trace = result["retrieval_trace"]
    assert trace["trigger_reason"] == "weak_signal_calibration"
    assert trace["calibration"]["forced"] is True
    assert trace["calibration"]["profiles"] == ["dns_anomaly"]
    assert any(
        hit["knowledge_id"] == "KB-PLAYBOOK-PB-DNS-ANOMALY-001"
        for hit in result["knowledge_hits"]
    )


def test_high_confidence_false_positive_does_not_waste_forced_calibration(tmp_path):
    service = _service(tmp_path)
    node = make_rag_retrieve_node(service)
    result = node({
        "alert": {
            "alert_id": "RAG-WEAK-DNS-FP",
            "rule_name": "ET INFO Observed DNS Query to .biz TLD",
            "description": "A workstation queried one .biz domain",
            "protocol": "DNS",
            "dst_port": 53,
            "raw_payload": {},
        },
        "normalized_features": {"direction": "内网到外网"},
        "judgment": "假阳",
        "confidence": 0.95,
    })
    assert result["rag_attempted"] is False
    trace = result["retrieval_trace"]
    assert trace["trigger_reason"] == "high_confidence_initial_judgment"
    assert trace["calibration"]["eligible"] is True
    assert trace["calibration"]["forced"] is False
    assert (
        trace["calibration"]["force_suppressed_reason"]
        == "initial_verdict_not_true_positive"
    )


def test_high_confidence_web_enumeration_uses_normal_confidence_gate(tmp_path):
    service = _service(tmp_path)
    node = make_rag_retrieve_node(service)
    result = node({
        "alert": {
            "alert_id": "RAG-STRONG-WEB-SCAN",
            "rule_name": "Web server 400 error code",
            "description": "One source enumerated thousands of distinct paths",
            "protocol": "HTTP",
            "dst_port": 80,
            "raw_payload": {},
        },
        "normalized_features": {"direction": "外网到内网"},
        "judgment": "真阳",
        "confidence": 0.95,
    })
    assert result["rag_attempted"] is False
    trace = result["retrieval_trace"]
    assert trace["calibration"]["eligible"] is False
    assert trace["calibration"]["forced"] is False


def test_graph_low_confidence_sample_uses_strict_rag_without_forced_change(tmp_path):
    service = _service(tmp_path)
    alert = {
        "alert_id": "RAG-DEMO-2",
        "timestamp": "2026-07-25T10:00:00Z",
        "source": "ids",
        "severity": "medium",
        "src_ip": "10.20.1.10",
        "dst_ip": "203.0.113.8",
        "dst_port": 53,
        "protocol": "DNS",
        "rule_name": "Unusual DNS traffic",
        "description": "Workstation generated uncommon DNS requests",
        "raw_payload": {},
    }
    result = judge_alert(
        alert,
        llm=get_llm(mock=True),
        enable_react=False,
        enable_rag=True,
        rag_service=service,
    )
    assert result["rag_attempted"] is True
    assert result["rag_used"] is True
    assert result["knowledge_hits"]
    assert result["retrieval_trace"]["hit_count"] >= 1
    assert all(
        hit["knowledge_id"].startswith("KB-")
        for hit in result["knowledge_hits"]
    )
    assert set(result["retrieval_trace"]["routing"]["profiles"]) == {
        "dns_anomaly"
    }
    assert result["rag_refinement"]["attempted"] is True
    # The mock does not cite a KB item, so late fusion must preserve the
    # independently produced initial verdict.
    assert result["rag_refinement"]["accepted"] is False
    assert result["judgment"] == result["initial_judgment"]
    assert result["evidence"] == []


def test_alert_retrieval_does_not_cross_unrelated_security_domains(tmp_path):
    service = _service(tmp_path)
    retrieval = service.retrieve_for_alert(
        {
            "alert_id": "opaque-web",
            "rule_name": "WordPress scan",
            "description": "Repeated HTTP requests to WordPress plugin paths",
            "protocol": "HTTP",
            "dst_port": 80,
            "raw_payload": {},
        },
        {"direction": "外联（内→外）"},
    )
    allowed = {
        "KB-PLAYBOOK-PB-WEB-ATTACK-001",
        "KB-ATTCK-T1190",
        "KB-ATTCK-T1071.001",
    }
    assert retrieval.hits
    assert {hit.knowledge_id for hit in retrieval.hits} <= allowed
    assert "web_attack" in retrieval.routing["profiles"]


def test_ambiguous_alert_skips_alert_time_retrieval(tmp_path):
    service = _service(tmp_path)
    retrieval = service.retrieve_for_alert(
        {
            "alert_id": "opaque-unknown",
            "rule_name": "Generic anomaly",
            "description": "Value exceeded an adaptive threshold",
            "raw_payload": {},
        },
        {},
    )
    assert retrieval.hits == []
    assert retrieval.skipped_reason == "unsupported_or_ambiguous_behavior"


def test_bundled_soc_corpus_passes_retrieval_coverage_audit(tmp_path):
    service = _service(tmp_path)
    audit = audit_retrieval(service)
    assert audit["total"] == len(RETRIEVAL_QUALITY_CASES)
    assert audit["passed"] == audit["total"]
    assert audit["coverage"] == 1.0
    assert all(item["profiles"] for item in audit["details"])


def test_bundled_corpus_contains_no_benchmark_answer_markers(tmp_path):
    service = _service(tmp_path)
    service.ensure_ready()
    rows = service.store._candidate_rows(None)
    corpus = "\n".join(
        f"{row['knowledge_id']} {row['title']} {row['content']}"
        for row in rows
    )
    assert "TP-001" not in corpus
    assert "FP-001" not in corpus
    assert "true_label" not in corpus
    assert "expected_label" not in corpus


def test_rag_guard_blocks_regressions_and_allows_grounded_pending_resolution():
    accepted, reason = _rag_refinement_acceptance(
        initial_judgment="真阳",
        initial_confidence=0.75,
        candidate_judgment="待查",
        candidate_confidence=0.4,
        valid_citations=["KB-PLAYBOOK-PB-WEB-ATTACK-001"],
    )
    assert accepted is False
    assert reason == "resolved_verdict_cannot_be_downgraded_to_pending"

    accepted, reason = _rag_refinement_acceptance(
        initial_judgment="待查",
        initial_confidence=0.4,
        candidate_judgment="真阳",
        candidate_confidence=0.85,
        valid_citations=["KB-ATTCK-T1190"],
    )
    assert accepted is True
    assert reason == "knowledge_grounded_refinement"


def test_rag_guard_allows_only_strong_playbook_backed_weak_signal_downgrade():
    accepted, reason = _rag_refinement_acceptance(
        initial_judgment="真阳",
        initial_confidence=0.95,
        candidate_judgment="假阳",
        candidate_confidence=0.9,
        valid_citations=["KB-PLAYBOOK-PB-DNS-ANOMALY-001"],
        weak_signal_calibration=True,
    )
    assert accepted is True
    assert reason == "weak_signal_false_positive_calibration"

    accepted, reason = _rag_refinement_acceptance(
        initial_judgment="真阳",
        initial_confidence=0.95,
        candidate_judgment="假阳",
        candidate_confidence=0.9,
        valid_citations=["KB-ATTCK-T1071.004"],
        weak_signal_calibration=True,
    )
    assert accepted is False
    assert reason == "opposite_verdict_requires_exceptional_confidence"

    accepted, reason = _rag_refinement_acceptance(
        initial_judgment="假阳",
        initial_confidence=0.95,
        candidate_judgment="真阳",
        candidate_confidence=0.99,
        valid_citations=["KB-PLAYBOOK-PB-DNS-ANOMALY-001"],
        weak_signal_calibration=True,
    )
    assert accepted is False
    assert reason == "opposite_verdict_requires_exceptional_confidence"


def test_rag_refine_prompt_explicitly_requests_complete_json_schema():
    prompt = build_rag_refine_prompt().invoke({
        "alert_json": "{}",
        "features_text": "(无)",
        "initial_judgment": "待查",
        "initial_confidence": 0.5,
        "initial_reason": "证据不足",
        "rag_context": "[KB-TEST] 测试知识",
    })
    rendered = "\n".join(str(message.content) for message in prompt.messages)
    assert "合法 JSON 对象" in rendered
    assert '"cited_knowledge"' in rendered
    assert '"confidence"' in rendered


def test_rag_refine_recovers_fenced_json_response():
    result = _parse_judgment_text(
        """```json
        {
          "cot": "安全知识与告警行为直接相关。",
          "judgment": "假阳",
          "confidence": "90%",
          "reason": "符合可核实的健康检查模式。",
          "cited_knowledge": ["KB-PLAYBOOK-PB-NETWORK-001"]
        }
        ```"""
    )
    assert result is not None
    assert result.judgment == "假阳"
    assert result.confidence == 0.9
    assert result.cot == ["安全知识与告警行为直接相关。"]


def test_rag_refine_uses_raw_response_when_langchain_parser_fails(
    monkeypatch,
):
    from app.agent import nodes

    raw = AIMessage(content="""```json
    {
      "cot": ["认证手册说明该模式属于正常成功登录。"],
      "judgment": "假阳",
      "confidence": 0.9,
      "reason": "成功认证且没有失败或攻击载荷。",
      "cited_knowledge": ["KB-PLAYBOOK-PB-AUTH-001"]
    }
    ```""")
    monkeypatch.setattr(
        nodes,
        "_bind_structured_output",
        lambda *_args, **_kwargs: RunnableLambda(
            lambda _inp, **_invoke_kwargs: {
                "raw": raw,
                "parsed": None,
                "parsing_error": ValueError("simulated parser failure"),
            }
        ),
    )
    node = make_rag_refine_node(get_llm(mock=True))
    out = node({
        "alert": {"alert_id": "RAG-RAW", "rule_name": "Authentication"},
        "normalized_features": {},
        "judgment": "待查",
        "confidence": 0.5,
        "reason": "证据不足",
        "initial_judgment": "待查",
        "initial_confidence": 0.5,
        "initial_reason": "证据不足",
        "rag_context": "[KB-PLAYBOOK-PB-AUTH-001] 认证研判手册",
        "knowledge_hits": [{
            "knowledge_id": "KB-PLAYBOOK-PB-AUTH-001",
        }],
        "execution_policy": {"max_llm_calls": 5},
        "llm_calls_used": 1,
        "cot_trace": [],
    })
    assert out["rag_refinement"]["accepted"] is True
    assert out["rag_refinement"]["parse_mode"] == "raw_recovered"
    assert out["judgment"] == "假阳"
    assert out["post_rag_judgment"] == "假阳"


def test_rag_refine_retries_without_json_mode_after_request_failure(
    monkeypatch,
):
    from app.agent import nodes

    monkeypatch.setattr(
        nodes,
        "_bind_structured_output",
        lambda *_args, **_kwargs: RunnableLambda(
            lambda _inp, **_invoke_kwargs: (_ for _ in ()).throw(
                ValueError("simulated response_format rejection")
            )
        ),
    )
    node = make_rag_refine_node(get_llm(mock=True))
    out = node({
        "alert": {
            "alert_id": "RAG-FALLBACK",
            "rule_name": "Health check",
            "description": "nightly monitor",
        },
        "normalized_features": {},
        "judgment": "待查",
        "confidence": 0.5,
        "reason": "证据不足",
        "initial_judgment": "待查",
        "initial_confidence": 0.5,
        "initial_reason": "证据不足",
        "rag_context": "[KB-PLAYBOOK-PB-NETWORK-001] health check",
        "knowledge_hits": [{
            "knowledge_id": "KB-PLAYBOOK-PB-NETWORK-001",
        }],
        "execution_policy": {"max_llm_calls": 5},
        "llm_calls_used": 1,
        "cot_trace": [],
    })
    assert out["rag_refinement"]["attempts"] == 2
    assert out["rag_refinement"]["parse_mode"] == "plain_json_fallback"
    assert out["rag_refinement"]["reason"] == "no_valid_knowledge_citation"
    assert out["post_rag_judgment"] == "待查"
