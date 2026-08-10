from __future__ import annotations

import asyncio

from app.api import stream as stream_api


def test_stream_graph_enables_multi_agent_as_independent_strategy(monkeypatch):
    captured: dict = {}

    class FakeGraph:
        def stream(self, state, *, config, stream_mode):
            assert state == {"alert": {"alert_id": "stream-test"}}
            assert config == {"recursion_limit": 25}
            assert stream_mode == "updates"
            yield {
                "multi_agent_plan": {
                    "multi_agent_steps": [],
                    "progress_ledger": {"status": "investigating"},
                }
            }

    def fake_build_graph(**kwargs):
        captured.update(kwargs)
        return FakeGraph()

    monkeypatch.setattr(stream_api, "build_graph", fake_build_graph)
    monkeypatch.setattr(stream_api, "get_llm", lambda **kwargs: object())

    async def collect_events():
        return [
            event
            async for event in stream_api._stream_graph(
                {"alert_id": "stream-test"},
                True,
                enable_rag=True,
                enable_multi_agent=True,
                provider="deepseek",
                model="deepseek-v4-flash",
            )
        ]

    events = asyncio.run(collect_events())

    assert captured["enable_react"] is False
    assert captured["enable_multi_agent"] is True
    assert captured["force_multi_agent"] is True
    assert captured["enable_rag"] is True
    assert events[0]["event"] == "multi_agent_plan"
    assert events[-1]["event"] == "done"
