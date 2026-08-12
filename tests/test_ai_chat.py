"""Tests for the Ragnar dashboard chat assistant (ai_chat.py).

The assistant runs a small, model-agnostic agentic loop: it retrieves from the
docs/ folder and drives a curated allowlist of tools via a text protocol
(``<tool>{...}</tool>`` -> ``<result>...</result>``). These tests pin the two
things most likely to break silently: the tool-call **parser** (which must
tolerate nested braces, missing tags, and reject unknown tools) and the **loop**
(tool call -> observation -> final plain-language answer), plus that tool
execution is confined to the allowlist.
"""

import os

import pytest

from ai_chat import RagnarChat, DocIndex, TOOLS

DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")


class ScriptedAI:
    """Fake AIService that returns a preset sequence of model replies."""

    model = "scripted"

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def chat_messages(self, messages, max_tokens=None):
        self.calls += 1
        if self._replies:
            return self._replies.pop(0)
        return "done"


def make_chat(replies, dispatch=None):
    calls = []

    def default_dispatch(tool, args, cookie):
        calls.append((tool, args, cookie))
        return {"ok": True, "status": 200, "data": {"tool": tool, "args": args}}

    chat = RagnarChat(ScriptedAI(replies), DOCS_DIR, dispatch or default_dispatch)
    chat._dispatch_calls = calls  # type: ignore[attr-defined]
    return chat


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,expected", [
    ('<tool>{"tool":"get_incidents","args":{}}</tool>', ("get_incidents", {})),
    ('<tool>{"tool":"deep_scan_host","args":{"ip":"10.0.0.1"}}</tool>',
     ("deep_scan_host", {"ip": "10.0.0.1"})),
    ('sure: {"tool":"get_incidents","args":{}}', ("get_incidents", {})),          # no tags
    ('```\n{"tool":"run_network_scan","args":{}}\n```', ("run_network_scan", {})),  # fenced
    ('{"tool":"get_network_devices"}', ("get_network_devices", {})),               # no args key
])
def test_parse_valid_tool_calls(text, expected):
    assert RagnarChat._parse_tool_call(text) == expected


@pytest.mark.parametrize("text", [
    "just a plain english answer, no tool here",
    '{"tool":"rm_rf","args":{}}',          # unknown tool -> rejected
    '{"notatool":"x"}',
    "",
    '<tool>not json</tool>',
])
def test_parse_rejects_non_calls(text):
    assert RagnarChat._parse_tool_call(text) is None


def test_balanced_json_handles_nesting():
    s = 'x {"tool":"t","args":{"a":{"b":1}}} y'
    raw = RagnarChat._balanced_json(s, s.index("{"))
    assert raw == '{"tool":"t","args":{"a":{"b":1}}}'


# --------------------------------------------------------------------------- #
# Loop
# --------------------------------------------------------------------------- #
def test_loop_runs_tools_then_answers():
    chat = make_chat([
        '<tool>{"tool":"run_network_scan","args":{}}</tool>',
        '<tool>{"tool":"deep_scan_host","args":{"ip":"192.168.1.5"}}</tool>',
        "Found 3 hosts; .5 exposes SSH. Recommend key-only auth.",
    ])
    res = chat.run([], "scan then deep scan .5", cookie="session=abc")
    assert len(res["actions"]) == 2
    assert res["actions"][0]["tool"] == "run_network_scan"
    assert res["actions"][1]["args"] == {"ip": "192.168.1.5"}
    assert all(a["ok"] for a in res["actions"])
    assert "SSH" in res["reply"]
    # the cookie is forwarded to the dispatcher untouched
    assert chat._dispatch_calls[0][2] == "session=abc"


def test_plain_answer_no_tools():
    chat = make_chat(["Watchtower is Ragnar's passive alert aggregator."])
    res = chat.run([], "what is watchtower?", cookie="")
    assert res["actions"] == []
    assert "Watchtower" in res["reply"]


def test_unknown_tool_is_never_dispatched():
    # Model asks for a tool that isn't in the registry -> treated as a plain
    # answer, dispatcher never called.
    chat = make_chat(['<tool>{"tool":"delete_everything","args":{}}</tool>'])
    res = chat.run([], "wipe the box", cookie="")
    assert res["actions"] == []
    assert chat._dispatch_calls == []


def test_deep_scan_requires_ip_via_dispatcher():
    # The real dispatcher (not our fake) enforces the ip arg; here we just check
    # the loop faithfully forwards whatever args the model produced.
    seen = {}

    def dispatch(tool, args, cookie):
        seen["args"] = args
        return {"ok": False, "error": "deep_scan_host requires an 'ip' argument"}

    chat = make_chat(
        ['<tool>{"tool":"deep_scan_host","args":{}}</tool>', "I need a target IP."],
        dispatch=dispatch,
    )
    res = chat.run([], "deep scan", cookie="")
    assert seen["args"] == {}
    assert res["actions"][0]["ok"] is False


def test_step_cap_forces_final_answer():
    # Model keeps asking for tools forever; the loop must stop and force an answer.
    chat = make_chat(['<tool>{"tool":"get_scan_status","args":{}}</tool>'] * 20
                     + ["final summary"])
    res = chat.run([], "loop forever", cookie="")
    assert len(res["actions"]) == RagnarChat.MAX_STEPS
    assert res["reply"]  # a non-empty final answer was produced


def test_search_docs_handled_locally_not_dispatched():
    chat = make_chat([
        '<tool>{"tool":"search_docs","args":{"query":"wardriving gps"}}</tool>',
        "Wardriving uses a USB GPS puck.",
    ])
    res = chat.run([], "how does wardriving gps work?", cookie="")
    # search_docs must NOT reach the external dispatcher
    assert chat._dispatch_calls == []
    assert res["actions"][0]["tool"] == "search_docs"
    assert res["actions"][0]["ok"] is True


# --------------------------------------------------------------------------- #
# Doc index
# --------------------------------------------------------------------------- #
def test_doc_index_builds_and_searches():
    idx = DocIndex(DOCS_DIR)
    assert len(idx.chunks) > 0
    hits = idx.search("mesh file transfer between units", k=3)
    assert hits, "expected doc hits for a mesh query"
    assert any("mesh" in h["file"].lower() for h in hits)


def test_every_action_tool_is_documented():
    for name, spec in TOOLS.items():
        assert spec.get("desc"), f"{name} missing description"
        assert "action" in spec, f"{name} missing action flag"
