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
import time

import pytest

from ai_chat import RagnarChat, DocIndex, TOOLS

DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")


class ScriptedAI:
    """Fake AIService that returns a preset sequence of model replies and records
    the message list it was handed on each call (for asserting context)."""

    model = "scripted"

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0
        self.seen = []   # the messages list handed to each call

    def chat_messages(self, messages, max_tokens=None):
        self.calls += 1
        self.seen.append([dict(m) for m in messages])
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


def test_doc_index_rebuilds_on_change(tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    (d / "a.md").write_text("# Alpha\nThe frobnicator handles zephyr widgets.\n")
    idx = DocIndex(str(d))
    assert idx.search("zephyr widgets", k=1)
    assert not idx.search("quasar modulator", k=1)
    # Edit the doc; the index must pick it up without a fresh object. Push the
    # mtimes clearly past the last build so the >0.5s rebuild guard fires (in
    # production docs never change sub-second, which is what the guard assumes).
    (d / "a.md").write_text("# Alpha\nThe quasar modulator aligns the array.\n")
    future = time.time() + 100
    os.utime(str(d / "a.md"), (future, future))
    os.utime(str(d), (future, future))
    hits = idx.search("quasar modulator", k=1)
    assert hits and "quasar" in hits[0]["text"].lower()


def test_idf_prefers_specific_terms(tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    # "network" is ubiquitous; "wardriving" is rare — a query mentioning both
    # should rank the wardriving doc first thanks to IDF weighting.
    for i in range(6):
        (d / f"common{i}.md").write_text(f"# Doc {i}\nThe network scan network node.\n")
    (d / "special.md").write_text("# Special\nWardriving network with GPS.\n")
    idx = DocIndex(str(d))
    hits = idx.search("wardriving network", k=1)
    assert hits and hits[0]["file"] == "special.md"


# --------------------------------------------------------------------------- #
# Context handling
# --------------------------------------------------------------------------- #
def test_history_is_filtered_to_user_and_assistant():
    chat = make_chat(["ok"])
    history = [
        {"role": "system", "content": "SHOULD NOT LEAK"},
        {"role": "user", "content": "earlier question"},
        {"role": "assistant", "content": "earlier answer"},
        {"role": "tool", "content": "SHOULD NOT LEAK"},
        {"role": "user", "content": ""},  # empty dropped
    ]
    chat.run(history, "now", cookie="")
    msgs = chat.ai.seen[0]
    roles = [m["role"] for m in msgs]
    # exactly one system message (our prompt), then the two valid history turns
    assert roles.count("system") == 1
    contents = " ".join(m["content"] for m in msgs)
    assert "SHOULD NOT LEAK" not in contents
    assert "earlier question" in contents and "earlier answer" in contents


def test_observation_is_truncated():
    big = {"blob": "x" * 10000}

    def dispatch(tool, args, cookie):
        return {"ok": True, "data": big}

    chat = make_chat(
        ['<tool>{"tool":"get_network_devices","args":{}}</tool>', "done summarizing"],
        dispatch=dispatch,
    )
    chat.run([], "read devices", cookie="")
    # Second model call carries the observation; it must be capped.
    second = chat.ai.seen[1]
    obs = second[-1]["content"]
    assert obs.startswith("<result>")
    assert len(obs) <= RagnarChat.OBS_LIMIT + 64
    assert "truncated" in obs


def test_action_error_is_flagged_and_loop_continues():
    def dispatch(tool, args, cookie):
        return {"ok": False, "error": "nmap not installed"}

    chat = make_chat(
        ['<tool>{"tool":"run_network_scan","args":{}}</tool>',
         "I couldn't scan — nmap looks missing."],
        dispatch=dispatch,
    )
    res = chat.run([], "scan", cookie="")
    assert res["actions"][0]["ok"] is False
    assert res["actions"][0]["summary"].startswith("✗")
    assert "nmap" in res["reply"]


def test_empty_message_short_circuits_without_calling_model():
    chat = make_chat(["should not be used"])
    res = chat.run([], "   ", cookie="")
    assert res["actions"] == []
    assert chat.ai.calls == 0
    assert res["reply"]


def test_model_returning_none_is_handled():
    class NoneAI:
        model = "none"
        def chat_messages(self, messages, max_tokens=None):
            return None
    chat = RagnarChat(NoneAI(), DOCS_DIR, lambda t, a, c: {"ok": True})
    res = chat.run([], "anything", cookie="")
    assert res["actions"] == []
    assert "did not respond" in res["reply"].lower()


def test_every_action_tool_is_documented():
    for name, spec in TOOLS.items():
        assert spec.get("desc"), f"{name} missing description"
        assert "action" in spec, f"{name} missing action flag"
