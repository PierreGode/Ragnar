"""Integration tests for the chat assistant's webapp seam (webapp_modern.py).

These exercise the parts ai_chat.py's own tests can't reach: the in-process
tool dispatch (``_chat_dispatch`` -> Flask ``test_client`` -> real endpoint),
the payload compaction (``_chat_compact``), and the ``/api/ai/chat`` endpoint
including its enable/ready gating.

Importing webapp_modern initialises a lot of subsystems; if that fails in a
bare environment we skip the whole module rather than error.
"""

import pytest

try:
    import webapp_modern as webapp
except Exception as exc:  # pragma: no cover - environment-dependent
    pytest.skip(f"webapp_modern unimportable here: {exc}", allow_module_level=True)


@pytest.fixture(autouse=True)
def _auth_off(monkeypatch):
    """Let internal test_client calls through before_request (no session in a
    unit test). Production auth is unaffected — this only patches the check."""
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)


class ScriptedAI:
    """Minimal stand-in for shared_data.ai_service."""
    model = "scripted"

    def __init__(self, replies):
        self._replies = list(replies)

    def is_enabled(self):
        return True

    def chat_messages(self, messages, max_tokens=None):
        return self._replies.pop(0) if self._replies else "done"


@pytest.fixture
def client():
    return webapp.app.test_client()


# --------------------------------------------------------------------------- #
# Compaction (pure function)
# --------------------------------------------------------------------------- #
def test_compact_devices_trims_fields_and_counts():
    raw = [{"ip": f"10.0.0.{i}", "hostname": "h", "vendor": "v", "status": "alive",
            "ports": ["22"], "threats": [], "secret_internal_field": "leak"}
           for i in range(90)]
    out = webapp._chat_compact("get_network_devices", raw)
    assert out["count"] == 90
    assert len(out["devices"]) == 60                     # capped
    assert set(out["devices"][0]) == {"ip", "hostname", "vendor", "status", "ports", "threats"}
    assert "secret_internal_field" not in out["devices"][0]


def test_compact_vulnerabilities():
    raw = {"vulnerabilities": [{"host": "10.0.0.5", "port": 445, "service": "smb",
                                "severity": "high", "vulnerability": "x", "extra": "y"}
                               for _ in range(70)]}
    out = webapp._chat_compact("get_vulnerabilities", raw)
    assert out["count"] == 70 and len(out["vulnerabilities"]) == 50
    assert "extra" not in out["vulnerabilities"][0]


def test_compact_passthrough_for_unknown_shape():
    assert webapp._chat_compact("get_scan_status", {"a": 1}) == {"a": 1}


# --------------------------------------------------------------------------- #
# Dispatch (in-process call to a real endpoint)
# --------------------------------------------------------------------------- #
def test_dispatch_reads_a_real_endpoint():
    # get_scan_status is a cheap read that always answers.
    res = webapp._chat_dispatch("get_scan_status", {}, "")
    assert res["ok"] is True
    assert res["status"] == 200
    assert isinstance(res["data"], dict)


def test_dispatch_unknown_tool_is_rejected():
    res = webapp._chat_dispatch("delete_everything", {}, "")
    assert res["ok"] is False and "unknown tool" in res["error"]


def test_dispatch_deep_scan_requires_ip():
    res = webapp._chat_dispatch("deep_scan_host", {}, "")
    assert res["ok"] is False and "ip" in res["error"].lower()


def test_every_route_target_is_a_registered_rule():
    rules = {r.rule for r in webapp.app.url_map.iter_rules()}
    for tool, (method, path) in webapp._CHAT_TOOL_ROUTES.items():
        assert path in rules, f"{tool} -> {path} is not a registered route"


# --------------------------------------------------------------------------- #
# /api/ai/chat endpoint + gating
# --------------------------------------------------------------------------- #
def test_chat_rejected_when_ai_disabled(client, monkeypatch):
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", False)
    r = client.post("/api/ai/chat", json={"message": "hi"})
    assert r.status_code == 400
    assert r.get_json()["success"] is False


def test_chat_503_when_service_not_ready(client, monkeypatch):
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", True)
    monkeypatch.setattr(webapp.shared_data, "ai_service", None, raising=False)
    r = client.post("/api/ai/chat", json={"message": "hi"})
    assert r.status_code == 503


def test_chat_empty_message_rejected(client, monkeypatch):
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", True)
    monkeypatch.setattr(webapp.shared_data, "ai_service",
                        ScriptedAI(["hello"]), raising=False)
    webapp._ragnar_chat = None  # force rebuild against the stub
    r = client.post("/api/ai/chat", json={"message": "   "})
    assert r.status_code == 400


def test_chat_full_turn_runs_a_real_tool(client, monkeypatch):
    # Model asks to read scan status, then answers in prose. The dispatch runs
    # the real /api/scan/status endpoint in-process.
    ai = ScriptedAI([
        '<tool>{"tool":"get_scan_status","args":{}}</tool>',
        "No scan is currently running.",
    ])
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", True)
    monkeypatch.setattr(webapp.shared_data, "ai_service", ai, raising=False)
    webapp._ragnar_chat = None  # force RagnarChat to bind to our stub

    r = client.post("/api/ai/chat", json={"message": "is a scan running?", "history": []})
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert "No scan is currently running" in data["reply"]
    assert len(data["actions"]) == 1
    assert data["actions"][0]["tool"] == "get_scan_status"
    assert data["actions"][0]["ok"] is True

    webapp._ragnar_chat = None  # don't leak the stub-bound chat to other tests


def test_chat_plain_answer_no_tools(client, monkeypatch):
    ai = ScriptedAI(["Watchtower aggregates the passive watchers into one feed."])
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", True)
    monkeypatch.setattr(webapp.shared_data, "ai_service", ai, raising=False)
    webapp._ragnar_chat = None

    r = client.post("/api/ai/chat", json={"message": "what is watchtower?"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["actions"] == []
    assert "Watchtower" in data["reply"]

    webapp._ragnar_chat = None
