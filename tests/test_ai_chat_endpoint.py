"""Integration tests for the chat assistant's webapp seam (webapp_modern.py).

These exercise the parts ai_chat.py's own tests can't reach: the in-process
tool dispatch (``_chat_dispatch`` -> Flask ``test_client`` -> real endpoint),
the payload compaction (``_chat_compact``), and the ``/api/ai/chat`` endpoint
including its enable/ready gating.

Importing webapp_modern initialises a lot of subsystems; if that fails in a
bare environment we skip the whole module rather than error.
"""

import pytest

from ai_chat import _MATCH_PROMPT

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
        if messages[0]["content"].startswith(_MATCH_PROMPT):
            return "0"
        return self._replies.pop(0) if self._replies else "done"


@pytest.fixture
def client():
    return webapp.app.test_client()


# --------------------------------------------------------------------------- #
# Compaction (pure function)
# --------------------------------------------------------------------------- #
def test_compact_devices_keeps_true_totals_and_drops_internal_fields():
    raw = [{"ip": f"10.0.0.{i}", "hostname": "h", "vendor": "v", "status": "alive",
            "ports": ["22"], "threats": [], "secret_internal_field": "leak"}
           for i in range(90)]
    out = webapp._chat_compact("get_network_devices", raw)
    assert out["total"] == 90 and out["matching"] == 90
    assert "leak" not in str(out)


def test_compact_vulnerabilities_passes_filters_through():
    raw = {"vulnerabilities": [{"host": "10.0.0.5", "port": 445, "service": "smb",
                                "severity": "high", "vulnerability": "x", "extra": "y"}
                               for _ in range(70)]}
    out = webapp._chat_compact("get_vulnerabilities", raw, {"severity": "critical"})
    assert out["matching"] == 0 and out["findings"] == []
    assert "extra" not in str(out)


def test_compact_passthrough_for_unknown_shape():
    assert webapp._chat_compact("get_wifi_status", {"a": 1}) == {"a": 1}


def test_scan_status_says_it_has_no_history():
    assert "not recorded" in webapp._chat_compact("get_scan_status", {"scanning": False})["note"]


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


def _logged_in_cookie(monkeypatch):
    """A real session cookie on a unit with a password set."""
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: True)
    client = webapp.app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
    name = webapp.app.config["SESSION_COOKIE_NAME"]
    return name, f"{name}={client.get_cookie(name).value}"


def test_tools_run_for_a_logged_in_user_on_a_password_protected_unit(monkeypatch):
    _, cookie = _logged_in_cookie(monkeypatch)
    result = webapp._chat_dispatch("get_scan_status", {}, cookie)
    assert result.get("status") != 401, result


def test_tools_stay_blocked_without_a_valid_session(monkeypatch):
    name, _ = _logged_in_cookie(monkeypatch)
    for cookie in ("", f"{name}=forged"):
        result = webapp._chat_dispatch("get_scan_status", {}, cookie)
        assert result["ok"] is False and result["status"] == 401


def test_chat_endpoint_requires_login_when_a_password_is_set(monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: True)
    response = webapp.app.test_client().post("/api/ai/chat", json={"message": "scan"})
    assert response.status_code == 401


def _chat_ready(monkeypatch, ai):
    monkeypatch.setattr(webapp.shared_data, "ai_service", ai, raising=False)
    monkeypatch.setitem(webapp.shared_data.config, "ai_enabled", True)
    monkeypatch.setattr(webapp, "_ragnar_chat", None)


def test_turning_chat_off_stops_requests_before_the_model_runs(client, monkeypatch):
    ai = ScriptedAI(["should never be used"])
    _chat_ready(monkeypatch, ai)
    monkeypatch.setitem(webapp.shared_data.config, "ai_chat_enabled", False)
    response = client.post("/api/ai/chat", json={"message": "scan the network"})
    assert response.status_code == 400
    assert "turned off" in response.get_json()["error"]
    assert ai._replies == ["should never be used"]


def test_chat_stays_on_for_configs_saved_before_the_setting_existed(client, monkeypatch):
    _chat_ready(monkeypatch, ScriptedAI(["hello"]))
    monkeypatch.delitem(webapp.shared_data.config, "ai_chat_enabled", raising=False)
    response = client.post("/api/ai/chat", json={"message": "hi"})
    assert response.status_code == 200
    assert response.get_json()["reply"] == "hello"


@pytest.mark.parametrize("setting", [True, False])
def test_status_reports_the_chat_setting(client, monkeypatch, setting):
    _chat_ready(monkeypatch, ScriptedAI([]))
    monkeypatch.setitem(webapp.shared_data.config, "ai_chat_enabled", setting)
    assert client.get("/api/ai/status").get_json()["chat_enabled"] is setting


# --------------------------------------------------------------------------- #
# Action tools against their real endpoints
# --------------------------------------------------------------------------- #
def _fake_wifi(monkeypatch, interfaces):
    calls = []

    def self_call(method, path, cookie, json_body=None):
        if method == "GET":
            return 200, {"interfaces": interfaces}
        calls.append((path, json_body))
        return 200, {"success": True}

    monkeypatch.setattr(webapp, "_chat_self_call", self_call)
    return calls


WIFI = [{"name": "wlan0", "scan_enabled": True}, {"name": "wlan1", "scan_enabled": False}]


def test_stop_wifi_scan_names_the_interfaces_that_are_scanning(monkeypatch):
    calls = _fake_wifi(monkeypatch, WIFI)
    result = webapp._chat_dispatch("stop_wifi_scan", {}, "")
    assert calls == [("/api/wifi/scan-control/stop", {"interface": "wlan0"})]
    assert result["ok"] is True and result["data"]["changed"] == ["wlan0"]


def test_start_wifi_scan_reports_when_it_is_already_on(monkeypatch):
    calls = _fake_wifi(monkeypatch, WIFI)
    result = webapp._chat_dispatch("start_wifi_scan", {}, "")
    assert calls == []
    assert "already on on wlan0" in result["data"]["note"]


def test_start_wifi_scan_picks_an_interface_when_all_are_off(monkeypatch):
    calls = _fake_wifi(monkeypatch, [{"name": "wlan0", "scan_enabled": False}])
    webapp._chat_dispatch("start_wifi_scan", {}, "")
    assert calls == [("/api/wifi/scan-control/start", {"interface": "wlan0"})]


def test_named_wifi_interface_is_respected(monkeypatch):
    calls = _fake_wifi(monkeypatch, WIFI)
    webapp._chat_dispatch("start_wifi_scan", {"interface": "wlan1"}, "")
    assert calls == [("/api/wifi/scan-control/start", {"interface": "wlan1"})]


def test_wifi_failure_is_not_reported_as_success(monkeypatch):
    def self_call(method, path, cookie, json_body=None):
        if method == "GET":
            return 200, {"interfaces": WIFI}
        return 404, {"success": False, "error": "interface not managed"}

    monkeypatch.setattr(webapp, "_chat_self_call", self_call)
    result = webapp._chat_dispatch("stop_wifi_scan", {}, "")
    assert result["ok"] is False
    assert result["data"]["failed"] == {"wlan0": "interface not managed"}


def test_wifi_tools_work_against_the_real_handler():
    """No interface is managed in the test app, so this reaches the real handler
    without changing anything, and must not fail on a missing argument."""
    result = webapp._chat_dispatch("stop_wifi_scan", {"interface": "wlan9"}, "")
    assert "interface is required" not in str(result)


def test_vulnerability_scan_uses_the_endpoint_that_starts_it(monkeypatch):
    calls = []
    monkeypatch.setattr(webapp, "_chat_self_call",
                        lambda m, p, c, b=None: calls.append((m, p)) or (200, {"success": True}))
    webapp._chat_dispatch("start_vulnerability_scan", {}, "")
    assert calls == [("POST", "/api/manual/scan/vulnerability")]


def test_vulnerability_scan_failure_is_reported(monkeypatch):
    monkeypatch.setattr(webapp, "_collect_manual_targets", lambda: [])
    result = webapp._chat_dispatch("start_vulnerability_scan", {}, "")
    assert result["ok"] is False
    assert "No targets" in str(result["data"])


# --------------------------------------------------------------------------- #
# Run / Cancel over HTTP
# --------------------------------------------------------------------------- #
ACTION = '<tool>{"tool":"run_network_scan","args":{}}</tool>'


def test_chat_returns_a_prompt_and_runs_nothing(client, monkeypatch):
    _chat_ready(monkeypatch, ScriptedAI([ACTION]))
    ran = []
    monkeypatch.setattr(webapp, "_chat_dispatch", lambda *a: ran.append(a) or {"ok": True})
    data = client.post("/api/ai/chat", json={"message": "scan"}).get_json()
    assert data["pending"]["label"] == "Scan the local network"
    assert ran == []


def test_only_an_explicit_true_runs_the_action(client, monkeypatch):
    _chat_ready(monkeypatch, ScriptedAI([ACTION, ACTION, "done"]))
    ran = []
    monkeypatch.setattr(webapp, "_chat_dispatch", lambda *a: ran.append(a[0]) or {"ok": True})
    token = client.post("/api/ai/chat", json={"message": "scan"}).get_json()["pending"]["id"]
    assert client.post("/api/ai/chat/confirm", json={"id": token, "approve": "yes"}).get_json()["success"]
    assert ran == []
    token = client.post("/api/ai/chat", json={"message": "scan"}).get_json()["pending"]["id"]
    client.post("/api/ai/chat/confirm", json={"id": token, "approve": True})
    assert ran == ["run_network_scan"]


def test_confirm_requires_login(monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: True)
    response = webapp.app.test_client().post("/api/ai/chat/confirm", json={"id": "x", "approve": True})
    assert response.status_code == 401


def test_turning_chat_off_also_blocks_a_pending_action(client, monkeypatch):
    _chat_ready(monkeypatch, ScriptedAI([ACTION]))
    ran = []
    monkeypatch.setattr(webapp, "_chat_dispatch", lambda *a: ran.append(a) or {"ok": True})
    token = client.post("/api/ai/chat", json={"message": "scan"}).get_json()["pending"]["id"]
    monkeypatch.setitem(webapp.shared_data.config, "ai_chat_enabled", False)
    response = client.post("/api/ai/chat/confirm", json={"id": token, "approve": True})
    assert response.status_code == 400 and ran == []
