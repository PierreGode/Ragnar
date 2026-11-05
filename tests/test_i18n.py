import json
import os
import re
from collections import Counter

import pytest

import ai_service
from ai_chat import RagnarChat

ROOT = os.path.join(os.path.dirname(__file__), "..")
PACK_DIR = os.path.join(ROOT, "web", "scripts", "i18n")
PLACEHOLDER = re.compile(r"\{\d+\}")


class _Shared:
    def __init__(self, **config):
        self.config = {"ai_enabled": False, **config}


def _service(language):
    svc = ai_service.AIService(_Shared(language=language))
    seen = []
    svc.is_enabled = lambda: True
    svc.client = object()
    svc.use_chat_api = False
    svc._ask_responses = lambda system, user, client=None, model=None: seen.append(system) or "ok"
    return svc, seen


@pytest.mark.parametrize("value,expected", [
    (None, "en"), ("", "en"), ("en", "en"), ("es", "es"), ("FR", "fr"),
    (" de ", "de"), ("xx", "en"), (42, "en"),
])
def test_response_language_falls_back_to_english(value, expected):
    assert ai_service.response_language({"language": value}) == expected


def test_response_language_survives_a_missing_config():
    assert ai_service.response_language(None) == "en"


def test_english_prompts_are_unchanged():
    assert ai_service.prose_language_directive("en") == ""
    assert ai_service.json_fields_language_directive("en", ("name",)) == ""


@pytest.mark.parametrize("code,name", [("es", "Spanish"), ("fr", "French"), ("de", "German")])
def test_prose_directive_names_the_language(code, name):
    text = ai_service.prose_language_directive(code)
    assert name in text and "CVE IDs" in text


def test_json_directive_only_localizes_the_named_fields():
    text = ai_service.json_fields_language_directive("de", ("name", "description"))
    assert '"name"' in text and '"description"' in text and "German" in text
    assert "JSON key" in text


def test_ask_appends_the_directive_for_prose():
    svc, seen = _service("es")
    svc._ask("You are Ragnar.", "Summarize.")
    assert seen[-1].startswith("You are Ragnar.")
    assert "Spanish" in seen[-1]


def test_ask_in_english_sends_the_prompt_verbatim():
    svc, seen = _service("en")
    svc._ask("You are Ragnar.", "Summarize.")
    assert seen[-1] == "You are Ragnar."


def test_machine_format_calls_opt_out():
    svc, seen = _service("fr")
    svc._ask("Reply with ONLY the device_type.", "x", localize=False)
    assert seen[-1] == "Reply with ONLY the device_type."


def test_complete_returns_json_without_a_language_directive():
    svc, seen = _service("de")
    svc.complete("make a playbook")
    assert "German" not in seen[-1]


def test_language_follows_the_config_live():
    svc, seen = _service("en")
    svc._ask("S", "U")
    svc.shared_data.config["language"] = "de"
    svc._ask("S", "U")
    assert seen[0] == "S" and "German" in seen[1]


def test_cached_analyses_are_kept_per_language():
    svc, _ = _service("en")
    key_en = svc._cache_key("summary", {"n": 1})
    svc.shared_data.config["language"] = "es"
    key_es = svc._cache_key("summary", {"n": 1})
    assert key_en != key_es
    svc.shared_data.config["language"] = "en"
    assert svc._cache_key("summary", {"n": 1}) == key_en


class _ChatAI:
    model = "fake"

    def __init__(self, directive=""):
        self._directive = directive

    def language_directive(self):
        return self._directive

    def chat_messages(self, messages, max_tokens=None):
        return "ok"


def _prompt(ai):
    chat = RagnarChat(ai, os.path.join(ROOT, "docs"), dispatch=lambda *a: {})
    return chat._system_prompt("")


def test_chat_prompt_gets_the_language_rule_and_keeps_tool_lines_english():
    prompt = _prompt(_ChatAI(ai_service.prose_language_directive("fr")))
    assert "French" in prompt
    assert "English tool name" in prompt


def test_chat_prompt_is_unchanged_in_english():
    english = _prompt(_ChatAI(""))
    assert "RESPONSE LANGUAGE" not in english


def test_chat_prompt_tolerates_an_ai_without_language_support():
    class Bare:
        model = "bare"

        def chat_messages(self, messages, max_tokens=None):
            return "ok"

    assert "RESPONSE LANGUAGE" not in _prompt(Bare())


def _packs():
    for lang in ("es", "fr", "de"):
        path = os.path.join(PACK_DIR, f"{lang}.json")
        if os.path.exists(path):
            yield lang, path


@pytest.mark.parametrize("lang,path", list(_packs()))
def test_language_pack_is_safe_to_apply(lang, path):
    with open(path, encoding="utf-8") as fh:
        pack = json.load(fh)
    assert isinstance(pack, dict) and pack
    problems = []
    for key, value in pack.items():
        if not isinstance(value, str) or not value.strip():
            problems.append((key, "empty"))
            continue
        if value != value.strip():
            problems.append((key, "edge whitespace"))
        if Counter(PLACEHOLDER.findall(key)) != Counter(PLACEHOLDER.findall(value)):
            problems.append((key, "placeholders"))
    assert not problems, f"{lang}: {problems[:10]}"


def test_all_packs_cover_the_same_keys():
    keys = {lang: set(json.load(open(path, encoding="utf-8"))) for lang, path in _packs()}
    if len(keys) > 1:
        first = next(iter(keys.values()))
        for lang, k in keys.items():
            assert k == first, f"{lang} differs: {sorted(k ^ first)[:10]}"


@pytest.fixture
def webapp(monkeypatch):
    try:
        import webapp_modern as module
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"webapp_modern unimportable here: {exc}")
    monkeypatch.setattr(module.shared_data, "save_config", lambda: None)
    monkeypatch.setitem(module.shared_data.config, "language", "en")
    monkeypatch.setattr(module.shared_data, "language", "en", raising=False)
    emitted = []
    monkeypatch.setattr(module.socketio, "emit", lambda *a, **k: emitted.append(a))
    module._test_emitted = emitted
    return module


def test_language_endpoint_round_trip(webapp, monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    client = webapp.app.test_client()
    assert client.get("/api/i18n/language").get_json()["language"] == "en"
    resp = client.post("/api/i18n/language", json={"language": "de"})
    assert resp.get_json() == {"success": True, "language": "de"}
    assert webapp.shared_data.config["language"] == "de"
    assert ("language_changed", {"language": "de"}) in webapp._test_emitted
    assert client.get("/api/i18n/language").get_json()["language"] == "de"


def test_language_endpoint_rejects_unknown_codes(webapp, monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    client = webapp.app.test_client()
    assert client.post("/api/i18n/language", json={"language": "xx"}).status_code == 400
    assert webapp.shared_data.config["language"] == "en"


def test_reading_the_language_is_public_but_changing_it_needs_login(webapp, monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: True)
    client = webapp.app.test_client()
    assert client.get("/api/i18n/language").status_code == 200
    assert client.get("/scripts/i18n/active.js").status_code == 200
    assert client.post("/api/i18n/language", json={"language": "es"}).status_code == 401


def test_boot_script_carries_the_active_pack(webapp, monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    client = webapp.app.test_client()
    body = client.get("/scripts/i18n/active.js").get_data(as_text=True)
    assert body.startswith("window.__RAGNAR_I18N__=") and '"lang": "en"' in body
    if not os.path.exists(os.path.join(PACK_DIR, "es.json")):
        pytest.skip("no Spanish pack in this checkout")
    webapp.shared_data.config["language"] = "es"
    body = client.get("/scripts/i18n/active.js").get_data(as_text=True)
    assert body.startswith('window.__RAGNAR_I18N__={"lang":"es"') and '"dict":{' in body


def test_pack_endpoint_serves_gzip_and_revalidates(webapp, monkeypatch):
    if not os.path.exists(os.path.join(PACK_DIR, "fr.json")):
        pytest.skip("no French pack in this checkout")
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    client = webapp.app.test_client()
    plain = client.get("/scripts/i18n/fr.json")
    assert plain.status_code == 200 and isinstance(plain.get_json(), dict)
    gz = client.get("/scripts/i18n/fr.json", headers={"Accept-Encoding": "gzip"})
    assert gz.headers.get("Content-Encoding") == "gzip"
    again = client.get("/scripts/i18n/fr.json", headers={"If-None-Match": plain.headers["ETag"]})
    assert again.status_code == 304
    assert client.get("/scripts/i18n/en.json").status_code == 404
    assert client.get("/scripts/i18n/xx.json").status_code == 404


def test_insights_from_another_language_are_not_served(webapp, monkeypatch):
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)

    class _Ready:
        def is_enabled(self):
            return True

    monkeypatch.setattr(webapp.shared_data, "ai_service", _Ready(), raising=False)
    started = []
    monkeypatch.setattr(webapp.socketio, "start_background_task", lambda fn: started.append(fn))
    state = webapp._ai_insights_state
    monkeypatch.setitem(state, "data", {"enabled": True, "network_summary": "English text"})
    monkeypatch.setitem(state, "ts", webapp.time.time())
    monkeypatch.setitem(state, "lang", "en")
    monkeypatch.setitem(state, "computing", False)
    client = webapp.app.test_client()

    assert client.get("/api/ai/insights").get_json().get("cached") is True
    webapp.shared_data.config["language"] = "es"
    body = client.get("/api/ai/insights").get_json()
    assert body.get("status") == "computing" and "network_summary" not in body
    assert started, "a rerun in the new language was not started"
