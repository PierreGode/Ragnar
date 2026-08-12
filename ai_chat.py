#!/usr/bin/env python3
"""Ragnar interactive chat assistant.

Drives a small agentic loop on top of :class:`ai_service.AIService`: the user
talks to "Ragnar" in a chat box on the dashboard, and the assistant can

  * answer questions about Ragnar using the project's own ``docs/`` folder
    (lightweight keyword retrieval — no embeddings, so it runs on a Pi Zero),
  * **take actions** — start scans, read results, drive Wi-Fi Defense — by
    calling a curated allowlist of the app's own HTTP endpoints, and
  * read those results back and explain them in plain language.

The design is deliberately model-agnostic. Rather than native function-calling
(which the OpenAI Responses API and self-hosted Ollama/LocalAI servers all
express differently), the assistant uses a tiny **text protocol**: to run a
tool it emits a single ``<tool>{"tool":"name","args":{...}}</tool>`` line; the
server executes it and feeds the result back as ``<result>…</result>``. This
works identically on OpenAI's cloud and on a local model, which is what the
project targets (see docs/AI_INTEGRATION.md).

Tool *execution* is not done here — it is delegated to a ``dispatch`` callable
provided by webapp_modern.py, which maps each allowed tool to an in-process
call against the existing, already-authenticated API endpoints. This module
owns the *specs* (names, descriptions, the prompt) and the loop; the webapp
owns the wiring. ``search_docs`` is the one tool handled locally, since the doc
index lives here.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Tool registry — the actions the assistant may take.
#
# Each entry: name -> {desc, args, action}. ``action`` marks a tool that
# changes state / starts work (vs. a read); it only affects how the tool is
# described to the model. Execution is delegated to the dispatcher passed into
# RagnarChat, EXCEPT ``search_docs`` which this module answers itself.
# ---------------------------------------------------------------------------
TOOLS: Dict[str, Dict[str, Any]] = {
    # ---- documentation -----------------------------------------------------
    "search_docs": {
        "desc": "Search Ragnar's own documentation (the docs/ folder) for how a "
                "feature works. Use this before answering 'how do I…' / 'what is…' "
                "questions about Ragnar.",
        "args": {"query": "string — what to look up"},
        "action": False,
    },
    # ---- read state --------------------------------------------------------
    "get_network_devices": {
        "desc": "List the devices Ragnar has discovered on the network (IP, MAC, "
                "hostname, vendor, status, open ports, flagged threats).",
        "args": {},
        "action": False,
    },
    "get_vulnerabilities": {
        "desc": "List discovered vulnerabilities / findings for the current "
                "network (host, port, service, severity).",
        "args": {},
        "action": False,
    },
    "get_ai_insights": {
        "desc": "Get the dashboard AI insight cards (network summary, vulnerability "
                "assessment, weaknesses, passive-monitoring posture).",
        "args": {},
        "action": False,
    },
    "get_watchtower": {
        "desc": "Get the Watchtower unified alert feed from the passive watchers "
                "(wifiwatch, ndpwatch, arp_guard, …) — recent alerts + summary.",
        "args": {},
        "action": False,
    },
    "get_incidents": {
        "desc": "Get correlated attack-chain incidents fused from the Watchtower "
                "alert stream.",
        "args": {},
        "action": False,
    },
    "get_scan_status": {
        "desc": "Get the current scanning status (whether a scan is running).",
        "args": {},
        "action": False,
    },
    "get_wifi_status": {
        "desc": "Get the Wi-Fi scan-control state (which interfaces are scanning).",
        "args": {},
        "action": False,
    },
    # ---- actions -----------------------------------------------------------
    "run_network_scan": {
        "desc": "Run an ARP + nmap sweep of the local network now and return the "
                "hosts found. Updates the network knowledge base.",
        "args": {},
        "action": True,
    },
    "start_vulnerability_scan": {
        "desc": "Start a background vulnerability scan across discovered hosts. "
                "Returns immediately; results land in the Network tab in a few "
                "minutes.",
        "args": {},
        "action": True,
    },
    "deep_scan_host": {
        "desc": "Run a deep TCP port scan against a single host by IP.",
        "args": {"ip": "string — target IPv4 address, e.g. 192.168.1.20"},
        "action": True,
    },
    "start_wifi_scan": {
        "desc": "Enable Wi-Fi scan-control (start the Wi-Fi scanning interface).",
        "args": {},
        "action": True,
    },
    "stop_wifi_scan": {
        "desc": "Disable Wi-Fi scan-control (stop the Wi-Fi scanning interface).",
        "args": {},
        "action": True,
    },
}


# ---------------------------------------------------------------------------
# Documentation index — tiny keyword retriever over docs/*.md.
# ---------------------------------------------------------------------------
_WORD_RE = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "and", "for", "with", "that", "this", "you", "your", "are", "was",
    "how", "what", "does", "can", "will", "into", "from", "have", "has", "not",
    "use", "used", "using", "when", "where", "which", "who", "why", "get",
    "set", "run", "ragnar", "a", "an", "of", "to", "in", "on", "is", "it",
    "do", "i", "my", "me", "about", "tell", "show",
}


def _tokens(text: str) -> List[str]:
    return [w for w in _WORD_RE.findall(text.lower()) if w not in _STOP and len(w) > 2]


class DocIndex:
    """Chunk docs/*.md by heading and rank chunks by keyword overlap.

    Deliberately dumb (no embeddings): a term-frequency overlap score plus a
    filename bonus. Good enough to pull the right section into the prompt, and
    it costs nothing at rest on a small board. Rebuilds when the docs/ mtime
    changes so edits show up without a restart.
    """

    def __init__(self, docs_dir: str):
        self.docs_dir = docs_dir
        self.chunks: List[Dict[str, Any]] = []
        self._mtime = 0.0
        self._build()

    def _dir_mtime(self) -> float:
        try:
            latest = os.path.getmtime(self.docs_dir)
        except OSError:
            return 0.0
        try:
            for name in os.listdir(self.docs_dir):
                if name.lower().endswith(".md"):
                    latest = max(latest, os.path.getmtime(os.path.join(self.docs_dir, name)))
        except OSError:
            pass
        return latest

    def _build(self) -> None:
        self.chunks = []
        try:
            names = sorted(n for n in os.listdir(self.docs_dir) if n.lower().endswith(".md"))
        except OSError:
            names = []
        for name in names:
            path = os.path.join(self.docs_dir, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for heading, body in self._split_sections(text):
                body = body.strip()
                if not body:
                    continue
                title = f"{name} — {heading}" if heading else name
                blob = f"{name} {heading} {body}"
                self.chunks.append({
                    "file": name,
                    "title": title,
                    "text": body,
                    "tf": self._tf(blob),
                })
        self._mtime = self._dir_mtime()

    @staticmethod
    def _split_sections(text: str) -> List[Tuple[str, str]]:
        """Split markdown into (heading, body) chunks on `#`/`##`/`###` lines."""
        sections: List[Tuple[str, str]] = []
        heading = ""
        buf: List[str] = []
        for line in text.splitlines():
            m = re.match(r"^#{1,3}\s+(.*)$", line)
            if m:
                if buf:
                    sections.append((heading, "\n".join(buf)))
                    buf = []
                heading = m.group(1).strip()
            else:
                buf.append(line)
        if buf:
            sections.append((heading, "\n".join(buf)))
        return sections

    @staticmethod
    def _tf(text: str) -> Dict[str, int]:
        tf: Dict[str, int] = {}
        for w in _tokens(text):
            tf[w] = tf.get(w, 0) + 1
        return tf

    def _maybe_rebuild(self) -> None:
        if abs(self._dir_mtime() - self._mtime) > 0.5:
            self._build()

    def search(self, query: str, k: int = 3, max_chars: int = 1400) -> List[Dict[str, str]]:
        self._maybe_rebuild()
        q = _tokens(query)
        if not q or not self.chunks:
            return []
        qset = set(q)
        scored = []
        for ch in self.chunks:
            tf = ch["tf"]
            score = sum(tf.get(w, 0) for w in qset)
            if score <= 0:
                continue
            # Bonus when the query terms hit the filename/heading (title).
            title_hits = len(qset & set(_tokens(ch["title"])))
            score += title_hits * 3
            scored.append((score, ch))
        scored.sort(key=lambda x: x[0], reverse=True)
        out = []
        for _, ch in scored[:k]:
            body = ch["text"]
            if len(body) > max_chars:
                body = body[:max_chars].rstrip() + " …"
            out.append({"file": ch["file"], "title": ch["title"], "text": body})
        return out


# ---------------------------------------------------------------------------
# The chat orchestrator.
# ---------------------------------------------------------------------------
_TOOL_TAG_RE = re.compile(r"<tool>.*?</tool>", re.DOTALL)

_OVERVIEW = (
    "Ragnar is a Raspberry-Pi network-security appliance: it discovers devices, "
    "runs port/vulnerability scans, does Wi-Fi analysis and passive Wi-Fi/wired "
    "defense (Watchtower), wardriving, and correlates incidents. It has a web "
    "dashboard with tabs: Dashboard, Networking, Wi-Fi, and more. You are the "
    "assistant embedded in that dashboard."
)


class RagnarChat:
    """Runs one assistant turn: retrieve docs, loop over tool calls, answer.

    Parameters
    ----------
    ai_service
        An :class:`ai_service.AIService`; must expose ``chat_messages(messages)``.
    docs_dir
        Path to the project ``docs/`` folder.
    dispatch
        Callable ``(tool_name, args, cookie) -> dict`` that executes an action
        tool and returns a JSON-able result. ``search_docs`` is handled here and
        never reaches the dispatcher.
    """

    MAX_STEPS = 5           # tool calls per user turn before we force an answer
    MAX_HISTORY = 12        # prior messages kept for context
    OBS_LIMIT = 3500        # chars of a tool result fed back to the model

    def __init__(self, ai_service, docs_dir: str, dispatch: Callable[[str, Dict, str], Dict]):
        self.ai = ai_service
        self.docs = DocIndex(docs_dir)
        self.dispatch = dispatch

    # -- prompt construction -------------------------------------------------
    def _tools_block(self) -> str:
        lines = []
        for name, spec in TOOLS.items():
            args = spec.get("args") or {}
            if args:
                arg_str = ", ".join(f"{k} ({v})" for k, v in args.items())
            else:
                arg_str = "no arguments"
            tag = "ACTION" if spec.get("action") else "read"
            lines.append(f'- {name} [{tag}]: {spec["desc"]} Args: {arg_str}.')
        return "\n".join(lines)

    def _system_prompt(self, doc_context: str) -> str:
        return (
            "You are Ragnar, the built-in assistant of the Ragnar network-security "
            "appliance. Be concise, technical, and practical. Speak plainly; a short "
            "answer beats a long one.\n\n"
            f"{_OVERVIEW}\n\n"
            "You can take real actions on this unit and read real data by calling "
            "tools. The operator has authorised you to run actions automatically — "
            "do NOT ask for confirmation, just do it, then report what you did and "
            "explain the result.\n\n"
            "TOOLS:\n"
            f"{self._tools_block()}\n\n"
            "TOOL PROTOCOL — follow exactly:\n"
            "- To call a tool, reply with ONE line and nothing else:\n"
            '  <tool>{\"tool\":\"NAME\",\"args\":{...}}</tool>\n'
            "- Do not add any prose in the same message as a <tool> call.\n"
            "- The system runs the tool and replies with <result>…</result>.\n"
            "- You may call tools several times in a row (e.g. scan, then read "
            "results). When you have enough information, reply to the user in plain "
            "text with NO <tool> tag.\n"
            "- Only use tools that exist above. If a request needs something no tool "
            "covers, explain what to do in the UI instead.\n"
            "- When you present scan/vulnerability results, interpret them: what "
            "matters, severity, and what the operator should do next.\n\n"
            "RELEVANT DOCUMENTATION (retrieved for this question; may be empty):\n"
            f"{doc_context or '(none retrieved — use search_docs if you need docs)'}"
        )

    @staticmethod
    def _format_docs(hits: List[Dict[str, str]]) -> str:
        if not hits:
            return ""
        parts = []
        for h in hits:
            parts.append(f"### {h['title']}\n{h['text']}")
        return "\n\n".join(parts)

    # -- tool-call parsing ---------------------------------------------------
    @staticmethod
    def _balanced_json(text: str, open_idx: int) -> Optional[str]:
        """Return the balanced ``{...}`` object starting at ``open_idx`` (handles
        nested braces, e.g. ``"args": {}``). None if unbalanced."""
        depth = 0
        for i in range(open_idx, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx:i + 1]
        return None

    @classmethod
    def _parse_tool_call(cls, text: str) -> Optional[Tuple[str, Dict]]:
        """Extract a tool call from the model's reply. Prefers the content of a
        ``<tool>…</tool>`` block; otherwise accepts a bare JSON object carrying a
        ``"tool"`` key (tolerating models that drop the tags or add a fence).
        Uses brace-matching so nested ``args`` objects parse correctly."""
        if not text:
            return None
        m = re.search(r"<tool>(.*?)</tool>", text, re.DOTALL)
        scope = m.group(1) if m else text
        ti = scope.find('"tool"')
        if ti == -1:
            return None
        open_idx = scope.rfind("{", 0, ti)
        if open_idx == -1:
            return None
        raw = cls._balanced_json(scope, open_idx)
        if not raw:
            return None
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            return None
        name = obj.get("tool")
        if not isinstance(name, str) or name not in TOOLS:
            return None
        args = obj.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        return name, args

    # -- execution -----------------------------------------------------------
    def _run_tool(self, name: str, args: Dict, cookie: str) -> Dict:
        if name == "search_docs":
            hits = self.docs.search(str(args.get("query", "")), k=3)
            return {"ok": True, "results": hits or "no matching docs"}
        try:
            result = self.dispatch(name, args, cookie)
            if not isinstance(result, dict):
                result = {"ok": True, "result": result}
            return result
        except Exception as exc:  # pragma: no cover - defensive
            return {"ok": False, "error": str(exc)}

    @staticmethod
    def _summarize_action(name: str, args: Dict, result: Dict) -> str:
        ok = bool(result.get("ok", result.get("success", True))) and not result.get("error")
        label = name.replace("_", " ")
        if args:
            label += " (" + ", ".join(f"{k}={v}" for k, v in args.items()) + ")"
        return ("✓ " if ok else "✗ ") + label

    # -- main entry ----------------------------------------------------------
    def run(self, history: List[Dict], user_message: str, cookie: str = "") -> Dict:
        """Run one turn. ``history`` is prior [{role, content}] (user/assistant).

        Returns ``{reply, actions, docs, model}``.
        """
        if not user_message or not user_message.strip():
            return {"reply": "Ask me something about Ragnar, or tell me what to scan.",
                    "actions": [], "docs": [], "model": getattr(self.ai, "model", "")}

        hits = self.docs.search(user_message, k=3)
        system = self._system_prompt(self._format_docs(hits))

        messages: List[Dict[str, str]] = [{"role": "system", "content": system}]
        for msg in (history or [])[-self.MAX_HISTORY:]:
            role = msg.get("role")
            content = msg.get("content")
            if role in ("user", "assistant") and isinstance(content, str) and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": user_message.strip()})

        actions: List[Dict] = []
        used_docs = [{"file": h["file"], "title": h["title"]} for h in hits]

        for step in range(self.MAX_STEPS):
            text = self.ai.chat_messages(messages)
            if not text:
                return {"reply": "The AI model did not respond. Check the AI "
                                 "configuration in the Config tab (token / endpoint).",
                        "actions": actions, "docs": used_docs,
                        "model": getattr(self.ai, "model", "")}

            call = self._parse_tool_call(text)
            if not call:
                # Plain answer — strip any stray tags and return.
                return {"reply": _TOOL_TAG_RE.sub("", text).strip() or text.strip(),
                        "actions": actions, "docs": used_docs,
                        "model": getattr(self.ai, "model", "")}

            name, args = call
            result = self._run_tool(name, args, cookie)
            actions.append({
                "tool": name,
                "args": args,
                "ok": bool(result.get("ok", result.get("success", True))) and not result.get("error"),
                "summary": self._summarize_action(name, args, result),
            })

            obs = json.dumps(result, default=str)
            if len(obs) > self.OBS_LIMIT:
                obs = obs[:self.OBS_LIMIT] + " …(truncated)"
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": f"<result>{obs}</result>"})

        # Ran out of steps — force a final plain-language answer.
        messages.append({"role": "user", "content":
                         "Now answer me directly in plain text based on the results "
                         "above. Do not call any more tools."})
        final = self.ai.chat_messages(messages)
        reply = _TOOL_TAG_RE.sub("", final or "").strip()
        if not reply:
            # The model still tried to call a tool (or returned nothing) even when
            # told to stop — don't hand back an empty bubble.
            reply = ("I ran the actions above but couldn't compose a summary. "
                     "Check the results in the relevant tab.")
        return {"reply": reply, "actions": actions, "docs": used_docs,
                "model": getattr(self.ai, "model", "")}
