#!/usr/bin/env python3
import ast
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SKIP_DIRS = {
    ".git", "node_modules", "python", "pager", "pager_lib", "pager_bin", "tests",
    "resources", "custom_components", "demos", "lab", "docker", "__pycache__",
    "web", "docs", "scripts", "bin", "files", "data", "config",
}
SKIP_FILES = {"PagerRagnar.py", "pagerctl.py", "pager_display.py", "pager_menu.py"}

MSG_KEYS = {
    "error", "message", "msg", "detail", "details", "hint", "reason", "warning", "note", "notes",
    "reply", "summary", "label", "title", "description", "status_text", "tip", "advice", "fix",
    "why", "next_step", "explanation", "text", "step", "headline", "verdict", "meaning", "impact",
    "remedy", "blurb", "recommendation", "suggestion", "status_label", "caption", "subtitle",
    "help", "issue", "problem", "cause", "evidence", "finding", "risk", "action_hint",
}

PLACEHOLDER = ""


MAX_VARIANTS = 8


def _product(a, b):
    return [x + y for x in a for y in b][:MAX_VARIANTS]


def _variants(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [_fields_to_placeholders(node.value)]
    if isinstance(node, ast.JoinedStr):
        out = [""]
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out = _product(out, [v.value])
            elif isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.IfExp):
                out = _product(out, _branch_variants(v.value))
            else:
                out = _product(out, [PLACEHOLDER])
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _variants(node.left), _variants(node.right)
        if a is None and b is None:
            return None
        return _product(a or [PLACEHOLDER], b or [PLACEHOLDER])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _variants(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _variants(node.func.value)
    if isinstance(node, ast.IfExp):
        return _branch_variants(node)
    return None


def _branch_variants(node):
    body, orelse = _variants(node.body), _variants(node.orelse)
    if body is None and orelse is None:
        return [PLACEHOLDER]
    return ((body or [PLACEHOLDER]) + (orelse or [PLACEHOLDER]))[:MAX_VARIANTS]


def _fields_to_placeholders(s):
    s = re.sub(r"\{[^{}]*\}", PLACEHOLDER, s)
    s = re.sub(r"%(?:\([^)]*\))?[-+ #0]*\d*(?:\.\d+)?[sdifr]", PLACEHOLDER, s)
    return s


def _key(raw):
    s = re.sub(PLACEHOLDER + r"(\s*" + PLACEHOLDER + r")+", PLACEHOLDER, raw)
    s = re.sub(r"\s+", " ", s).strip()
    n = iter(range(1000))
    return re.sub(PLACEHOLDER, lambda m: "{%d}" % next(n), s)


def _natural(key):
    lit = re.sub(r"\{\d+\}", " ", key)
    if len(re.findall(r"[A-Za-z]", lit)) < 3:
        return False
    if len([w for w in lit.split() if re.search(r"[A-Za-z]{2}", w)]) < 2:
        return False
    if re.match(r"^(https?:|/|\.|#)", key):
        return False
    if re.search(r"[{};]\s*$|=>|\\n", lit):
        return False
    starts = key.startswith("{")
    ends = key.endswith("}")
    if starts and ends and len([w for w in lit.split() if len(w) > 1]) < 2:
        return False
    return True


def _add(out, raw, where):
    if raw is None:
        return
    for variant in (raw if isinstance(raw, list) else [raw]):
        for line in variant.split("\n"):
            k = _key(line)
            if k and _natural(k):
                refs = out.setdefault(k, [])
                if len(refs) < 4:
                    refs.append(where)


def _scan(path, rel, out):
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return
    chat = rel == "ai_chat.py"
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in MSG_KEYS:
                    _add(out, _variants(v), f"{rel}:{getattr(v, 'lineno', 0)}")
        if not chat:
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_answer":
            if len(node.args) >= 2:
                _add(out, _variants(node.args[1]), f"{rel}:{node.lineno}")
        if isinstance(node, ast.FunctionDef) and node.name == "_action_label":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    for v in sub.values:
                        labels = _variants(v) or []
                        _add(out, labels, f"{rel}:{v.lineno}")
                        _add(out, [lab + "?" for lab in labels], f"{rel}:{v.lineno}")


def collect(root=ROOT):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        top = rel_dir.split(os.sep)[0]
        if top in SKIP_DIRS:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".py") or name in SKIP_FILES:
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            _scan(path, rel, out)
    return out


if __name__ == "__main__":
    json.dump(collect(sys.argv[1] if len(sys.argv) > 1 else ROOT), sys.stdout, sort_keys=True)
