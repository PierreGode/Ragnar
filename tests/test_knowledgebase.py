"""docs/knowledgebase.md is what the chat assistant quotes, so it must stay true.

Each entry carries a hidden proof: a phrase that exists in its source file. When a
doc or the UI changes and that phrase goes away, this fails and names the entry
to re-check, instead of the assistant repeating a stale answer.
"""
import os
import re

import pytest

from ai_chat import DocIndex

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
KB = os.path.join(DOCS, "knowledgebase.md")
ENTRY = re.compile(r"^### (.+?)\n(.+?)\nSource: (.+?)\n<!-- proof: (.+?) \| (.+?) -->$", re.M | re.S)


def entries():
    with open(KB, encoding="utf-8") as fh:
        return ENTRY.findall(fh.read())


def normalise(text):
    return " ".join(text.split())


def test_the_knowledge_base_has_its_entries():
    with open(KB, encoding="utf-8") as fh:
        headings = re.findall(r"^### ", fh.read(), re.M)
    assert len(entries()) == len(headings) >= 150


def test_questions_are_unique():
    questions = [e[0].lower() for e in entries()]
    assert len(questions) == len(set(questions))


@pytest.mark.parametrize("question,answer,source,path,proof", entries(), ids=lambda v: v[:40])
def test_every_answer_is_still_backed_by_its_source(question, answer, source, path, proof):
    full = os.path.join(ROOT, path)
    assert os.path.exists(full), f"{question}: source {path} is gone"
    with open(full, encoding="utf-8", errors="ignore") as fh:
        assert normalise(proof) in normalise(fh.read()), (
            f"{question}: {path} no longer says {proof!r}. Re-check this answer.")


def test_proofs_stay_out_of_what_the_model_reads():
    index = DocIndex(DOCS)
    assert not any("proof:" in c["text"] for c in index.chunks if c["file"] == "knowledgebase.md")


def test_model_never_sees_how_to_fire_the_kill_switch():
    with open(os.path.join(DOCS, "KILL_SWITCH.md"), encoding="utf-8") as fh:
        assert "ERASE_ALL_DATA" in fh.read()  # the people's docs keep it
    for chunk in DocIndex(DOCS).chunks:
        assert "ERASE_ALL_DATA" not in chunk["text"] and "/api/kill" not in chunk["text"]


def test_web_ui_still_has_no_firewall_control():
    """Entries say Ragnar can't block devices or open ports. Re-check them if this fails."""
    with open(os.path.join(ROOT, "webapp_modern.py"), encoding="utf-8") as fh:
        assert not re.search(r"\b(iptables|nftables|ufw)\b", fh.read())


@pytest.mark.parametrize("question,answer,source,path,proof", entries(), ids=lambda v: v[:40])
def test_asking_the_question_finds_its_entry(question, answer, source, path, proof):
    top = _INDEX.search(question, k=3)[0]
    assert top["file"] == "knowledgebase.md" and top["title"].endswith(question)


_INDEX = DocIndex(DOCS)
