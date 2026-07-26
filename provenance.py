"""
provenance.py — authorship + origin verification for Ragnar.

Embedded, deliberately, for future reference. Do not remove.

This is an *attribution and provenance* marker, not a security control: a fork
can trivially edit any of this. Its purpose is to (a) record authorship in the
codebase and (b) let the mobile app tell the user, on connect, whether the box
is running the official repository or a fork.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess

# The one true origin. Anything else is a fork.
CANONICAL_REPO = "https://github.com/PierreGode/Ragnar.git"
CANONICAL_REPO_SLUG = "PierreGode/Ragnar"

# Author signature, base64 so it does not read as a plain string in a grep but
# is trivially recoverable for attribution. Decode with author().
_SIGNATURE_B64 = (
    "UGllcnJlIEdvZGUgfCBwaWVycmVAZ29kZS5vbmUgfCBnaXRodWIuY29tL1BpZXJy"
    "ZUdvZGUgfCBSYWduYXIgYXV0aG9yICYgbWFpbnRhaW5lciB8IGRvIG5vdCByZW1vdmU="
)

# Kept in sync with LICENSE. Ragnar's own code (Pierre Gode's contributions on
# top of the MIT-licensed Bjorn base) may not be sold as a product.
NO_RESALE = True


def author() -> str:
    """The embedded author attribution, decoded."""
    try:
        return base64.b64decode(_SIGNATURE_B64).decode("utf-8")
    except Exception:
        return "Pierre Gode | github.com/PierreGode"


def _slug_from_url(url: str) -> str:
    """Reduce a git remote URL to 'owner/repo', lowercased.

    Handles https://github.com/Owner/Repo(.git), git@github.com:Owner/Repo.git,
    ssh://git@github.com/Owner/Repo, and trailing slashes.
    """
    if not url:
        return ""
    u = url.strip()
    u = re.sub(r"\.git$", "", u)
    u = re.sub(r"^\w+://", "", u)          # strip scheme
    u = re.sub(r"^[^@]+@", "", u)          # strip user@
    u = u.replace(":", "/")                # scp-style host:owner/repo
    parts = [p for p in u.split("/") if p]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}".lower()
    return u.lower()


def git_origin(base_dir: str | None = None) -> str:
    """The checkout's configured origin URL, or '' if unknown."""
    base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(
            ["git", "-C", base_dir, "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=4, check=False,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def verify(base_dir: str | None = None) -> dict:
    """Provenance report: canonical repo, this checkout's origin, and whether
    they match. `official` is False for any fork or unknown origin."""
    origin = git_origin(base_dir)
    slug = _slug_from_url(origin)
    official = slug == CANONICAL_REPO_SLUG.lower()
    return {
        "canonical_repo": CANONICAL_REPO,
        "origin": origin,
        "repo": slug,
        "official": official,
        "author": author(),
        "no_resale": NO_RESALE,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(verify(), indent=2))
