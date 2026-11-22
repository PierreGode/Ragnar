#!/usr/bin/env python3
"""
Ragnar edition detection -- the "hidden switch".

The extended capabilities (coordinated security workflows, the offensive tool
surface, Nexmon onboard-Wi-Fi integration) belong to ONE thing only: the genuine
**Ragnar OS Ulfberht image**. They are gated on a build-time marker that is
written exclusively by the image build (see the RagnarOS `ulfberht/` pipeline),
NEVER by install_ragnar.sh.

That means: on the standard Ragnar OS image, and on anyone's own Kali box where
they merely `git clone` Ragnar and run the installer, this reports
edition="standard" and the UI shows nothing new -- the switch stays hidden.
Being Kali-based is NOT enough; only the official Ulfberht image carries the
marker.

Pure standard library, no side effects, never raises, safe to import anywhere.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess

# The ONLY signal that unlocks the edition: a marker file the image build
# writes. install_ragnar.sh must never create it. (An env override is allowed
# for development/testing only.)
_MARKER_PATHS = ("/etc/ragnar-edition", "/boot/firmware/ragnar-edition")
_ENV_OVERRIDE = "RAGNAR_EDITION"

EDITION_ULFBERHT = "ulfberht"
EDITION_STANDARD = "standard"

EDITION_NAMES = {
    EDITION_ULFBERHT: "Ragnar OS Ulfberht",
    EDITION_STANDARD: "Ragnar OS",
}

# Offensive / analysis tools worth surfacing when present: (binary, label,
# category). Detection is by presence on PATH only -- we never run them here.
# Metasploit is detected via msfconsole. Curated, not exhaustive.
_TOOL_CATALOG = (
    ("nmap", "Nmap", "recon"),
    ("masscan", "Masscan", "recon"),
    ("aircrack-ng", "Aircrack-ng", "wifi"),
    ("airodump-ng", "Airodump-ng", "wifi"),
    ("wifite", "Wifite", "wifi"),
    ("kismet", "Kismet", "wifi"),
    ("reaver", "Reaver", "wifi"),
    ("bully", "Bully", "wifi"),
    ("hcxdumptool", "hcxdumptool", "wifi"),
    ("hashcat", "Hashcat", "cracking"),
    ("john", "John the Ripper", "cracking"),
    ("hydra", "Hydra", "cracking"),
    ("bettercap", "Bettercap", "mitm"),
    ("ettercap", "Ettercap", "mitm"),
    ("responder", "Responder", "mitm"),
    ("mitm6", "mitm6", "mitm"),
    ("tshark", "TShark", "capture"),
    ("tcpdump", "tcpdump", "capture"),
    ("sqlmap", "sqlmap", "web"),
    ("nikto", "Nikto", "web"),
    ("nuclei", "Nuclei", "web"),
    ("ffuf", "ffuf", "web"),
    ("gobuster", "Gobuster", "web"),
    ("wpscan", "WPScan", "web"),
    ("msfconsole", "Metasploit", "exploit"),
    ("setoolkit", "SET", "exploit"),
    ("enum4linux", "enum4linux", "smb"),
    ("crackmapexec", "CrackMapExec", "smb"),
    ("netexec", "NetExec", "smb"),
    # ── Active Directory / internal (baked into the Ulfberht image) ──────────
    # Representative impacket binary; impacket-scripts installs many (impacket-*).
    ("impacket-secretsdump", "Impacket", "ad"),
    ("evil-winrm", "Evil-WinRM", "ad"),
    ("certipy", "Certipy (AD CS)", "ad"),
    ("kerbrute", "Kerbrute", "ad"),
    ("bloodhound-python", "BloodHound.py", "ad"),
    ("ldapdomaindump", "ldapdomaindump", "ad"),
    ("windapsearch", "windapsearch", "ad"),
    # ── Pivoting (baked into the Ulfberht image) ─────────────────────────────
    ("ligolo-proxy", "Ligolo-ng", "pivot"),
    ("chisel", "Chisel", "pivot"),
    ("sshuttle", "sshuttle", "pivot"),
    ("proxychains4", "proxychains4", "pivot"),
    # ── Recon / OSINT (optional extras — install from the Engagements tab) ────
    ("subfinder", "Subfinder", "recon"),
    ("httpx", "httpx", "recon"),
    ("dnsx", "dnsx", "recon"),
    ("katana", "Katana", "web"),
    ("dnsrecon", "DNSRecon", "recon"),
    ("dnsenum", "dnsenum", "recon"),
    ("theHarvester", "theHarvester", "recon"),
    ("searchsploit", "SearchSploit", "exploit"),
    # ── Wi-Fi extras (optional — install from the Engagements tab) ───────────
    ("mdk4", "MDK4", "wifi"),
    ("eaphammer", "EAPHammer", "wifi"),
    ("hostapd-wpe", "hostapd-wpe", "wifi"),
)

# Nexmon packages (onboard-Wi-Fi monitor/injection support on the Ulfberht base).
_NEXMON_PACKAGES = ("brcmfmac-nexmon-dkms", "firmware-nexmon")

_cache = None


def _read_kv(path):
    data = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                data[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def _read_marker():
    """The image-build marker, or {} if this isn't the official Ulfberht image."""
    env = os.environ.get(_ENV_OVERRIDE)
    if env:
        return {"edition": env.strip().lower()}
    for path in _MARKER_PATHS:
        data = _read_kv(path)
        if data.get("edition"):
            return data
    return {}


def _read_os_release():
    return _read_kv("/etc/os-release")


def _dpkg_installed(pkg):
    dpkg = shutil.which("dpkg-query") or shutil.which("dpkg")
    if not dpkg:
        return False
    try:
        res = subprocess.run(
            [dpkg, "-s", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _detect_tools():
    found = []
    for binary, label, category in _TOOL_CATALOG:
        path = shutil.which(binary)
        if path:
            found.append({"bin": binary, "name": label,
                          "category": category, "path": path})
    return found


def _detect_nexmon():
    pkgs = [p for p in _NEXMON_PACKAGES if _dpkg_installed(p)]
    fw = bool(glob.glob("/lib/firmware/brcm/*nexmon*")
              or glob.glob("/usr/lib/firmware/brcm/*nexmon*"))
    return {"available": bool(pkgs) or fw, "packages": pkgs, "firmware_present": fw}


def detect(refresh=False):
    """Return a dict describing the running edition. Cached; never raises.

    Extended capabilities are reported only when the official Ulfberht image
    marker is present -- being on a Kali base is deliberately NOT sufficient.
    """
    global _cache
    if _cache is not None and not refresh:
        return _cache

    marker = _read_marker()
    is_ulfberht = (marker.get("edition", "").lower() == EDITION_ULFBERHT)
    edition = EDITION_ULFBERHT if is_ulfberht else EDITION_STANDARD

    osr = _read_os_release()
    base_id = (osr.get("ID") or "unknown").lower()

    result = {
        "edition": edition,
        "edition_name": marker.get("name") or EDITION_NAMES[edition],
        "is_ulfberht": is_ulfberht,
        # kept as an alias so existing callers keep working; it now means
        # "is this the official security edition image", NOT "is the base Kali".
        "is_security_distro": is_ulfberht,
        "base_id": base_id,
        "base_pretty": osr.get("PRETTY_NAME") or base_id,
        "image_build": marker.get("build_date") or marker.get("build") or "",
        "image_id": marker.get("image_id") or "",
        "nexmon": {"available": False, "packages": [], "firmware_present": False},
        "tools": [],
        "tool_count": 0,
    }
    if is_ulfberht:
        try:
            result["nexmon"] = _detect_nexmon()
        except Exception:
            pass
        try:
            result["tools"] = _detect_tools()
            result["tool_count"] = len(result["tools"])
        except Exception:
            pass

    _cache = result
    return result


if __name__ == "__main__":
    print(json.dumps(detect(), indent=2))
