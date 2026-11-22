"""Guard the NetworkManager uplink drop-in that keeps the box's IP stable.

Regression cover for the "Ragnar keeps switching IP on wired and wireless"
report (PR #1028). The offensive (Ulfberht / Red Team) edition's tooling
(monitor mode, macchanger, Nexmon) changes interface MACs; with NetworkManager's
default ``cloned-mac-address=preserve`` that changed MAC was carried into the
managed uplink, so the router handed out a new DHCP lease and the box's IP kept
moving. The fix pins the uplink to the permanent hardware MAC and keys the DHCP
lease on it.

Two scripts write ``/etc/NetworkManager/conf.d/99-ragnar-wifi.conf``:
``install_ragnar.sh`` at install time and ``scripts/provision_network_tools.sh``
on every update (so existing boxes self-heal). The file content must stay
identical in both, and ``preserve`` must never come back.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL = REPO / "install_ragnar.sh"
PROVISION = REPO / "scripts" / "provision_network_tools.sh"

# Lines every copy of the drop-in must carry, and the one that must be gone.
REQUIRED = (
    "wifi.scan-rand-mac-address=no",
    "wifi.cloned-mac-address=permanent",
    "ethernet.cloned-mac-address=permanent",
    "ipv4.dhcp-client-id=mac",
)
FORBIDDEN = "cloned-mac-address=preserve"


def _install_body() -> str:
    text = INSTALL.read_text()
    m = re.search(
        r"cat > /etc/NetworkManager/conf\.d/99-ragnar-wifi\.conf << EOF\n(.*?)\nEOF\n",
        text,
        re.DOTALL,
    )
    assert m, "install_ragnar.sh no longer writes 99-ragnar-wifi.conf via a << EOF heredoc"
    return m.group(1)


def _provision_body() -> str:
    text = PROVISION.read_text()
    m = re.search(r"cat << 'NMEOF'\n(.*?)\nNMEOF\n", text, re.DOTALL)
    assert m, "provision_network_tools.sh no longer carries the NMEOF drop-in heredoc"
    return m.group(1)


def test_install_pins_stable_uplink():
    body = _install_body()
    for line in REQUIRED:
        assert line in body, f"install drop-in missing: {line}"
    assert FORBIDDEN not in body, "install drop-in reintroduced cloned-mac-address=preserve"


def test_provision_pins_stable_uplink():
    body = _provision_body()
    for line in REQUIRED:
        assert line in body, f"provision drop-in missing: {line}"
    assert FORBIDDEN not in body, "provision drop-in reintroduced cloned-mac-address=preserve"


def test_install_and_update_write_identical_content():
    # Drift here means install and update would leave a box in different states.
    assert _install_body() == _provision_body(), (
        "99-ragnar-wifi.conf differs between install_ragnar.sh and "
        "scripts/provision_network_tools.sh"
    )


def test_update_path_actually_reasserts_the_dropin():
    # The whole point of the update-path copy: existing boxes get healed. Make
    # sure the provisioner writes the file and is wired into the shared updater.
    prov = PROVISION.read_text()
    assert "/etc/NetworkManager/conf.d/99-ragnar-wifi.conf" in prov
    assert "nmcli connection reload" in prov, "update must reload NM so the fix arms"
    post = (REPO / "scripts" / "post_update.sh").read_text()
    assert "provision_network_tools.sh" in post, (
        "post_update.sh must run provision_network_tools.sh for the fix to reach "
        "updated boxes"
    )
