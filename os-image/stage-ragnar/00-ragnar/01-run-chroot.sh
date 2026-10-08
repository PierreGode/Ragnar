#!/bin/bash -e
#
# Runs INSIDE the image chroot (pi-gen), on top of Raspberry Pi OS Lite.
# Clones Ragnar and runs its installer in build-safe unattended mode, then wires
# up the per-device first-boot finalisation. No service is started here — there
# is no init in a chroot — only enabled, so everything comes up on the device's
# first real boot.
#
# Everything device-specific (SSH host keys, TLS cert, hostname, display, mesh)
# is deferred to scripts/ragnar-firstboot.sh on first boot. See docs/ragnar-os.md.

RAGNAR_USER="ragnar"
RAGNAR_PATH="/home/${RAGNAR_USER}/Ragnar"
REPO_URL="${RAGNAR_REPO_URL:-https://github.com/PierreGode/Ragnar.git}"
REPO_BRANCH="${RAGNAR_REPO_BRANCH:-main}"

echo "=== Ragnar OS: building image rootfs ==="
echo "    repo:   $REPO_URL ($REPO_BRANCH)"

export DEBIAN_FRONTEND=noninteractive

# git is needed to clone a real .git (so the device can self-update later).
apt-get install -y --no-install-recommends git ca-certificates >/dev/null 2>&1 || true

# Fetch Ragnar. The installer can also clone itself, but doing it here lets us
# pin the branch and fail the build loudly if the clone fails.
rm -rf "$RAGNAR_PATH"
mkdir -p "/home/${RAGNAR_USER}"
git clone --branch "$REPO_BRANCH" --depth 1 "$REPO_URL" "$RAGNAR_PATH"
# Restore full history markers enough for the in-app updater (shallow is fine;
# update_ragnar.sh unshallows when needed).

# Run the installer build-safe + unattended. The profile choices below bake a
# lean, headless-by-default, display-capable image:
#   headless                -> web UI only, never seizes a board's display pins
#   ALL_DISPLAYS=1          -> every screen driver present, so a user can enable
#                              a display later via /boot/firmware/ragnar.conf
#   ADVANCED=no             -> skip heavy scanners (nuclei/ZAP); install from the
#                              web UI on a capable device
#   FORCE_PI=1              -> the target is a Pi even if the build host is x86
cd "$RAGNAR_PATH"
chmod +x install_ragnar.sh
RAGNAR_PROFILE=headless \
RAGNAR_INSTALL_ALL_DISPLAYS=1 \
RAGNAR_INSTALL_ADVANCED=no \
RAGNAR_INSTALL_PISUGAR=n \
RAGNAR_FORCE_PI=1 \
    ./install_ragnar.sh --image-build

# ── First-boot finalisation unit ────────────────────────────────────────────
chmod +x "$RAGNAR_PATH/scripts/ragnar-firstboot.sh"
install -m 0644 "$RAGNAR_PATH/scripts/ragnar-firstboot.service" /etc/systemd/system/ragnar-firstboot.service
# systemd may not answer in a chroot; fall back to the wants symlink.
systemctl enable ragnar-firstboot.service >/dev/null 2>&1 || \
    ln -sf /etc/systemd/system/ragnar-firstboot.service \
        /etc/systemd/system/multi-user.target.wants/ragnar-firstboot.service

# ── Per-device uniqueness: strip baked identity ─────────────────────────────
# SSH host keys regenerate on first boot (OpenSSH's own unit + our firstboot).
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
# machine-id must be empty so systemd mints a unique one per device.
: > /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
# Any TLS cert that leaked in gets regenerated per device by Ragnar/firstboot.
rm -f "$RAGNAR_PATH/certs/ragnar.key" "$RAGNAR_PATH/certs/ragnar.crt" 2>/dev/null || true

# ── Branding (MOTD) ─────────────────────────────────────────────────────────
cat > /etc/motd <<'MOTD'

    ____                             ___  ____
   |  _ \ __ _  __ _ _ __   __ _ _ _|   \/ ___|
   | |_) / _` |/ _` | '_ \ / _` | '__| | |\___ \
   |  _ < (_| | (_| | | | | (_| | |  | |_|___) |
   |_| \_\__,_|\__, |_| |_|\__,_|_|  |___/____/
                |___/      Ragnar OS for Raspberry Pi

  Web UI:  http://<this-device-ip>:8000   (https on :8000 too)
  No network yet? Join Wi-Fi "Ragnar" (pass: ragnarconnect),
  then open http://192.168.4.1:8000 to pick a network.

  Enable a screen or set a hostname: edit ragnar.conf on the
  boot partition. Docs: https://github.com/PierreGode/Ragnar
  For authorized security testing only.

MOTD

echo "=== Ragnar OS: rootfs build complete ==="
