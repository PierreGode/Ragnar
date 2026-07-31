#!/usr/bin/env python3
"""
ragnar_return — Pwnagotchi web plugin to swap back to Ragnar from the browser.

Pwnagotchi's own web UI runs on :8080. When the user swaps back to Ragnar the
Ragnar service comes up on :8000, but the browser tab stays on the now-dead
:8080 portal with nothing to redirect it. The hardware button
(scripts/ragnar_swap_button.py) has the same limitation: it can move the
service but not the browser.

This plugin closes that gap on the web side. It exposes a page at
    http://<host>:8080/plugins/ragnar_return
with a "Return to Ragnar" button. Clicking it:
  1. POSTs to /plugins/ragnar_return/swap, which stops Pwnagotchi/bettercap and
     starts Ragnar via systemd-run (survives pwnagotchi's cgroup teardown), then
  2. the page polls http://<host>:8000 and redirects the browser there once
     Ragnar answers consistently.

The page also polls in the background from load, so if the swap is triggered by
the hardware button while this page is open, the tab still follows to Ragnar.

Enable with `main.plugins.ragnar_return.enabled = true` (the Ragnar installer
does this and symlinks the file into /etc/pwnagotchi/custom_plugins).
"""

import logging
import subprocess

import pwnagotchi.plugins as plugins

# Mirror the swap sequence used by scripts/ragnar_swap_button.py so both the
# hardware button and this web button behave identically.
_SWAP_CMD = (
    'sleep 1'
    ' && systemctl stop pwnagotchi.service'
    ' && systemctl stop bettercap.service'
    ' && systemctl stop ragnar-swap-button.service'
    ' && sleep 2'
    ' && systemctl start ragnar.service'
)

# Standalone HTML so it renders even as Pwnagotchi is torn down. No external
# assets — the portal is often the only thing reachable at swap time.
_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Return to Ragnar</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#0f172a; color:#e2e8f0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .card { width:min(92vw,420px); background:rgba(30,41,59,.7); border:1px solid rgba(148,163,184,.25);
          border-radius:16px; padding:28px; text-align:center; box-shadow:0 10px 40px rgba(0,0,0,.4); }
  h1 { font-size:1.35rem; margin:0 0 6px; }
  p  { color:#94a3b8; font-size:.9rem; margin:0 0 20px; line-height:1.5; }
  button { width:100%; padding:14px 18px; font-size:1rem; font-weight:600; color:#fff; border:0;
           border-radius:12px; background:#16a34a; cursor:pointer; transition:background .15s, opacity .15s; }
  button:hover:not(:disabled) { background:#15803d; }
  button:disabled { opacity:.7; cursor:not-allowed; }
  .status { margin-top:16px; font-size:.85rem; color:#cbd5e1; min-height:1.2em; }
  .spin { display:inline-block; width:14px; height:14px; margin-right:8px; vertical-align:-2px;
          border:2px solid #4ade80; border-top-color:transparent; border-radius:50%; animation:s 1s linear infinite; }
  @keyframes s { to { transform:rotate(360deg); } }
</style>
</head>
<body>
  <div class="card">
    <h1>&#129445; Return to Ragnar</h1>
    <p>Stops Pwnagotchi and starts Ragnar. This tab will move to Ragnar
       (port&nbsp;8000) automatically once it&rsquo;s back up.</p>
    <button id="btn">Return to Ragnar</button>
    <div class="status" id="status"></div>
  </div>
<script>
  var RAGNAR_URL = window.location.protocol + '//' + window.location.hostname + ':8000';
  var btn = document.getElementById('btn');
  var statusEl = document.getElementById('status');
  var polling = false;

  function setStatus(html) { statusEl.innerHTML = html; }

  // Redirect only after Ragnar answers consistently — a single opaque success
  // means the port is up before the app can actually render (see the forward
  // swap fix on the Ragnar side).
  function pollAndRedirect() {
    if (polling) return;
    polling = true;
    var okStreak = 0, elapsed = 0;
    var NEEDED_OK = 4, MAX_WAIT = 120;
    setStatus('<span class="spin"></span>Waiting for Ragnar to come back...');
    var timer = setInterval(function () {
      elapsed++;
      fetch(RAGNAR_URL, { mode: 'no-cors', cache: 'no-store' }).then(function () {
        okStreak++;
        if (okStreak >= NEEDED_OK) {
          clearInterval(timer);
          setStatus('Ragnar is up &mdash; redirecting...');
          window.location.href = RAGNAR_URL;
        } else {
          setStatus('<span class="spin"></span>Ragnar starting... ' + elapsed + 's');
        }
      }).catch(function () {
        okStreak = 0;
        setStatus('<span class="spin"></span>Waiting for Ragnar to come back... ' + elapsed + 's');
      });
      if (elapsed >= MAX_WAIT) {
        clearInterval(timer);
        setStatus('Still waiting. <a style="color:#4ade80" href="' + RAGNAR_URL + '">Open Ragnar manually</a>.');
      }
    }, 1000);
  }

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Switching to Ragnar...';
    fetch('/plugins/ragnar_return/swap', { method: 'POST' })
      .then(function () { pollAndRedirect(); })
      .catch(function () {
        // The server may be torn down before the response returns — that's the
        // swap working, so start polling anyway.
        pollAndRedirect();
      });
  });

  // If the hardware button triggers the swap while this page is open, follow
  // Ragnar back without needing a click.
  pollAndRedirect();
</script>
</body>
</html>"""


class RagnarReturn(plugins.Plugin):
    __author__ = 'Ragnar'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __name__ = 'ragnar_return'
    __description__ = 'Adds a web button to swap back from Pwnagotchi to Ragnar and redirect the browser to :8000.'

    def on_loaded(self):
        logging.info('[ragnar_return] plugin loaded — /plugins/ragnar_return is available')

    def _trigger_swap(self):
        """Stop Pwnagotchi/bettercap and start Ragnar via a transient unit.

        systemd-run detaches the sequence into its own cgroup so it survives
        pwnagotchi being killed a moment later.
        """
        subprocess.Popen(
            ['systemd-run', '--no-block', '--collect',
             '--unit=pwnagotchi-to-ragnar-swap',
             'bash', '-c', _SWAP_CMD],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logging.info('[ragnar_return] scheduled swap: stop pwnagotchi -> start ragnar')

    def on_webhook(self, path, request):
        # POST /plugins/ragnar_return/swap → kick off the swap, ack immediately.
        if path == 'swap' and request.method == 'POST':
            try:
                self._trigger_swap()
                return ('{"ok": true}', 200, {'Content-Type': 'application/json'})
            except Exception as exc:  # noqa: BLE001 - report any failure to the UI
                logging.error(f'[ragnar_return] swap failed: {exc}')
                return ('{"ok": false}', 500, {'Content-Type': 'application/json'})

        # GET /plugins/ragnar_return (path is None) → the button + redirect page.
        return _PAGE
