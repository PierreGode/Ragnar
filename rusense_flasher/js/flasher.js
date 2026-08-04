/* RuSense CSI Node — Web Flasher
 * Uses esptool-js v0.6.0 via CDN.
 * Adapted from the Ragnar/Piglet web flasher (MIT / CC BY-NC-SA 4.0).
 * Flashes the multi-part ESP-IDF image (bootloader + partition-table +
 * ota_data + app) for ESP32-S3 and ESP32-C6 CSI sensor nodes.
 */

let _esptool = null;

async function getEsptool() {
  if (_esptool) return _esptool;
  _esptool = await import("https://unpkg.com/esptool-js@0.6.0/bundle.js");
  return _esptool;
}

/* ── UI helpers ── */
const $  = (id) => document.getElementById(id);
const log = (msg) => {
  const el = $("flash-log");
  el.textContent += msg + "\n";
  el.scrollTop = el.scrollHeight;
};

function showFlashOverlay() {
  $("flash-overlay").hidden = false;
  $("flash-close").hidden = true;
  $("flash-confirm-row").hidden = true;
  $("flash-log").textContent = "";
  $("flash-bar").style.width = "0%";
  $("flash-pct").textContent = "";
  $("flash-status").textContent = "Initializing…";
}

function setStatus(msg)  { $("flash-status").textContent = msg; }
function setProgress(pct) {
  $("flash-bar").style.width = pct + "%";
  $("flash-pct").textContent = Math.round(pct) + "%";
}

function waitForConfirm() {
  return new Promise((resolve) => {
    const row   = $("flash-confirm-row");
    const btnYes = $("flash-confirm-yes");
    const btnNo  = $("flash-confirm-no");
    row.hidden = false;
    function cleanup(result) {
      row.hidden = true;
      btnYes.removeEventListener("click", onYes);
      btnNo.removeEventListener("click", onNo);
      resolve(result);
    }
    const onYes = () => cleanup(true);
    const onNo  = () => cleanup(false);
    btnYes.addEventListener("click", onYes);
    btnNo.addEventListener("click",  onNo);
  });
}

/* ── Main flash flow ── */
window.flashDevice = async function (manifestPath) {
  if (!("serial" in navigator)) {
    alert(
      "Web Serial is not supported in this browser.\n" +
      "Use Chrome, Edge, or Opera on desktop."
    );
    return;
  }

  showFlashOverlay();

  let transport = null;

  try {
    /* 1 — Fetch manifest first so we know the target chip */
    setStatus("Fetching firmware manifest…");
    const mResp = await fetch(manifestPath);
    if (!mResp.ok) throw new Error("Manifest fetch failed (" + mResp.status + ")");
    const manifest = await mResp.json();
    const build = manifest.builds[0];
    const parts = build.parts || [];
    if (!parts.length) throw new Error("Manifest has no firmware parts");
    log("Firmware : " + manifest.name);
    log("Target   : " + build.chipFamily);
    log("Version  : " + (manifest.version || "—"));
    log("Parts    : " + parts.length);

    /* 2 — Request serial port (requires user gesture) */
    setStatus("Select the " + build.chipFamily + " serial port…");
    let port;
    try {
      port = await navigator.serial.requestPort();
    } catch (_) {
      setStatus("No port selected.");
      $("flash-close").hidden = false;
      return;
    }

    /* 3 — Load esptool-js */
    setStatus("Loading flasher library…");
    const { ESPLoader, Transport } = await getEsptool();

    /* 4 — Download every firmware part, relative to the manifest URL */
    setStatus("Downloading firmware…");
    const base = manifestPath.substring(0, manifestPath.lastIndexOf("/") + 1);
    const fileArray = [];
    let totalBytes = 0;
    for (const part of parts) {
      const url = part.path.startsWith("http") ? part.path : base + part.path;
      const resp = await fetch(url);
      if (!resp.ok) throw new Error("Download failed for " + part.path + " (" + resp.status + ")");
      const data = new Uint8Array(await resp.arrayBuffer());
      fileArray.push({ data, address: part.offset });
      totalBytes += data.length;
      log("  " + part.path.split("/").pop() +
          " @ 0x" + part.offset.toString(16) +
          " (" + (data.length / 1024).toFixed(0) + " KB)");
    }
    log("Total    : " + (totalBytes / 1024).toFixed(0) + " KB across " + fileArray.length + " parts");

    /* 5 — Connect to device */
    setStatus("Connecting to " + build.chipFamily + "…");
    transport = new Transport(port, true);
    const terminal = {
      clean()          {},
      writeLine(data)  { log(data); },
      write(_data)     {},
    };
    const loader = new ESPLoader({ transport, baudrate: 115200, terminal });
    const chip   = await loader.main();
    log("Connected: " + chip);

    /* 6 — Verify chip family */
    const norm = (s) => s.replace(/[-_ ]/g, "").toUpperCase();
    if (!norm(chip).startsWith(norm(build.chipFamily))) {
      throw new Error(
        "Wrong chip! Expected " + build.chipFamily + " but got " + chip + "."
      );
    }

    /* 7 — Ask user to confirm before erasing/flashing */
    setStatus("Ready — press Flash Now to continue");
    log("\n✅ Device verified: " + chip);
    log("Erase + flash will begin on confirm.\n");

    const confirmed = await waitForConfirm();
    if (!confirmed) {
      setStatus("Flashing cancelled.");
      await transport.disconnect();
      $("flash-close").hidden = false;
      return;
    }

    /* 8 — Erase flash */
    if (manifest.new_install_prompt_erase !== false) {
      setStatus("Erasing flash…");
      log("Erasing…");
      await loader.eraseFlash();
      log("Erase complete.");
    }

    /* 9 — Write all firmware parts. esptool-js flashes them in fileArray
     *      order; weight the progress bar by cumulative byte size so it
     *      advances smoothly across parts instead of resetting per file. */
    setStatus("Flashing firmware…");
    const priorBytes = [];
    {
      let acc = 0;
      for (const f of fileArray) { priorBytes.push(acc); acc += f.data.length; }
    }
    await loader.writeFlash({
      fileArray,
      flashSize: "keep",
      flashMode: "keep",
      flashFreq: "keep",
      eraseAll:  false,
      compress:  true,
      reportProgress(fileIndex, written, total) {
        const done = (priorBytes[fileIndex] || 0) + (written / total) * fileArray[fileIndex].data.length;
        setProgress((done / totalBytes) * 100);
      },
    });

    setProgress(100);
    log("\n✅ Flash complete!");
    setStatus("Done — press RST on the board to boot.");
    await transport.disconnect();

  } catch (err) {
    log("\n❌ Error: " + err.message);
    setStatus("Error: " + err.message);
    if (transport) {
      try { await transport.disconnect(); } catch (_) {}
    }
  } finally {
    $("flash-close").hidden = false;
  }
};

/* ── WiFi / server provisioning ──
 * Flashing erases NVS, so a freshly-forged node falls back to compiled defaults
 * (wrong SSID + server 192.168.1.100) and never connects. This writes the real
 * WiFi + server into the csi_cfg NVS namespace at 0x9000 — the exact partition
 * RuView's provision.py produces (nvs_gen.js is byte-verified against it). */
window.provisionDevice = async function () {
  if (!("serial" in navigator)) {
    alert("Web Serial is not supported in this browser.\nUse Chrome, Edge, or Opera on desktop.");
    return;
  }
  const ssid = ($("prov-ssid").value || "").trim();
  const password = $("prov-pass").value || "";               // don't trim — passwords may hold spaces
  let targetIp = ($("prov-ip").value || "").trim();
  const targetPort = parseInt($("prov-port").value, 10) || 5005;

  /* Normalize the server IP. Users paste the dashboard URL ("http://192.168.0.147:8000/")
   * here; the firmware's target_ip field holds at most 15 chars, so ":8000" gets silently
   * truncated to ":8", inet_pton() rejects it, and the node's UDP sender never starts
   * (boot log: "Invalid target IP: x.x.x.x:8 / Failed to initialize UDP sender"). Strip
   * scheme/path/port down to the bare IPv4, and refuse anything that isn't one. */
  let strippedPort = null;
  if (targetIp) {
    targetIp = targetIp.replace(/^[a-z]+:\/\//i, "").replace(/[/?#].*$/, "");
    const portSuffix = targetIp.match(/^(.*):(\d{1,5})$/);
    if (portSuffix) { targetIp = portSuffix[1]; strippedPort = portSuffix[2]; }
    const octets = targetIp.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!octets || octets.slice(1).some((o) => parseInt(o, 10) > 255)) {
      alert(
        "Server IP must be a plain IPv4 address like 192.168.1.20 — no http://, no :port, no hostname.\n" +
        "It's the address of your Ragnar box; the CSI stream goes to the UDP port in the Port field (default 5005)."
      );
      return;
    }
  }
  const nodeIdRaw = ($("prov-node").value || "").trim();
  const nodeId = nodeIdRaw === "" ? 1 : parseInt(nodeIdRaw, 10);
  if (!ssid)     { alert("Enter your 2.4 GHz WiFi SSID."); return; }
  if (!targetIp) { alert("Enter the RuSense server IP (your Ragnar box's address)."); return; }
  if (!Number.isInteger(nodeId) || nodeId < 0 || nodeId > 255) {
    alert("Node ID must be a whole number 0-255. Give each node in the mesh a different ID.");
    return;
  }
  if (typeof window.buildCsiCfgNvs !== "function") { alert("Provisioning module failed to load."); return; }

  showFlashOverlay();
  let transport = null;
  try {
    setStatus("Select the CSI node's serial port…");
    let port;
    try { port = await navigator.serial.requestPort(); }
    catch (_) { setStatus("No port selected."); $("flash-close").hidden = false; return; }

    setStatus("Loading flasher library…");
    const { ESPLoader, Transport } = await getEsptool();

    setStatus("Building provisioning data…");
    const extAntenna = !!($("prov-ext-ant") && $("prov-ext-ant").checked);
    const nvs = window.buildCsiCfgNvs({ ssid, password, target_ip: targetIp, target_port: targetPort, node_id: nodeId, ext_antenna: extAntenna });
    log("Antenna   : " + (extAntenna ? "external u.FL (XIAO C6)" : "on-board"));
    log("WiFi SSID : " + ssid);
    log("Server    : " + targetIp + ":" + targetPort);
    if (strippedPort) {
      log("Note      : ':" + strippedPort + "' was stripped from the Server IP — CSI streams to UDP " +
          targetPort + " (the Port field), not the web-dashboard port.");
    }
    log("Node ID   : " + nodeId);
    log("Edge tier : 0 (raw CSI — server-side fusion)");
    log("NVS       : " + nvs.length + " bytes @ 0x9000 (csi_cfg)");

    setStatus("Connecting…");
    transport = new Transport(port, true);
    const terminal = { clean() {}, writeLine(data) { log(data); }, write() {} };
    const loader = new ESPLoader({ transport, baudrate: 115200, terminal });
    const chip = await loader.main();
    log("Connected: " + chip);

    setStatus("Ready — press Flash Now to write the WiFi config");
    log("\nThis writes ONLY the WiFi/server config (NVS @ 0x9000).");
    log("Flash the firmware first with Forge if you haven't.\n");
    const confirmed = await waitForConfirm();
    if (!confirmed) {
      setStatus("Provisioning cancelled.");
      await transport.disconnect();
      $("flash-close").hidden = false;
      return;
    }

    setStatus("Writing WiFi config…");
    await loader.writeFlash({
      fileArray: [{ data: nvs, address: 0x9000 }],
      flashSize: "keep", flashMode: "keep", flashFreq: "keep",
      eraseAll: false, compress: true,          // only the NVS sectors — firmware untouched
      reportProgress(_i, written, total) { setProgress((written / total) * 100); },
    });
    setProgress(100);
    log("\n✅ WiFi config written.");
    log("Press RST — the node should join \"" + ssid + "\" and stream to " + targetIp + ":" + targetPort + ".");
    setStatus("Provisioned — press RST to reboot.");
    await transport.disconnect();
  } catch (err) {
    log("\n❌ Error: " + err.message);
    setStatus("Error: " + err.message);
    if (transport) { try { await transport.disconnect(); } catch (_) {} }
  } finally {
    $("flash-close").hidden = false;
  }
};

/* ── Serial monitor ──
 * ESP32-S3/C6 nodes talk over the chip's native USB-Serial-JTAG. When the
 * device resets (RST button, crash, brownout), that USB device re-enumerates
 * and the open Web Serial port dies — so a monitor that stops reading on the
 * first error silently hides boot-loops. Instead we announce the drop, keep
 * re-attaching to the granted port, and flag rapid reset cycles. */
let serialPort         = null;
let serialReader       = null;
let serialWriter       = null;
let serialWantReconnect = false;
let serialResetTimes   = [];

function serialLogWrite(text) {
  const el = $("serial-log");
  el.textContent += text;
  el.scrollTop = el.scrollHeight;
}

async function attachSerial(port) {
  const baud = parseInt($("serial-baud-select").value, 10);
  await port.open({ baudRate: baud });
  serialPort   = port;
  serialWriter = port.writable.getWriter();
  const decoder = new TextDecoderStream();
  port.readable.pipeTo(decoder.writable).catch(() => {});
  serialReader = decoder.readable.getReader();

  (async () => {
    try {
      for (;;) {
        const { value, done } = await serialReader.read();
        if (done) break;
        serialLogWrite(value);
      }
    } catch (_) { /* port gone (device reset/unplug) or reader cancelled */ }
    try { serialWriter.releaseLock(); } catch (_) {}
    try { await port.close(); } catch (_) {}
    if (serialPort === port) { serialPort = null; serialReader = null; serialWriter = null; }
    if (serialWantReconnect) onSerialDropped();
  })();
}

async function onSerialDropped() {
  serialLogWrite("\n[⚡ port lost — the device reset or was unplugged; reconnecting…]\n");
  const now = Date.now();
  serialResetTimes = serialResetTimes.filter((t) => now - t < 15000);
  serialResetTimes.push(now);
  if (serialResetTimes.length === 3) {
    serialLogWrite(
      "[⚠️ 3 resets in <15 s — the node is BOOT-LOOPING. Most common cause: brownout at WiFi\n" +
      " power-up (first boot after a forge runs full RF calibration = peak current). Try a\n" +
      " direct USB-3 port with a short data cable — no hub. On XIAO boards also make sure\n" +
      " the U.FL antenna is snapped on. Note: panic/brownout banners only print on UART0,\n" +
      " which XIAO boards don't expose — over USB the log just cuts out like this.]\n");
  }
  while (serialWantReconnect && !serialPort) {
    await new Promise((r) => setTimeout(r, 600));
    if (!serialWantReconnect) return;
    let ports = [];
    try { ports = await navigator.serial.getPorts(); } catch (_) {}
    for (const p of ports) {
      if (!serialWantReconnect || serialPort) return;
      try {
        await attachSerial(p);
        serialLogWrite("[🔌 reconnected]\n");
        return;
      } catch (_) { /* still re-enumerating or not this port — keep polling */ }
    }
  }
}

window.openLogs = async function () {
  if (!("serial" in navigator)) {
    alert("Web Serial not supported. Use Chrome, Edge, or Opera.");
    return;
  }
  $("serial-overlay").hidden = false;
  $("serial-log").textContent = "";

  if (serialPort) return;   // already connected

  try {
    const port = await navigator.serial.requestPort();
    serialWantReconnect = true;
    serialResetTimes = [];
    await attachSerial(port);
  } catch (_) {
    serialPort = null;
    $("serial-overlay").hidden = true;
  }
};

async function closeSerial() {
  serialWantReconnect = false;
  try { if (serialReader) { await serialReader.cancel(); serialReader = null; } } catch (_) {}
  try { if (serialWriter) { serialWriter.releaseLock(); serialWriter = null; } } catch (_) {}
  try { if (serialPort)   { await serialPort.close();   serialPort = null;   } } catch (_) {}
  $("serial-overlay").hidden = true;
}

/* ── Wire-up after DOM ready ── */
document.addEventListener("DOMContentLoaded", () => {
  /* Flash overlay buttons */
  $("flash-close").addEventListener("click", () => {
    $("flash-overlay").hidden = true;
  });

  /* Serial overlay buttons */
  $("serial-close").addEventListener("click", closeSerial);
  $("serial-clear").addEventListener("click", () => {
    $("serial-log").textContent = "";
  });

  $("serial-baud-select").addEventListener("change", async () => {
    if (serialPort) {
      await closeSerial();
      openLogs();
    }
  });

  $("serial-send").addEventListener("click", async () => {
    const input = $("serial-input");
    const text  = input.value.trim();
    if (!text || !serialWriter) return;
    const encoder = new TextEncoder();
    await serialWriter.write(encoder.encode(text + "\n"));
    input.value = "";
  });
  $("serial-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("serial-send").click();
  });

  /* Browser compatibility check */
  if (!("serial" in navigator)) {
    $("browserWarn").style.display = "block";
  }

  /* Load build version from version.json */
  fetch("version.json")
    .then((r) => r.json())
    .then((v) => {
      const el = $("build");
      if (el) el.textContent = v.build || v.sha || "—";
    })
    .catch(() => {});
});
