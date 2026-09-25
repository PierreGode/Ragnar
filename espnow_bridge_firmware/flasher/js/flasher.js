/* Ragnar ESP32-C6 Coordinator — Web Flasher
 * Uses esptool-js v0.6.0 via CDN.
 * Adapted from Piglet web flasher (MIT / CC BY-NC-SA 4.0).
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
    /* 1 — Request serial port (requires user gesture) */
    setStatus("Select the ESP32-C6 serial port…");
    let port;
    try {
      port = await navigator.serial.requestPort();
    } catch (_) {
      setStatus("No port selected.");
      $("flash-close").hidden = false;
      return;
    }

    /* 2 — Load esptool-js */
    setStatus("Loading flasher library…");
    const { ESPLoader, Transport } = await getEsptool();

    /* 3 — Fetch manifest */
    setStatus("Fetching firmware manifest…");
    const mResp = await fetch(manifestPath);
    if (!mResp.ok) throw new Error("Manifest fetch failed (" + mResp.status + ")");
    const manifest = await mResp.json();
    const build = manifest.builds[0];
    const part  = build.parts[0];
    log("Firmware : " + manifest.name);
    log("Target   : " + build.chipFamily);
    log("Version  : " + (manifest.version || "—"));

    /* 4 — Download firmware binary */
    setStatus("Downloading firmware…");
    const base  = manifestPath.substring(0, manifestPath.lastIndexOf("/") + 1);
    const fwUrl = part.path.startsWith("http") ? part.path : base + part.path;
    const fwResp = await fetch(fwUrl);
    if (!fwResp.ok) throw new Error("Firmware download failed (" + fwResp.status + ")");
    const fwData = new Uint8Array(await fwResp.arrayBuffer());
    log("Size     : " + (fwData.length / 1024).toFixed(0) + " KB");

    /* 5 — Connect to device */
    setStatus("Connecting to ESP32-C6…");
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

    /* 9 — Write firmware */
    setStatus("Flashing firmware…");
    log("Writing " + (fwData.length / 1024).toFixed(0) + " KB at 0x" +
        part.offset.toString(16).padStart(4, "0") + "…");

    const fileArray = [{ data: fwData, address: part.offset }];
    await loader.writeFlash({
      fileArray,
      flashSize: "keep",
      flashMode: "keep",
      flashFreq: "keep",
      eraseAll:  false,
      compress:  true,
      reportProgress(fileIndex, written, total) {
        setProgress((written / total) * 100);
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

/* ── Serial monitor ── */
let serialPort    = null;
let serialReader  = null;
let serialWriter  = null;
let serialReading = false;

window.openLogs = async function () {
  if (!("serial" in navigator)) {
    alert("Web Serial not supported. Use Chrome, Edge, or Opera.");
    return;
  }
  $("serial-overlay").hidden = false;
  $("serial-log").textContent = "";

  if (serialPort) return;   // already connected

  try {
    serialPort = await navigator.serial.requestPort();
    const baud = parseInt($("serial-baud-select").value, 10);
    await serialPort.open({ baudRate: baud });

    serialWriter  = serialPort.writable.getWriter();
    const decoder = new TextDecoderStream();
    serialPort.readable.pipeTo(decoder.writable).catch(() => {});
    serialReader  = decoder.readable.getReader();

    serialReading = true;
    (async () => {
      while (serialReading) {
        try {
          const { value, done } = await serialReader.read();
          if (done) break;
          const el = $("serial-log");
          el.textContent += value;
          el.scrollTop = el.scrollHeight;
        } catch (_) { break; }
      }
    })();
  } catch (_) {
    serialPort = null;
    $("serial-overlay").hidden = true;
  }
};

async function closeSerial() {
  serialReading = false;
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
