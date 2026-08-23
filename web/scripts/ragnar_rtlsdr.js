// ragnar_rtlsdr.js — Sub-GHz SDR tab (RTL-SDR): ISM device scanner + waterfall.
// Talks to /api/net/rtl/*. One dongle, so ISM and Waterfall are mutually
// exclusive; the backend enforces it, the UI just reflects it.
'use strict';

const _rtl = {
    mode: 'ism',
    available: false,
    detect: null,
    statusPoll: null,
    ism:   { running: false, poll: null },
    power: { running: false, poll: null, seq: 0, rows: [], floor: -120, bandHz: null, maxhold: null, error: null },
};

// ---- lifecycle -------------------------------------------------------------
function rtlsdrEnter() {
    rtlRefreshStatus();
    if (!_rtl.statusPoll) _rtl.statusPoll = setInterval(rtlRefreshStatus, 15000);
    rtlSetMode(_rtl.mode, true);
}

function rtlsdrLeave() {
    if (_rtl.statusPoll) { clearInterval(_rtl.statusPoll); _rtl.statusPoll = null; }
    if (_rtl.ism.poll) { clearInterval(_rtl.ism.poll); _rtl.ism.poll = null; }
    if (_rtl.power.poll) { clearInterval(_rtl.power.poll); _rtl.power.poll = null; }
    if (_rtl.ism.running) { fetch('/api/net/rtl/ism/stop', { method: 'POST' }).catch(() => {}); _rtl.ism.running = false; }
    if (_rtl.power.running) { fetch('/api/net/rtl/power/stop', { method: 'POST' }).catch(() => {}); _rtl.power.running = false; }
}
window.addEventListener('beforeunload', () => { if (_rtl.ism.running || _rtl.power.running) rtlsdrLeave(); });

function rtlRefreshStatus() {
    fetch('/api/net/rtl/status').then(r => r.json()).then(st => {
        const det = st.detect || {};
        _rtl.detect = det;
        _rtl.available = !!det.available;
        _rtl.ism.running = !!(st.ism && st.ism.running);
        _rtl.power.running = !!(st.power && st.power.running);
        const el = document.getElementById('rtl-detect');
        if (el) {
            if (det.available) {
                const who = det.tuner ? (det.tuner + ' tuner') : (det.device || 'RTL-SDR');
                el.innerHTML = '<span class="text-emerald-400">●</span> ' + rtlEsc(who) + ' ready';
            } else {
                el.innerHTML = '<span class="text-slate-500">○</span> ' + rtlEsc(det.error || 'No RTL-SDR detected');
            }
        }
        rtlSyncButtons();
    }).catch(() => {});
}

function rtlSyncButtons() {
    const dis = !_rtl.available;
    ['rtl-ism-toggle', 'rtl-power-toggle'].forEach(id => {
        const b = document.getElementById(id);
        if (b) { b.disabled = dis; b.classList.toggle('opacity-40', dis); b.classList.toggle('cursor-not-allowed', dis); }
    });
    rtlSetToggle('rtl-ism-toggle', _rtl.ism.running);
    rtlSetToggle('rtl-power-toggle', _rtl.power.running);
}

function rtlSetToggle(id, running) {
    const b = document.getElementById(id);
    if (!b) return;
    b.textContent = running ? 'Stop' : 'Start';
    b.classList.toggle('bg-emerald-600', !running);
    b.classList.toggle('hover:bg-emerald-500', !running);
    b.classList.toggle('bg-rose-600', running);
    b.classList.toggle('hover:bg-rose-500', running);
}

// ---- mode switch -----------------------------------------------------------
function rtlSetMode(mode, force) {
    if (mode === _rtl.mode && !force) return;
    // Switching modes frees the dongle: stop whatever is running.
    if (_rtl.ism.running) rtlIsmStop();
    if (_rtl.power.running) rtlPowerStop();
    _rtl.mode = mode;
    document.getElementById('rtl-view-ism').classList.toggle('hidden', mode !== 'ism');
    document.getElementById('rtl-view-power').classList.toggle('hidden', mode !== 'power');
    [['rtl-mode-ism', 'ism'], ['rtl-mode-power', 'power']].forEach(([id, m]) => {
        const b = document.getElementById(id);
        if (!b) return;
        const on = m === mode;
        b.classList.toggle('bg-Ragnar-600', on);
        b.classList.toggle('text-white', on);
        b.classList.toggle('text-slate-300', !on);
        b.classList.toggle('hover:bg-slate-700', !on);
    });
    if (mode === 'ism') rtlRenderDevices({ devices: [], count: 0, events: 0 });
    else rtlDrawWaterfall();
    rtlSyncButtons();
}

// ---- ISM scanner -----------------------------------------------------------
function rtlIsmToggle() { _rtl.ism.running ? rtlIsmStop() : rtlIsmStart(); }

function rtlIsmStart() {
    if (!_rtl.available) return;
    const band = (document.getElementById('rtl-ism-band') || {}).value || '433';
    fetch('/api/net/rtl/ism/start', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ band }) }).then(r => r.json()).then(res => {
        if (res && res.error) { rtlIsmStat('⚠ ' + res.error); return; }
        _rtl.ism.running = true; rtlSetToggle('rtl-ism-toggle', true);
        if (_rtl.ism.poll) clearInterval(_rtl.ism.poll);
        _rtl.ism.poll = setInterval(rtlIsmPoll, 1500);
        rtlIsmPoll();
    }).catch(() => rtlIsmStat('⚠ start failed'));
}

function rtlIsmStop() {
    if (_rtl.ism.poll) { clearInterval(_rtl.ism.poll); _rtl.ism.poll = null; }
    _rtl.ism.running = false; rtlSetToggle('rtl-ism-toggle', false);
    fetch('/api/net/rtl/ism/stop', { method: 'POST' }).catch(() => {});
}

function rtlIsmPoll() {
    fetch('/api/net/rtl/ism/devices').then(r => r.json()).then(d => {
        if (d.error) rtlIsmStat('⚠ ' + d.error);
        else rtlIsmStat(d.count + ' device' + (d.count === 1 ? '' : 's') + ' · ' + d.events + ' events');
        rtlRenderDevices(d);
    }).catch(() => {});
}

function rtlIsmStat(t) { const el = document.getElementById('rtl-ism-stat'); if (el) el.textContent = t; }

function rtlRenderDevices(d) {
    const tb = document.getElementById('rtl-ism-tbody');
    const empty = document.getElementById('rtl-ism-empty');
    if (!tb) return;
    const rows = d.devices || [];
    if (!rows.length) {
        tb.innerHTML = '';
        if (empty) empty.textContent = _rtl.ism.running ? 'Listening… decoded devices will appear here.'
            : 'Start the scanner to list nearby 433/868/915 MHz devices.';
        return;
    }
    if (empty) empty.textContent = '';
    const now = Date.now() / 1000;
    tb.innerHTML = rows.map(r => {
        const fields = Object.entries(r.fields || {}).map(([k, v]) => rtlEsc(k) + '=' + rtlEsc(String(v))).join(', ');
        const freq = r.freq_mhz ? (r.freq_mhz.toFixed(3) + ' MHz') : '—';
        const rssi = (r.rssi === null || r.rssi === undefined) ? '—' : (Math.round(r.rssi * 10) / 10 + ' dB');
        const ago = r.last_ts ? Math.max(0, Math.round(now - r.last_ts)) + 's' : '—';
        return `<tr class="hover:bg-slate-800/40">
            <td class="px-3 py-2 text-white">${rtlEsc(r.model || '')}</td>
            <td class="px-3 py-2 text-slate-300">${r.id === null || r.id === undefined ? (rtlEsc(String(r.channel ?? '—'))) : rtlEsc(String(r.id))}</td>
            <td class="px-3 py-2 text-right text-slate-400">${freq}</td>
            <td class="px-3 py-2 text-right text-slate-400">${rssi}</td>
            <td class="px-3 py-2 text-right text-slate-400">${r.count || 0}</td>
            <td class="px-3 py-2 text-right text-slate-400">${ago}</td>
            <td class="px-3 py-2 text-slate-400 text-xs">${fields}</td>
        </tr>`;
    }).join('');
}

// ---- Sub-GHz waterfall -----------------------------------------------------
function rtlPowerToggle() { _rtl.power.running ? rtlPowerStop() : rtlPowerStart(); }

function rtlPowerStart() {
    if (!_rtl.available) return;
    const band = (document.getElementById('rtl-power-band') || {}).value || '433';
    _rtl.power.seq = 0; _rtl.power.rows = []; _rtl.power.maxhold = null; _rtl.power.error = null;
    fetch('/api/net/rtl/power/start', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ band }) }).then(r => r.json()).then(res => {
        if (res && res.error) { rtlPowerStat('⚠ ' + res.error); return; }
        _rtl.power.running = true; rtlSetToggle('rtl-power-toggle', true);
        if (_rtl.power.poll) clearInterval(_rtl.power.poll);
        _rtl.power.poll = setInterval(rtlPowerPoll, 500);
    }).catch(() => rtlPowerStat('⚠ start failed'));
}

function rtlPowerStop() {
    if (_rtl.power.poll) { clearInterval(_rtl.power.poll); _rtl.power.poll = null; }
    _rtl.power.running = false; rtlSetToggle('rtl-power-toggle', false);
    fetch('/api/net/rtl/power/stop', { method: 'POST' }).catch(() => {});
}

function rtlPowerPoll() {
    const s = _rtl.power;
    fetch('/api/net/rtl/power/frames?since=' + s.seq).then(r => r.json()).then(d => {
        s.error = d.error || null;
        if (d.band_hz) s.bandHz = d.band_hz;
        if (typeof d.floor_dbm === 'number') s.floor = d.floor_dbm;
        if (d.max_hold) s.maxhold = d.max_hold;
        (d.frames || []).forEach(f => { s.seq = f.seq; s.rows.unshift(f.power); });
        if (s.rows.length > 600) s.rows.length = 600;
        const fb = s.rows.length ? '' : (s.error ? ('⚠ ' + s.error) : 'sweeping…');
        rtlPowerStat(fb);
        rtlDrawWaterfall();
    }).catch(() => {});
}

function rtlPowerStat(t) { const el = document.getElementById('rtl-power-stat'); if (el) el.textContent = t; }

// dBm -> colour: dark → blue → cyan → green → yellow → red.
function rtlColor(dbm, floor) {
    const top = -20, lo = (typeof floor === 'number' ? floor : -110);
    let t = (dbm - lo) / (top - lo); t = Math.max(0, Math.min(1, t));
    const stops = [[8, 12, 30], [30, 60, 170], [30, 190, 200], [40, 200, 70], [235, 220, 40], [235, 60, 40]];
    const seg = t * (stops.length - 1), i = Math.floor(seg), f = seg - i;
    const a = stops[i], b = stops[Math.min(stops.length - 1, i + 1)];
    return `rgb(${Math.round(a[0] + (b[0] - a[0]) * f)},${Math.round(a[1] + (b[1] - a[1]) * f)},${Math.round(a[2] + (b[2] - a[2]) * f)})`;
}

function rtlDrawWaterfall() {
    const s = _rtl.power;
    const canvas = document.getElementById('rtl-waterfall');
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth, H = canvas.clientHeight || 360;
    if (W < 20 || H < 20) return;
    canvas.width = W * dpr; canvas.height = H * dpr;
    const ctx = canvas.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const padL = 52, padR = 12, padT = 12, padB = 22;
    const plotW = W - padL - padR;
    const specH = Math.max(70, Math.round(H * 0.26)), gap = 8;
    const wfTop = padT + specH + gap, wfH = H - padB - wfTop;
    const loHz = s.bandHz ? s.bandHz[0] : 433050000;
    const hiHz = s.bandHz ? s.bandHz[1] : 434790000;

    if (!_rtl.available || s.error || !s.rows.length) {
        ctx.fillStyle = '#0b1220'; ctx.fillRect(padL, wfTop, plotW, wfH);
        ctx.fillStyle = '#64748b'; ctx.font = '13px sans-serif'; ctx.textAlign = 'center';
        const msg = !_rtl.available ? '📻 Connect an RTL-SDR to see the sub-GHz waterfall'
            : s.error ? ('⚠ ' + s.error) : 'Starting rtl_power sweep…';
        ctx.fillText(msg, W / 2, wfTop + wfH / 2);
        return;
    }

    const nb = s.rows[0].length;
    const colW = plotW / nb;
    const rowH = Math.max(1, wfH / Math.min(s.rows.length, Math.floor(wfH)));
    for (let r = 0; r < s.rows.length; r++) {
        const y = wfTop + r * rowH;
        if (y > wfTop + wfH) break;
        const row = s.rows[r];
        for (let bi = 0; bi < nb; bi++) {
            ctx.fillStyle = rtlColor(row[bi], s.floor);
            ctx.fillRect(padL + bi * colW, y, Math.ceil(colW), Math.ceil(rowH));
        }
    }

    // spectrum line: current + max-hold
    ctx.fillStyle = '#0b1220'; ctx.fillRect(padL, padT, plotW, specH);
    const sTop = -20, sBot = s.floor;
    const yFor = (db) => padT + (sTop - Math.max(sBot, Math.min(sTop, db))) / (sTop - sBot) * specH;
    const xForBin = (bi) => padL + (bi + 0.5) / nb * plotW;
    ctx.strokeStyle = '#1e293b'; ctx.fillStyle = '#475569'; ctx.font = '9px sans-serif'; ctx.textAlign = 'right';
    for (let v = sTop; v >= sBot; v -= 20) {
        const y = yFor(v); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
        ctx.fillText(v + '', padL - 3, y + 3);
    }
    const trace = (arr, stroke, wdt) => {
        if (!arr) return;
        ctx.strokeStyle = stroke; ctx.lineWidth = wdt; ctx.beginPath();
        for (let bi = 0; bi < arr.length; bi++) { const x = xForBin(bi), y = yFor(arr[bi]); bi ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }
        ctx.stroke();
    };
    trace(s.maxhold, 'rgba(148,163,184,0.7)', 1);
    trace(s.rows[0], '#22d3ee', 1.5);

    // frequency axis (MHz)
    ctx.fillStyle = '#64748b'; ctx.font = '9px sans-serif'; ctx.textAlign = 'center';
    const ticks = 6;
    for (let i = 0; i <= ticks; i++) {
        const fx = padL + (i / ticks) * plotW;
        const mhz = (loHz + (i / ticks) * (hiHz - loHz)) / 1e6;
        ctx.fillText(mhz.toFixed(mhz < 1000 ? 1 : 0), fx, H - 8);
    }
}

// small HTML escaper for table cells
function rtlEsc(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

window.rtlsdrEnter = rtlsdrEnter;
window.rtlsdrLeave = rtlsdrLeave;
