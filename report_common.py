#!/usr/bin/env python3
"""Shared building blocks for Ragnar's printable survey/incident reports.

Every report (wardriving survey, Wi-Fi spectrum, WIDS incident) is a single
self-contained HTML page with inlined CSS and a print stylesheet, so the
browser's "Save as PDF" turns it into a shareable deliverable. Keeping the CSS,
stat cards, bars, tables and page shell here is what makes the three reports
read as one product instead of three look-alikes.

These helpers are pure formatting — callers pass plain dicts/lists and get a
string back. Nothing here touches the filesystem, a radio, or the network.
"""

import html as _html
from datetime import datetime


def esc(v):
    """HTML-escape any value; None becomes an empty string."""
    return _html.escape('' if v is None else str(v))


# Shared stylesheet — identical across all reports so they look like one family.
REPORT_CSS = """
:root { --fg:#0f172a; --muted:#64748b; --line:#e2e8f0; --bg:#ffffff; --accent:#4f46e5; --panel:#f8fafc; }
* { box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg); background:#eef2f6; margin:0; line-height:1.5; }
.page { max-width:960px; margin:24px auto; background:var(--bg); padding:40px 44px;
  box-shadow:0 1px 4px rgba(0,0,0,.08); border-radius:8px; }
h1 { font-size:26px; margin:0 0 4px; }
h2 { font-size:17px; margin:32px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--line); }
.sub { color:var(--muted); font-size:13px; }
.hdr { display:flex; justify-content:space-between; align-items:flex-start; gap:24px;
  border-bottom:3px solid var(--accent); padding-bottom:16px; }
.brand { font-weight:700; color:var(--accent); letter-spacing:.5px; }
.grade { text-align:center; min-width:120px; }
.grade .g { font-size:52px; font-weight:800; line-height:1; }
.grade .g.small { font-size:26px; }
.grade .gl { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
.grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
.grid3 { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:28px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px 16px; }
.sc-val { font-size:24px; font-weight:700; }
.sc-lbl { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
.sc-sub { font-size:12px; color:var(--muted); margin-top:2px; }
.bar-row { display:flex; align-items:center; gap:10px; margin:7px 0; font-size:13px; }
.bar-lbl { width:190px; flex-shrink:0; }
.bar-track { flex:1; background:#eef2f6; border-radius:5px; height:14px; overflow:hidden; }
.bar-fill { display:block; height:100%; border-radius:5px; }
.bar-num { width:90px; text-align:right; flex-shrink:0; font-variant-numeric:tabular-nums; }
.muted { color:var(--muted); }
.chans { display:flex; align-items:flex-end; gap:6px; height:130px; padding-top:8px;
  border-bottom:1px solid var(--line); }
.chan { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; height:100%; }
.chan-bar { width:60%; min-height:2px; background:var(--accent); border-radius:3px 3px 0 0; }
.chan-num { font-size:10px; color:var(--muted); margin-top:2px; }
.chan-lbl { font-size:11px; font-weight:600; }
table { width:100%; border-collapse:collapse; font-size:12.5px; margin-top:6px; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.5px; }
td { font-variant-numeric:tabular-nums; }
tbody tr:nth-child(even) { background:var(--panel); }
.pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600; }
.note { padding:12px 16px; border-radius:8px; font-size:13px; }
.note.bad { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; }
.note.warn { background:#fffbeb; border:1px solid #fde68a; color:#92400e; }
.note.ok { background:#f0fdf4; border:1px solid #bbf7d0; color:#166534; }
.ai-note { background:#f5f3ff; border:1px solid #ddd6fe; border-left:4px solid var(--accent);
  border-radius:8px; padding:14px 18px; font-size:13px; color:#312e5e; }
.ai-note p { margin:0 0 8px; }
.ai-note .ai-h { font-weight:700; color:#4338ca; margin:12px 0 4px; font-size:13px; }
.ai-note .ai-h:first-child { margin-top:0; }
.ai-note ul.ai-list { margin:4px 0 8px; padding-left:20px; }
.ai-note li { margin:2px 0; }
.ai-note code { background:#ece9fb; padding:1px 5px; border-radius:4px;
  font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; }
.foot { margin-top:36px; padding-top:14px; border-top:1px solid var(--line);
  color:var(--muted); font-size:11px; display:flex; justify-content:space-between; }
@media print {
  body { background:#fff; }
  .page { box-shadow:none; margin:0; max-width:none; border-radius:0; padding:0 12px; }
  h2 { page-break-after:avoid; }
  table, .chans { page-break-inside:avoid; }
}
"""


def stat_card(label, value, sub=''):
    """A single KPI tile (big number + label, optional sub-line)."""
    sub_html = '<div class="sc-sub">%s</div>' % esc(sub) if sub else ''
    return ('<div class="card"><div class="sc-val">%s</div>'
            '<div class="sc-lbl">%s</div>%s</div>'
            % (esc(value), esc(label), sub_html))


def bar_row(label, count, total, color):
    """A horizontal proportion bar (share of `total`)."""
    pct = (count / total * 100) if total else 0
    return ('<div class="bar-row"><span class="bar-lbl">%s</span>'
            '<span class="bar-track"><span class="bar-fill" style="width:%.1f%%;background:%s"></span></span>'
            '<span class="bar-num">%s <span class="muted">(%.0f%%)</span></span></div>'
            % (esc(label), pct, color, esc(count), pct))


def data_table(headers, rows):
    """A table from a header list and a list of already-stringifiable rows.

    Each cell may be either a plain value (escaped) or a ('raw', html) tuple to
    inject pre-built markup such as a coloured severity pill."""
    if not rows:
        return '<p class="muted">None.</p>'
    head = ''.join('<th>%s</th>' % esc(h) for h in headers)
    body = ''
    for r in rows:
        cells = ''
        for c in r:
            if isinstance(c, tuple) and len(c) == 2 and c[0] == 'raw':
                cells += '<td>%s</td>' % c[1]
            else:
                cells += '<td>%s</td>' % esc(c)
        body += '<tr>%s</tr>' % cells
    return ('<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>'
            % (head, body))


def pill(text, color):
    """An inline coloured status pill (raw HTML — pass via ('raw', ...) cells)."""
    return ('<span class="pill" style="background:%s;color:#fff">%s</span>'
            % (color, esc(text)))


def _inline_md(text):
    """Escape a line, then re-enable **bold** and `code` spans only. Everything
    else stays literal, so untrusted model text can't inject markup."""
    out = esc(text)
    import re as _re
    out = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', out)
    out = _re.sub(r'`([^`]+?)`', r'<code>\1</code>', out)
    return out


def markdown_lite(text):
    """Render the small markdown subset the AI helpers emit (bold, `code`,
    `-`/`*`/`1.` bullet lists, `**Header:**` lines and blank-line paragraphs)
    into safe HTML. All text is HTML-escaped first; only bold/code are re-added.

    Deliberately tiny — it exists so the AI analysis reads as formatted prose in
    the printable report instead of a wall of asterisks, without pulling in a
    full markdown dependency."""
    import re as _re
    lines = str(text or '').replace('\r\n', '\n').split('\n')
    html = []
    in_list = False

    def _close_list():
        nonlocal in_list
        if in_list:
            html.append('</ul>')
            in_list = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            _close_list()
            continue
        m = _re.match(r'^\s*(?:[-*•]|\d+[.)])\s+(.*)$', line)
        if m:
            if not in_list:
                html.append('<ul class="ai-list">')
                in_list = True
            html.append('<li>%s</li>' % _inline_md(m.group(1)))
            continue
        _close_list()
        # A line that's entirely a bold run reads as a sub-heading.
        h = _re.match(r'^\*\*(.+?):?\*\*:?$', stripped)
        if h:
            html.append('<div class="ai-h">%s</div>' % _inline_md(h.group(1)))
        else:
            html.append('<p>%s</p>' % _inline_md(stripped))
    _close_list()
    return '\n'.join(html)


def ai_analysis_section(ai, *, heading='AI analysis'):
    """Render a stashed AI analysis dict ({text, connected, overlays, ts}) as a
    report section. Returns '' when there's no usable analysis text."""
    if not isinstance(ai, dict):
        return ''
    text = (ai.get('text') or '').strip()
    if not text:
        return ''
    meta = []
    c = ai.get('connected') or {}
    if c.get('ssid') or c.get('bssid'):
        band = (' · %s GHz' % c['band']) if c.get('band') else ''
        ch = (' ch %s' % c['channel']) if c.get('channel') not in (None, '') else ''
        meta.append('Connection: %s%s%s' % (esc(c.get('ssid') or c.get('bssid')), band, ch))
    ov = ai.get('overlays') or []
    if ov:
        label = {'bt': 'Bluetooth/BLE', 'zigbee': 'Zigbee'}
        meta.append('Includes ' + ', '.join(label.get(o, o) for o in ov))
    meta_html = ('<div class="sub" style="margin:-4px 0 10px">%s</div>'
                 % ' · '.join(meta)) if meta else ''
    return ('<h2>%s</h2>%s<div class="ai-note">%s</div>'
            '<p class="sub" style="margin-top:8px">Generated by Ragnar\'s AI '
            'assistant from the scan data shown above. Advisory only.</p>'
            % (esc(heading), meta_html, markdown_lite(text)))


def page_shell(*, title, brand, heading, subtitle_html, verdict, verdict_label,
               verdict_color, body, footer_note='Informal report — not a certified assessment',
               generated=None):
    """Wrap a report body in the shared header/footer chrome and return a full
    self-contained HTML document."""
    generated = generated or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    v = str(verdict)
    g_class = 'g small' if len(v) > 2 else 'g'
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>%s</style></head>
<body><div class="page">
<div class="hdr">
  <div>
    <div class="brand">%s</div>
    <h1>%s</h1>
    %s
  </div>
  <div class="grade">
    <div class="%s" style="color:%s">%s</div>
    <div class="gl">%s</div>
  </div>
</div>
%s
<div class="foot">
  <span>Generated by Ragnar · %s</span>
  <span>%s</span>
</div>
</div></body></html>""" % (
        esc(title), REPORT_CSS, esc(brand), esc(heading), subtitle_html,
        g_class, verdict_color, esc(verdict), esc(verdict_label), body,
        esc(generated), esc(footer_note))


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return '—'


# ---------------------------------------------------------------------------
# WIDS incident report (from wifi_defense.do_scan / analyze output)
# ---------------------------------------------------------------------------

_DEF_TYPE_LABEL = {
    'deauth': 'Deauth / disassoc',
    'beacon_flood': 'Beacon flood',
    'karma': 'KARMA / MANA',
    'rogue_ap': 'Rogue AP / evil twin',
}
_DEF_SEV_LABEL = {
    'flood': 'FLOOD', 'evil_twin': 'EVIL TWIN', 'karma': 'KARMA',
    'duplicate_ssid': 'DUPLICATE SSID', 'beacon_warn': 'WARNING',
    'seen': 'OBSERVED',
}
_DEF_SEV_COLOR = {
    'flood': '#dc2626', 'evil_twin': '#dc2626', 'karma': '#dc2626',
    'duplicate_ssid': '#ea580c', 'beacon_warn': '#ea580c', 'seen': '#64748b',
}


def build_defense_report_html(scan, device_name='Ragnar'):
    """Render a WIDS incident report from a wifi_defense.do_scan() result."""
    scan = scan or {}
    threat = (scan.get('threat') or 'clear').lower()
    verdict = {'clear': 'CLEAR', 'warning': 'WARNING', 'critical': 'CRITICAL'}.get(threat, threat.upper())
    vcolor = {'clear': '#16a34a', 'warning': '#ea580c', 'critical': '#dc2626'}.get(threat, '#64748b')
    counts = scan.get('counts') or {}
    airspace = scan.get('airspace') or {}
    detections = scan.get('detections') or []
    aps = scan.get('aps') or []

    ch = scan.get('channel')
    ch_str = (' · channel %s' % ch) if ch not in (None, '', 'auto') else ' · all-channel hop'
    subtitle = (
        '<div class="sub">Interface <strong>%s</strong> · monitor %s · %ss capture%s</div>'
        '<div class="sub">Captured %s</div>'
        % (esc(scan.get('interface')), esc(scan.get('monitor') or '—'),
           esc(scan.get('seconds', '?')), ch_str, _fmt_ts(scan.get('timestamp')))
    )

    body = []
    body.append('<h2>Summary</h2><div class="grid4">')
    body.append(stat_card('Frames captured', scan.get('frames', 0)))
    body.append(stat_card('Deauth / disassoc', counts.get('deauth', 0)))
    body.append(stat_card('Beacons', counts.get('beacon', 0)))
    body.append(stat_card('Access points', len(aps)))
    body.append('</div>')

    # Detections / incidents
    body.append('<h2>Detected threats</h2>')
    if detections:
        note_cls = 'bad' if threat == 'critical' else 'warn'
        body.append('<div class="note %s">%d detection(s) fired in this capture window. Review each below.</div>'
                    % (note_cls, len(detections)))
        rows = []
        for d in detections:
            sev = d.get('severity', '')
            rows.append([
                _DEF_TYPE_LABEL.get(d.get('type'), d.get('type', '—')),
                ('raw', pill(_DEF_SEV_LABEL.get(sev, sev.upper()), _DEF_SEV_COLOR.get(sev, '#64748b'))),
                d.get('detail', ''),
            ])
        body.append(data_table(['Type', 'Severity', 'Detail'], rows))
    else:
        body.append('<div class="note ok">No deauth floods, beacon floods, KARMA, or rogue/evil-twin APs '
                    'were detected in this capture window.</div>')

    # Airspace posture
    body.append('<h2>Airspace</h2><div class="grid4">')
    body.append(stat_card('Distinct SSIDs', airspace.get('ssids', 0),
                          'threshold %s' % airspace.get('beacon_ssid_threshold', '—')))
    body.append(stat_card('Distinct BSSIDs', airspace.get('bssids', 0),
                          'threshold %s' % airspace.get('beacon_bssid_threshold', '—')))
    body.append(stat_card('Randomized BSSIDs', airspace.get('random_bssids', 0)))
    body.append(stat_card('LA ratio', '%.0f%%' % (float(airspace.get('la_ratio', 0)) * 100),
                          'high = spoofed MACs'))
    body.append('</div>')

    # AP inventory
    body.append('<h2>Access-point inventory</h2>')
    ap_rows = [[a.get('ssid') or '<hidden>', a.get('bssid'), a.get('channel'),
                '%s dBm' % a.get('rssi', '?'), a.get('beacons', 0)]
               for a in aps[:150]]
    body.append(data_table(['SSID', 'BSSID', 'Ch', 'RSSI', 'Beacons'], ap_rows))

    return page_shell(
        title='Ragnar WIDS Incident Report',
        brand='RAGNAR · WIRELESS DEFENSE',
        heading='Wi-Fi Intrusion-Detection Report',
        subtitle_html='<div class="sub">Device %s</div>%s' % (esc(device_name or 'Ragnar'), subtitle),
        verdict=verdict, verdict_label='Threat level', verdict_color=vcolor,
        body='\n'.join(body),
        footer_note='Passive detection-only capture — informal, not a certified assessment',
    )


# ---------------------------------------------------------------------------
# Spectrum survey report (from wifi_analyzer.do_scan output)
# ---------------------------------------------------------------------------

_RATING_LABEL = {'clear': 'CLEAR', 'moderate': 'MODERATE', 'congested': 'CONGESTED'}
_RATING_COLOR = {'clear': '#16a34a', 'moderate': '#ca8a04', 'congested': '#dc2626'}
_RATING_RANK = {'clear': 0, 'moderate': 1, 'congested': 2}
_BAND_LABEL = {'2.4': '2.4 GHz', '5': '5 GHz', '6': '6 GHz'}


_PRESSURE_COLOR = {'low': '#64748b', 'moderate': '#ca8a04', 'high': '#dc2626'}
_BT_KIND_LABEL = {'le': 'BLE', 'classic': 'Classic', 'dual': 'Dual'}


def _pressure_pills(channels):
    """Per-Wi-Fi-channel coexistence-pressure chips shared by the BT/Zigbee
    overlay sections (channels carry {wifi_channel, level, pressure})."""
    chips = []
    for c in channels or []:
        col = _PRESSURE_COLOR.get(c.get('level'), '#64748b')
        chips.append('<span class="pill" style="background:%s;color:#fff">ch%s: %s</span>'
                     % (col, esc(c.get('wifi_channel')), esc(c.get('level') or '—')))
    if not chips:
        return ''
    return ('<p class="sub" style="margin:8px 0 4px">Estimated Wi-Fi-channel pressure '
            '(heuristic, not measured):</p><div style="display:flex;gap:6px;flex-wrap:wrap">%s</div>'
            % ' '.join(chips))


def bt_overlay_section(bt):
    """Render the Bluetooth / BLE 2.4 GHz overlay (bt_scanner.do_scan payload)
    as a report section. Returns '' when there's nothing to show."""
    if not isinstance(bt, dict):
        return ''
    devices = bt.get('devices') or []
    inter = bt.get('interference') or {}
    if not devices and not bt.get('device_count'):
        return ''
    body = ['<h2>Bluetooth / BLE (2.4 GHz coexistence)</h2><div class="grid4">']
    body.append(stat_card('BT/BLE devices', bt.get('device_count', len(devices))))
    body.append(stat_card('BLE', inter.get('le_count', 0)))
    body.append(stat_card('Classic / dual', inter.get('classic_count', 0)))
    body.append(stat_card('Close (strong)', inter.get('strong_count', 0)))
    body.append('</div>')
    body.append(_pressure_pills(inter.get('channels')))
    rows = [[d.get('name') or '(no name)',
             _BT_KIND_LABEL.get(d.get('kind'), d.get('kind') or '—'),
             d.get('vendor') or '—',
             d.get('major_class') or '—',
             ('%s dBm' % d['rssi']) if d.get('rssi') is not None else '—']
            for d in devices[:60]]
    body.append(data_table(['Device', 'Type', 'Vendor', 'Class', 'RSSI'], rows))
    note = bt.get('coexistence_note') or (inter.get('note') if isinstance(inter, dict) else '')
    if note:
        body.append('<p class="sub" style="margin-top:8px">%s</p>' % esc(note))
    return '\n'.join(body)


def zigbee_overlay_section(zb):
    """Render the Zigbee / 802.15.4 overlay (zigbee_overlay.build_overlay
    payload) as a report section. Returns '' when there's nothing to show."""
    if not isinstance(zb, dict):
        return ''
    devices = zb.get('devices') or []
    inter = zb.get('interference') or {}
    if not devices and not zb.get('device_count'):
        return ''
    body = ['<h2>Zigbee / 802.15.4 (2.4 GHz coexistence)</h2><div class="grid4">']
    body.append(stat_card('Zigbee devices', zb.get('device_count', len(devices))))
    body.append(stat_card('Active channels', inter.get('channel_count', 0)))
    body.append(stat_card('Close (strong)', inter.get('strong_count', 0)))
    markers = inter.get('markers') or []
    busiest = max(markers, key=lambda m: m.get('count', 0), default=None)
    body.append(stat_card('Busiest channel',
                          ('%s' % busiest['channel']) if busiest else '—',
                          ('%s dev' % busiest['count']) if busiest else ''))
    body.append('</div>')
    body.append(_pressure_pills(inter.get('wifi_channels')))
    rows = [[d.get('addr') or d.get('short_addr') or '—',
             d.get('panid') or '—',
             d.get('channel') if d.get('channel') is not None else '—',
             d.get('proto') or '—',
             d.get('vendor') or '—',
             ('%s dBm' % d['rssi']) if d.get('rssi') is not None else '—',
             d.get('lqi') if d.get('lqi') is not None else '—']
            for d in devices[:60]]
    body.append(data_table(['Address', 'PAN ID', 'Ch', 'Proto', 'Vendor', 'RSSI', 'LQI'], rows))
    note = zb.get('companion_note') or (inter.get('note') if isinstance(inter, dict) else '')
    if note:
        body.append('<p class="sub" style="margin-top:8px">%s</p>' % esc(note))
    return '\n'.join(body)


def build_spectrum_report_html(scan, device_name='Ragnar', bt=None, zb=None, ai=None):
    """Render a Wi-Fi spectrum / channel-congestion report from a
    wifi_analyzer.do_scan() result.

    Optional companions mirror the analyzer panel: `bt` / `zb` are the live
    2.4 GHz Bluetooth / Zigbee overlay payloads, and `ai` is a stashed AI
    analysis ({text, connected, overlays}). Each is rendered only when present."""
    scan = scan or {}
    aps = scan.get('aps') or []
    spectrum = scan.get('spectrum') or {}
    groups = scan.get('groups') or {}
    interference = scan.get('interference') or {}

    # Overall verdict = worst band rating present.
    worst = 'clear'
    for band, info in spectrum.items():
        r = info.get('rating', 'clear')
        if _RATING_RANK.get(r, 0) > _RATING_RANK.get(worst, 0):
            worst = r
    verdict = _RATING_LABEL.get(worst, worst.upper())
    vcolor = _RATING_COLOR.get(worst, '#64748b')

    active_bands = [_BAND_LABEL[b] for b in ('2.4', '5', '6') if b in spectrum]
    nf = scan.get('noise_floor')
    subtitle = (
        '<div class="sub">Interface <strong>%s</strong> · %s · noise floor %s</div>'
        '<div class="sub">Scanned %s</div>'
        % (esc(scan.get('interface')), esc(scan.get('phy') or '?'),
           ('%s dBm' % nf) if nf is not None else '—', _fmt_ts(scan.get('timestamp')))
    )

    body = []
    body.append('<h2>Summary</h2><div class="grid4">')
    body.append(stat_card('Access points', scan.get('ap_count', len(aps))))
    body.append(stat_card('Networks (SSIDs)', groups.get('network_count', 0)))
    body.append(stat_card('Bands active', ', '.join(active_bands) or '—'))
    body.append(stat_card('Noise floor', ('%s dBm' % nf) if nf is not None else '—'))
    body.append('</div>')

    # Per-band congestion picture
    for band in ('2.4', '5', '6'):
        info = spectrum.get(band)
        if not info:
            continue
        rating = info.get('rating', 'clear')
        rec = ', '.join(str(c) for c in info.get('recommend', [])) or '—'
        wa = info.get('width_advice') or {}
        body.append('<h2>%s congestion &nbsp;'
                    '<span class="pill" style="background:%s;color:#fff">%s</span></h2>'
                    % (esc(_BAND_LABEL[band]), _RATING_COLOR.get(rating, '#64748b'),
                       esc(_RATING_LABEL.get(rating, rating.upper()))))
        body.append('<div class="grid3">')
        body.append(stat_card('APs on band', info.get('ap_count', 0)))
        body.append(stat_card('Recommended channels', rec))
        body.append(stat_card('Suggested width', ('%s MHz' % wa.get('mhz')) if wa.get('mhz') else '—'))
        body.append('</div>')
        if wa.get('reason'):
            body.append('<p class="sub" style="margin-top:8px">%s</p>' % esc(wa['reason']))
        # Channel congestion histogram (score per channel; higher = worse)
        chans = info.get('channels') or []
        if chans:
            cmax = max((c.get('score', 0) for c in chans), default=1) or 1
            bars = ''
            for c in sorted(chans, key=lambda c: c.get('channel', 0)):
                h = (c.get('score', 0) / cmax * 100)
                lbl = 'Channel %s: %d AP(s), score %.1f%s' % (
                    c.get('channel'), c.get('ap_count', 0), c.get('score', 0),
                    ' (DFS/radar)' if c.get('radar') else '')
                bars += ('<div class="chan"><span class="chan-bar" style="height:%.0f%%" title="%s"></span>'
                         '<span class="chan-num">%d</span><span class="chan-lbl">%s</span></div>'
                         % (h, esc(lbl), c.get('ap_count', 0), esc(c.get('channel'))))
            body.append('<div class="chans">%s</div>' % bars)

    # Interference groups
    co = interference.get('co_channel') or []
    adj = interference.get('adjacent_overlap') or []
    if co or adj:
        body.append('<h2>Interference</h2><div class="grid2" style="grid-template-columns:1fr 1fr">')
        body.append(stat_card('Co-channel groups', len(co)))
        body.append(stat_card('Adjacent-overlap groups', len(adj)))
        body.append('</div>')

    # Networks (SSID view)
    body.append('<h2>Networks</h2>')
    net_rows = [[n.get('ssid') or '<hidden>', '/'.join(n.get('bands', [])),
                 n.get('ap_count', len(n.get('bssids', []))), n.get('security') or '—',
                 ('%s dBm' % n['best_signal']) if n.get('best_signal') is not None else '—']
                for n in (groups.get('networks') or [])[:150]]
    body.append(data_table(['SSID', 'Bands', 'APs', 'Security', 'Best signal'], net_rows))

    # Strongest APs
    body.append('<h2>Strongest access points</h2>')
    ap_sorted = sorted(aps, key=lambda a: -(a.get('signal') if a.get('signal') is not None else -999))
    ap_rows = [[a.get('ssid') or '<hidden>', a.get('bssid'),
                '%s GHz' % a.get('band', '?'), a.get('channel'),
                '%s MHz' % a.get('width', '?'),
                ('%s dBm' % a['signal']) if a.get('signal') is not None else '—',
                ('%s dB' % a['snr']) if a.get('snr') is not None else '—',
                a.get('standard') or '—', a.get('security') or '—']
               for a in ap_sorted[:60]]
    body.append(data_table(['SSID', 'BSSID', 'Band', 'Ch', 'Width', 'Signal', 'SNR', 'Standard', 'Security'], ap_rows))

    # 2.4 GHz non-Wi-Fi overlays (only when the panel captured them).
    body.append(bt_overlay_section(bt))
    body.append(zigbee_overlay_section(zb))

    # AI analysis, if the user ran one on this panel (matches the on-screen read).
    body.append(ai_analysis_section(ai, heading='AI analysis'))

    return page_shell(
        title='Ragnar Wi-Fi Spectrum Report',
        brand='RAGNAR · SPECTRUM SURVEY',
        heading='Wi-Fi Spectrum & Channel Report',
        subtitle_html='<div class="sub">Device %s</div>%s' % (esc(device_name or 'Ragnar'), subtitle),
        verdict=verdict, verdict_label='RF congestion', verdict_color=vcolor,
        body='\n'.join(body),
        footer_note='Passive spectrum survey — informal, not a certified assessment',
    )
