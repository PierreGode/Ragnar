/*
 * RagnarSkyView — fullscreen GPS sky view with a real starfield behind the
 * satellites. Shared by the desktop dashboard (ragnar_modern.js) and the
 * phone-access page (wardrive_mobile.html); both just call
 * RagnarSkyView.open().
 *
 * Satellites come from GET /api/wardriving/diagnostics (gps.sky — per-satellite
 * azimuth/elevation/SNR, same data the small diagnostics plot draws). Stars are
 * a bundled bright-star catalog (web/vendor/star_catalog.json, RA/Dec J2000)
 * projected to the observer's local sky from the GPS fix + the device clock, so
 * the star field lines up with the satellites in one true-north frame.
 *
 * Stars render ONLY when there is a live position fix — without lat/lon we
 * cannot place them. Satellites always render.
 *
 * No external libraries, no CDN: pure SVG + vanilla JS. The astronomy transform
 * (RA/Dec -> alt/az) is standard sidereal-time math, self-tested against
 * Polaris (alt == latitude, az == 0).
 */
(function () {
  'use strict';

  const D2R = Math.PI / 180, R2D = 180 / Math.PI;
  const CATALOG_URL = '/web/vendor/star_catalog.json';
  const REFRESH_MS = 1000;

  // Constellation colours mirror the small diagnostics plot.
  const SAT_COLORS = {
    GPS: '#34d399', GLONASS: '#f87171', Galileo: '#60a5fa',
    BeiDou: '#fbbf24', QZSS: '#a78bfa', NavIC: '#f472b6', combined: '#94a3b8'
  };
  // Full constellation names for the star info card.
  const CONSTELLATIONS = {
    And: 'Andromeda', Ant: 'Antlia', Aps: 'Apus', Aql: 'Aquila', Aqr: 'Aquarius',
    Ara: 'Ara', Ari: 'Aries', Aur: 'Auriga', Boo: 'Boötes', Cae: 'Caelum',
    Cam: 'Camelopardalis', Cap: 'Capricornus', Car: 'Carina', Cas: 'Cassiopeia',
    Cen: 'Centaurus', Cep: 'Cepheus', Cet: 'Cetus', Cha: 'Chamaeleon',
    Cir: 'Circinus', CMa: 'Canis Major', CMi: 'Canis Minor', Cnc: 'Cancer',
    Col: 'Columba', Com: 'Coma Berenices', CrA: 'Corona Australis',
    CrB: 'Corona Borealis', Crt: 'Crater', Cru: 'Crux', Crv: 'Corvus',
    CVn: 'Canes Venatici', Cyg: 'Cygnus', Del: 'Delphinus', Dor: 'Dorado',
    Dra: 'Draco', Equ: 'Equuleus', Eri: 'Eridanus', For: 'Fornax',
    Gem: 'Gemini', Gru: 'Grus', Her: 'Hercules', Hor: 'Horologium',
    Hya: 'Hydra', Hyi: 'Hydrus', Ind: 'Indus', Lac: 'Lacerta', Leo: 'Leo',
    Lep: 'Lepus', Lib: 'Libra', LMi: 'Leo Minor', Lup: 'Lupus', Lyn: 'Lynx',
    Lyr: 'Lyra', Men: 'Mensa', Mic: 'Microscopium', Mon: 'Monoceros',
    Mus: 'Musca', Nor: 'Norma', Oct: 'Octans', Oph: 'Ophiuchus', Ori: 'Orion',
    Pav: 'Pavo', Peg: 'Pegasus', Per: 'Perseus', Phe: 'Phoenix', Pic: 'Pictor',
    PsA: 'Piscis Austrinus', Psc: 'Pisces', Pup: 'Puppis', Pyx: 'Pyxis',
    Ret: 'Reticulum', Scl: 'Sculptor', Sco: 'Scorpius', Sct: 'Scutum',
    Ser: 'Serpens', Sex: 'Sextans', Sge: 'Sagitta', Sgr: 'Sagittarius',
    Tau: 'Taurus', Tel: 'Telescopium', TrA: 'Triangulum Australe',
    Tri: 'Triangulum', Tuc: 'Tucana', UMa: 'Ursa Major', UMi: 'Ursa Minor',
    Vel: 'Vela', Vir: 'Virgo', Vol: 'Volans', Vul: 'Vulpecula'
  };

  // ---- Astronomy -------------------------------------------------------
  function julianDay(date) { return date.getTime() / 86400000 + 2440587.5; }
  function gmstDeg(date) {
    const d = julianDay(date) - 2451545.0;
    return (((280.46061837 + 360.98564736629 * d) % 360) + 360) % 360;
  }
  // RA/Dec (deg) + observer lat/lon (deg, E+) -> {alt, az} deg (az from N, CW).
  function raDecToAltAz(ra, dec, lat, lon, date) {
    const lst = ((gmstDeg(date) + lon) % 360 + 360) % 360;
    const H = (((lst - ra) % 360) + 360) % 360;
    const Hr = H * D2R, dr = dec * D2R, phr = lat * D2R;
    const sinAlt = Math.sin(dr) * Math.sin(phr) + Math.cos(dr) * Math.cos(phr) * Math.cos(Hr);
    const alt = Math.asin(Math.max(-1, Math.min(1, sinAlt)));
    let cosA = (Math.sin(dr) - Math.sin(phr) * sinAlt) / (Math.cos(phr) * Math.cos(alt));
    cosA = Math.max(-1, Math.min(1, cosA));
    let az = Math.acos(cosA) * R2D;
    if (Math.sin(Hr) > 0) az = 360 - az;
    return { alt: alt * R2D, az };
  }

  // ---- State -----------------------------------------------------------
  let overlay = null, svg = null, infoCard = null, subtitleEl = null, noteEl = null, detailEl = null;
  let catalog = null, catalogLoading = null;
  let timer = null, onEsc = null, resizeH = null;
  let enhanced = false;
  // mode: 'live' (this boot's fix) | 'last' (persisted last-known) | 'none'
  let lastData = { sky: [], lat: null, lon: null, mode: 'none', t: null };
  // Screen-space projected objects for click hit-testing.
  let projected = [];

  function esc(s) {
    return String(s).replace(/[<>&"]/g, c =>
      ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  }

  // Resolve the sky origin: a live fix wins; else the server's persisted
  // last-known position (survives reboots); else nothing.
  function positionFromStatus(status) {
    status = status || {};
    const lat = status.latitude, lon = status.longitude;
    if (status.has_fix && typeof lat === 'number' && typeof lon === 'number')
      return { lat, lon, mode: 'live', t: null };
    const lk = status.last_known;
    if (lk && typeof lk.lat === 'number' && typeof lk.lon === 'number')
      return { lat: lk.lat, lon: lk.lon, mode: 'last', t: lk.t };
    return { lat: null, lon: null, mode: 'none', t: null };
  }

  function agoText(epochSec) {
    if (!epochSec) return '';
    const s = Math.max(0, Date.now() / 1000 - epochSec);
    if (s < 90) return 'moments ago';
    if (s < 5400) return Math.round(s / 60) + ' min ago';
    if (s < 172800) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' days ago';
  }

  function loadCatalog() {
    if (catalog) return Promise.resolve(catalog);
    if (catalogLoading) return catalogLoading;
    catalogLoading = fetch(CATALOG_URL)
      .then(r => r.ok ? r.json() : null)
      .then(j => { catalog = j; return j; })
      .catch(() => { catalog = null; return null; });
    return catalogLoading;
  }

  // ---- Rendering -------------------------------------------------------
  function render() {
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const S = Math.max(200, Math.min(rect.width, rect.height));
    const c = S / 2, R = c - Math.max(26, S * 0.06);
    const date = new Date();
    projected = [];
    const parts = [];
    let visibleStars = 0, namedStars = 0, trackedSats = 0, snrSum = 0;
    let strongestSat = null, strongestSnr = -1;

    // Sky disc + gradient.
    parts.push(`<defs><radialGradient id="skgrad" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="${enhanced ? '#132d4f' : '#0b1830'}"/><stop offset="70%" stop-color="${enhanced ? '#081328' : '#070d1c'}"/>
      <stop offset="100%" stop-color="#03060f"/></radialGradient>
      <radialGradient id="sv-halo" cx="50%" cy="50%" r="50%"><stop offset="68%" stop-color="rgba(14,165,233,0)"/><stop offset="100%" stop-color="rgba(56,189,248,.24)"/></radialGradient>
      <clipPath id="sv-sky-clip"><circle cx="${c}" cy="${c}" r="${R}"/></clipPath>
      <filter id="sv-star-glow" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="1.6" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`);
    parts.push(`<circle cx="${c}" cy="${c}" r="${R}" fill="url(#skgrad)"/>`);
    if (enhanced) {
      parts.push(`<circle cx="${c}" cy="${c}" r="${R}" fill="url(#sv-halo)"/>`);
      const bandPts = [];
      for (let i = 0; i <= 30; i++) {
        const x = c - R * 1.05 + (R * 2.1 * i / 30);
        const t = (i / 30) * Math.PI * 2.2;
        const y = c + Math.sin(t) * R * .2 + (i / 30 - .5) * R * .18;
        bandPts.push(`${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`);
      }
      parts.push(`<path d="${bandPts.join(' ')}" clip-path="url(#sv-sky-clip)" fill="none" stroke="rgba(186,230,253,.12)" stroke-width="${(R * .2).toFixed(1)}" stroke-linecap="round"/>`);
      parts.push(`<path d="${bandPts.join(' ')}" clip-path="url(#sv-sky-clip)" fill="none" stroke="rgba(255,255,255,.16)" stroke-width="${Math.max(1, R * .015).toFixed(1)}" stroke-linecap="round" stroke-dasharray="2 12"/>`);
      for (let i = 0; i < 140; i++) {
        const seed = (i * 9301 + 49297) % 233280;
        const seed2 = (i * 23399 + 18919) % 104729;
        const rr = R * Math.sqrt(seed / 233280);
        const a = (seed2 / 104729) * Math.PI * 2;
        const x = c + rr * Math.cos(a), y = c + rr * Math.sin(a);
        const op = 0.08 + ((i % 9) / 9) * 0.22;
        parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(0.35 + (i % 5) * 0.08).toFixed(2)}" fill="#dbeafe" opacity="${op.toFixed(2)}"/>`);
      }
      for (const tilt of [-28, 18]) {
        parts.push(`<ellipse cx="${c}" cy="${c}" rx="${(R * .9).toFixed(1)}" ry="${(R * .19).toFixed(1)}" fill="none" stroke="rgba(125,211,252,.16)" stroke-width="${Math.max(1, R * .01).toFixed(1)}" transform="rotate(${tilt} ${c} ${c})"/>`);
      }
      parts.push(`<circle cx="${c}" cy="${c}" r="${(R * .985).toFixed(1)}" fill="none" stroke="rgba(186,230,253,.34)" stroke-width="${Math.max(1, R * .007).toFixed(1)}"/>`);
      parts.push(`<g clip-path="url(#sv-sky-clip)" opacity=".42"><line x1="${c}" y1="${c}" x2="${c}" y2="${(c - R).toFixed(1)}" stroke="rgba(125,211,252,.34)" stroke-width="${Math.max(1, R * .008).toFixed(1)}" stroke-linecap="round"><animateTransform attributeName="transform" type="rotate" from="0 ${c} ${c}" to="360 ${c} ${c}" dur="32s" repeatCount="indefinite"/></line></g>`);
    }

    // Stars — drawn whenever we have any position (live fix or last-known).
    const { lat, lon, mode } = lastData;
    const hasPos = lat != null && lon != null;
    const consLabels = new Map();
    const consStars = new Map();
    if (hasPos && catalog && Array.isArray(catalog.stars)) {
      const cols = catalog.colors || [];
      const rScale = R / 260;
      for (const st of catalog.stars) {
        const [ra, dec, mag, cidx, name, cons] = st;
        const p = raDecToAltAz(ra, dec, lat, lon, date);
        if (p.alt <= 0) continue;                 // below the horizon
        const rr = R * (90 - p.alt) / 90;
        const a = p.az * D2R;
        const x = c + rr * Math.sin(a), y = c - rr * Math.cos(a);
        visibleStars++;
        if (name) namedStars++;
        let rad = (2.6 - (mag + 1.5) * 0.33) * rScale;
        rad = Math.max(0.45 * rScale, rad);
        const op = Math.max(0.3, Math.min(1, 1.1 - (mag + 1.5) * 0.12));
        const fill = cols[cidx] || '#f8f7ff';
        const glow = enhanced && mag < 1.9 ? ' filter="url(#sv-star-glow)"' : '';
        parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(enhanced ? rad * 1.16 : rad).toFixed(2)}" fill="${fill}" opacity="${op.toFixed(2)}"${glow}/>`);
        projected.push({ kind: 'star', x, y, name, cons, mag, alt: p.alt, az: p.az });
        // Label only the brightest handful so the sky stays legible.
        if (name && mag < (enhanced ? 2.1 : 1.6)) {
          parts.push(`<text x="${(x + rad + 4).toFixed(1)}" y="${(y + 3).toFixed(1)}" fill="#dbeafe" font-size="${(S * (enhanced ? 0.014 : 0.016)).toFixed(1)}" opacity="${enhanced ? '0.62' : '0.75'}">${esc(name)}</text>`);
        }
        if (enhanced && cons && mag < 2.7) {
          const cur = consLabels.get(cons) || { x: 0, y: 0, n: 0, mag: 99 };
          cur.x += x; cur.y += y; cur.n += 1; cur.mag = Math.min(cur.mag, mag);
          consLabels.set(cons, cur);
          if (!consStars.has(cons)) consStars.set(cons, []);
          consStars.get(cons).push({ x, y, mag });
        }
      }
      if (enhanced) {
        [...consStars.values()].forEach(stars => {
          stars.sort((a, b) => a.mag - b.mag);
          stars.slice(0, 5).forEach((st, idx, arr) => {
            if (!idx) return;
            const prev = arr[idx - 1];
            const dx = st.x - prev.x, dy = st.y - prev.y;
            if ((dx * dx + dy * dy) > R * R * .22) return;
            parts.push(`<line x1="${prev.x.toFixed(1)}" y1="${prev.y.toFixed(1)}" x2="${st.x.toFixed(1)}" y2="${st.y.toFixed(1)}" stroke="rgba(125,211,252,.14)" stroke-width="${Math.max(.6, R * .0035).toFixed(1)}" stroke-dasharray="${Math.max(2, R * .008).toFixed(1)} ${Math.max(5, R * .018).toFixed(1)}"/>`);
          });
        });
        [...consLabels.entries()]
          .filter(([, v]) => v.n >= 2)
          .sort((a, b) => a[1].mag - b[1].mag)
          .slice(0, 10)
          .forEach(([cons, v]) => {
            const label = (CONSTELLATIONS[cons] || cons).toUpperCase();
            parts.push(`<text x="${(v.x / v.n).toFixed(1)}" y="${(v.y / v.n).toFixed(1)}" fill="#7dd3fc" font-size="${(S * 0.014).toFixed(1)}" text-anchor="middle" opacity="0.32" letter-spacing="1.8">${esc(label)}</text>`);
          });
      }
    }

    // Elevation rings + cardinal axes on top of the stars.
    for (const f of [1, 2 / 3, 1 / 3]) {
      parts.push(`<circle cx="${c}" cy="${c}" r="${(R * f).toFixed(1)}" fill="none" stroke="${enhanced ? '#31506f' : '#28364d'}" stroke-width="1"/>`);
    }
    if (enhanced) {
      for (const [label, f] of [['0 deg', 1], ['30 deg', 2 / 3], ['60 deg', 1 / 3]]) {
        parts.push(`<text x="${(c + 6).toFixed(1)}" y="${(c - R * f - 4).toFixed(1)}" fill="#6486a6" font-size="${(S * .013).toFixed(1)}">${label}</text>`);
      }
      for (let az = 0; az < 360; az += 15) {
        const a = az * D2R;
        const major = az % 45 === 0;
        const r1 = R - (major ? S * .022 : S * .012), r2 = R;
        const x1 = c + r1 * Math.sin(a), y1 = c - r1 * Math.cos(a);
        const x2 = c + r2 * Math.sin(a), y2 = c - r2 * Math.cos(a);
        parts.push(`<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="rgba(148,197,235,.42)" stroke-width="${major ? 1.3 : .8}"/>`);
        if (major) {
          const lx = c + (R - S * .045) * Math.sin(a), ly = c - (R - S * .045) * Math.cos(a);
          parts.push(`<text x="${lx.toFixed(1)}" y="${(ly + S * .004).toFixed(1)}" fill="#5f7f9c" font-size="${(S * .012).toFixed(1)}" text-anchor="middle">${az}</text>`);
        }
      }
    }
    parts.push(`<line x1="${c}" y1="${c - R}" x2="${c}" y2="${c + R}" stroke="${enhanced ? '#31506f' : '#28364d'}" stroke-width="1"/>`);
    parts.push(`<line x1="${c - R}" y1="${c}" x2="${c + R}" y2="${c}" stroke="${enhanced ? '#31506f' : '#28364d'}" stroke-width="1"/>`);
    const cardFont = (S * 0.028).toFixed(1);
    for (const [lab, az] of [['N', 0], ['E', 90], ['S', 180], ['W', 270]]) {
      const a = az * D2R;
      const lx = c + (R + S * 0.03) * Math.sin(a), ly = c - (R + S * 0.03) * Math.cos(a);
      parts.push(`<text x="${lx.toFixed(1)}" y="${(ly + parseFloat(cardFont) / 3).toFixed(1)}" fill="#7f93ad" font-size="${cardFont}" text-anchor="middle" font-weight="600">${lab}</text>`);
    }

    // Satellites — bigger, coloured, clickable, on top of everything.
    const satR = Math.max(3.5, R * 0.02);
    for (const s of (lastData.sky || [])) {
      if (s.az == null || s.elev == null) continue;
      const elev = Math.max(0, Math.min(90, s.elev));
      const rr = R * (90 - elev) / 90;
      const a = s.az * D2R;
      const x = c + rr * Math.sin(a), y = c - rr * Math.cos(a);
      const col = SAT_COLORS[s.constellation] || '#94a3b8';
      const hasSnr = typeof s.snr === 'number' && s.snr > 0;
      const op = hasSnr ? (0.35 + 0.65 * Math.min(1, s.snr / 50)) : 0.4;
      if (hasSnr) {
        trackedSats++;
        snrSum += s.snr;
        if (s.snr > strongestSnr) { strongestSnr = s.snr; strongestSat = s; }
      }
      if (enhanced && hasSnr) {
        const halo = satR * (2.8 + Math.min(1.6, s.snr / 25));
        parts.push(`<line x1="${c}" y1="${c}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="${col}" stroke-width="1" opacity="${Math.min(.24, .07 + s.snr / 260).toFixed(2)}" stroke-dasharray="3 8"/>`);
        parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${halo.toFixed(1)}" fill="${col}" opacity="${(0.05 + Math.min(.12, s.snr / 500)).toFixed(2)}"/>`);
      }
      parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${satR.toFixed(1)}" fill="${hasSnr ? col : 'none'}" stroke="${col}" stroke-width="1.5" opacity="${op.toFixed(2)}"/>`);
      parts.push(`<text x="${x.toFixed(1)}" y="${(y - satR - 2).toFixed(1)}" fill="${col}" font-size="${(S * 0.014).toFixed(1)}" text-anchor="middle" opacity="0.85">${esc(s.prn != null ? s.prn : '')}</text>`);
      projected.push({ kind: 'sat', x, y, sat: s });
    }

    svg.innerHTML = parts.join('');

    // Subtitle + note.
    if (subtitleEl) {
      const t = date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
      const pos = hasPos
        ? `${lat.toFixed(4)}, ${lon.toFixed(4)}${mode === 'last' ? ' (last-known)' : ''}`
        : 'no position';
      const nsat = (lastData.sky || []).length;
      subtitleEl.textContent = `${pos}  ·  ${nsat} satellite${nsat === 1 ? '' : 's'}  ·  ${t}`;
    }
    if (noteEl) {
      if (mode === 'live') {
        noteEl.style.display = 'none';
      } else if (mode === 'last') {
        noteEl.style.display = '';
        const age = agoText(lastData.t);
        noteEl.textContent = 'Stars placed from last-known position'
          + (age ? ' (' + age + ')' : '') + ' — no live fix yet.';
      } else {
        noteEl.style.display = '';
        noteEl.textContent = catalog
          ? 'Stars need a GPS position — no fix and no last-known yet.'
          : 'Star catalog unavailable — showing satellites only.';
      }
    }
    if (detailEl) {
      if (!enhanced) {
        detailEl.style.display = 'none';
      } else {
        detailEl.style.display = '';
        const avgSnr = trackedSats ? (snrSum / trackedSats).toFixed(1) + ' dB' : 'none';
        const strong = strongestSat ? `${esc(strongestSat.constellation || 'sat')} ${esc(strongestSat.prn != null ? strongestSat.prn : '')} / ${strongestSnr} dB` : 'none';
        const consCount = enhanced ? consLabels.size : 0;
        detailEl.innerHTML = `<div class="sv-detail-card"><b>Sky sample</b><span><i>Visible stars</i><em>${visibleStars}</em></span><span><i>Named stars</i><em>${namedStars}</em></span><span><i>Constellation clusters</i><em>${consCount}</em></span></div>
          <div class="sv-detail-card"><b>GNSS signal</b><span><i>Tracked satellites</i><em>${trackedSats}/${(lastData.sky || []).length}</em></span><span><i>Average SNR</i><em>${avgSnr}</em></span><span><i>Strongest</i><em>${strong}</em></span></div>
          <div class="sv-detail-card"><b>Overlay</b><span><i>Azimuth grid</i><em>15 deg</em></span><span><i>Elevation rings</i><em>0 / 30 / 60</em></span><span><i>Objects</i><em>clickable</em></span></div>`;
      }
    }
  }

  function showInfo(obj, clientX, clientY) {
    if (!infoCard) return;
    let html;
    if (obj.kind === 'sat') {
      const s = obj.sat;
      const hasSnr = typeof s.snr === 'number' && s.snr > 0;
      html = `<div class="sv-info-title" style="color:${SAT_COLORS[s.constellation] || '#94a3b8'}">🛰️ ${esc(s.constellation)}${s.prn != null ? ' · PRN ' + esc(s.prn) : ''}</div>
        <div class="sv-info-row">Elevation <b>${Math.round(s.elev)}°</b></div>
        <div class="sv-info-row">Azimuth <b>${Math.round(s.az)}°</b></div>
        <div class="sv-info-row">Signal <b>${hasSnr ? s.snr + ' dB' : 'untracked'}</b></div>`;
    } else {
      const nm = obj.name || 'Unnamed star';
      const consFull = obj.cons ? (CONSTELLATIONS[obj.cons] || obj.cons) : null;
      html = `<div class="sv-info-title">✦ ${esc(nm)}</div>
        ${consFull ? `<div class="sv-info-row">Constellation <b>${esc(consFull)}</b></div>` : ''}
        <div class="sv-info-row">Magnitude <b>${obj.mag.toFixed(2)}</b></div>
        <div class="sv-info-row">Elevation <b>${Math.round(obj.alt)}°</b></div>
        <div class="sv-info-row">Azimuth <b>${Math.round(obj.az)}°</b></div>`;
    }
    infoCard.innerHTML = html +
      '<div class="sv-info-close">tap anywhere to dismiss</div>';
    infoCard.style.display = 'block';
    // Keep the card on-screen near the tap.
    const ow = overlay.getBoundingClientRect();
    let left = clientX + 14, top = clientY + 14;
    const cw = 210, ch = infoCard.offsetHeight || 150;
    if (left + cw > ow.width) left = clientX - cw - 14;
    if (top + ch > ow.height) top = clientY - ch - 14;
    infoCard.style.left = Math.max(8, left) + 'px';
    infoCard.style.top = Math.max(8, top) + 'px';
  }

  function onSvgClick(ev) {
    if (infoCard && infoCard.style.display === 'block') {
      infoCard.style.display = 'none';
      return;
    }
    const rect = svg.getBoundingClientRect();
    // The SVG viewBox equals its pixel box (viewBox set in setup), so client
    // px map 1:1 to the coordinates we stored.
    const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
    let best = null, bestD = 22 * 22;   // ~22px pick radius
    for (const o of projected) {
      const dx = o.x - px, dy = o.y - py, d = dx * dx + dy * dy;
      // Satellites win ties (bigger, more important); nudge their distance.
      const eff = o.kind === 'sat' ? d * 0.5 : d;
      if (eff < bestD) { bestD = eff; best = o; }
    }
    if (best) showInfo(best, ev.clientX, ev.clientY);
  }

  function refresh() {
    // The lightweight, uncached GPS endpoint (status + sky) — polled at 1 Hz so
    // the view is actually live, unlike the heavy 5 s-cached /diagnostics one.
    // Its body IS the status object (has_fix/lat/lon/last_known at top level),
    // with a `sky` array alongside.
    fetch('/api/wardriving/gps', { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d || !overlay) return;
        const p = positionFromStatus(d);
        lastData = { sky: d.sky || [], lat: p.lat, lon: p.lon, mode: p.mode, t: p.t };
        render();
      })
      .catch(() => {});
  }

  // ---- Public API ------------------------------------------------------
  function open(initial) {
    if (overlay) return;
    enhanced = !!(initial && initial.enhanced);
    // Seed from whatever the caller already has so the first frame isn't blank.
    if (initial && (initial.sky || initial.status)) {
      const p = positionFromStatus(initial.status);
      lastData = { sky: initial.sky || [], lat: p.lat, lon: p.lon, mode: p.mode, t: p.t };
    }

    overlay = document.createElement('div');
    overlay.id = 'ragnar-skyview';
    overlay.innerHTML = `
      <style>
        #ragnar-skyview{position:fixed;inset:0;z-index:99999;background:#03060f;
          display:flex;flex-direction:column;font-family:system-ui,-apple-system,sans-serif;}
        #ragnar-skyview .sv-head{display:flex;align-items:center;gap:12px;padding:12px 16px;
          border-bottom:1px solid #17233a;flex:0 0 auto;}
        #ragnar-skyview .sv-title{font-size:15px;font-weight:600;color:#e2e8f0;letter-spacing:.02em;}
        #ragnar-skyview .sv-sub{font-size:12px;color:#7f93ad;font-family:ui-monospace,monospace;margin-left:2px;}
        #ragnar-skyview .sv-spacer{flex:1;}
        #ragnar-skyview .sv-legend{display:flex;flex-wrap:wrap;gap:10px;font-size:11px;color:#9fb0c3;}
        #ragnar-skyview .sv-legend i{display:inline-block;width:8px;height:8px;border-radius:9999px;margin-right:4px;vertical-align:middle;}
        #ragnar-skyview .sv-diag-btn{display:none;align-items:center;gap:7px;border:1px solid rgba(125,211,252,.28);
          background:rgba(8,20,38,.72);color:#dbeafe;border-radius:8px;padding:8px 10px;font-size:11px;
          font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;white-space:nowrap;
          box-shadow:inset 0 1px 0 rgba(255,255,255,.05);}
        #ragnar-skyview .sv-diag-btn:hover,#ragnar-skyview .sv-diag-btn:focus{border-color:rgba(125,211,252,.58);background:rgba(14,38,66,.86);outline:none;}
        #ragnar-skyview .sv-close{cursor:pointer;background:#17233a;color:#e2e8f0;border:none;
          border-radius:8px;width:34px;height:34px;font-size:18px;line-height:1;flex:0 0 auto;}
        #ragnar-skyview .sv-close:hover{background:#243350;}
        #ragnar-skyview .sv-stage{flex:1;position:relative;min-height:0;}
        #ragnar-skyview svg{position:absolute;inset:0;width:100%;height:100%;cursor:crosshair;}
        #ragnar-skyview .sv-note{position:absolute;left:50%;bottom:14px;transform:translateX(-50%);
          background:rgba(180,121,30,.18);border:1px solid rgba(234,179,8,.4);color:#f4d9a6;
          padding:6px 12px;border-radius:8px;font-size:12px;}
        #ragnar-skyview .sv-info{position:absolute;display:none;min-width:170px;max-width:210px;
          background:rgba(10,17,32,.96);border:1px solid #2a3a55;border-radius:10px;padding:10px 12px;
          box-shadow:0 8px 30px rgba(0,0,0,.55);pointer-events:none;z-index:5;}
        #ragnar-skyview .sv-info-title{font-size:13px;font-weight:600;margin-bottom:6px;color:#e2e8f0;}
        #ragnar-skyview .sv-info-row{display:flex;justify-content:space-between;gap:14px;font-size:12px;
          color:#9fb0c3;padding:1px 0;}
        #ragnar-skyview .sv-info-row b{color:#e2e8f0;font-weight:600;}
        #ragnar-skyview .sv-info-close{margin-top:7px;font-size:10px;color:#5f6f85;text-align:center;}
        #ragnar-skyview .sv-brand{display:none;position:absolute;left:16px;top:16px;z-index:4;
          pointer-events:none;color:#dbeafe;text-shadow:0 1px 18px rgba(14,165,233,.45);}
        #ragnar-skyview .sv-brand b{display:block;font-size:11px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;}
        #ragnar-skyview .sv-brand span{display:block;margin-top:3px;color:#7fa7c8;font-size:11px;letter-spacing:.05em;}
        #ragnar-skyview .sv-detail{display:none;position:absolute;right:14px;bottom:14px;z-index:4;
          width:min(360px,calc(100vw - 28px));gap:8px;pointer-events:none;}
        #ragnar-skyview .sv-detail-card{background:linear-gradient(180deg,rgba(8,20,38,.76),rgba(3,8,18,.64));
          border:1px solid rgba(125,211,252,.24);border-radius:10px;padding:10px 12px;
          box-shadow:0 14px 36px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.04);backdrop-filter:blur(10px);}
        #ragnar-skyview .sv-detail-card b{display:block;color:#dbeafe;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;}
        #ragnar-skyview .sv-detail-card span{display:flex;align-items:baseline;justify-content:space-between;gap:14px;color:#9fb0c3;font-size:11px;line-height:1.55;}
        #ragnar-skyview .sv-detail-card i{font-style:normal;color:#7f93ad;}
        #ragnar-skyview .sv-detail-card em{font-style:normal;color:#e2e8f0;text-align:right;max-width:58%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
        #ragnar-skyview.sv-enhanced{background:radial-gradient(circle at 50% 35%,#113050 0,#06101f 42%,#02050d 76%);}
        #ragnar-skyview.sv-enhanced .sv-head{background:linear-gradient(90deg,rgba(14,165,233,.14),rgba(15,23,42,.32),rgba(125,211,252,.09));}
        #ragnar-skyview.sv-enhanced svg{cursor:crosshair;}
        #ragnar-skyview.sv-enhanced .sv-diag-btn{display:inline-flex;}
        #ragnar-skyview.sv-enhanced .sv-brand{display:block;}
        #ragnar-skyview.sv-enhanced .sv-detail{display:grid;}
        @media (max-width:760px){#ragnar-skyview .sv-legend{display:none;}#ragnar-skyview.sv-enhanced .sv-detail{display:none;}}
      </style>
      <div class="sv-head">
        <span class="sv-title">${enhanced ? 'Ragnar Starview' : 'GPS Sky View'}</span>
        <span class="sv-sub" id="sv-sub"></span>
        <span class="sv-spacer"></span>
        <div class="sv-legend">
          <span><i style="background:#34d399"></i>GPS</span>
          <span><i style="background:#f87171"></i>GLONASS</span>
          <span><i style="background:#60a5fa"></i>Galileo</span>
          <span><i style="background:#fbbf24"></i>BeiDou</span>
          <span><i style="background:#f8f7ff"></i>stars</span>
        </div>
        <button class="sv-diag-btn" type="button" title="Open full wardriving GPS diagnostics">GPS Diagnostics</button>
        <button class="sv-close" title="Close (Esc)">✕</button>
      </div>
      <div class="sv-stage">
        <div class="sv-brand"><b>Ragnar observatory</b><span>live GNSS sky telemetry</span></div>
        <svg preserveAspectRatio="xMidYMid meet"></svg>
        <div class="sv-note"></div>
        <div class="sv-detail"></div>
        <div class="sv-info"></div>
      </div>`;
    document.body.appendChild(overlay);
    if (enhanced) overlay.classList.add('sv-enhanced');
    overlay.style.setProperty('overflow', 'hidden');
    document.body.style.overflow = 'hidden';

    svg = overlay.querySelector('svg');
    subtitleEl = overlay.querySelector('#sv-sub');
    noteEl = overlay.querySelector('.sv-note');
    detailEl = overlay.querySelector('.sv-detail');
    infoCard = overlay.querySelector('.sv-info');
    const diagBtn = overlay.querySelector('.sv-diag-btn');
    if (diagBtn) {
      diagBtn.addEventListener('click', () => {
        window.dispatchEvent(new CustomEvent('ragnar:open-gps-diagnostics'));
        close();
      });
    }
    overlay.querySelector('.sv-close').addEventListener('click', close);
    svg.addEventListener('click', onSvgClick);

    // Match the SVG viewBox to its pixel size so screen clicks map 1:1.
    function syncViewBox() {
      const r = svg.getBoundingClientRect();
      svg.setAttribute('viewBox', `0 0 ${r.width} ${r.height}`);
      render();
    }
    resizeH = syncViewBox;
    window.addEventListener('resize', resizeH);

    onEsc = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onEsc);

    loadCatalog().then(() => { syncViewBox(); });
    syncViewBox();
    refresh();
    timer = setInterval(refresh, REFRESH_MS);
  }

  function close() {
    if (!overlay) return;
    clearInterval(timer); timer = null;
    document.removeEventListener('keydown', onEsc); onEsc = null;
    window.removeEventListener('resize', resizeH); resizeH = null;
    overlay.remove(); overlay = null;
    svg = infoCard = subtitleEl = noteEl = detailEl = null;
    enhanced = false;
    document.body.style.overflow = '';
  }

  window.RagnarSkyView = { open, close };
})();
