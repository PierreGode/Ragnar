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
  const PLANETS = [
    { name: 'Mercury', period: 87.969, l0: 252.25, r: 0.387, mag: -0.3, color: '#f8d8a8', size: 3.2 },
    { name: 'Venus', period: 224.701, l0: 181.98, r: 0.723, mag: -4.0, color: '#fff3b0', size: 5.4 },
    { name: 'Mars', period: 686.98, l0: 355.43, r: 1.524, mag: -1.3, color: '#fb8b66', size: 4.2 },
    { name: 'Jupiter', period: 4332.59, l0: 34.35, r: 5.203, mag: -2.2, color: '#ffd7a3', size: 5.8 },
    { name: 'Saturn', period: 10759.22, l0: 50.08, r: 9.537, mag: 0.4, color: '#f5d58a', size: 5.0 },
    { name: 'Uranus', period: 30688.5, l0: 314.05, r: 19.19, mag: 5.7, color: '#9ee8ff', size: 3.5 },
    { name: 'Neptune', period: 60182, l0: 304.35, r: 30.07, mag: 7.8, color: '#7aa7ff', size: 3.3 }
  ];
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

  function normDeg(v) { return ((v % 360) + 360) % 360; }

  function eclipticToRaDec(x, y, z) {
    const eps = 23.439291 * D2R;
    const xe = x;
    const ye = y * Math.cos(eps) - z * Math.sin(eps);
    const ze = y * Math.sin(eps) + z * Math.cos(eps);
    const ra = normDeg(Math.atan2(ye, xe) * R2D);
    const dec = Math.atan2(ze, Math.sqrt(xe * xe + ye * ye)) * R2D;
    return { ra, dec };
  }

  function planetPositions(date, lat, lon) {
    const d = julianDay(date) - 2451545.0;
    const earthL = normDeg(100.46 + 360 * d / 365.256) * D2R;
    const earth = { x: Math.cos(earthL), y: Math.sin(earthL), z: 0 };
    return PLANETS.map(p => {
      const L = normDeg(p.l0 + 360 * d / p.period) * D2R;
      const geo = { x: p.r * Math.cos(L) - earth.x, y: p.r * Math.sin(L) - earth.y, z: 0 };
      const eq = eclipticToRaDec(geo.x, geo.y, geo.z);
      const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
      return { ...p, ra: eq.ra, dec: eq.dec, alt: sky.alt, az: sky.az };
    });
  }

  function moonPosition(date, lat, lon) {
    const d = julianDay(date) - 2451545.0;
    const L = normDeg(218.316 + 13.176396 * d);
    const M = normDeg(134.963 + 13.064993 * d);
    const F = normDeg(93.272 + 13.229350 * d);
    const lonMoon = L + 6.289 * Math.sin(M * D2R);
    const latMoon = 5.128 * Math.sin(F * D2R);
    const lr = lonMoon * D2R, br = latMoon * D2R;
    const eq = eclipticToRaDec(Math.cos(br) * Math.cos(lr), Math.cos(br) * Math.sin(lr), Math.sin(br));
    const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
    return { name: 'Moon', ra: eq.ra, dec: eq.dec, alt: sky.alt, az: sky.az, color: '#e5eefb', mag: -12.0 };
  }

  function eclipticSamples(date, lat, lon, W, H) {
    const pts = [];
    for (let deg = 0; deg <= 360; deg += 4) {
      const lr = deg * D2R;
      const eq = eclipticToRaDec(Math.cos(lr), Math.sin(lr), 0);
      const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
      if (sky.alt > 0) pts.push(fullSkyPoint(sky.az, sky.alt, W, H));
    }
    return pts;
  }

  function pathFromPoints(points) {
    if (!points || points.length < 2) return '';
    return points.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  }

  function starTone(fill) {
    const f = String(fill || '').toLowerCase();
    if (f.includes('ff') && f.includes('d')) return 'warm white';
    if (f.includes('b') || f.includes('c')) return 'blue-white';
    if (f.includes('f8')) return 'white';
    return 'catalog color';
  }

  // ---- State -----------------------------------------------------------
  let overlay = null, svg = null, infoCard = null, subtitleEl = null, noteEl = null, detailEl = null, cursorEl = null;
  let catalog = null, catalogLoading = null;
  let timer = null, onEsc = null, resizeH = null;
  let enhanced = false;
  let skyZoom = 1;
  let skyPanX = 0, skyPanY = 0;
  let suppressNextClick = false;
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

  function fullSkyPoint(az, alt, W, H) {
    const baseX = (normDeg(az) / 360) * W;
    const baseY = (1 - Math.max(0, Math.min(90, alt)) / 90) * H;
    return {
      x: W / 2 + (baseX - W / 2) * skyZoom + skyPanX,
      y: H / 2 + (baseY - H / 2) * skyZoom + skyPanY
    };
  }

  function skyFromScreenPoint(x, y, W, H) {
    const baseX = W / 2 + (x - skyPanX - W / 2) / skyZoom;
    const baseY = H / 2 + (y - skyPanY - H / 2) / skyZoom;
    return {
      az: normDeg((baseX / W) * 360),
      alt: Math.max(0, Math.min(90, (1 - baseY / H) * 90))
    };
  }

  function cardinalName(az) {
    const dirs = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
    return dirs[Math.round(normDeg(az) / 22.5) % 16];
  }

  function radarPoint(az, elev, c, R) {
    const rr = R * (90 - Math.max(0, Math.min(90, elev))) / 90;
    const a = az * D2R;
    return { x: c.x + rr * Math.sin(a), y: c.y - rr * Math.cos(a) };
  }

  function renderEnhanced() {
    const rect = svg.getBoundingClientRect();
    const W = Math.max(320, rect.width), H = Math.max(260, rect.height);
    const date = new Date();
    const parts = [];
    projected = [];
    let visibleStars = 0, namedStars = 0, trackedSats = 0, snrSum = 0;
    let strongestSat = null, strongestSnr = -1;
    const { lat, lon, mode } = lastData;
    const hasPos = lat != null && lon != null;
    const radarR = Math.max(58, Math.min(122, W * 0.1, H * 0.17));
    const radarC = { x: 20 + radarR, y: 58 + radarR };
    const starGroups = new Map();
    const constellationLabels = new Map();

    parts.push(`<defs>
      <linearGradient id="sv-full-bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#091d33"/><stop offset="46%" stop-color="#041020"/><stop offset="100%" stop-color="#02050d"/></linearGradient>
      <radialGradient id="sv-zenith" cx="50%" cy="12%" r="65%"><stop offset="0" stop-color="rgba(56,189,248,.22)"/><stop offset="65%" stop-color="rgba(56,189,248,0)"/></radialGradient>
      <linearGradient id="sv-horizon" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="rgba(251,191,36,0)"/><stop offset="100%" stop-color="rgba(251,191,36,.16)"/></linearGradient>
      <radialGradient id="sv-planet-glow" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="rgba(255,255,255,.58)"/><stop offset="100%" stop-color="rgba(255,255,255,0)"/></radialGradient>
      <filter id="sv-full-glow" x="-120%" y="-120%" width="340%" height="340%"><feGaussianBlur stdDeviation="2.2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`);
    parts.push(`<rect x="0" y="0" width="${W}" height="${H}" fill="url(#sv-full-bg)"/>`);
    parts.push(`<rect x="0" y="0" width="${W}" height="${H}" fill="url(#sv-zenith)"/>`);
    parts.push(`<rect x="0" y="${(H * .72).toFixed(1)}" width="${W}" height="${(H * .28).toFixed(1)}" fill="url(#sv-horizon)" opacity=".7"/>`);

    const mw = [];
    for (let i = 0; i <= 46; i++) {
      const az = i * (360 / 46);
      const alt = 42 + Math.sin((i / 46) * Math.PI * 2.2 + 0.7) * 18 + Math.sin((i / 46) * Math.PI * 7) * 5;
      mw.push(fullSkyPoint(az, Math.max(6, Math.min(86, alt)), W, H));
    }
    const mwPath = pathFromPoints(mw);
    if (mwPath) {
      parts.push(`<path d="${mwPath}" fill="none" stroke="rgba(186,230,253,.09)" stroke-width="${Math.max(42, H * .11).toFixed(1)}" stroke-linecap="round"/>`);
      parts.push(`<path d="${mwPath}" fill="none" stroke="rgba(255,255,255,.12)" stroke-width="${Math.max(1.2, H * .003).toFixed(1)}" stroke-linecap="round" stroke-dasharray="3 16"/>`);
    }

    for (let alt = 15; alt <= 75; alt += 15) {
      const y = fullSkyPoint(180, alt, W, H).y;
      if (y < -40 || y > H + 40) continue;
      parts.push(`<line x1="0" y1="${y.toFixed(1)}" x2="${W}" y2="${y.toFixed(1)}" stroke="rgba(125,211,252,.09)" stroke-width="1"/>`);
      parts.push(`<text x="${W - 16}" y="${(y - 5).toFixed(1)}" fill="#6688a8" font-size="11" text-anchor="end">${alt} deg</text>`);
    }
    for (let az = 0; az < 360; az += 30) {
      const x = fullSkyPoint(az, 45, W, H).x;
      if (x < -40 || x > W + 40) continue;
      parts.push(`<line x1="${x.toFixed(1)}" y1="0" x2="${x.toFixed(1)}" y2="${H}" stroke="rgba(125,211,252,.075)" stroke-width="1"/>`);
      parts.push(`<text x="${x.toFixed(1)}" y="${H - 16}" fill="#6688a8" font-size="11" text-anchor="middle">${az}</text>`);
    }
    for (const [label, az] of [['N', 0], ['NE', 45], ['E', 90], ['SE', 135], ['S', 180], ['SW', 225], ['W', 270], ['NW', 315]]) {
      const p = fullSkyPoint(az, 3, W, H);
      if (p.x < -40 || p.x > W + 40) continue;
      parts.push(`<text x="${p.x.toFixed(1)}" y="${Math.min(H - 34, Math.max(28, p.y)).toFixed(1)}" fill="#bae6fd" font-size="18" font-weight="700" text-anchor="middle" opacity=".26" letter-spacing="2">${label}</text>`);
    }

    for (let i = 0; i < 520; i++) {
      const x = ((i * 977 + 37) % 1000) / 1000 * W;
      const y = ((i * 601 + 191) % 1000) / 1000 * H;
      const op = 0.03 + (i % 17) * 0.006;
      parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(0.35 + (i % 4) * 0.08).toFixed(2)}" fill="#dbeafe" opacity="${op.toFixed(2)}"/>`);
    }

    if (hasPos) {
      const ecl = pathFromPoints(eclipticSamples(date, lat, lon, W, H));
      if (ecl) {
        parts.push(`<path d="${ecl}" fill="none" stroke="rgba(251,191,36,.26)" stroke-width="1.2" stroke-dasharray="10 12"/>`);
        parts.push(`<text x="${Math.max(170, W * .18).toFixed(1)}" y="${Math.max(80, H * .18).toFixed(1)}" fill="#f8d58a" font-size="11" opacity=".72">ecliptic plane</text>`);
      }
    }

    if (hasPos && catalog && Array.isArray(catalog.stars)) {
      const cols = catalog.colors || [];
      for (const st of catalog.stars) {
        const [ra, dec, mag, cidx, name, cons] = st;
        const p = raDecToAltAz(ra, dec, lat, lon, date);
        if (p.alt <= 0) continue;
        const pt = fullSkyPoint(p.az, p.alt, W, H);
        if (pt.x < -40 || pt.x > W + 40 || pt.y < -40 || pt.y > H + 40) continue;
        visibleStars++;
        if (name) namedStars++;
        const rad = Math.max(0.45, (3.15 - (mag + 1.5) * 0.36) * Math.sqrt(skyZoom));
        const op = Math.max(0.26, Math.min(1, 1.12 - (mag + 1.5) * 0.12));
        const fill = cols[cidx] || '#f8f7ff';
        const pulse = mag < 1.8 ? `<animate attributeName="opacity" values="${op.toFixed(2)};${Math.max(.34, op - .22).toFixed(2)};${op.toFixed(2)}" dur="${(3.8 + (mag + 1.5) * .7).toFixed(1)}s" repeatCount="indefinite"/>` : '';
        if (mag < 0.9) {
          const spike = Math.max(5, rad * 3.4);
          parts.push(`<g opacity=".38"><line x1="${(pt.x - spike).toFixed(1)}" y1="${pt.y.toFixed(1)}" x2="${(pt.x + spike).toFixed(1)}" y2="${pt.y.toFixed(1)}" stroke="${fill}" stroke-width=".8"/><line x1="${pt.x.toFixed(1)}" y1="${(pt.y - spike).toFixed(1)}" x2="${pt.x.toFixed(1)}" y2="${(pt.y + spike).toFixed(1)}" stroke="${fill}" stroke-width=".8"/></g>`);
        }
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${rad.toFixed(2)}" fill="${fill}" opacity="${op.toFixed(2)}"${mag < 1.8 ? ' filter="url(#sv-full-glow)"' : ''}>${pulse}</circle>`);
        projected.push({ kind: 'star', x: pt.x, y: pt.y, name, cons, mag, ra, dec, alt: p.alt, az: p.az, color: fill });
        if (name && (mag < 1.2 || (skyZoom > 1.55 && mag < 2.2))) {
          parts.push(`<text x="${(pt.x + rad + 5).toFixed(1)}" y="${(pt.y + 3).toFixed(1)}" fill="#dbeafe" font-size="${(11 + skyZoom).toFixed(1)}" opacity="0.68">${esc(name)}</text>`);
        }
        if (cons && mag < 2.7) {
          if (!starGroups.has(cons)) starGroups.set(cons, []);
          starGroups.get(cons).push({ ...pt, mag });
          const label = constellationLabels.get(cons) || { x: 0, y: 0, n: 0, mag: 99 };
          label.x += pt.x; label.y += pt.y; label.n += 1; label.mag = Math.min(label.mag, mag);
          constellationLabels.set(cons, label);
        }
      }
      [...starGroups.values()].forEach(stars => {
        stars.sort((a, b) => a.mag - b.mag);
        stars.slice(0, 5).forEach((st, idx, arr) => {
          if (!idx) return;
          const prev = arr[idx - 1], dx = st.x - prev.x, dy = st.y - prev.y;
          if (dx * dx + dy * dy > 90000) return;
          parts.push(`<line x1="${prev.x.toFixed(1)}" y1="${prev.y.toFixed(1)}" x2="${st.x.toFixed(1)}" y2="${st.y.toFixed(1)}" stroke="rgba(125,211,252,.13)" stroke-width="1" stroke-dasharray="3 10"/>`);
        });
      });
      [...constellationLabels.entries()]
        .filter(([, v]) => v.n >= 2)
        .sort((a, b) => a[1].mag - b[1].mag)
        .slice(0, Math.round(10 + skyZoom * 6))
        .forEach(([cons, v]) => {
          const name = CONSTELLATIONS[cons] || cons;
          const x = v.x / v.n, y = v.y / v.n;
          if (x < 0 || x > W || y < 0 || y > H) return;
          parts.push(`<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" fill="#93c5fd" font-size="${(10 + skyZoom * .8).toFixed(1)}" text-anchor="middle" opacity=".22" letter-spacing="1.7">${esc(name.toUpperCase())}</text>`);
        });
    }

    if (hasPos) {
      const moon = moonPosition(date, lat, lon);
      if (moon.alt > 0) {
        const mp = fullSkyPoint(moon.az, moon.alt, W, H);
        if (mp.x > -80 && mp.x < W + 80 && mp.y > -80 && mp.y < H + 80) {
          parts.push(`<circle cx="${mp.x.toFixed(1)}" cy="${mp.y.toFixed(1)}" r="34" fill="url(#sv-planet-glow)" opacity=".22"/>`);
          parts.push(`<circle cx="${mp.x.toFixed(1)}" cy="${mp.y.toFixed(1)}" r="9" fill="#dbeafe" opacity=".92" filter="url(#sv-full-glow)"/>`);
          parts.push(`<circle cx="${(mp.x + 4).toFixed(1)}" cy="${(mp.y - 1).toFixed(1)}" r="8.8" fill="#071120" opacity=".42"/>`);
          parts.push(`<text x="${(mp.x + 17).toFixed(1)}" y="${(mp.y + 4).toFixed(1)}" fill="#dbeafe" font-size="12" opacity=".88">Moon</text>`);
          projected.push({ kind: 'planet', x: mp.x, y: mp.y, planet: moon });
        }
      }
      for (const planet of planetPositions(date, lat, lon)) {
        if (planet.alt <= 0) continue;
        const pt = fullSkyPoint(planet.az, planet.alt, W, H);
        if (pt.x < -70 || pt.x > W + 70 || pt.y < -70 || pt.y > H + 70) continue;
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${(planet.size * 3.2).toFixed(1)}" fill="url(#sv-planet-glow)" opacity=".34"/>`);
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${(planet.size * 0.95).toFixed(1)}" fill="${planet.color}" filter="url(#sv-full-glow)"><animate attributeName="r" values="${(planet.size * .85).toFixed(1)};${(planet.size * 1.05).toFixed(1)};${(planet.size * .85).toFixed(1)}" dur="5.5s" repeatCount="indefinite"/></circle>`);
        parts.push(`<text x="${(pt.x + planet.size + 7).toFixed(1)}" y="${(pt.y + 4).toFixed(1)}" fill="${planet.color}" font-size="12" opacity=".86">${planet.name}</text>`);
        projected.push({ kind: 'planet', x: pt.x, y: pt.y, planet });
      }
    }

    for (const s of (lastData.sky || [])) {
      if (s.az == null || s.elev == null) continue;
      const pt = fullSkyPoint(s.az, Math.max(0, s.elev), W, H);
      const col = SAT_COLORS[s.constellation] || '#94a3b8';
      const hasSnr = typeof s.snr === 'number' && s.snr > 0;
      if (hasSnr) { trackedSats++; snrSum += s.snr; if (s.snr > strongestSnr) { strongestSnr = s.snr; strongestSat = s; } }
      if (pt.x >= -50 && pt.x <= W + 50 && pt.y >= -50 && pt.y <= H + 50) {
        const satR = hasSnr ? 4.2 + Math.min(4, s.snr / 14) : 4;
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${(satR * 4).toFixed(1)}" fill="${col}" opacity="${hasSnr ? .08 : .035}"/>`);
        parts.push(`<path d="M${(pt.x - 7).toFixed(1)} ${pt.y.toFixed(1)} L${pt.x.toFixed(1)} ${(pt.y - 7).toFixed(1)} L${(pt.x + 7).toFixed(1)} ${pt.y.toFixed(1)} L${pt.x.toFixed(1)} ${(pt.y + 7).toFixed(1)} Z" fill="${hasSnr ? col : 'none'}" stroke="${col}" stroke-width="1.4" opacity="${hasSnr ? .9 : .42}"/>`);
        parts.push(`<text x="${pt.x.toFixed(1)}" y="${(pt.y - 12).toFixed(1)}" fill="${col}" font-size="10" text-anchor="middle" opacity=".82">${esc(s.prn != null ? s.prn : '')}</text>`);
        projected.push({ kind: 'sat', x: pt.x, y: pt.y, sat: s });
      }
    }

    parts.push(`<g opacity=".66"><circle cx="${radarC.x}" cy="${radarC.y}" r="${radarR}" fill="rgba(2,6,15,.48)" stroke="rgba(125,211,252,.32)" stroke-width="1.2"/>`);
    for (const f of [1, 2 / 3, 1 / 3]) parts.push(`<circle cx="${radarC.x}" cy="${radarC.y}" r="${(radarR * f).toFixed(1)}" fill="none" stroke="rgba(125,211,252,.18)" stroke-width="1"/>`);
    for (const az of [0, 90, 180, 270]) {
      const a = az * D2R;
      parts.push(`<line x1="${radarC.x}" y1="${radarC.y}" x2="${(radarC.x + radarR * Math.sin(a)).toFixed(1)}" y2="${(radarC.y - radarR * Math.cos(a)).toFixed(1)}" stroke="rgba(125,211,252,.17)"/>`);
    }
    for (const s of (lastData.sky || [])) {
      if (s.az == null || s.elev == null) continue;
      const rp = radarPoint(s.az, s.elev, radarC, radarR);
      const col = SAT_COLORS[s.constellation] || '#94a3b8';
      parts.push(`<circle cx="${rp.x.toFixed(1)}" cy="${rp.y.toFixed(1)}" r="2.6" fill="${col}" opacity=".82"/>`);
    }
    parts.push(`<text x="${radarC.x}" y="${(radarC.y + radarR + 16).toFixed(1)}" fill="#7fa7c8" font-size="10" text-anchor="middle">GNSS radar</text></g>`);

    svg.innerHTML = parts.join('');
    if (subtitleEl) {
      const pos = hasPos ? `${lat.toFixed(4)}, ${lon.toFixed(4)}${mode === 'last' ? ' (last-known)' : ''}` : 'no position';
      subtitleEl.textContent = `${pos}  ·  zoom ${skyZoom.toFixed(1)}x  ·  ${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
    }
    if (noteEl) noteEl.style.display = hasPos ? 'none' : '';
    if (detailEl) {
      const avgSnr = trackedSats ? (snrSum / trackedSats).toFixed(1) + ' dB' : 'none';
      const strong = strongestSat ? `${esc(strongestSat.constellation || 'sat')} ${esc(strongestSat.prn != null ? strongestSat.prn : '')} / ${strongestSnr} dB` : 'none';
      detailEl.style.display = '';
      detailEl.innerHTML = `<div class="sv-detail-card"><b>Sky model</b><span><i>Projection</i><em>alt/az panorama</em></span><span><i>Reference</i><em>ecliptic + Milky Way</em></span><span><i>Zoom</i><em>${skyZoom.toFixed(1)}x</em></span></div>
        <div class="sv-detail-card"><b>Catalog</b><span><i>Visible stars</i><em>${visibleStars}</em></span><span><i>Named stars</i><em>${namedStars}</em></span><span><i>Constellation labels</i><em>${constellationLabels.size}</em></span></div>
        <div class="sv-detail-card"><b>Live layer</b><span><i>Planets + Moon</i><em>${hasPos ? planetPositions(date, lat, lon).filter(p => p.alt > 0).length + (moonPosition(date, lat, lon).alt > 0 ? 1 : 0) : 0}</em></span><span><i>Tracked sats</i><em>${trackedSats}/${(lastData.sky || []).length}</em></span><span><i>Strongest</i><em>${strong}</em></span></div>`;
    }
  }

  function updateCursorReadout(ev) {
    if (!enhanced || !cursorEl || !svg) return;
    const r = svg.getBoundingClientRect();
    const x = ev.clientX - r.left, y = ev.clientY - r.top;
    if (x < 0 || y < 0 || x > r.width || y > r.height) {
      cursorEl.textContent = 'az --  alt --';
      return;
    }
    const sky = skyFromScreenPoint(x, y, r.width, r.height);
    cursorEl.textContent = `az ${sky.az.toFixed(1)} deg ${cardinalName(sky.az)}  /  alt ${sky.alt.toFixed(1)} deg`;
  }

  // ---- Rendering -------------------------------------------------------
  function render() {
    if (!svg) return;
    if (enhanced) { renderEnhanced(); return; }
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
    } else if (obj.kind === 'planet') {
      const p = obj.planet;
      html = `<div class="sv-info-title" style="color:${p.color}">● ${esc(p.name)}</div>
        <div class="sv-info-row">Elevation <b>${Math.round(p.alt)}°</b></div>
        <div class="sv-info-row">Azimuth <b>${Math.round(p.az)}°</b></div>
        <div class="sv-info-row">RA <b>${(p.ra / 15).toFixed(2)}h</b></div>
        <div class="sv-info-row">Dec <b>${p.dec.toFixed(1)}°</b></div>
        <div class="sv-info-row">Visual mag <b>${p.mag}</b></div>
        <div class="sv-info-row">Model <b>${p.name === 'Moon' ? 'lunar approximation' : 'low-precision live'}</b></div>`;
    } else {
      const nm = obj.name || 'Unnamed star';
      const consFull = obj.cons ? (CONSTELLATIONS[obj.cons] || obj.cons) : null;
      html = `<div class="sv-info-title">✦ ${esc(nm)}</div>
        ${consFull ? `<div class="sv-info-row">Constellation <b>${esc(consFull)}</b></div>` : ''}
        <div class="sv-info-row">Magnitude <b>${obj.mag.toFixed(2)}</b></div>
        <div class="sv-info-row">RA <b>${obj.ra != null ? (obj.ra / 15).toFixed(2) + 'h' : '—'}</b></div>
        <div class="sv-info-row">Dec <b>${obj.dec != null ? obj.dec.toFixed(1) + '°' : '—'}</b></div>
        <div class="sv-info-row">Elevation <b>${Math.round(obj.alt)}°</b></div>
        <div class="sv-info-row">Azimuth <b>${Math.round(obj.az)}°</b></div>
        <div class="sv-info-row">Tone <b><span style="color:${esc(obj.color || '#f8f7ff')}">${esc(starTone(obj.color))}</span></b></div>
        <div class="sv-info-row">Class <b>${obj.mag < 1 ? 'navigation star' : (obj.mag < 3 ? 'bright naked-eye' : 'catalog star')}</b></div>`;
    }
    infoCard.innerHTML = html +
      '<div class="sv-info-close">tap anywhere to dismiss</div>';
    infoCard.style.display = 'block';
    // Keep the card on-screen near the tap.
    const ow = overlay.getBoundingClientRect();
    let left = clientX + 14, top = clientY + 14;
    const cw = 240, ch = infoCard.offsetHeight || 180;
    if (left + cw > ow.width) left = clientX - cw - 14;
    if (top + ch > ow.height) top = clientY - ch - 14;
    infoCard.style.left = Math.max(8, left) + 'px';
    infoCard.style.top = Math.max(8, top) + 'px';
  }

  function onSvgClick(ev) {
    if (enhanced && suppressNextClick) {
      suppressNextClick = false;
      return;
    }
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

  function diagValue(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback || '—';
    if (typeof value === 'boolean') return value ? 'yes' : 'no';
    return String(value);
  }

  function diagAge(epochSec) {
    if (typeof epochSec !== 'number' || !isFinite(epochSec) || epochSec <= 0) return '—';
    return agoText(epochSec);
  }

  function diagRows(rows) {
    return rows.map(([label, value, tone]) => {
      const cls = tone === 'warn' ? ' sv-warn' : (tone === 'good' ? ' sv-good' : '');
      return `<div class="sv-diag-row${cls}"><span>${esc(label)}</span><b>${esc(diagValue(value))}</b></div>`;
    }).join('');
  }

  function diagCard(title, rows) {
    return `<section class="sv-diag-card"><h3>${esc(title)}</h3>${diagRows(rows)}</section>`;
  }

  function gpsUsbDevices(diag) {
    const devices = (((diag || {}).power || {}).usb_devices || []);
    return devices.filter(d => {
      const text = [d.product, d.manufacturer, d.usb_id, (d.interfaces || []).join(' ')]
        .filter(Boolean).join(' ').toLowerCase();
      return text.includes('gps') || text.includes('gnss') || text.includes('nmea') || text.includes('u-blox') || text.includes('ttyacm') || text.includes('ttyusb');
    });
  }

  function renderGpsDiagnosticsPopup(diag, live) {
    const modal = overlay && overlay.querySelector('.sv-diag-modal');
    const body = overlay && overlay.querySelector('.sv-diag-modal-body');
    if (!modal || !body) return;
    diag = diag || {};
    live = live || {};
    const gps = live || {};
    const deepGps = diag.gps || {};
    const sky = Array.isArray(deepGps.sky) && deepGps.sky.length ? deepGps.sky : (Array.isArray(gps.sky) ? gps.sky : []);
    const constellations = Array.isArray(deepGps.constellations) ? deepGps.constellations : [];
    const gpsUsb = gpsUsbDevices(diag);
    const primaryUsb = gpsUsb[0] || null;
    const hasGpsManager = deepGps.present !== false && !(gps.error === 'GPS not initialized');
    const hardwareState = primaryUsb
      ? 'USB receiver detected'
      : (deepGps.present === false ? 'GPS manager not initialized' : 'not detected');
    const tracked = sky.filter(s => typeof s.snr === 'number' && s.snr > 0);
    const strongest = tracked.slice().sort((a, b) => b.snr - a.snr)[0];
    const avgSnr = tracked.length
      ? (tracked.reduce((sum, s) => sum + s.snr, 0) / tracked.length).toFixed(1) + ' dB'
      : '—';
    const status = gps.status || {};
    const pos = positionFromStatus(gps);
    const sats = gps.satellites !== undefined || gps.satellites_in_view !== undefined
      ? `${gps.satellites || 0} used / ${gps.satellites_in_view || 0} in view`
      : `${tracked.length} tracked / ${sky.length} in view`;
    const cards = [];

    cards.push(diagCard('Fix and Position', [
      ['Fix', gps.has_fix ? 'yes' : 'no', gps.has_fix ? 'good' : 'warn'],
      ['Fix quality', gps.fix_quality],
      ['Latitude', pos.lat != null ? pos.lat.toFixed(6) : gps.latitude],
      ['Longitude', pos.lon != null ? pos.lon.toFixed(6) : gps.longitude],
      ['Altitude', gps.altitude != null ? Number(gps.altitude).toFixed(1) + ' m' : null],
      ['Speed', gps.speed_kmh != null ? Number(gps.speed_kmh).toFixed(1) + ' km/h' : null],
      ['Course', gps.course != null ? Number(gps.course).toFixed(0) + ' deg' : null],
      ['Position source', pos.mode === 'last' ? 'last-known' : pos.mode]
    ]));

    cards.push(diagCard('Receiver Health', [
      ['Connected', gps.connected],
      ['Hardware', hardwareState, primaryUsb ? 'good' : (gps.connected ? 'good' : 'warn')],
      ['Receiver', primaryUsb ? (primaryUsb.product || primaryUsb.manufacturer || primaryUsb.usb_id) : null],
      ['USB interface', primaryUsb && primaryUsb.interfaces ? primaryUsb.interfaces.join(', ') : null],
      ['Source', gps.source || status.source],
      ['Port', gps.port || status.port],
      ['Satellites', sats],
      ['SNR max', gps.snr_max != null ? gps.snr_max + ' dB' : (strongest ? strongest.snr + ' dB' : null)],
      ['Average SNR', avgSnr],
      ['HDOP', gps.hdop],
      ['GPS manager', hasGpsManager ? 'initialized' : 'not initialized', hasGpsManager ? 'good' : 'warn'],
      ['GPS error', gps.error || status.error, gps.error || status.error ? 'warn' : null]
    ]));

    cards.push(diagCard('Timing', [
      ['Last update', diagAge(gps.last_update || status.last_update)],
      ['Last NMEA', diagAge(gps.last_sentence || status.last_sentence)],
      ['Time to first fix', gps.ttff_seconds != null ? gps.ttff_seconds + 's' : null],
      ['Searching for', gps.searching_seconds != null ? Math.round(gps.searching_seconds) + 's' : null,
        gps.searching_seconds > 120 ? 'warn' : null],
      ['Diagnostics sampled', diag.generated_at ? diagAge(diag.generated_at) : 'now']
    ]));

    cards.push(diagCard('Signal Summary', [
      ['Satellites in sky plot', sky.length],
      ['Tracked with SNR', tracked.length],
      ['Strongest satellite', strongest
        ? `${strongest.constellation || 'sat'} ${strongest.prn != null ? strongest.prn : ''} / ${strongest.snr} dB`
        : null],
      ['Constellations', constellations.length || [...new Set(sky.map(s => s.constellation).filter(Boolean))].length]
    ]));

    if (primaryUsb && !hasGpsManager) {
      cards.push(diagCard('Initialization Hint', [
        ['Device state', 'receiver visible on USB', 'good'],
        ['Wardriving status', 'disabled or not running', 'warn'],
        ['Next check', 'enable/start wardriving GPS to initialize live feed'],
        ['Detected draw', primaryUsb.max_power_ma != null ? primaryUsb.max_power_ma + ' mA' : null]
      ]));
    }

    const constellationHtml = constellations.length
      ? `<section class="sv-diag-card sv-diag-wide"><h3>Constellation Breakdown</h3><div class="sv-diag-chips">${constellations.map(c => `<span><b>${esc(c.constellation || 'GNSS')}</b>${esc(diagValue(c.in_view))} in view${c.snr_max != null ? ' / ' + esc(c.snr_max + ' dB') : ''}</span>`).join('')}</div></section>`
      : '';
    const skyRows = sky.slice().sort((a, b) => (b.snr || 0) - (a.snr || 0)).map(s =>
      `<tr><td>${esc(s.constellation || '—')}</td><td>${esc(diagValue(s.prn))}</td><td>${esc(diagValue(s.elev))}</td><td>${esc(diagValue(s.az))}</td><td>${esc(s.snr != null ? s.snr + ' dB' : 'untracked')}</td></tr>`
    ).join('');
    const skyTable = `<section class="sv-diag-card sv-diag-wide"><h3>Satellites</h3>
      <div class="sv-diag-table-wrap"><table><thead><tr><th>System</th><th>PRN</th><th>Elev</th><th>Az</th><th>SNR</th></tr></thead><tbody>${skyRows || '<tr><td colspan="5">No satellite sky data yet.</td></tr>'}</tbody></table></div></section>`;

    body.innerHTML = `<div class="sv-diag-grid">${cards.join('')}${constellationHtml}${skyTable}</div>`;
    modal.classList.add('open');
  }

  function openGpsDiagnosticsPopup() {
    if (!overlay) return;
    const modal = overlay.querySelector('.sv-diag-modal');
    const body = overlay.querySelector('.sv-diag-modal-body');
    if (!modal || !body) return;
    modal.classList.add('open');
    body.innerHTML = '<div class="sv-diag-loading">Reading GPS diagnostics...</div>';
    Promise.all([
      fetch('/api/wardriving/diagnostics', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null),
      fetch('/api/wardriving/gps', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null)
    ]).then(([diag, live]) => {
      if (!diag && !live) {
        body.innerHTML = '<div class="sv-diag-loading sv-warn">GPS diagnostics are unavailable right now.</div>';
        return;
      }
      renderGpsDiagnosticsPopup(diag, live);
    });
  }

  function closeGpsDiagnosticsPopup() {
    if (!overlay) return;
    const modal = overlay.querySelector('.sv-diag-modal');
    if (modal) modal.classList.remove('open');
  }

  function clampSkyPan(nextX, nextY, zoom) {
    if (!svg) return { x: nextX, y: nextY };
    const r = svg.getBoundingClientRect();
    const z = zoom == null ? skyZoom : zoom;
    const maxX = Math.max(0, r.width * (z - 1) * 0.55 + 160);
    const maxY = Math.max(0, r.height * (z - 1) * 0.55 + 120);
    return {
      x: Math.max(-maxX, Math.min(maxX, nextX)),
      y: Math.max(-maxY, Math.min(maxY, nextY))
    };
  }

  function setSkyZoom(next, anchor) {
    const oldZoom = skyZoom;
    const newZoom = Math.max(0.75, Math.min(4, next));
    if (anchor && svg && newZoom !== oldZoom) {
      const r = svg.getBoundingClientRect();
      const ax = anchor.x - r.left;
      const ay = anchor.y - r.top;
      const cx = r.width / 2;
      const cy = r.height / 2;
      const ratio = newZoom / oldZoom;
      const nextPan = clampSkyPan(
        ax - cx - (ax - cx - skyPanX) * ratio,
        ay - cy - (ay - cy - skyPanY) * ratio,
        newZoom
      );
      skyPanX = nextPan.x;
      skyPanY = nextPan.y;
    }
    skyZoom = newZoom;
    const label = overlay && overlay.querySelector('.sv-zoom-label');
    if (label) label.textContent = skyZoom.toFixed(1) + 'x';
    render();
  }

  function setSkyPan(nextX, nextY) {
    const nextPan = clampSkyPan(nextX, nextY);
    skyPanX = nextPan.x;
    skyPanY = nextPan.y;
    render();
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
        #ragnar-skyview .sv-diag-modal{position:absolute;inset:0;z-index:8;display:none;align-items:center;justify-content:center;
          padding:24px;background:rgba(1,5,13,.68);backdrop-filter:blur(6px);}
        #ragnar-skyview .sv-diag-modal.open{display:flex;}
        #ragnar-skyview .sv-diag-window{width:min(1040px,calc(100vw - 32px));max-height:min(780px,calc(100vh - 32px));
          display:flex;flex-direction:column;border:1px solid rgba(125,211,252,.25);border-radius:14px;
          background:linear-gradient(180deg,rgba(8,20,38,.96),rgba(2,6,15,.96));
          box-shadow:0 28px 80px rgba(0,0,0,.58), inset 0 1px 0 rgba(255,255,255,.05);overflow:hidden;}
        #ragnar-skyview .sv-diag-top{display:flex;align-items:center;gap:14px;padding:14px 16px;border-bottom:1px solid rgba(125,211,252,.16);}
        #ragnar-skyview .sv-diag-top h2{margin:0;color:#e2e8f0;font-size:15px;letter-spacing:.12em;text-transform:uppercase;}
        #ragnar-skyview .sv-diag-top span{color:#7f93ad;font-size:12px;}
        #ragnar-skyview .sv-diag-top button{margin-left:auto;border:1px solid rgba(148,163,184,.28);background:rgba(15,23,42,.74);color:#e2e8f0;border-radius:8px;width:32px;height:32px;cursor:pointer;}
        #ragnar-skyview .sv-diag-modal-body{overflow:auto;padding:16px;}
        #ragnar-skyview .sv-diag-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;}
        #ragnar-skyview .sv-diag-card{background:rgba(3,8,18,.58);border:1px solid rgba(125,211,252,.16);border-radius:11px;padding:12px;}
        #ragnar-skyview .sv-diag-card h3{margin:0 0 10px;color:#bae6fd;font-size:11px;text-transform:uppercase;letter-spacing:.11em;}
        #ragnar-skyview .sv-diag-wide{grid-column:1 / -1;}
        #ragnar-skyview .sv-diag-row{display:flex;align-items:baseline;justify-content:space-between;gap:18px;padding:4px 0;border-top:1px solid rgba(148,163,184,.08);font-size:12px;}
        #ragnar-skyview .sv-diag-row:first-of-type{border-top:0;}
        #ragnar-skyview .sv-diag-row span{color:#7f93ad;}
        #ragnar-skyview .sv-diag-row b{color:#e2e8f0;font-weight:600;text-align:right;overflow-wrap:anywhere;}
        #ragnar-skyview .sv-good b{color:#86efac;}
        #ragnar-skyview .sv-warn b,#ragnar-skyview .sv-warn{color:#fca5a5;}
        #ragnar-skyview .sv-diag-chips{display:flex;flex-wrap:wrap;gap:8px;}
        #ragnar-skyview .sv-diag-chips span{border:1px solid rgba(125,211,252,.18);border-radius:999px;padding:6px 9px;color:#9fb0c3;font-size:12px;background:rgba(15,23,42,.46);}
        #ragnar-skyview .sv-diag-chips b{color:#dbeafe;margin-right:7px;}
        #ragnar-skyview .sv-diag-table-wrap{overflow:auto;max-height:260px;}
        #ragnar-skyview .sv-diag-table-wrap table{width:100%;border-collapse:collapse;font-size:12px;}
        #ragnar-skyview .sv-diag-table-wrap th,#ragnar-skyview .sv-diag-table-wrap td{padding:7px 8px;border-top:1px solid rgba(148,163,184,.1);text-align:left;color:#cbd5e1;}
        #ragnar-skyview .sv-diag-table-wrap th{position:sticky;top:0;background:#081426;color:#7dd3fc;font-size:10px;text-transform:uppercase;letter-spacing:.08em;}
        #ragnar-skyview .sv-diag-loading{padding:28px;color:#9fb0c3;text-align:center;font-size:13px;}
        #ragnar-skyview .sv-brand{display:none;position:absolute;left:16px;top:16px;z-index:4;
          pointer-events:none;color:#dbeafe;text-shadow:0 1px 18px rgba(14,165,233,.45);}
        #ragnar-skyview .sv-brand b{display:block;font-size:11px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;}
        #ragnar-skyview .sv-brand span{display:block;margin-top:3px;color:#7fa7c8;font-size:11px;letter-spacing:.05em;}
        #ragnar-skyview .sv-cursor{display:none;position:absolute;left:16px;top:48px;z-index:4;color:#9fb0c3;
          font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.03em;pointer-events:none;
          background:rgba(3,8,18,.35);border:1px solid rgba(125,211,252,.12);border-radius:8px;padding:5px 8px;}
        #ragnar-skyview .sv-layer-key{display:none;position:absolute;left:16px;bottom:62px;z-index:4;pointer-events:none;
          background:rgba(3,8,18,.33);border:1px solid rgba(125,211,252,.12);border-radius:10px;padding:8px 10px;
          color:#8fb4d1;font-size:10px;line-height:1.65;backdrop-filter:blur(8px);}
        #ragnar-skyview .sv-layer-key b{display:block;color:#dbeafe;font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:3px;opacity:.72;}
        #ragnar-skyview .sv-layer-key span{display:flex;align-items:center;gap:7px;white-space:nowrap;opacity:.72;}
        #ragnar-skyview .sv-layer-key i{display:inline-block;width:16px;height:2px;border-radius:999px;background:#7dd3fc;opacity:.7;}
        #ragnar-skyview .sv-layer-key .ecl i{background:#f8d58a;border-top:1px dashed #f8d58a;}
        #ragnar-skyview .sv-layer-key .mw i{height:6px;background:rgba(186,230,253,.18);}
        #ragnar-skyview .sv-layer-key .sat i{height:6px;width:6px;border-radius:999px;background:#34d399;}
        #ragnar-skyview .sv-zoom{display:none;position:absolute;left:16px;bottom:18px;z-index:4;gap:6px;align-items:center;
          background:rgba(3,8,18,.56);border:1px solid rgba(125,211,252,.22);border-radius:10px;padding:6px;backdrop-filter:blur(10px);}
        #ragnar-skyview .sv-zoom button{width:32px;height:30px;border:1px solid rgba(148,163,184,.22);border-radius:7px;background:rgba(15,23,42,.72);color:#dbeafe;font-size:16px;line-height:1;cursor:pointer;}
        #ragnar-skyview .sv-zoom button:hover{background:rgba(14,38,66,.86);border-color:rgba(125,211,252,.46);}
        #ragnar-skyview .sv-zoom span{min-width:46px;text-align:center;color:#9fb0c3;font-size:11px;font-family:ui-monospace,monospace;}
        #ragnar-skyview .sv-detail{display:none;position:absolute;right:14px;bottom:14px;z-index:4;
          width:min(360px,calc(100vw - 28px));gap:8px;pointer-events:none;}
        #ragnar-skyview .sv-detail-card{background:linear-gradient(180deg,rgba(8,20,38,.34),rgba(3,8,18,.28));
          border:1px solid rgba(125,211,252,.12);border-radius:10px;padding:10px 12px;opacity:.6;
          box-shadow:0 14px 36px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.025);backdrop-filter:blur(10px);}
        #ragnar-skyview .sv-detail-card b{display:block;color:#dbeafe;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;opacity:.78;}
        #ragnar-skyview .sv-detail-card span{display:flex;align-items:baseline;justify-content:space-between;gap:14px;color:#9fb0c3;font-size:11px;line-height:1.55;opacity:.82;}
        #ragnar-skyview .sv-detail-card i{font-style:normal;color:#7f93ad;}
        #ragnar-skyview .sv-detail-card em{font-style:normal;color:#e2e8f0;text-align:right;max-width:58%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
        #ragnar-skyview.sv-enhanced{background:radial-gradient(circle at 50% 35%,#113050 0,#06101f 42%,#02050d 76%);}
        #ragnar-skyview.sv-enhanced .sv-head{background:linear-gradient(90deg,rgba(14,165,233,.14),rgba(15,23,42,.32),rgba(125,211,252,.09));}
        #ragnar-skyview.sv-enhanced svg{cursor:grab;touch-action:none;}
        #ragnar-skyview.sv-enhanced.sv-dragging svg{cursor:grabbing;}
        #ragnar-skyview.sv-enhanced .sv-diag-btn{display:inline-flex;}
        #ragnar-skyview.sv-enhanced .sv-brand{display:block;}
        #ragnar-skyview.sv-enhanced .sv-cursor{display:block;}
        #ragnar-skyview.sv-enhanced .sv-layer-key{display:block;}
        #ragnar-skyview.sv-enhanced .sv-zoom{display:flex;}
        #ragnar-skyview.sv-enhanced .sv-detail{display:grid;}
        @media (max-width:760px){#ragnar-skyview .sv-legend{display:none;}#ragnar-skyview.sv-enhanced .sv-detail{display:none;}#ragnar-skyview .sv-layer-key{display:none;}#ragnar-skyview .sv-diag-grid{grid-template-columns:1fr;}#ragnar-skyview .sv-diag-modal{padding:12px;}}
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
        <div class="sv-cursor">az --  alt --</div>
        <svg preserveAspectRatio="xMidYMid meet"></svg>
        <div class="sv-note"></div>
        <div class="sv-layer-key"><b>Layers</b><span class="mw"><i></i>Milky Way density</span><span class="ecl"><i></i>Ecliptic plane</span><span><i></i>Alt / az grid</span><span class="sat"><i></i>GNSS satellites</span></div>
        <div class="sv-zoom"><button class="sv-zoom-out" type="button" title="Zoom out">−</button><span class="sv-zoom-label">1.0x</span><button class="sv-zoom-in" type="button" title="Zoom in">+</button></div>
        <div class="sv-detail"></div>
        <div class="sv-info"></div>
        <div class="sv-diag-modal" role="dialog" aria-modal="true" aria-label="GPS diagnostics">
          <div class="sv-diag-window">
            <div class="sv-diag-top"><div><h2>GPS Diagnostics</h2><span>live receiver, fix, constellation, and satellite telemetry</span></div><button class="sv-diag-close" type="button" title="Close diagnostics">✕</button></div>
            <div class="sv-diag-modal-body"></div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    if (enhanced) overlay.classList.add('sv-enhanced');
    overlay.style.setProperty('overflow', 'hidden');
    document.body.style.overflow = 'hidden';

    svg = overlay.querySelector('svg');
    subtitleEl = overlay.querySelector('#sv-sub');
    noteEl = overlay.querySelector('.sv-note');
    detailEl = overlay.querySelector('.sv-detail');
    cursorEl = overlay.querySelector('.sv-cursor');
    infoCard = overlay.querySelector('.sv-info');
    const zoomLabel = overlay.querySelector('.sv-zoom-label');
    if (zoomLabel) zoomLabel.textContent = skyZoom.toFixed(1) + 'x';
    const zoomIn = overlay.querySelector('.sv-zoom-in');
    const zoomOut = overlay.querySelector('.sv-zoom-out');
    if (zoomIn) zoomIn.addEventListener('click', () => setSkyZoom(skyZoom + 0.25));
    if (zoomOut) zoomOut.addEventListener('click', () => setSkyZoom(skyZoom - 0.25));
    const diagBtn = overlay.querySelector('.sv-diag-btn');
    if (diagBtn) {
      diagBtn.addEventListener('click', openGpsDiagnosticsPopup);
    }
    const diagClose = overlay.querySelector('.sv-diag-close');
    if (diagClose) diagClose.addEventListener('click', closeGpsDiagnosticsPopup);
    const diagModal = overlay.querySelector('.sv-diag-modal');
    if (diagModal) diagModal.addEventListener('click', (e) => { if (e.target === diagModal) closeGpsDiagnosticsPopup(); });
    overlay.querySelector('.sv-close').addEventListener('click', close);
    svg.addEventListener('click', onSvgClick);
    let dragState = null;
    svg.addEventListener('pointerdown', (e) => {
      if (!enhanced || e.button !== 0) return;
      dragState = { id: e.pointerId, x: e.clientX, y: e.clientY, panX: skyPanX, panY: skyPanY, moved: false };
      svg.setPointerCapture(e.pointerId);
      overlay.classList.add('sv-dragging');
    });
    svg.addEventListener('pointermove', (e) => {
      updateCursorReadout(e);
      if (!dragState || e.pointerId !== dragState.id) return;
      const dx = e.clientX - dragState.x, dy = e.clientY - dragState.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) dragState.moved = true;
      setSkyPan(dragState.panX + dx, dragState.panY + dy);
    });
    function finishDrag(e) {
      if (!dragState || e.pointerId !== dragState.id) return;
      if (dragState.moved) {
        suppressNextClick = true;
        e.preventDefault();
      }
      try { svg.releasePointerCapture(e.pointerId); } catch (_) {}
      overlay.classList.remove('sv-dragging');
      window.setTimeout(() => { dragState = null; }, 0);
    }
    svg.addEventListener('pointerup', finishDrag);
    svg.addEventListener('pointercancel', finishDrag);
    svg.addEventListener('pointerleave', () => { if (cursorEl) cursorEl.textContent = 'az --  alt --'; });
    svg.addEventListener('wheel', (e) => {
      if (!enhanced) return;
      e.preventDefault();
      setSkyZoom(skyZoom + (e.deltaY < 0 ? 0.18 : -0.18), { x: e.clientX, y: e.clientY });
    }, { passive: false });

    // Match the SVG viewBox to its pixel size so screen clicks map 1:1.
    function syncViewBox() {
      const r = svg.getBoundingClientRect();
      svg.setAttribute('viewBox', `0 0 ${r.width} ${r.height}`);
      render();
    }
    resizeH = syncViewBox;
    window.addEventListener('resize', resizeH);

    onEsc = (e) => {
      if (e.key !== 'Escape') return;
      const diagModal = overlay && overlay.querySelector('.sv-diag-modal.open');
      if (diagModal) closeGpsDiagnosticsPopup();
      else close();
    };
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
    svg = infoCard = subtitleEl = noteEl = detailEl = cursorEl = null;
    enhanced = false;
    skyZoom = 1;
    skyPanX = skyPanY = 0;
    suppressNextClick = false;
    document.body.style.overflow = '';
  }

  window.RagnarSkyView = { open, close };
})();
