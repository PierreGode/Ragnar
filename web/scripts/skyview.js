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
  const PLANET_IMG = {
    Sun:     '/web/vendor/sky/Inner-Planets/Sun.png',
    Moon:    '/web/vendor/sky/Inner-Planets/Moon.png',
    Mercury: '/web/vendor/sky/Inner-Planets/Mercury.png',
    Venus:   '/web/vendor/sky/Inner-Planets/Venus.png',
    Mars:    '/web/vendor/sky/Inner-Planets/Mars.png',
    Jupiter: '/web/vendor/sky/Outer-Planets/Jupiter.png',
    Saturn:  '/web/vendor/sky/Outer-Planets/Saturn.png',
    Uranus:  '/web/vendor/sky/Outer-Planets/Uranus.png',
    Neptune: '/web/vendor/sky/Outer-Planets/Neptune.png'
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

  function normDeg(v) { return ((v % 360) + 360) % 360; }

  function issSkyFromLatLon(issLat, issLon, issAltKm, obsLat, obsLon) {
    const R = 6371.0;
    const lat1 = issLat * D2R, lon1 = issLon * D2R;
    const lat2 = obsLat * D2R, lon2 = obsLon * D2R;
    const r1 = R + issAltKm;
    const iX = r1 * Math.cos(lat1) * Math.cos(lon1);
    const iY = r1 * Math.cos(lat1) * Math.sin(lon1);
    const iZ = r1 * Math.sin(lat1);
    const oX = R * Math.cos(lat2) * Math.cos(lon2);
    const oY = R * Math.cos(lat2) * Math.sin(lon2);
    const oZ = R * Math.sin(lat2);
    const dx = iX - oX, dy = iY - oY, dz = iZ - oZ;
    const sLat = Math.sin(lat2), cLat = Math.cos(lat2);
    const sLon = Math.sin(lon2), cLon = Math.cos(lon2);
    const east  = -sLon * dx + cLon * dy;
    const north = -sLat * cLon * dx - sLat * sLon * dy + cLat * dz;
    const up    =  cLat * cLon * dx + cLat * sLon * dy + sLat * dz;
    const rng = Math.sqrt(east * east + north * north + up * up);
    const az = normDeg(Math.atan2(east, north) * R2D);
    const el = Math.asin(up / rng) * R2D;
    return { az, el, range_km: rng };
  }

  function refreshISS() {
    const now = Date.now();
    if (now - issLastFetch < 25000) return;
    issLastFetch = now;
    fetch('/api/iss/position', { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d || d.error) return;
        issState = {
          lat: d.latitude, lon: d.longitude,
          alt_km: d.altitude, velocity: d.velocity,
          t: Math.round(d.timestamp || (now / 1000))
        };
      })
      .catch(() => {});
  }

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
      const distanceAu = Math.sqrt(geo.x * geo.x + geo.y * geo.y + geo.z * geo.z);
      return { ...p, ra: eq.ra, dec: eq.dec, alt: sky.alt, az: sky.az, distanceAu };
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

  function fmtDeg(v, digits) {
    if (typeof v !== 'number' || !isFinite(v)) return '—';
    return v.toFixed(digits == null ? 1 : digits) + '°';
  }

  function fmtRa(ra) {
    if (typeof ra !== 'number' || !isFinite(ra)) return '—';
    const h = ra / 15;
    const hh = Math.floor(h);
    const mm = Math.floor((h - hh) * 60);
    const ss = Math.round((((h - hh) * 60) - mm) * 60);
    return `${hh}h ${String(mm).padStart(2, '0')}m ${String(ss).padStart(2, '0')}s`;
  }

  function altitudeBand(alt) {
    if (alt >= 75) return 'near zenith';
    if (alt >= 45) return 'high sky';
    if (alt >= 20) return 'mid altitude';
    if (alt >= 5) return 'low horizon';
    return 'at horizon';
  }

  function airmass(alt) {
    if (typeof alt !== 'number' || alt <= 0) return '—';
    return (1 / Math.max(0.12, Math.sin(alt * D2R))).toFixed(2) + 'x';
  }

  function magnitudeClass(mag) {
    if (mag < 0) return 'brilliant';
    if (mag < 1) return 'navigation star';
    if (mag < 3) return 'bright naked-eye';
    if (mag < 5.5) return 'naked-eye under dark sky';
    return 'faint catalog object';
  }

  function brightnessVsVega(mag) {
    if (typeof mag !== 'number' || !isFinite(mag)) return '—';
    const ratio = Math.pow(2.512, -mag);
    if (ratio >= 10) return ratio.toFixed(0) + 'x Vega';
    if (ratio >= 1) return ratio.toFixed(1) + 'x Vega';
    return (ratio * 100).toFixed(0) + '% of Vega';
  }

  function signalQuality(snr) {
    if (typeof snr !== 'number' || snr <= 0) return 'not tracked';
    if (snr >= 40) return 'excellent';
    if (snr >= 30) return 'strong';
    if (snr >= 20) return 'usable';
    return 'weak';
  }

  function planetCategory(name) {
    if (name === 'Moon') return 'natural satellite';
    if (name === 'Mercury' || name === 'Venus') return 'inner planet';
    if (name === 'Mars') return 'terrestrial planet';
    if (name === 'Jupiter' || name === 'Saturn') return 'gas giant';
    return 'ice giant';
  }

  // ---- Sun, Moon phase, twilight --------------------------------------
  // Low-precision solar ecliptic longitude (deg), good to ~0.01 deg.
  function sunEclipticLon(date) {
    const d = julianDay(date) - 2451545.0;
    const g = normDeg(357.529 + 0.98560028 * d) * D2R;
    const q = normDeg(280.459 + 0.98564736 * d);
    return normDeg(q + 1.915 * Math.sin(g) + 0.020 * Math.sin(2 * g));
  }
  function sunPosition(date, lat, lon) {
    const L = sunEclipticLon(date) * D2R;
    const eq = eclipticToRaDec(Math.cos(L), Math.sin(L), 0);
    const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
    return { name: 'Sun', ra: eq.ra, dec: eq.dec, alt: sky.alt, az: sky.az, color: '#ffdf7e', mag: -26.7 };
  }
  const MOON_PHASES = ['New Moon', 'Waxing Crescent', 'First Quarter', 'Waxing Gibbous',
    'Full Moon', 'Waning Gibbous', 'Last Quarter', 'Waning Crescent'];
  function moonIllumination(date) {
    const d = julianDay(date) - 2451545.0;
    const Lm = normDeg(218.316 + 13.176396 * d);
    const M = normDeg(134.963 + 13.064993 * d);
    const lonMoon = normDeg(Lm + 6.289 * Math.sin(M * D2R));
    const elong = normDeg(lonMoon - sunEclipticLon(date));   // 0 = new, 180 = full
    return {
      elong,
      illum: (1 - Math.cos(elong * D2R)) / 2,
      waxing: elong < 180,
      phase: MOON_PHASES[Math.floor(normDeg(elong + 22.5) / 45) % 8],
      ageDays: (elong / 360) * 29.53
    };
  }
  function twilightPhase(alt) {
    if (alt >= -0.833) return { key: 'day', label: 'Daytime', dark: 0 };
    if (alt >= -6) return { key: 'civil', label: 'Civil twilight', dark: 0.3 };
    if (alt >= -12) return { key: 'nautical', label: 'Nautical twilight', dark: 0.6 };
    if (alt >= -18) return { key: 'astro', label: 'Astronomical twilight', dark: 0.85 };
    return { key: 'night', label: 'Astronomical night', dark: 1 };
  }
  // Forward-scan the next crossing of a solar-altitude threshold (5-min steps).
  function nextSunCrossing(fromMs, lat, lon, threshold, goingUp) {
    const step = 5 * 60000;
    let prev = sunPosition(new Date(fromMs), lat, lon).alt - threshold;
    for (let i = 1; i <= 300; i++) {
      const t = fromMs + i * step;
      const cur = sunPosition(new Date(t), lat, lon).alt - threshold;
      if ((goingUp && prev < 0 && cur >= 0) || (!goingUp && prev > 0 && cur <= 0)) return t;
      prev = cur;
    }
    return null;
  }
  function clockUtc(ms) {
    if (!ms) return '—';
    return new Date(ms).toISOString().slice(11, 16) + ' UTC';
  }
  function inText(ms, fromMs) {
    if (!ms) return '';
    const m = Math.round((ms - fromMs) / 60000);
    if (m <= 0) return 'now';
    if (m < 60) return 'in ' + m + ' min';
    return 'in ' + Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm';
  }

  // ---- GNSS geometry (DOP) + integrity --------------------------------
  // Invert a 4x4 via Gauss-Jordan; null if singular.
  function invert4(m) {
    const a = m.map((r, i) => r.concat([0, 0, 0, 0].map((_, j) => (i === j ? 1 : 0))));
    for (let col = 0; col < 4; col++) {
      let piv = col;
      for (let r = col + 1; r < 4; r++) if (Math.abs(a[r][col]) > Math.abs(a[piv][col])) piv = r;
      if (Math.abs(a[piv][col]) < 1e-9) return null;
      [a[col], a[piv]] = [a[piv], a[col]];
      const d = a[col][col];
      for (let j = 0; j < 8; j++) a[col][j] /= d;
      for (let r = 0; r < 4; r++) {
        if (r === col) continue;
        const f = a[r][col];
        for (let j = 0; j < 8; j++) a[r][j] -= f * a[col][j];
      }
    }
    return a.map(r => r.slice(4));
  }
  // PDOP/HDOP/VDOP/TDOP/GDOP from tracked satellite az/el geometry.
  function computeDOP(sats) {
    const rows = [];
    for (const s of sats) {
      if (s.az == null || s.elev == null) continue;
      if (!(typeof s.snr === 'number' && s.snr > 0)) continue;
      if (s.elev < 3) continue;
      const el = s.elev * D2R, az = s.az * D2R;
      const ce = Math.cos(el);
      rows.push([ce * Math.sin(az), ce * Math.cos(az), Math.sin(el), 1]);
    }
    if (rows.length < 4) return { n: rows.length, ok: false };
    const ata = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
    for (const r of rows)
      for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) ata[i][j] += r[i] * r[j];
    const q = invert4(ata);
    if (!q) return { n: rows.length, ok: false };
    const gd = Math.sqrt(Math.max(0, q[0][0] + q[1][1] + q[2][2] + q[3][3]));
    return {
      n: rows.length, ok: true,
      gdop: gd,
      pdop: Math.sqrt(Math.max(0, q[0][0] + q[1][1] + q[2][2])),
      hdop: Math.sqrt(Math.max(0, q[0][0] + q[1][1])),
      vdop: Math.sqrt(Math.max(0, q[2][2])),
      tdop: Math.sqrt(Math.max(0, q[3][3]))
    };
  }
  function dopVerdict(pdop) {
    if (pdop == null) return { label: 'insufficient', tone: 'warn' };
    if (pdop < 2) return { label: 'excellent', tone: 'good' };
    if (pdop < 4) return { label: 'good', tone: 'good' };
    if (pdop < 6) return { label: 'moderate', tone: '' };
    if (pdop < 10) return { label: 'fair', tone: 'warn' };
    return { label: 'poor geometry', tone: 'warn' };
  }
  function stdev(arr) {
    if (arr.length < 2) return 0;
    const m = arr.reduce((a, b) => a + b, 0) / arr.length;
    return Math.sqrt(arr.reduce((a, b) => a + (b - m) * (b - m), 0) / arr.length);
  }
  function haversineM(a, b) {
    if (!a || !b) return 0;
    const R = 6371000, dLat = (b.lat - a.lat) * D2R, dLon = (b.lon - a.lon) * D2R;
    const s = Math.sin(dLat / 2) ** 2 +
      Math.cos(a.lat * D2R) * Math.cos(b.lat * D2R) * Math.sin(dLon / 2) ** 2;
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
  }
  // Experimental spoofing / jamming heuristics over the live sky snapshot.
  function integrityCheck(sats, jumpM) {
    const tracked = sats.filter(s => typeof s.snr === 'number' && s.snr > 0);
    const reasons = [];
    let level = 'ok';
    const bump = (lv) => { if (lv === 'suspect' || level === 'suspect') level = 'suspect'; else if (lv === 'caution') level = 'caution'; };
    const snrs = tracked.map(s => s.snr);
    if (tracked.length >= 6) {
      const sd = stdev(snrs), mean = snrs.reduce((a, b) => a + b, 0) / snrs.length;
      if (sd < 1.2 && mean > 40) { reasons.push('Uniform high SNR across ' + tracked.length + ' sats (possible spoof)'); bump('suspect'); }
      else if (sd < 2 && mean > 35) { reasons.push('Low SNR spread — power looks synthetic'); bump('caution'); }
    }
    if (snrs.some(v => v > 55)) { reasons.push('Improbably high SNR (>55 dB)'); bump('caution'); }
    const cons = new Set(tracked.map(s => s.constellation).filter(Boolean));
    if (tracked.length >= 8 && cons.size === 1) { reasons.push('All tracked sats one constellation'); bump('caution'); }
    if (jumpM > 3000) { reasons.push('Position jumped ' + Math.round(jumpM) + ' m between polls'); bump('suspect'); }
    const dup = {};
    for (const v of snrs) dup[v] = (dup[v] || 0) + 1;
    const maxDup = Math.max(0, ...Object.values(dup));
    if (tracked.length >= 6 && maxDup >= Math.ceil(tracked.length * 0.6)) { reasons.push(maxDup + ' sats share an identical SNR value'); bump('suspect'); }
    if (!reasons.length) reasons.push(tracked.length ? 'No anomalies in current snapshot' : 'No tracked satellites to assess');
    return { level, reasons, tracked: tracked.length };
  }

  // ---- GNSS satellite orbit model (approximate, for the time scrubber) -
  // Satellites arrive as a live az/el snapshot with no orbit attached. To let
  // the time scrubber move them we reconstruct each satellite's geocentric
  // position from its az/el plus a per-constellation nominal orbit radius, learn
  // its orbital plane from the motion seen between live polls, then advance a
  // CIRCULAR orbit at the Keplerian mean rate. Deliberately approximate (ignores
  // eccentricity, J2 drift, and mixed-altitude constellations like BeiDou/QZSS)
  // and only ever drives the scrubbed view — at offset 0 the measured az/el is
  // used verbatim, so it is an exact no-op live.
  const GM_EARTH = 398600.4418;   // km^3/s^2
  const EARTH_R_KM = 6371.0;
  // Nominal geocentric orbit radius (km, ~semi-major axis) per constellation.
  const ORBIT_KM = {
    GPS: 26560, GLONASS: 25510, Galileo: 29600, BeiDou: 27900,
    QZSS: 42164, NavIC: 42164, combined: 27000
  };
  function vcross(a, b) { return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]; }
  function vdot(a, b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }
  function vlen(a) { return Math.sqrt(vdot(a, a)); }
  function vnorm(a) { const L = vlen(a) || 1; return [a[0] / L, a[1] / L, a[2] / L]; }
  function vadd(a, b) { return [a[0] + b[0], a[1] + b[1], a[2] + b[2]]; }
  function vscale(a, s) { return [a[0] * s, a[1] * s, a[2] * s]; }
  // Rotate v about unit axis k by angle a (Rodrigues).
  function rodrigues(v, k, a) {
    const c = Math.cos(a), s = Math.sin(a), kd = vdot(k, v), kv = vcross(k, v);
    return [
      v[0] * c + kv[0] * s + k[0] * kd * (1 - c),
      v[1] * c + kv[1] * s + k[1] * kd * (1 - c),
      v[2] * c + kv[2] * s + k[2] * kd * (1 - c)
    ];
  }
  // Observer ECEF (spherical Earth) + local ENU basis for lat/lon (deg).
  function observerFrame(lat, lon) {
    const la = lat * D2R, lo = lon * D2R;
    const cla = Math.cos(la), sla = Math.sin(la), clo = Math.cos(lo), slo = Math.sin(lo);
    return {
      ecef: [EARTH_R_KM * cla * clo, EARTH_R_KM * cla * slo, EARTH_R_KM * sla],
      east: [-slo, clo, 0],
      north: [-sla * clo, -sla * slo, cla],
      up: [cla * clo, cla * slo, sla]
    };
  }
  // az/el (deg) -> satellite ECEF on the sphere of radius Rs (km), or null.
  function azElToEcef(az, el, fr, Rs) {
    const a = az * D2R, e = el * D2R, ce = Math.cos(e);
    const d = vadd(vadd(vscale(fr.east, Math.sin(a) * ce), vscale(fr.north, Math.cos(a) * ce)), vscale(fr.up, Math.sin(e)));
    // |O + r d|^2 = Rs^2  ->  r^2 + 2(O·d) r + (|O|^2 - Rs^2) = 0 ; d is unit.
    const b = 2 * vdot(fr.ecef, d), c = vdot(fr.ecef, fr.ecef) - Rs * Rs;
    const disc = b * b - 4 * c;
    if (disc < 0) return null;
    const r = (-b + Math.sqrt(disc)) / 2;
    if (r <= 0) return null;
    return vadd(fr.ecef, vscale(d, r));
  }
  // satellite ECEF -> {az, elev} (deg) at observer frame.
  function ecefToAzEl(sat, fr) {
    const los = [sat[0] - fr.ecef[0], sat[1] - fr.ecef[1], sat[2] - fr.ecef[2]];
    const e = vdot(los, fr.east), n = vdot(los, fr.north), u = vdot(los, fr.up);
    return { az: normDeg(Math.atan2(e, n) * R2D), elev: Math.atan2(u, Math.sqrt(e * e + n * n)) * R2D };
  }
  function eciFromEcef(v, g) { const c = Math.cos(g), s = Math.sin(g); return [c * v[0] - s * v[1], s * v[0] + c * v[1], v[2]]; }
  function ecefFromEci(v, g) { const c = Math.cos(g), s = Math.sin(g); return [c * v[0] + s * v[1], -s * v[0] + c * v[1], v[2]]; }
  function satKey(s) { return (s.constellation || '?') + '/' + (s.prn != null ? s.prn : '?'); }
  function orbitRadius(cons) { return ORBIT_KM[cons] || ORBIT_KM.combined; }
  // Per-satellite orbit tracks learned from live polls: key -> {eciRef, eciNow, Rs}.
  let satTrack = new Map();
  function trackSatsLive(sky, lat, lon) {
    if (lat == null || lon == null) return;
    const fr = observerFrame(lat, lon);
    const g = gmstDeg(new Date()) * D2R;
    const alive = new Set();
    for (const s of sky) {
      if (s.az == null || s.elev == null || s.prn == null) continue;
      const ecef = azElToEcef(s.az, Math.max(0.1, s.elev), fr, orbitRadius(s.constellation));
      if (!ecef) continue;
      const eci = eciFromEcef(ecef, g);
      const key = satKey(s);
      alive.add(key);
      const t = satTrack.get(key);
      if (!t) satTrack.set(key, { eciRef: eci, eciNow: eci, Rs: orbitRadius(s.constellation) });
      else { t.eciNow = eci; t.Rs = orbitRadius(s.constellation); }
    }
    for (const k of [...satTrack.keys()]) if (!alive.has(k)) satTrack.delete(k);
  }
  // Predicted az/el for a live sat at the scrubbed time; null if not modelable
  // yet (needs two separated live samples to fix the orbital plane).
  function predictSat(s, offsetMs, fr) {
    const t = satTrack.get(satKey(s));
    if (!t) return null;
    if (vlen(vcross(vnorm(t.eciRef), vnorm(t.eciNow))) < 1e-3) return null;   // no baseline motion yet
    const n = vnorm(vcross(t.eciRef, t.eciNow));   // plane normal, motion sense ref -> now
    const w = Math.sqrt(GM_EARTH / (t.Rs * t.Rs * t.Rs));
    const eciT = rodrigues(t.eciNow, n, w * (offsetMs / 1000));
    const g = gmstDeg(new Date(Date.now() + offsetMs)) * D2R;
    return ecefToAzEl(ecefFromEci(eciT, g), fr);
  }
  // The satellite set as it should appear for the current view time. At offset 0
  // (or without a position) this is the raw live sky; when scrubbed, modelable
  // sats carry propagated az/elev and a `modeled` flag; the rest stay put.
  function skyForView() {
    const sky = lastData.sky || [];
    if (timeOffsetMs === 0 || lastData.lat == null || lastData.lon == null) return sky;
    const fr = observerFrame(lastData.lat, lastData.lon);
    return sky.map(s => {
      if (s.az == null || s.elev == null || s.prn == null) return s;
      const p = predictSat(s, timeOffsetMs, fr);
      return p ? { ...s, az: p.az, elev: p.elev, modeled: true } : s;
    });
  }

  // ---- GNSS obstruction / multipath sky survey ------------------------
  // Accumulates, per 5-deg az/el cell, how often a satellite is seen there vs
  // how often it is actually tracked (has SNR). Cells frequently transited but
  // rarely locked are obstructed (buildings / trees / antenna mask). Persisted
  // to localStorage so a survey builds up across visits.
  const SURVEY_KEY = 'ragnar_skyview_survey_v2';
  const AZ_BINS = 72, EL_BINS = 18;
  let survey = { seen: null, lock: null, snr: null, n: 0 };
  let surveyDirty = 0;
  function surveyInit() {
    if (survey.seen) return;
    survey.seen = new Int32Array(AZ_BINS * EL_BINS);
    survey.lock = new Int32Array(AZ_BINS * EL_BINS);
    survey.snr = new Float32Array(AZ_BINS * EL_BINS);
    survey.n = 0;
    try {
      const raw = localStorage.getItem(SURVEY_KEY);
      if (raw) {
        const o = JSON.parse(raw);
        if (o && o.seen && o.seen.length === AZ_BINS * EL_BINS) {
          survey.seen.set(o.seen); survey.lock.set(o.lock); survey.snr.set(o.snr); survey.n = o.n || 0;
        }
      }
    } catch (_) {}
  }
  function surveyPersist() {
    try {
      localStorage.setItem(SURVEY_KEY, JSON.stringify({
        seen: Array.from(survey.seen), lock: Array.from(survey.lock),
        snr: Array.from(survey.snr, v => Math.round(v)), n: survey.n
      }));
    } catch (_) {}
    surveyDirty = 0;
  }
  function surveyBin(az, el) {
    const a = Math.floor(normDeg(az) / (360 / AZ_BINS)) % AZ_BINS;
    const e = Math.min(EL_BINS - 1, Math.max(0, Math.floor(Math.max(0, Math.min(90, el)) / (90 / EL_BINS))));
    return e * AZ_BINS + a;
  }
  function surveyAccumulate(sats) {
    surveyInit();
    let touched = false;
    for (const s of sats) {
      if (s.az == null || s.elev == null || s.elev < 0) continue;
      const b = surveyBin(s.az, s.elev);
      survey.seen[b]++;
      if (typeof s.snr === 'number' && s.snr > 0) { survey.lock[b]++; survey.snr[b] += s.snr; }
      touched = true;
    }
    if (touched) { survey.n++; if (++surveyDirty >= 12) surveyPersist(); }
  }
  function surveyReset() {
    surveyInit();
    survey.seen.fill(0); survey.lock.fill(0); survey.snr.fill(0); survey.n = 0;
    surveyPersist();
  }
  function surveyStats() {
    surveyInit();
    let seenCells = 0, open = 0, blocked = 0, weakest = null;
    for (let b = 0; b < survey.seen.length; b++) {
      const seen = survey.seen[b];
      if (seen < 2) continue;
      seenCells++;
      const ratio = survey.lock[b] / seen;
      if (ratio >= 0.5) open++; else {
        blocked++;
        if (!weakest || ratio < weakest.ratio) {
          const e = Math.floor(b / AZ_BINS), a = b % AZ_BINS;
          weakest = { ratio, az: a * (360 / AZ_BINS) + (360 / AZ_BINS) / 2, el: e * (90 / EL_BINS) + (90 / EL_BINS) / 2 };
        }
      }
    }
    return { seenCells, open, blocked, score: seenCells ? Math.round(100 * open / seenCells) : null, samples: survey.n, weakest };
  }

  // ---- State -----------------------------------------------------------
  let overlay = null, svg = null, infoCard = null, subtitleEl = null, noteEl = null, detailEl = null, cursorEl = null;
  let catalog = null, catalogLoading = null;
  let constLines = null, constLinesLoading = null;
  let deepSky = null, deepSkyLoading = null;
  let timer = null, onEsc = null, resizeH = null;
  let enhanced = false;
  let skyZoom = 1;
  let skyPanX = 0, skyPanY = 0;
  let suppressNextClick = false;
  // Layer toggles (enhanced Starview only).
  let showConstellations = true, showDeepSky = false, showObstruction = false;
  // Time-travel scrubber offset (ms). 0 = live now.
  let timeOffsetMs = 0;
  // Previous fix + last measured jump, for the integrity position-jump check.
  let prevFix = null, integrityJumpM = 0;
  // mode: 'live' | 'last' | 'browser' | 'default' | 'none'
  let lastData = { sky: [], lat: null, lon: null, mode: 'none', t: null };
  let browserGeo = null;
  let issState = null;
  let issLastFetch = 0;
  // Screen-space projected objects for click hit-testing.
  let projected = [];
  function viewDate() { return new Date(Date.now() + timeOffsetMs); }

  function timezoneDefault() {
    const offMin = -new Date().getTimezoneOffset();
    const lon = Math.max(-180, Math.min(180, (offMin / 60) * 15));
    return { lat: 45, lon, mode: 'default', t: null };
  }

  function esc(s) {
    return String(s).replace(/[<>&"]/g, c =>
      ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  }

  // Priority: live fix -> last-known -> browser geolocation -> timezone default.
  function positionFromStatus(status) {
    status = status || {};
    const lat = status.latitude, lon = status.longitude;
    if (status.has_fix && typeof lat === 'number' && typeof lon === 'number')
      return { lat, lon, mode: 'live', t: null };
    const lk = status.last_known;
    if (lk && typeof lk.lat === 'number' && typeof lk.lon === 'number')
      return { lat: lk.lat, lon: lk.lon, mode: 'last', t: lk.t };
    if (browserGeo && typeof browserGeo.lat === 'number' && typeof browserGeo.lon === 'number')
      return { lat: browserGeo.lat, lon: browserGeo.lon, mode: 'browser', t: browserGeo.t };
    return timezoneDefault();
  }

  function requestBrowserGeo() {
    if (browserGeo || !navigator.geolocation) return;
    try {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          browserGeo = {
            lat: pos.coords.latitude,
            lon: pos.coords.longitude,
            t: Math.round(pos.timestamp / 1000)
          };
          if (overlay && lastData.mode !== 'live' && lastData.mode !== 'last') {
            lastData.lat = browserGeo.lat;
            lastData.lon = browserGeo.lon;
            lastData.mode = 'browser';
            lastData.t = browserGeo.t;
            render();
          }
        },
        () => {},
        { enableHighAccuracy: false, timeout: 6000, maximumAge: 3600000 }
      );
    } catch (_) {}
  }

  function modeSuffix(mode) {
    if (mode === 'last') return ' (last-known)';
    if (mode === 'browser') return ' (browser)';
    if (mode === 'default') return ' (approx)';
    return '';
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

  function loadConstLines() {
    if (constLines) return Promise.resolve(constLines);
    if (constLinesLoading) return constLinesLoading;
    constLinesLoading = fetch('/web/vendor/constellation_lines.json')
      .then(r => r.ok ? r.json() : null)
      .then(j => { constLines = j; return j; })
      .catch(() => { constLines = null; return null; });
    return constLinesLoading;
  }

  function loadDeepSky() {
    if (deepSky) return Promise.resolve(deepSky);
    if (deepSkyLoading) return deepSkyLoading;
    deepSkyLoading = fetch('/web/vendor/deep_sky.json')
      .then(r => r.ok ? r.json() : null)
      .then(j => { deepSky = j; return j; })
      .catch(() => { deepSky = null; return null; });
    return deepSkyLoading;
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
    const date = viewDate();
    const isNow = timeOffsetMs === 0;
    const parts = [];
    projected = [];
    const whatsUp = [];
    let visibleStars = 0, namedStars = 0;
    // One canonical satellite set drives the panorama, the radar, AND the GNSS
    // quality card so all three agree. When scrubbed it carries modeled az/elev.
    const viewSky = skyForView();
    const inViewSats = viewSky.filter(s => s.az != null && s.elev != null && s.elev >= 0);
    const trackedList = inViewSats.filter(s => typeof s.snr === 'number' && s.snr > 0);
    const trackedSats = trackedList.length;
    const snrSum = trackedList.reduce((a, s) => a + s.snr, 0);
    const strongestSat = trackedList.reduce((b, s) => (!b || s.snr > b.snr ? s : b), null);
    const strongestSnr = strongestSat ? strongestSat.snr : -1;
    const modeledCount = inViewSats.filter(s => s.modeled).length;
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
      <radialGradient id="sv-sun-core" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#fffbe6"/><stop offset="40%" stop-color="#ffd76a"/><stop offset="80%" stop-color="#f59e0b"/><stop offset="100%" stop-color="#c2410c"/></radialGradient>
      <radialGradient id="sv-sun-corona" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="rgba(255,240,180,.55)"/><stop offset="35%" stop-color="rgba(255,180,60,.28)"/><stop offset="100%" stop-color="rgba(255,120,20,0)"/></radialGradient>
      <radialGradient id="sv-p-Mercury" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#c9b099"/><stop offset="55%" stop-color="#8a7663"/><stop offset="100%" stop-color="#4b3d30"/></radialGradient>
      <radialGradient id="sv-p-Venus" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#fff3c8"/><stop offset="55%" stop-color="#f0d494"/><stop offset="100%" stop-color="#8f6a2a"/></radialGradient>
      <radialGradient id="sv-p-Mars" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#f0a375"/><stop offset="45%" stop-color="#c96844"/><stop offset="100%" stop-color="#5a2110"/></radialGradient>
      <radialGradient id="sv-p-Jupiter" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#f5dfb5"/><stop offset="60%" stop-color="#b98858"/><stop offset="100%" stop-color="#5f3d1f"/></radialGradient>
      <radialGradient id="sv-p-Saturn" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#f8e7b6"/><stop offset="60%" stop-color="#e6cf9a"/><stop offset="100%" stop-color="#8a6f3f"/></radialGradient>
      <radialGradient id="sv-p-Uranus" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#dff5fa"/><stop offset="60%" stop-color="#a7ddec"/><stop offset="100%" stop-color="#3d7f95"/></radialGradient>
      <radialGradient id="sv-p-Neptune" cx="35%" cy="35%" r="70%"><stop offset="0" stop-color="#7fa4d4"/><stop offset="55%" stop-color="#3762a8"/><stop offset="100%" stop-color="#0e2a5c"/></radialGradient>
      <linearGradient id="sv-p-Jupiter-bands" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="rgba(120,80,40,.55)"/><stop offset="18%" stop-color="rgba(240,220,180,0)"/><stop offset="30%" stop-color="rgba(120,80,40,.5)"/><stop offset="45%" stop-color="rgba(240,220,180,0)"/><stop offset="58%" stop-color="rgba(140,90,50,.55)"/><stop offset="72%" stop-color="rgba(240,220,180,0)"/><stop offset="88%" stop-color="rgba(90,60,30,.6)"/></linearGradient>
      <linearGradient id="sv-iss-panel" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="100%" stop-color="#1e3a8a"/></linearGradient>
      <filter id="sv-full-glow" x="-120%" y="-120%" width="340%" height="340%"><feGaussianBlur stdDeviation="2.2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`);
    parts.push(`<rect x="0" y="0" width="${W}" height="${H}" fill="url(#sv-full-bg)"/>`);
    parts.push(`<rect x="0" y="0" width="${W}" height="${H}" fill="url(#sv-zenith)"/>`);
    parts.push(`<rect x="0" y="${(H * .72).toFixed(1)}" width="${W}" height="${(H * .28).toFixed(1)}" fill="url(#sv-horizon)" opacity=".7"/>`);

    // GNSS obstruction / multipath survey heatmap (az/el cells, live-accumulated).
    if (showObstruction) {
      surveyInit();
      const azStep = 360 / AZ_BINS, elStep = 90 / EL_BINS;
      for (let e = 0; e < EL_BINS; e++) {
        for (let a = 0; a < AZ_BINS; a++) {
          const seen = survey.seen[e * AZ_BINS + a];
          if (seen < 2) continue;
          const ratio = survey.lock[e * AZ_BINS + a] / seen;
          const az0 = a * azStep, el0 = e * elStep;
          const p1 = fullSkyPoint(az0, el0, W, H), p2 = fullSkyPoint(az0 + azStep, el0, W, H);
          const p3 = fullSkyPoint(az0 + azStep, el0 + elStep, W, H), p4 = fullSkyPoint(az0, el0 + elStep, W, H);
          if ([p1, p2, p3, p4].some(p => p.x < -60 || p.x > W + 60 || p.y < -60 || p.y > H + 60)) continue;
          // green (open) -> amber -> red (obstructed)
          const hue = Math.round(ratio * 120);
          const op = (0.1 + Math.min(0.32, seen / 120) * (1 - ratio * 0.5)).toFixed(2);
          parts.push(`<path d="M${p1.x.toFixed(1)} ${p1.y.toFixed(1)} L${p2.x.toFixed(1)} ${p2.y.toFixed(1)} L${p3.x.toFixed(1)} ${p3.y.toFixed(1)} L${p4.x.toFixed(1)} ${p4.y.toFixed(1)} Z" fill="hsl(${hue},80%,45%)" opacity="${op}"/>`);
        }
      }
    }

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

    // Real IAU constellation figures (d3-celestial line data) projected live.
    if (hasPos && showConstellations && constLines && constLines.lines) {
      for (const cid in constLines.lines) {
        for (const seg of constLines.lines[cid]) {
          let prev = null;
          for (const [ra, dec] of seg) {
            const p = raDecToAltAz(ra, dec, lat, lon, date);
            const cur = p.alt > 0 ? fullSkyPoint(p.az, p.alt, W, H) : null;
            if (prev && cur && Math.abs(cur.x - prev.x) < W * 0.5) {
              parts.push(`<line x1="${prev.x.toFixed(1)}" y1="${prev.y.toFixed(1)}" x2="${cur.x.toFixed(1)}" y2="${cur.y.toFixed(1)}" stroke="rgba(125,211,252,.28)" stroke-width="1"/>`);
            }
            prev = cur;
          }
        }
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
        if (name && mag < 1.6) whatsUp.push({ kind: 'star', name, alt: p.alt, az: p.az, mag });
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
      // Fallback join-the-brightest lines only if the real figure data is absent.
      if (!(showConstellations && constLines && constLines.lines)) {
        [...starGroups.values()].forEach(stars => {
          stars.sort((a, b) => a.mag - b.mag);
          stars.slice(0, 5).forEach((st, idx, arr) => {
            if (!idx) return;
            const prev = arr[idx - 1], dx = st.x - prev.x, dy = st.y - prev.y;
            if (dx * dx + dy * dy > 90000) return;
            parts.push(`<line x1="${prev.x.toFixed(1)}" y1="${prev.y.toFixed(1)}" x2="${st.x.toFixed(1)}" y2="${st.y.toFixed(1)}" stroke="rgba(125,211,252,.13)" stroke-width="1" stroke-dasharray="3 10"/>`);
          });
        });
      }
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

    // Deep-sky (Messier) objects, projected live.
    if (hasPos && showDeepSky && deepSky && Array.isArray(deepSky.objects)) {
      const tnames = deepSky.type_names || {};
      for (const o of deepSky.objects) {
        const [ra, dec, mag, id, alt, type] = o;
        const p = raDecToAltAz(ra, dec, lat, lon, date);
        if (p.alt <= 0) continue;
        const pt = fullSkyPoint(p.az, p.alt, W, H);
        if (pt.x < -30 || pt.x > W + 30 || pt.y < -30 || pt.y > H + 30) continue;
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="4.4" fill="none" stroke="#c4b5fd" stroke-width="1.1" stroke-dasharray="2 2" opacity=".8"/>`);
        if (skyZoom > 1.35 || (mag != null && mag < 6)) {
          parts.push(`<text x="${(pt.x + 7).toFixed(1)}" y="${(pt.y + 3).toFixed(1)}" fill="#c4b5fd" font-size="10" opacity=".7">${esc(alt || id)}</text>`);
        }
        projected.push({ kind: 'dso', x: pt.x, y: pt.y, ra, dec, alt: p.alt, az: p.az, mag, id, name: alt, dtype: tnames[type] || type });
        whatsUp.push({ kind: 'dso', name: alt || id, alt: p.alt, az: p.az, mag });
      }
    }

    if (hasPos) {
      // Sun.
      const sun = sunPosition(date, lat, lon);
      if (sun.alt > -1) {
        const sp = fullSkyPoint(sun.az, Math.max(0, sun.alt), W, H);
        if (sp.x > -80 && sp.x < W + 80) {
          const sunSize = 40;
          // Noisy corona — 3 stacked layers with slightly non-integer periods
          // + random per-render seeds so the pattern never repeats cleanly.
          const seed = () => (Math.random() * 3 + 1).toFixed(2);
          parts.push(`<circle cx="${sp.x.toFixed(1)}" cy="${sp.y.toFixed(1)}" r="84" fill="url(#sv-sun-corona)" opacity=".55"><animate attributeName="opacity" values="0.3;0.72;0.4;0.65;0.3" dur="${seed()}s" repeatCount="indefinite"/><animate attributeName="r" values="78;95;82;90;78" dur="${seed()}s" repeatCount="indefinite"/></circle>`);
          parts.push(`<circle cx="${sp.x.toFixed(1)}" cy="${sp.y.toFixed(1)}" r="60" fill="url(#sv-sun-corona)" opacity=".65"><animate attributeName="opacity" values="0.45;0.9;0.55;0.8;0.45" dur="${seed()}s" repeatCount="indefinite"/><animate attributeName="r" values="55;68;58;65;55" dur="${seed()}s" repeatCount="indefinite"/></circle>`);
          parts.push(`<circle cx="${sp.x.toFixed(1)}" cy="${sp.y.toFixed(1)}" r="44" fill="url(#sv-sun-corona)" opacity=".8"><animate attributeName="opacity" values="0.7;1;0.75;0.95;0.7" dur="${seed()}s" repeatCount="indefinite"/></circle>`);
          // Sun disc.
          parts.push(`<image href="${PLANET_IMG.Sun}" x="${(sp.x - sunSize).toFixed(1)}" y="${(sp.y - sunSize).toFixed(1)}" width="${(sunSize * 2).toFixed(1)}" height="${(sunSize * 2).toFixed(1)}"/>`);
          // Short-lived flare spikes — regenerated each render, animated to
          // fade in and out once. Because render() runs ~1Hz, there's always
          // a fresh set overlapping the previous one.
          const nFlares = 5 + Math.floor(Math.random() * 5);
          for (let i = 0; i < nFlares; i++) {
            const ang = Math.random() * 360;
            const len = 34 + Math.random() * 42;
            const wid = (1 + Math.random() * 2).toFixed(1);
            const dur = (0.6 + Math.random() * 1.6).toFixed(2);
            const peak = (0.4 + Math.random() * 0.5).toFixed(2);
            const r = 200 + Math.floor(Math.random() * 55);
            const g = 180 + Math.floor(Math.random() * 65);
            const b = 90 + Math.floor(Math.random() * 60);
            parts.push(`<line x1="0" y1="0" x2="0" y2="${(-len).toFixed(1)}" stroke="rgba(${r},${g},${b},1)" stroke-width="${wid}" stroke-linecap="round" transform="translate(${sp.x.toFixed(1)} ${sp.y.toFixed(1)}) rotate(${ang.toFixed(1)})" opacity="0"><animate attributeName="opacity" values="0;${peak};0" dur="${dur}s" repeatCount="1" fill="freeze"/></line>`);
          }
          // Occasional big glare — bright, longer, brighter color.
          if (Math.random() < 0.35) {
            const ang = Math.random() * 360;
            const len = 100 + Math.random() * 90;
            const dur = (1.8 + Math.random() * 1.6).toFixed(2);
            parts.push(`<line x1="0" y1="0" x2="0" y2="${(-len).toFixed(1)}" stroke="rgba(255,240,180,1)" stroke-width="4" stroke-linecap="round" filter="url(#sv-full-glow)" transform="translate(${sp.x.toFixed(1)} ${sp.y.toFixed(1)}) rotate(${ang.toFixed(1)})" opacity="0"><animate attributeName="opacity" values="0;0.95;0.55;0" dur="${dur}s" repeatCount="1" fill="freeze"/></line>`);
          }
          parts.push(`<text x="${sp.x.toFixed(1)}" y="${(sp.y + sunSize + 14).toFixed(1)}" fill="#ffdf7e" font-size="12" text-anchor="middle" opacity=".95">Sun</text>`);
          projected.push({ kind: 'planet', x: sp.x, y: sp.y, planet: sun });
        }
      }
      if (sun.alt > 0) whatsUp.push({ kind: 'sun', name: 'Sun', alt: sun.alt, az: sun.az, mag: -26.7 });

      // Moon.
      const moon = moonPosition(date, lat, lon);
      const ill = moonIllumination(date);
      moon.illum = ill.illum; moon.phase = ill.phase; moon.waxing = ill.waxing; moon.ageDays = ill.ageDays;
      if (moon.alt > 0) {
        const mp = fullSkyPoint(moon.az, moon.alt, W, H);
        if (mp.x > -80 && mp.x < W + 80 && mp.y > -80 && mp.y < H + 80) {
          const mSize = 22;
          parts.push(`<image href="${PLANET_IMG.Moon}" x="${(mp.x - mSize).toFixed(1)}" y="${(mp.y - mSize).toFixed(1)}" width="${(mSize * 2).toFixed(1)}" height="${(mSize * 2).toFixed(1)}"/>`);
          // Overlay a dark cap for the unlit fraction so phase is still visible.
          const k = Math.max(0.03, Math.min(0.97, ill.illum));
          const off = (ill.waxing ? -1 : 1) * mSize * (1 - 2 * k);
          const cid = 'sv-moonshade-' + (mp.x | 0) + '-' + (mp.y | 0);
          parts.push(`<defs><clipPath id="${cid}"><circle cx="${mp.x.toFixed(1)}" cy="${mp.y.toFixed(1)}" r="${mSize}"/></clipPath></defs>`);
          parts.push(`<circle cx="${(mp.x + off).toFixed(1)}" cy="${mp.y.toFixed(1)}" r="${mSize}" fill="rgba(3,8,18,.72)" clip-path="url(#${cid})"/>`);
          parts.push(`<text x="${mp.x.toFixed(1)}" y="${(mp.y + mSize + 14).toFixed(1)}" fill="#dbeafe" font-size="12" text-anchor="middle" opacity=".88">Moon</text>`);
          projected.push({ kind: 'planet', x: mp.x, y: mp.y, planet: moon });
        }
        whatsUp.push({ kind: 'moon', name: 'Moon', alt: moon.alt, az: moon.az, mag: -12 });
      }
      for (const planet of planetPositions(date, lat, lon)) {
        if (planet.alt <= 0) continue;
        const pt = fullSkyPoint(planet.az, planet.alt, W, H);
        if (pt.x < -70 || pt.x > W + 70 || pt.y < -70 || pt.y > H + 70) continue;
        const size = planet.size * 3.2;
        const href = PLANET_IMG[planet.name];
        if (href) {
          parts.push(`<image href="${href}" x="${(pt.x - size).toFixed(1)}" y="${(pt.y - size).toFixed(1)}" width="${(size * 2).toFixed(1)}" height="${(size * 2).toFixed(1)}"/>`);
        } else {
          parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${(planet.size * 1.6).toFixed(1)}" fill="${planet.color}"/>`);
        }
        parts.push(`<text x="${pt.x.toFixed(1)}" y="${(pt.y + size + 14).toFixed(1)}" fill="${planet.color}" font-size="12" text-anchor="middle" opacity=".92">${planet.name}</text>`);
        projected.push({ kind: 'planet', x: pt.x, y: pt.y, planet });
        whatsUp.push({ kind: 'planet', name: planet.name, alt: planet.alt, az: planet.az, mag: planet.mag });
      }
      // ISS — live position from api.wheretheiss.at (silently absent if offline).
      if (issState) {
        const iss = issSkyFromLatLon(issState.lat, issState.lon, issState.alt_km, lat, lon);
        if (iss.el > 0) {
          const ip = fullSkyPoint(iss.az, iss.el, W, H);
          if (ip.x > -80 && ip.x < W + 80 && ip.y > -80 && ip.y < H + 80) {
            const iw = 14, ih = 8;
            const panelW = 6, panelH = 12;
            parts.push(`<g transform="translate(${ip.x.toFixed(1)} ${ip.y.toFixed(1)}) rotate(-12)">
              <circle cx="0" cy="0" r="22" fill="url(#sv-planet-glow)" opacity=".24"/>
              <rect x="${(-panelW - iw/2 - 1).toFixed(1)}" y="${(-panelH/2).toFixed(1)}" width="${panelW}" height="${panelH}" fill="url(#sv-iss-panel)" stroke="#0f172a" stroke-width=".4"/>
              <rect x="${(iw/2 + 1).toFixed(1)}" y="${(-panelH/2).toFixed(1)}" width="${panelW}" height="${panelH}" fill="url(#sv-iss-panel)" stroke="#0f172a" stroke-width=".4"/>
              <rect x="${(-iw/2).toFixed(1)}" y="${(-ih/2).toFixed(1)}" width="${iw}" height="${ih}" fill="#dedede" stroke="#0f172a" stroke-width=".5" rx="1"/>
              <rect x="-2" y="${(-ih/2 - 3).toFixed(1)}" width="4" height="3" fill="#e5e7eb"/>
              <circle cx="0" cy="0" r="1.4" fill="#facc15"/>
            </g>`);
            parts.push(`<text x="${(ip.x + 20).toFixed(1)}" y="${(ip.y + 4).toFixed(1)}" fill="#a7f3d0" font-size="12" opacity=".95">ISS</text>`);
            projected.push({ kind: 'iss', x: ip.x, y: ip.y, iss: Object.assign({}, issState, iss) });
            whatsUp.push({ kind: 'iss', name: 'ISS', alt: iss.el, az: iss.az, mag: -3 });
          }
        }
      }
    }

    // Satellites (panorama) — driven by the shared viewSky so the count/positions
    // match the radar and the GNSS card. Modeled (scrubbed) sats draw dashed.
    for (const s of inViewSats) {
      const pt = fullSkyPoint(s.az, s.elev, W, H);
      const col = SAT_COLORS[s.constellation] || '#94a3b8';
      const hasSnr = typeof s.snr === 'number' && s.snr > 0;
      if (pt.x >= -50 && pt.x <= W + 50 && pt.y >= -50 && pt.y <= H + 50) {
        const satSize = hasSnr ? 12 + Math.min(6, s.snr / 8) : 11;
        const op = hasSnr ? (s.modeled ? .5 : .95) : .5;
        parts.push(`<image href="/web/vendor/sky/sat/satellite.png" x="${(pt.x - satSize).toFixed(1)}" y="${(pt.y - satSize).toFixed(1)}" width="${(satSize * 2).toFixed(1)}" height="${(satSize * 2).toFixed(1)}" opacity="${op}"/>`);
        // Constellation-colored dot at the base so identity is still readable.
        parts.push(`<circle cx="${pt.x.toFixed(1)}" cy="${(pt.y + satSize + 2).toFixed(1)}" r="2.4" fill="${col}" opacity=".9"/>`);
        parts.push(`<text x="${pt.x.toFixed(1)}" y="${(pt.y + satSize + 16).toFixed(1)}" fill="${col}" font-size="10" text-anchor="middle" opacity=".82">${esc((s.constellation || '') + (s.prn != null ? ' ' + s.prn : ''))}</text>`);
        projected.push({ kind: 'sat', x: pt.x, y: pt.y, sat: s });
      }
    }

    parts.push(`<g opacity=".66"><circle cx="${radarC.x}" cy="${radarC.y}" r="${radarR}" fill="rgba(2,6,15,.48)" stroke="rgba(125,211,252,.32)" stroke-width="1.2"/>`);
    for (const f of [1, 2 / 3, 1 / 3]) parts.push(`<circle cx="${radarC.x}" cy="${radarC.y}" r="${(radarR * f).toFixed(1)}" fill="none" stroke="rgba(125,211,252,.18)" stroke-width="1"/>`);
    for (const az of [0, 90, 180, 270]) {
      const a = az * D2R;
      parts.push(`<line x1="${radarC.x}" y1="${radarC.y}" x2="${(radarC.x + radarR * Math.sin(a)).toFixed(1)}" y2="${(radarC.y - radarR * Math.cos(a)).toFixed(1)}" stroke="rgba(125,211,252,.17)"/>`);
    }
    parts.push(`<g opacity=".74"><path d="M${radarC.x} ${radarC.y} L${radarC.x} ${(radarC.y - radarR).toFixed(1)} A${radarR} ${radarR} 0 0 1 ${(radarC.x + radarR * .42).toFixed(1)} ${(radarC.y - radarR * .91).toFixed(1)} Z" fill="rgba(125,211,252,.12)"><animateTransform attributeName="transform" type="rotate" from="0 ${radarC.x} ${radarC.y}" to="360 ${radarC.x} ${radarC.y}" dur="4.8s" repeatCount="indefinite"/></path><line x1="${radarC.x}" y1="${radarC.y}" x2="${radarC.x}" y2="${(radarC.y - radarR).toFixed(1)}" stroke="rgba(125,211,252,.55)" stroke-width="1.3" stroke-linecap="round"><animateTransform attributeName="transform" type="rotate" from="0 ${radarC.x} ${radarC.y}" to="360 ${radarC.x} ${radarC.y}" dur="4.8s" repeatCount="indefinite"/></line></g>`);
    // Radar sats share viewSky with the panorama/card. Green dots are now the
    // 🛰 glyph; a constellation-coloured ring behind it encodes system + lock
    // (solid = tracked, dim = visible-only, dashed = modeled/scrubbed).
    for (const s of inViewSats) {
      const rp = radarPoint(s.az, s.elev, radarC, radarR);
      const col = SAT_COLORS[s.constellation] || '#94a3b8';
      const hasSnr = typeof s.snr === 'number' && s.snr > 0;
      const dash = s.modeled ? ' stroke-dasharray="2 1.5"' : '';
      parts.push(`<circle cx="${rp.x.toFixed(1)}" cy="${rp.y.toFixed(1)}" r="5" fill="rgba(2,6,15,.55)" stroke="${col}" stroke-width="${hasSnr ? 1.4 : 0.9}" opacity="${hasSnr ? .9 : .45}"${dash}/>`);
      parts.push(`<text x="${rp.x.toFixed(1)}" y="${(rp.y + 3.6).toFixed(1)}" font-size="9" text-anchor="middle" opacity="${hasSnr ? .96 : .5}">🛰️</text>`);
    }
    parts.push(`<text x="${radarC.x}" y="${(radarC.y + radarR + 16).toFixed(1)}" fill="#7fa7c8" font-size="10" text-anchor="middle">GNSS radar · ${inViewSats.length} in view · ${trackedSats} tracked</text></g>`);

    svg.innerHTML = parts.join('');
    const nowMs = date.getTime();
    if (subtitleEl) {
      const pos = hasPos ? `${lat.toFixed(4)}, ${lon.toFixed(4)}${modeSuffix(mode)}` : 'no position';
      const sim = isNow ? '' : `  ·  ⏱ ${timeOffsetMs > 0 ? '+' : '−'}${fmtOffset(Math.abs(timeOffsetMs))}${modeledCount ? '  ·  ' + modeledCount + ' sats modeled' : ''}`;
      subtitleEl.textContent = `${pos}  ·  zoom ${skyZoom.toFixed(1)}x  ·  ${date.toISOString().replace('T', ' ').slice(0, 19)} UTC${sim}`;
    }
    if (noteEl) {
      if (mode === 'live' || mode === 'last') noteEl.style.display = 'none';
      else {
        noteEl.style.display = '';
        noteEl.textContent = mode === 'browser'
          ? 'Sky placed from browser location — GPS will refine when it fixes.'
          : 'Sky placed from a rough timezone estimate — GPS will refine when it fixes.';
      }
    }
    if (detailEl) {
      const avgSnr = trackedSats ? (snrSum / trackedSats).toFixed(1) + ' dB' : 'none';
      const strong = strongestSat ? `${esc(strongestSat.constellation || 'sat')} ${esc(strongestSat.prn != null ? strongestSat.prn : '')} / ${strongestSnr} dB` : 'none';

      // Sky conditions (Sun / twilight / Moon).
      let condCard = '';
      if (hasPos) {
        const sun = sunPosition(date, lat, lon);
        const tw = twilightPhase(sun.alt);
        const ill = moonIllumination(date);
        const darkPct = Math.round(tw.dark * 100);
        const nextSet = nextSunCrossing(nowMs, lat, lon, -0.833, false);
        const nextRise = nextSunCrossing(nowMs, lat, lon, -0.833, true);
        const nextDark = nextSunCrossing(nowMs, lat, lon, -18, false);
        const nextEvent = sun.alt > -0.833
          ? `sunset ${inText(nextSet, nowMs)}`
          : `sunrise ${inText(nextRise, nowMs)}`;
        condCard = `<div class="sv-detail-card"><b>Sky conditions</b>
          <span><i>Sun</i><em class="${tw.key === 'day' ? 'sv-em-warn' : 'sv-em-good'}">${tw.label} (${fmtDeg(sun.alt, 0)})</em></span>
          <span><i>Darkness</i><em>${darkPct}%${tw.key !== 'night' && nextDark ? ' · astro dark ' + inText(nextDark, nowMs) : ''}</em></span>
          <span><i>Next</i><em>${nextEvent}</em></span>
          <span><i>Moon</i><em>${ill.phase} · ${Math.round(ill.illum * 100)}%</em></span></div>`;
      }

      // GNSS geometry + integrity + open-sky survey + SNR/elevation scatter.
      // Uses the same viewSky as the panorama and radar so every count agrees.
      const dop = computeDOP(inViewSats);
      const dv = dopVerdict(dop.ok ? dop.pdop : null);
      const integ = integrityCheck(inViewSats, integrityJumpM);
      const st = surveyStats();
      const integTone = integ.level === 'suspect' ? 'sv-em-warn' : (integ.level === 'caution' ? 'sv-em-warn' : 'sv-em-good');
      const gnssCard = `<div class="sv-detail-card"><b>GNSS quality${isNow ? '' : ' · modeled'}</b>
        <span><i>In view / tracked</i><em>${inViewSats.length} / ${trackedSats}</em></span>
        <span><i>Geometry (PDOP)</i><em class="sv-em-${dv.tone || 'plain'}">${dop.ok ? dop.pdop.toFixed(1) + ' · ' + dv.label + ' · ' + dop.n + ' sats' : dv.label}</em></span>
        <span><i>HDOP / VDOP</i><em>${dop.ok ? dop.hdop.toFixed(1) + ' / ' + dop.vdop.toFixed(1) : '—'}</em></span>
        <span><i>Avg SNR</i><em>${avgSnr}</em></span>
        <span><i>Open-sky survey</i><em>${st.score != null ? st.score + '% (' + st.seenCells + ' cells)' : 'building…'}</em></span>
        <span><i>Integrity</i><em class="${integTone}">${integ.level.toUpperCase()}</em></span>
        <div class="sv-scatter">${snrElevScatter(inViewSats)}</div>
        <div class="sv-integ-note">${isNow ? esc(integ.reasons[0]) : 'Modeled orbits (approx) — only satellites visible now are propagated; risen sats not shown.'}</div></div>`;

      // What's up now — brightest objects above the horizon.
      const seenNames = new Set();
      const up = whatsUp
        .filter(o => { if (seenNames.has(o.name)) return false; seenNames.add(o.name); return o.alt > 8; })
        .sort((a, b) => (a.mag ?? 9) - (b.mag ?? 9))
        .slice(0, 7);
      const upRows = up.map(o => `<span><i>${WU_ICON[o.kind] || '·'} ${esc(o.name)}</i><em>${fmtDeg(o.alt, 0)} ${cardinalName(o.az)}${o.mag != null ? ' · m' + o.mag.toFixed(1) : ''}</em></span>`).join('') || '<span><i>Nothing above 8°</i><em>—</em></span>';
      const upCard = `<div class="sv-detail-card"><b>What's up now</b>${upRows}</div>`;

      detailEl.style.display = '';
      detailEl.innerHTML = condCard + gnssCard + upCard +
        `<div class="sv-detail-card"><b>Catalog</b><span><i>Visible stars</i><em>${visibleStars}</em></span><span><i>Deep-sky shown</i><em>${showDeepSky ? projected.filter(p => p.kind === 'dso').length : 'off'}</em></span><span><i>Constellations</i><em>${showConstellations && constLines ? 'IAU figures' : 'labels'}</em></span></div>`;
    }
  }

  function fmtOffset(ms) {
    const m = Math.round(ms / 60000);
    if (m < 60) return m + 'm';
    if (m < 1440) return Math.floor(m / 60) + 'h' + (m % 60 ? String(m % 60).padStart(2, '0') : '');
    return Math.floor(m / 1440) + 'd' + (Math.floor(m / 60) % 24 || '') + (Math.floor(m / 60) % 24 ? 'h' : '');
  }
  const WU_ICON = { sun: '☀', moon: '☾', planet: '●', star: '✦', dso: '◇' };
  // Compact SNR-vs-elevation scatter (antenna/multipath sanity check).
  // Pure HTML/CSS dots — no inline-SVG aspect-ratio surprises.
  function snrElevScatter(sats) {
    let dots = '';
    for (const s of sats) {
      if (s.elev == null || !(typeof s.snr === 'number' && s.snr > 0)) continue;
      const left = 14 + (Math.max(0, Math.min(90, s.elev)) / 90) * 82;
      const top = 8 + (1 - Math.max(0, Math.min(55, s.snr)) / 55) * 78;
      dots += `<span class="sv-sc-dot" style="left:${left.toFixed(1)}%;top:${top.toFixed(1)}%;background:${SAT_COLORS[s.constellation] || '#94a3b8'}"></span>`;
    }
    return `<span class="sv-sc-yl sv-sc-yl-t">55</span><span class="sv-sc-yl sv-sc-yl-b">0dB</span>` +
      `<span class="sv-sc-xl sv-sc-xl-l">0°</span><span class="sv-sc-xl sv-sc-xl-r">90° el</span>${dots}`;
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
        ? `${lat.toFixed(4)}, ${lon.toFixed(4)}${modeSuffix(mode)}`
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
      } else if (mode === 'browser') {
        noteEl.style.display = '';
        noteEl.textContent = 'Stars placed from browser location — GPS will refine when it fixes.';
      } else if (mode === 'default') {
        noteEl.style.display = '';
        noteEl.textContent = 'Stars placed from a rough timezone estimate — GPS will refine when it fixes.';
      } else {
        noteEl.style.display = '';
        noteEl.textContent = catalog
          ? 'Stars need a GPS position — no fix yet.'
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
        <div class="sv-info-section">Sky position</div>
        <div class="sv-info-row">Elevation <b>${fmtDeg(s.elev, 0)}</b></div>
        <div class="sv-info-row">Azimuth <b>${fmtDeg(s.az, 0)} ${cardinalName(s.az)}</b></div>
        <div class="sv-info-row">Altitude band <b>${altitudeBand(s.elev)}</b></div>
        <div class="sv-info-section">Receiver signal</div>
        <div class="sv-info-row">Signal <b>${hasSnr ? s.snr + ' dB' : 'untracked'}</b></div>
        <div class="sv-info-row">Quality <b>${signalQuality(s.snr)}</b></div>
        <div class="sv-info-row">Tracking <b>${hasSnr ? 'locked by receiver' : 'visible, no SNR lock'}</b></div>
        <div class="sv-info-section">GNSS identity</div>
        <div class="sv-info-row">System <b>${esc(s.constellation || 'unknown')}</b></div>
        <div class="sv-info-row">PRN/SVID <b>${esc(s.prn != null ? s.prn : '—')}</b></div>`;
    } else if (obj.kind === 'planet') {
      const p = obj.planet;
      html = `<div class="sv-info-title" style="color:${p.color}">● ${esc(p.name)}</div>
        <div class="sv-info-section">Sky position</div>
        <div class="sv-info-row">Elevation <b>${fmtDeg(p.alt, 1)}</b></div>
        <div class="sv-info-row">Azimuth <b>${fmtDeg(p.az, 1)} ${cardinalName(p.az)}</b></div>
        <div class="sv-info-row">Altitude band <b>${altitudeBand(p.alt)}</b></div>
        <div class="sv-info-row">Airmass <b>${airmass(p.alt)}</b></div>
        <div class="sv-info-section">Equatorial coordinates</div>
        <div class="sv-info-row">RA <b>${fmtRa(p.ra)}</b></div>
        <div class="sv-info-row">Dec <b>${fmtDeg(p.dec, 2)}</b></div>
        <div class="sv-info-section">Object profile</div>
        <div class="sv-info-row">Type <b>${p.name === 'Sun' ? 'the Sun (G2V star)' : planetCategory(p.name)}</b></div>
        <div class="sv-info-row">Visual mag <b>${p.mag}</b></div>
        <div class="sv-info-row">Brightness <b>${brightnessVsVega(p.mag)}</b></div>
        ${p.name === 'Moon' && p.phase ? `<div class="sv-info-row">Phase <b>${esc(p.phase)}</b></div>
        <div class="sv-info-row">Illumination <b>${Math.round(p.illum * 100)}%</b></div>
        <div class="sv-info-row">Moon age <b>${p.ageDays.toFixed(1)} days</b></div>` : ''}
        ${p.distanceAu != null ? `<div class="sv-info-row">Distance <b>${p.distanceAu.toFixed(2)} AU approx</b></div>` : ''}
        ${p.period ? `<div class="sv-info-row">Orbital period <b>${Math.round(p.period)} days</b></div>` : ''}
        ${p.r ? `<div class="sv-info-row">Mean solar dist. <b>${p.r.toFixed(2)} AU</b></div>` : ''}
        <div class="sv-info-row">Model <b>${p.name === 'Moon' ? 'lunar approximation' : (p.name === 'Sun' ? 'low-precision solar' : 'low-precision live')}</b></div>`;
    } else if (obj.kind === 'iss') {
      const i = obj.iss || {};
      html = `<div class="sv-info-title" style="color:#a7f3d0">🛰️ International Space Station</div>
        <div class="sv-info-section">Sky position</div>
        <div class="sv-info-row">Elevation <b>${fmtDeg(i.el, 1)}</b></div>
        <div class="sv-info-row">Azimuth <b>${fmtDeg(i.az, 1)} ${cardinalName(i.az)}</b></div>
        <div class="sv-info-row">Range <b>${i.range_km != null ? i.range_km.toFixed(0) + ' km' : '—'}</b></div>
        <div class="sv-info-section">Orbit</div>
        <div class="sv-info-row">Altitude <b>${i.alt_km != null ? i.alt_km.toFixed(0) + ' km' : '—'}</b></div>
        <div class="sv-info-row">Speed <b>${i.velocity != null ? i.velocity.toFixed(0) + ' km/h' : '—'}</b></div>
        <div class="sv-info-row">Sub-point <b>${i.lat != null ? i.lat.toFixed(3) + ', ' + i.lon.toFixed(3) : '—'}</b></div>
        <div class="sv-info-section">Source</div>
        <div class="sv-info-row">Data <b>api.wheretheiss.at (live)</b></div>
        <div class="sv-info-row">Crew capacity <b>7 astronauts</b></div>`;
    } else if (obj.kind === 'dso') {
      html = `<div class="sv-info-title" style="color:#c4b5fd">◇ ${esc(obj.name || obj.id)}</div>
        <div class="sv-info-section">Deep-sky identity</div>
        <div class="sv-info-row">Catalog <b>${esc(obj.id)}</b></div>
        ${obj.name && obj.name !== obj.id ? `<div class="sv-info-row">Name <b>${esc(obj.name)}</b></div>` : ''}
        <div class="sv-info-row">Type <b>${esc(obj.dtype || 'deep-sky object')}</b></div>
        <div class="sv-info-row">Magnitude <b>${obj.mag != null ? obj.mag : '—'}</b></div>
        <div class="sv-info-row">Class <b>${obj.mag != null ? magnitudeClass(obj.mag) : 'telescopic'}</b></div>
        <div class="sv-info-section">Equatorial coordinates</div>
        <div class="sv-info-row">RA <b>${fmtRa(obj.ra)}</b></div>
        <div class="sv-info-row">Dec <b>${fmtDeg(obj.dec, 2)}</b></div>
        <div class="sv-info-section">Local sky</div>
        <div class="sv-info-row">Elevation <b>${fmtDeg(obj.alt, 1)}</b></div>
        <div class="sv-info-row">Azimuth <b>${fmtDeg(obj.az, 1)} ${cardinalName(obj.az)}</b></div>
        <div class="sv-info-row">Altitude band <b>${altitudeBand(obj.alt)}</b></div>
        <div class="sv-info-row">Airmass <b>${airmass(obj.alt)}</b></div>`;
    } else {
      const nm = obj.name || 'Unnamed star';
      const consFull = obj.cons ? (CONSTELLATIONS[obj.cons] || obj.cons) : null;
      html = `<div class="sv-info-title">✦ ${esc(nm)}</div>
        <div class="sv-info-section">Catalog identity</div>
        ${consFull ? `<div class="sv-info-row">Constellation <b>${esc(consFull)}</b></div>` : ''}
        <div class="sv-info-row">Designation <b>${esc(nm)}</b></div>
        <div class="sv-info-row">Magnitude <b>${obj.mag.toFixed(2)}</b></div>
        <div class="sv-info-row">Class <b>${magnitudeClass(obj.mag)}</b></div>
        <div class="sv-info-row">Brightness <b>${brightnessVsVega(obj.mag)}</b></div>
        <div class="sv-info-section">Equatorial coordinates</div>
        <div class="sv-info-row">RA <b>${fmtRa(obj.ra)}</b></div>
        <div class="sv-info-row">Dec <b>${fmtDeg(obj.dec, 2)}</b></div>
        <div class="sv-info-section">Local sky</div>
        <div class="sv-info-row">Elevation <b>${fmtDeg(obj.alt, 1)}</b></div>
        <div class="sv-info-row">Azimuth <b>${fmtDeg(obj.az, 1)} ${cardinalName(obj.az)}</b></div>
        <div class="sv-info-row">Altitude band <b>${altitudeBand(obj.alt)}</b></div>
        <div class="sv-info-row">Airmass <b>${airmass(obj.alt)}</b></div>
        <div class="sv-info-section">Appearance</div>
        <div class="sv-info-row">Tone <b><span style="color:${esc(obj.color || '#f8f7ff')}">${esc(starTone(obj.color))}</span></b></div>
        <div class="sv-info-row">Marker <b>${obj.mag < 0.9 ? 'diffraction spike' : 'point source'}</b></div>`;
    }
    infoCard.innerHTML = html +
      '<div class="sv-info-close">tap anywhere to dismiss</div>';
    infoCard.style.display = 'block';
    // Keep the card on-screen near the tap.
    const ow = overlay.getBoundingClientRect();
    let left = clientX + 14, top = clientY + 14;
    const cw = 310, ch = infoCard.offsetHeight || 240;
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
    refreshISS();
    // The lightweight, uncached GPS endpoint (status + sky) — polled at 1 Hz so
    // the view is actually live, unlike the heavy 5 s-cached /diagnostics one.
    // Its body IS the status object (has_fix/lat/lon/last_known at top level),
    // with a `sky` array alongside.
    fetch('/api/wardriving/gps', { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d || !overlay) return;
        const p = positionFromStatus(d);
        // Position-jump magnitude for the integrity check (live fixes only).
        if (p.mode === 'live' && p.lat != null && p.lon != null) {
          const cur = { lat: p.lat, lon: p.lon };
          integrityJumpM = prevFix ? haversineM(prevFix, cur) : 0;
          prevFix = cur;
        } else {
          integrityJumpM = 0;
        }
        lastData = { sky: d.sky || [], lat: p.lat, lon: p.lon, mode: p.mode, t: p.t };
        // Feed the obstruction/multipath survey once per live poll (not per redraw).
        if (enhanced) {
          surveyAccumulate(lastData.sky);
          // Learn each satellite's orbital plane from the live stream so the time
          // scrubber can propagate it (approximate circular-orbit model).
          trackSatsLive(lastData.sky, p.lat, p.lon);
        }
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
    } else {
      const p = positionFromStatus(null);
      lastData = { sky: [], lat: p.lat, lon: p.lon, mode: p.mode, t: p.t };
    }
    requestBrowserGeo();

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
        #ragnar-skyview .sv-info{position:absolute;display:none;min-width:230px;max-width:310px;
          background:rgba(10,17,32,.96);border:1px solid #2a3a55;border-radius:10px;padding:10px 12px;
          box-shadow:0 8px 30px rgba(0,0,0,.55);pointer-events:none;z-index:5;}
        #ragnar-skyview .sv-info-title{font-size:13px;font-weight:600;margin-bottom:6px;color:#e2e8f0;}
        #ragnar-skyview .sv-info-section{margin:9px 0 4px;padding-top:6px;border-top:1px solid rgba(148,163,184,.16);
          color:#7dd3fc;font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:700;}
        #ragnar-skyview .sv-info-section:first-of-type{border-top:0;padding-top:0;}
        #ragnar-skyview .sv-info-row{display:flex;justify-content:space-between;gap:14px;font-size:12px;
          color:#9fb0c3;padding:1px 0;}
        #ragnar-skyview .sv-info-row b{color:#e2e8f0;font-weight:600;text-align:right;overflow-wrap:anywhere;}
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
        #ragnar-skyview .sv-detail-card{background:linear-gradient(180deg,rgba(9,21,39,.97),rgba(3,8,18,.96));
          border:1px solid rgba(125,211,252,.18);border-radius:10px;padding:10px 12px;opacity:1;
          box-shadow:0 14px 36px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.03);backdrop-filter:blur(14px);}
        #ragnar-skyview .sv-detail-card b{display:block;color:#dbeafe;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;opacity:.9;}
        #ragnar-skyview .sv-detail-card span{display:flex;align-items:baseline;justify-content:space-between;gap:14px;color:#9fb0c3;font-size:11px;line-height:1.55;}
        #ragnar-skyview .sv-detail-card i{font-style:normal;color:#7f93ad;}
        #ragnar-skyview .sv-detail-card em{font-style:normal;color:#e2e8f0;text-align:right;max-width:58%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
        #ragnar-skyview .sv-detail-card em.sv-em-good{color:#86efac;}
        #ragnar-skyview .sv-detail-card em.sv-em-warn{color:#fca5a5;}
        #ragnar-skyview .sv-scatter{position:relative;margin-top:10px;height:60px;border-radius:6px;
          background:rgba(1,4,10,.7);border:1px solid rgba(125,211,252,.16);}
        #ragnar-skyview .sv-sc-dot{position:absolute;width:5px;height:5px;border-radius:50%;transform:translate(-50%,-50%);opacity:.92;}
        #ragnar-skyview .sv-sc-yl,#ragnar-skyview .sv-sc-xl{position:absolute;color:#6688a8;font-size:8px;pointer-events:none;}
        #ragnar-skyview .sv-sc-yl-t{left:3px;top:2px;}
        #ragnar-skyview .sv-sc-yl-b{left:3px;bottom:2px;}
        #ragnar-skyview .sv-sc-xl-l{left:20px;bottom:2px;}
        #ragnar-skyview .sv-sc-xl-r{right:4px;bottom:2px;}
        #ragnar-skyview .sv-integ-note{margin-top:6px;font-size:10px;color:#7f93ad;white-space:normal;line-height:1.4;}
        #ragnar-skyview .sv-snap{cursor:pointer;background:#17233a;color:#e2e8f0;border:none;border-radius:8px;width:34px;height:34px;font-size:15px;line-height:1;flex:0 0 auto;}
        #ragnar-skyview .sv-snap:hover{background:#243350;}
        #ragnar-skyview .sv-vr{cursor:pointer;background:linear-gradient(180deg,#0ea5e9,#0369a1);color:#fff;border:none;border-radius:8px;width:34px;height:34px;font-size:15px;line-height:1;flex:0 0 auto;box-shadow:0 0 0 1px rgba(125,211,252,.35);}
        #ragnar-skyview .sv-vr:hover{filter:brightness(1.15);}
        #ragnar-skyview .sv-controls{display:none;position:absolute;left:50%;top:12px;transform:translateX(-50%);z-index:5;gap:6px;flex-wrap:wrap;justify-content:center;
          background:rgba(3,8,18,.5);border:1px solid rgba(125,211,252,.16);border-radius:12px;padding:6px;backdrop-filter:blur(10px);max-width:calc(100vw - 32px);}
        #ragnar-skyview .sv-chip{cursor:pointer;border:1px solid rgba(148,163,184,.22);background:rgba(15,23,42,.66);color:#9fb0c3;border-radius:8px;
          padding:5px 10px;font-size:11px;font-weight:600;letter-spacing:.02em;white-space:nowrap;}
        #ragnar-skyview .sv-chip:hover{border-color:rgba(125,211,252,.46);color:#dbeafe;}
        #ragnar-skyview .sv-chip.on{background:rgba(14,165,233,.22);border-color:rgba(125,211,252,.6);color:#e6f4ff;}
        #ragnar-skyview .sv-time{display:none;position:absolute;left:50%;bottom:18px;transform:translateX(-50%);z-index:5;align-items:center;gap:10px;
          background:rgba(3,8,18,.56);border:1px solid rgba(125,211,252,.2);border-radius:12px;padding:8px 12px;backdrop-filter:blur(10px);width:min(560px,calc(100vw - 40px));}
        #ragnar-skyview .sv-time input[type=range]{flex:1;accent-color:#38bdf8;height:3px;}
        #ragnar-skyview .sv-time .sv-time-lab{min-width:96px;text-align:center;color:#dbeafe;font-family:ui-monospace,monospace;font-size:11px;}
        #ragnar-skyview .sv-time button{border:1px solid rgba(148,163,184,.24);background:rgba(15,23,42,.72);color:#dbeafe;border-radius:7px;padding:4px 9px;font-size:11px;cursor:pointer;}
        #ragnar-skyview .sv-time button:hover{border-color:rgba(125,211,252,.5);}
        #ragnar-skyview.sv-enhanced .sv-controls{display:flex;}
        #ragnar-skyview.sv-enhanced .sv-time{display:flex;}
        #ragnar-skyview.sv-enhanced .sv-snap{display:block;}
        #ragnar-skyview .sv-snap{display:none;}
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
        <button class="sv-snap" type="button" title="Save PNG snapshot">📷</button>
        <button class="sv-vr" type="button" title="Side-by-side 3D (Quest 3 / SBS)">🥽</button>
        <button class="sv-close" title="Close (Esc)">✕</button>
      </div>
      <div class="sv-stage">
        <div class="sv-controls">
          <button class="sv-chip on" data-layer="constellations" type="button">✦ Constellations</button>
          <button class="sv-chip" data-layer="deepsky" type="button">◇ Deep sky</button>
          <button class="sv-chip" data-layer="obstruction" type="button">▦ Sky survey</button>
          <button class="sv-chip" data-survey="reset" type="button" title="Clear the accumulated obstruction survey">⟲ Reset survey</button>
        </div>
        <div class="sv-brand"><b>Ragnar observatory</b><span>live GNSS sky telemetry</span></div>
        <div class="sv-cursor">az --  alt --</div>
        <svg preserveAspectRatio="xMidYMid meet"></svg>
        <div class="sv-note"></div>
        <div class="sv-time">
          <button class="sv-time-now" type="button" title="Back to live">● Live</button>
          <input class="sv-time-range" type="range" min="-720" max="720" step="5" value="0" aria-label="Time offset (minutes)">
          <span class="sv-time-lab">now</span>
        </div>
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
    // Layer toggle chips + survey reset.
    overlay.querySelectorAll('.sv-chip[data-layer]').forEach(chip => {
      chip.addEventListener('click', () => {
        const layer = chip.dataset.layer;
        if (layer === 'constellations') showConstellations = !showConstellations;
        else if (layer === 'deepsky') { showDeepSky = !showDeepSky; if (showDeepSky) loadDeepSky().then(render); }
        else if (layer === 'obstruction') showObstruction = !showObstruction;
        chip.classList.toggle('on');
        render();
      });
    });
    const surveyResetBtn = overlay.querySelector('.sv-chip[data-survey="reset"]');
    if (surveyResetBtn) surveyResetBtn.addEventListener('click', () => { surveyReset(); render(); });
    // Time scrubber.
    const timeRange = overlay.querySelector('.sv-time-range');
    const timeLab = overlay.querySelector('.sv-time-lab');
    const timeNow = overlay.querySelector('.sv-time-now');
    function applyTime() {
      const mins = parseInt(timeRange.value, 10) || 0;
      timeOffsetMs = mins * 60000;
      if (timeLab) timeLab.textContent = mins === 0 ? 'now' : (mins > 0 ? '+' : '−') + fmtOffset(Math.abs(timeOffsetMs));
      render();
    }
    if (timeRange) timeRange.addEventListener('input', applyTime);
    if (timeNow) timeNow.addEventListener('click', () => { timeRange.value = 0; applyTime(); });
    const snapBtn = overlay.querySelector('.sv-snap');
    if (snapBtn) snapBtn.addEventListener('click', saveSnapshot);
    const vrBtn = overlay.querySelector('.sv-vr');
    if (vrBtn) {
      vrBtn.addEventListener('click', () => {
        if (window.RagnarSkyViewVR && typeof window.RagnarSkyViewVR.enter === 'function') {
          window.RagnarSkyViewVR.enter({
            lat: lastData.lat, lon: lastData.lon,
            sky: lastData.sky, mode: lastData.mode,
            date: viewDate()
          });
        }
      });
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
    if (enhanced) {
      loadConstLines().then(() => { if (overlay) render(); });
      surveyInit();
    }
    syncViewBox();
    refresh();
    timer = setInterval(refresh, REFRESH_MS);
  }

  // Rasterise the current SVG sky to a PNG the operator can save.
  function saveSnapshot() {
    if (!svg) return;
    const r = svg.getBoundingClientRect();
    const w = Math.max(2, Math.round(r.width)), h = Math.max(2, Math.round(r.height));
    const clone = svg.cloneNode(true);
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    clone.setAttribute('width', w); clone.setAttribute('height', h);
    const xml = new XMLSerializer().serializeToString(clone);
    const url = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(xml);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#02050d'; ctx.fillRect(0, 0, w, h);
      ctx.drawImage(img, 0, 0);
      try {
        const a = document.createElement('a');
        a.href = canvas.toDataURL('image/png');
        a.download = 'ragnar-starview-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.png';
        document.body.appendChild(a); a.click(); a.remove();
      } catch (_) {}
    };
    img.onerror = () => {};
    img.src = url;
  }

  function close() {
    if (!overlay) return;
    if (surveyDirty) surveyPersist();
    clearInterval(timer); timer = null;
    document.removeEventListener('keydown', onEsc); onEsc = null;
    window.removeEventListener('resize', resizeH); resizeH = null;
    overlay.remove(); overlay = null;
    svg = infoCard = subtitleEl = noteEl = detailEl = cursorEl = null;
    enhanced = false;
    skyZoom = 1;
    skyPanX = skyPanY = 0;
    suppressNextClick = false;
    timeOffsetMs = 0;
    showConstellations = true; showDeepSky = false; showObstruction = false;
    prevFix = null; integrityJumpM = 0;
    satTrack = new Map();
    document.body.style.overflow = '';
  }

  window.RagnarSkyView = { open, close };
})();
