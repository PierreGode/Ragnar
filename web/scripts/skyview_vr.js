/*
 * RagnarSkyViewVR — real WebXR immersive-vr Starview for Meta Quest 3.
 * Loaded lazily by the 🥽 button in skyview.js. Uses three.js from CDN.
 *
 * Coordinate frame in three.js: +X east, +Y up (zenith), -Z north (forward).
 */
(function () {
  'use strict';

  const THREE_URL = '/web/vendor/three/three.module.js';
  const CATALOG_URL = '/web/vendor/star_catalog.json';
  const CONST_URL = '/web/vendor/constellation_lines.json';
  let THREE = null;
  const D2R = Math.PI / 180, R2D = 180 / Math.PI;
  const R_STARS = 400;
  const R_PLANETS = 260;
  const R_SATS = 180;
  const R_COMPASS = 150;

  const SAT_COLORS = {
    GPS: 0x34d399, GLONASS: 0xf87171, Galileo: 0x60a5fa,
    BeiDou: 0xfbbf24, QZSS: 0xa78bfa, NavIC: 0xf472b6, combined: 0x94a3b8
  };
  const PLANETS = [
    { name: 'Mercury', period: 87.969, l0: 252.25, r: 0.387, color: 0xf8d8a8, size: 3.4 },
    { name: 'Venus',   period: 224.701, l0: 181.98, r: 0.723, color: 0xfff3b0, size: 5.6 },
    { name: 'Mars',    period: 686.98,  l0: 355.43, r: 1.524, color: 0xfb8b66, size: 4.4 },
    { name: 'Jupiter', period: 4332.59, l0: 34.35,  r: 5.203, color: 0xffd7a3, size: 6.4 },
    { name: 'Saturn',  period: 10759.22,l0: 50.08,  r: 9.537, color: 0xf5d58a, size: 5.6 },
    { name: 'Uranus',  period: 30688.5, l0: 314.05, r: 19.19, color: 0x9ee8ff, size: 3.6 },
    { name: 'Neptune', period: 60182,   l0: 304.35, r: 30.07, color: 0x7aa7ff, size: 3.4 }
  ];

  let threeLoading = null;
  let catalogCache = null, constLinesCache = null;
  let session = null, renderer = null, scene = null, camera = null;
  let baseGroup = null;   // holds sky content, follows camera position
  let pointables = [];
  let controllers = [];
  let rayLines = [];
  let raycaster = null;
  let infoPanel = null;
  let hoveredObject = null;
  let statusOverlay = null;
  let currentSnapshot = null;
  let skyDomeMesh = null;
  let passthrough = true;
  try { passthrough = localStorage.getItem('ragnar.skyview.xr.passthrough') !== '0'; } catch (_) {}

  // ---- Astronomy (duplicated so this module is independent) ----------
  function julianDay(date) { return date.getTime() / 86400000 + 2440587.5; }
  function gmstDeg(date) {
    const d = julianDay(date) - 2451545.0;
    return (((280.46061837 + 360.98564736629 * d) % 360) + 360) % 360;
  }
  function normDeg(v) { return ((v % 360) + 360) % 360; }
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
  function eclipticToRaDec(x, y, z) {
    const eps = 23.439291 * D2R;
    const xe = x, ye = y * Math.cos(eps) - z * Math.sin(eps), ze = y * Math.sin(eps) + z * Math.cos(eps);
    const ra = normDeg(Math.atan2(ye, xe) * R2D);
    const dec = Math.atan2(ze, Math.sqrt(xe * xe + ye * ye)) * R2D;
    return { ra, dec };
  }
  function planetSkyPositions(date, lat, lon) {
    const d = julianDay(date) - 2451545.0;
    const earthL = normDeg(100.46 + 360 * d / 365.256) * D2R;
    const ex = Math.cos(earthL), ey = Math.sin(earthL);
    return PLANETS.map(p => {
      const L = normDeg(p.l0 + 360 * d / p.period) * D2R;
      const px = p.r * Math.cos(L), py = p.r * Math.sin(L);
      const dx = px - ex, dy = py - ey;
      const eq = eclipticToRaDec(dx, dy, 0);
      const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
      return { name: p.name, color: p.color, size: p.size, alt: sky.alt, az: sky.az, ra: eq.ra, dec: eq.dec };
    });
  }
  function sunEclipticLon(date) {
    const d = julianDay(date) - 2451545.0;
    const g = normDeg(357.528 + 0.9856003 * d) * D2R;
    return normDeg(280.460 + 0.9856474 * d + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g));
  }
  function sunSky(date, lat, lon) {
    const lam = sunEclipticLon(date) * D2R;
    const eq = eclipticToRaDec(Math.cos(lam), Math.sin(lam), 0);
    return raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
  }
  function moonSky(date, lat, lon) {
    const d = julianDay(date) - 2451545.0;
    const L = normDeg(218.316 + 13.176396 * d);
    const M = normDeg(134.963 + 13.064993 * d);
    const F = normDeg(93.272 + 13.229350 * d);
    const lonM = L + 6.289 * Math.sin(M * D2R);
    const latM = 5.128 * Math.sin(F * D2R);
    const lr = lonM * D2R, br = latM * D2R;
    const eq = eclipticToRaDec(Math.cos(br) * Math.cos(lr), Math.cos(br) * Math.sin(lr), Math.sin(br));
    const sky = raDecToAltAz(eq.ra, eq.dec, lat, lon, date);
    const elong = normDeg(lonM - sunEclipticLon(date));
    return { alt: sky.alt, az: sky.az, illum: (1 - Math.cos(elong * D2R)) / 2, elong };
  }

  // Convert az (from N, CW) + alt (deg) to a three.js unit direction.
  function altAzToVec(az, alt, R) {
    const a = alt * D2R, z = az * D2R;
    const cA = Math.cos(a);
    return new THREE.Vector3(R * cA * Math.sin(z), R * Math.sin(a), -R * cA * Math.cos(z));
  }

  // ---- Loader helpers ------------------------------------------------
  function loadThree() {
    if (THREE) return Promise.resolve();
    if (threeLoading) return threeLoading;
    threeLoading = import(THREE_URL).then(mod => { THREE = mod; })
      .catch(err => { threeLoading = null; throw err; });
    return threeLoading;
  }
  function loadJSON(url, cacheRef) {
    if (cacheRef && cacheRef.value) return Promise.resolve(cacheRef.value);
    return fetch(url).then(r => r.ok ? r.json() : null).then(j => {
      if (cacheRef) cacheRef.value = j;
      return j;
    }).catch(() => null);
  }
  const catalogRef = { get value() { return catalogCache; }, set value(v) { catalogCache = v; } };
  const constLinesRef = { get value() { return constLinesCache; }, set value(v) { constLinesCache = v; } };

  // ---- Scene builders ------------------------------------------------
  function buildStars(catalog, lat, lon, date) {
    const positions = [], colors = [], sizes = [];
    const meta = [];
    const colTable = catalog.colors || [];
    for (const st of catalog.stars) {
      const [ra, dec, mag, cidx, name, cons] = st;
      const p = raDecToAltAz(ra, dec, lat, lon, date);
      if (p.alt < -12) continue;
      const v = altAzToVec(p.az, p.alt, R_STARS);
      positions.push(v.x, v.y, v.z);
      const hex = colTable[cidx] || '#ffffff';
      const c = new THREE.Color(hex);
      colors.push(c.r, c.g, c.b);
      const size = Math.max(3.5, 22 - (mag + 1.5) * 3.4);
      sizes.push(size);
      meta.push({ kind: 'star', ra, dec, mag, name, cons, alt: p.alt, az: p.az, color: hex });
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geom.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    geom.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
    const mat = new THREE.ShaderMaterial({
      uniforms: {},
      vertexShader:
        'attribute float size;\nvarying vec3 vCol;\nvoid main(){ vCol = color; vec4 mv = modelViewMatrix * vec4(position, 1.0); gl_PointSize = size; gl_Position = projectionMatrix * mv; }',
      fragmentShader:
        'varying vec3 vCol;\nvoid main(){ vec2 uv = gl_PointCoord - 0.5; float d = length(uv); if (d > 0.5) discard; float a = smoothstep(0.5, 0.05, d); gl_FragColor = vec4(vCol, a); }',
      vertexColors: true, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending
    });
    const points = new THREE.Points(geom, mat);
    points.userData.stars = meta;
    return points;
  }

  function buildConstellationLines(constLines, lat, lon, date) {
    const positions = [];
    for (const cid in constLines.lines) {
      for (const seg of constLines.lines[cid]) {
        let prevAbove = null;
        for (let i = 0; i < seg.length; i++) {
          const [ra, dec] = seg[i];
          const p = raDecToAltAz(ra, dec, lat, lon, date);
          if (p.alt <= 0) { prevAbove = null; continue; }
          const v = altAzToVec(p.az, p.alt, R_STARS - 5);
          if (prevAbove) {
            positions.push(prevAbove.x, prevAbove.y, prevAbove.z, v.x, v.y, v.z);
          }
          prevAbove = v;
        }
      }
    }
    if (!positions.length) return null;
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    const mat = new THREE.LineBasicMaterial({ color: 0x7dd3fc, transparent: true, opacity: 0.35 });
    return new THREE.LineSegments(geom, mat);
  }

  function makeLabelSprite(text, color) {
    const canvas = document.createElement('canvas');
    canvas.width = 512; canvas.height = 128;
    const ctx = canvas.getContext('2d');
    ctx.font = 'bold 60px system-ui, sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillStyle = color || '#e2e8f0';
    ctx.shadowColor = 'rgba(2, 6, 15, 0.9)';
    ctx.shadowBlur = 14;
    ctx.fillText(text, 256, 64);
    const tex = new THREE.CanvasTexture(canvas);
    tex.needsUpdate = true;
    const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, depthTest: false });
    const sprite = new THREE.Sprite(mat);
    sprite.scale.set(30, 7.5, 1);
    return sprite;
  }

  function buildPlanets(lat, lon, date) {
    const group = new THREE.Group();
    // Sun.
    const sun = sunSky(date, lat, lon);
    if (sun.alt > -3) {
      const sMat = new THREE.MeshBasicMaterial({ color: 0xffdf7e });
      const sMesh = new THREE.Mesh(new THREE.SphereGeometry(10, 24, 16), sMat);
      const pos = altAzToVec(sun.az, Math.max(0, sun.alt), R_PLANETS);
      sMesh.position.copy(pos);
      sMesh.userData = { kind: 'sun', name: 'Sun', alt: sun.alt, az: sun.az };
      pointables.push(sMesh);
      group.add(sMesh);
      const label = makeLabelSprite('Sun', '#ffdf7e');
      label.position.copy(pos).multiplyScalar(1.08);
      group.add(label);
    }
    // Moon.
    const moon = moonSky(date, lat, lon);
    if (moon.alt > -3) {
      const mMat = new THREE.MeshBasicMaterial({ color: 0xd0d5de });
      const mMesh = new THREE.Mesh(new THREE.SphereGeometry(8, 24, 16), mMat);
      const pos = altAzToVec(moon.az, Math.max(0, moon.alt), R_PLANETS);
      mMesh.position.copy(pos);
      mMesh.userData = { kind: 'moon', name: 'Moon', alt: moon.alt, az: moon.az, illum: moon.illum };
      pointables.push(mMesh);
      group.add(mMesh);
      const label = makeLabelSprite('Moon', '#e2e8f0');
      label.position.copy(pos).multiplyScalar(1.1);
      group.add(label);
    }
    // Planets.
    const planets = planetSkyPositions(date, lat, lon);
    for (const p of planets) {
      if (p.alt < -3) continue;
      const mat = new THREE.MeshBasicMaterial({ color: p.color });
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(p.size * 0.7, 20, 14), mat);
      const pos = altAzToVec(p.az, Math.max(0, p.alt), R_PLANETS);
      mesh.position.copy(pos);
      mesh.userData = { kind: 'planet', name: p.name, alt: p.alt, az: p.az, ra: p.ra, dec: p.dec };
      pointables.push(mesh);
      group.add(mesh);
      const label = makeLabelSprite(p.name, '#f5d58a');
      label.position.copy(pos).multiplyScalar(1.12);
      group.add(label);
    }
    return group;
  }

  function buildSatellites(sky) {
    const group = new THREE.Group();
    if (!sky || !sky.length) return group;
    for (const s of sky) {
      if (s.az == null || s.elev == null || s.elev < 0) continue;
      const color = SAT_COLORS[s.constellation] || 0x94a3b8;
      const geom = new THREE.SphereGeometry(2.6, 16, 10);
      const mat = new THREE.MeshBasicMaterial({ color });
      const mesh = new THREE.Mesh(geom, mat);
      mesh.position.copy(altAzToVec(s.az, s.elev, R_SATS));
      mesh.userData = { kind: 'sat', sat: s, alt: s.elev, az: s.az };
      pointables.push(mesh);
      group.add(mesh);
      // Faint ring for tracked (SNR > 0) sats.
      if (typeof s.snr === 'number' && s.snr > 0) {
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(3.2, 4.6, 24),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.45, side: THREE.DoubleSide })
        );
        ring.position.copy(mesh.position);
        ring.lookAt(new THREE.Vector3(0, 0, 0));
        group.add(ring);
      }
    }
    return group;
  }

  function buildCompass() {
    const group = new THREE.Group();
    const dirs = [
      { label: 'N', az: 0, color: '#fca5a5' },
      { label: 'E', az: 90, color: '#dbeafe' },
      { label: 'S', az: 180, color: '#dbeafe' },
      { label: 'W', az: 270, color: '#dbeafe' }
    ];
    for (const d of dirs) {
      const sp = makeLabelSprite(d.label, d.color);
      sp.scale.set(38, 9.5, 1);
      sp.position.copy(altAzToVec(d.az, 3, R_COMPASS));
      group.add(sp);
    }
    // Horizon ring.
    const ringGeom = new THREE.RingGeometry(R_COMPASS - 1, R_COMPASS + 1, 128);
    ringGeom.rotateX(-Math.PI / 2);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.18, side: THREE.DoubleSide });
    group.add(new THREE.Mesh(ringGeom, ringMat));
    // Ground disc, subtle.
    const ground = new THREE.Mesh(
      new THREE.CircleGeometry(R_COMPASS - 5, 96),
      new THREE.MeshBasicMaterial({ color: 0x081226, transparent: true, opacity: 0.35, side: THREE.DoubleSide })
    );
    ground.rotation.x = -Math.PI / 2;
    ground.position.y = -1.2;
    group.add(ground);
    return group;
  }

  function buildCompassAR() {
    const group = new THREE.Group();
    const dirs = [
      { label: 'N', az: 0, color: '#fca5a5' },
      { label: 'E', az: 90, color: '#dbeafe' },
      { label: 'S', az: 180, color: '#dbeafe' },
      { label: 'W', az: 270, color: '#dbeafe' }
    ];
    for (const d of dirs) {
      const sp = makeLabelSprite(d.label, d.color);
      sp.scale.set(30, 7.5, 1);
      sp.position.copy(altAzToVec(d.az, 2, R_COMPASS));
      group.add(sp);
    }
    return group;
  }

  function buildSkyDome() {
    const geom = new THREE.SphereGeometry(R_STARS * 1.4, 32, 16);
    const mat = new THREE.ShaderMaterial({
      side: THREE.BackSide,
      vertexShader: 'varying vec3 vN; void main(){ vN = normalize(position); gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }',
      fragmentShader: 'varying vec3 vN; void main(){ float t = clamp(vN.y * 0.5 + 0.5, 0.0, 1.0); vec3 low = vec3(0.005, 0.010, 0.024); vec3 hi = vec3(0.020, 0.055, 0.110); gl_FragColor = vec4(mix(low, hi, t), 1.0); }'
    });
    return new THREE.Mesh(geom, mat);
  }

  // ---- Info panel (canvas texture on a billboard) --------------------
  function buildInfoPanel() {
    const canvas = document.createElement('canvas');
    canvas.width = 1024; canvas.height = 512;
    const tex = new THREE.CanvasTexture(canvas);
    const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, side: THREE.DoubleSide, depthTest: false });
    const mesh = new THREE.Mesh(new THREE.PlaneGeometry(48, 24), mat);
    mesh.userData._canvas = canvas;
    mesh.userData._texture = tex;
    mesh.renderOrder = 999;
    mesh.visible = false;
    return mesh;
  }

  function drawInfoPanel(mesh, title, lines, accent) {
    const canvas = mesh.userData._canvas;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // Backdrop.
    ctx.fillStyle = 'rgba(3, 10, 22, 0.94)';
    ctx.strokeStyle = accent || '#38bdf8';
    ctx.lineWidth = 4;
    const r = 24;
    ctx.beginPath();
    ctx.moveTo(r, 0); ctx.lineTo(canvas.width - r, 0);
    ctx.quadraticCurveTo(canvas.width, 0, canvas.width, r);
    ctx.lineTo(canvas.width, canvas.height - r);
    ctx.quadraticCurveTo(canvas.width, canvas.height, canvas.width - r, canvas.height);
    ctx.lineTo(r, canvas.height);
    ctx.quadraticCurveTo(0, canvas.height, 0, canvas.height - r);
    ctx.lineTo(0, r);
    ctx.quadraticCurveTo(0, 0, r, 0);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
    // Title.
    ctx.fillStyle = accent || '#7dd3fc';
    ctx.font = 'bold 56px system-ui, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(title, 40, 34);
    // Lines.
    ctx.font = '38px system-ui, sans-serif';
    ctx.fillStyle = '#e2e8f0';
    let y = 130;
    for (const line of lines) {
      ctx.fillText(line, 40, y);
      y += 54;
    }
    mesh.userData._texture.needsUpdate = true;
  }

  function fmtDeg(v, dp) {
    return (v == null || !isFinite(v)) ? '—' : v.toFixed(dp == null ? 1 : dp) + '°';
  }
  function cardinal(az) {
    const dirs = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
    return dirs[Math.round(normDeg(az) / 22.5) % 16];
  }

  function showInfoFor(obj, ctl) {
    if (!infoPanel) return;
    const d = obj.userData;
    let title = '', lines = [], accent = '#7dd3fc';
    if (d.kind === 'sat') {
      const s = d.sat;
      accent = '#34d399';
      title = '🛰 ' + (s.constellation || 'satellite') + (s.prn != null ? ' · PRN ' + s.prn : '');
      lines = [
        'Elevation ' + fmtDeg(s.elev, 0),
        'Azimuth ' + fmtDeg(s.az, 0) + ' ' + cardinal(s.az),
        'Signal ' + (typeof s.snr === 'number' && s.snr > 0 ? s.snr + ' dB' : 'untracked'),
        'System ' + (s.constellation || 'unknown')
      ];
    } else if (d.kind === 'planet' || d.kind === 'sun' || d.kind === 'moon') {
      accent = d.kind === 'sun' ? '#ffdf7e' : (d.kind === 'moon' ? '#e2e8f0' : '#f5d58a');
      title = '● ' + d.name;
      lines = [
        'Elevation ' + fmtDeg(d.alt, 1),
        'Azimuth ' + fmtDeg(d.az, 1) + ' ' + cardinal(d.az)
      ];
      if (d.kind === 'moon' && d.illum != null) lines.push('Illumination ' + Math.round(d.illum * 100) + '%');
    } else if (d.kind === 'star') {
      accent = d.color || '#e2e8f0';
      title = '✦ ' + (d.name || 'star') + (d.cons ? ' · ' + d.cons : '');
      lines = [
        'Magnitude ' + (d.mag != null ? d.mag.toFixed(2) : '—'),
        'Elevation ' + fmtDeg(d.alt, 1),
        'Azimuth ' + fmtDeg(d.az, 1) + ' ' + cardinal(d.az)
      ];
    } else {
      return;
    }
    drawInfoPanel(infoPanel, title, lines, accent);
    // Place the panel ~4m in front of the controller, facing the head.
    const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion);
    infoPanel.position.copy(ctl.position).addScaledVector(dir, 5);
    infoPanel.lookAt(camera.position);
    infoPanel.visible = true;
    // Haptic pulse if the controller supports it.
    try {
      const src = ctl.userData._inputSource;
      const act = src && src.gamepad && src.gamepad.hapticActuators && src.gamepad.hapticActuators[0];
      if (act && act.pulse) act.pulse(0.55, 60);
    } catch (_) {}
  }

  // ---- Nearest-object pick along a controller ray -------------------
  function pickAlongRay(origin, dir) {
    // Cheap: iterate pointables, project onto ray, keep the closest small
    // angular offset (bigger radius = wider forgiveness).
    let best = null, bestScore = Infinity;
    const tmp = new THREE.Vector3();
    for (const o of pointables) {
      tmp.copy(o.getWorldPosition(new THREE.Vector3())).sub(origin);
      const t = tmp.dot(dir);
      if (t <= 0) continue;
      const projX = t * dir.x, projY = t * dir.y, projZ = t * dir.z;
      const dx = tmp.x - projX, dy = tmp.y - projY, dz = tmp.z - projZ;
      const perp = Math.sqrt(dx * dx + dy * dy + dz * dz);
      // The angular tolerance (rad) — scale by 8 deg for planets/sats, 5 deg for stars.
      const tolDeg = o.userData.kind === 'star' ? 3.5 : 6;
      const tol = t * Math.tan(tolDeg * D2R);
      if (perp > tol) continue;
      const score = perp / (tol || 1);
      if (score < bestScore) { bestScore = score; best = o; }
    }
    return best;
  }

  function onSelectStart(ev) {
    const ctl = ev.target;
    const origin = new THREE.Vector3().setFromMatrixPosition(ctl.matrixWorld);
    const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion).normalize();
    // Also allow picking bright stars from the points cloud.
    const starHit = pickStar(origin, dir);
    const solidHit = pickAlongRay(origin, dir);
    if (starHit && (!solidHit || starHit.dist < 6)) {
      showInfoFor({ userData: starHit.meta }, ctl);
    } else if (solidHit) {
      showInfoFor(solidHit, ctl);
    } else {
      if (infoPanel) infoPanel.visible = false;
    }
  }

  function pickStar(origin, dir) {
    if (!scene) return null;
    let starObj = null;
    scene.traverse(o => { if (o.isPoints && o.userData && o.userData.stars) starObj = o; });
    if (!starObj) return null;
    let bestScore = Infinity, best = null;
    const meta = starObj.userData.stars;
    // Only inspect the brightest ~250 stars — rays land near them most often
    // and we don't want to iterate 3k points per trigger press.
    const sorted = meta.slice().sort((a, b) => a.mag - b.mag).slice(0, 250);
    const tmp = new THREE.Vector3();
    for (const m of sorted) {
      tmp.copy(altAzToVec(m.az, m.alt, R_STARS)).sub(origin);
      const t = tmp.dot(dir);
      if (t <= 0) continue;
      const dx = tmp.x - t * dir.x, dy = tmp.y - t * dir.y, dz = tmp.z - t * dir.z;
      const perp = Math.sqrt(dx * dx + dy * dy + dz * dz);
      const tol = t * Math.tan(2.5 * D2R);
      if (perp > tol) continue;
      const score = perp / (tol || 1);
      if (score < bestScore) { bestScore = score; best = { meta: m, dist: perp }; }
    }
    return best;
  }

  function highlightAlong(ctl) {
    const origin = new THREE.Vector3().setFromMatrixPosition(ctl.matrixWorld);
    const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion).normalize();
    const hit = pickAlongRay(origin, dir);
    if (hit === hoveredObject) return;
    if (hoveredObject && hoveredObject.userData._origColor != null) {
      hoveredObject.material.color.set(hoveredObject.userData._origColor);
    }
    hoveredObject = hit;
    if (hoveredObject && hoveredObject.material && hoveredObject.material.color) {
      if (hoveredObject.userData._origColor == null) {
        hoveredObject.userData._origColor = hoveredObject.material.color.getHex();
      }
      hoveredObject.material.color.set(0xffffff);
    }
  }

  // ---- Session lifecycle --------------------------------------------
  function showXrUnavailableModal(reason) {
    const insecure = !window.isSecureContext;
    const hasXR = !!navigator.xr;
    let body = '';
    if (insecure) {
      body =
        '<p style="margin:0 0 10px;font-size:13px;line-height:1.55;color:#cbd5e1;"><b style="color:#fca5a5;">Insecure origin.</b> Meta Quest Browser blocks WebXR on plain HTTP. Ragnar is served over HTTP on your LAN, so <code style="color:#fecaca;">navigator.xr</code> is disabled here.</p>' +
        '<p style="margin:0 0 6px;font-size:12px;color:#9fb0c3;">Easiest fix — let Ragnar generate a self-signed certificate and switch you over:</p>' +
        '<div style="margin:0 0 14px;">' +
          '<button type="button" class="sv-xr-ssl-btn" style="width:100%;background:linear-gradient(180deg,#10b981,#047857);color:#fff;border:none;border-radius:8px;padding:11px 16px;cursor:pointer;font-weight:600;letter-spacing:.03em;font-size:13px;">🔐 Generate SSL and switch to HTTPS</button>' +
          '<div class="sv-xr-ssl-status" style="margin-top:8px;font-size:11px;color:#9fb0c3;min-height:14px;"></div>' +
        '</div>' +
        '<p style="margin:0 0 6px;font-size:11px;color:#7f93ad;">Or, manually:</p>' +
        '<ol style="margin:0 0 12px 20px;padding:0;font-size:11px;color:#94a3b8;line-height:1.65;">' +
          '<li>On the Quest, open <code style="color:#e0f2fe;">chrome://flags</code> → <b>Insecure origins</b> → add <code style="color:#e0f2fe;">' + location.origin + '</code>.</li>' +
        '</ol>' +
        '<div style="background:#02050d;border:1px solid rgba(125,211,252,.2);color:#94a3b8;padding:8px 10px;border-radius:8px;font-size:10px;font-family:ui-monospace,monospace;">' +
          'isSecureContext: ' + window.isSecureContext + ' · navigator.xr: ' + (hasXR ? 'present' : 'undefined') +
        '</div>';
    } else {
      body =
        '<p style="margin:0 0 12px;font-size:13px;line-height:1.55;color:#cbd5e1;">' + (reason || 'WebXR is not available in this browser.') + '</p>' +
        '<div style="background:#02050d;border:1px solid rgba(125,211,252,.2);color:#e0f2fe;padding:10px 12px;border-radius:8px;font-size:12px;font-family:ui-monospace,monospace;margin-bottom:12px;">' +
          'isSecureContext: ' + window.isSecureContext + '<br>' +
          'navigator.xr: ' + (hasXR ? 'present' : 'undefined') + '<br>' +
          'user-agent: ' + (navigator.userAgent || '').slice(0, 90) +
        '</div>' +
        '<p style="margin:0 0 8px;font-size:12px;color:#9fb0c3;">If you\'re not in a headset, open this URL on your Quest 3:</p>' +
        '<code style="display:block;background:#02050d;border:1px solid rgba(125,211,252,.2);color:#e0f2fe;padding:10px 12px;border-radius:8px;font-size:13px;word-break:break-all;">' + location.href + '</code>';
    }
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;z-index:100010;background:rgba(1,4,10,.82);display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,-apple-system,sans-serif;backdrop-filter:blur(6px);';
    modal.innerHTML =
      '<div style="max-width:520px;width:100%;background:linear-gradient(180deg,#081426,#02050d);color:#e2e8f0;border:1px solid rgba(125,211,252,.35);border-radius:14px;padding:22px 24px;box-shadow:0 22px 60px rgba(0,0,0,.6);">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">' +
          '<div style="font-size:24px;">🥽</div>' +
          '<h3 style="margin:0;color:#7dd3fc;font-size:16px;letter-spacing:.06em;text-transform:uppercase;">' + (insecure ? 'HTTPS required' : 'VR not available') + '</h3>' +
        '</div>' +
        body +
        '<div style="display:flex;justify-content:flex-end;margin-top:16px;">' +
          '<button type="button" style="background:linear-gradient(180deg,#0ea5e9,#0369a1);color:#fff;border:none;border-radius:8px;padding:9px 18px;cursor:pointer;font-weight:600;letter-spacing:.03em;">Got it</button>' +
        '</div>' +
      '</div>';
    const closeBtn = modal.querySelector('button:not(.sv-xr-ssl-btn)');
    if (closeBtn) closeBtn.addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
    const sslBtn = modal.querySelector('.sv-xr-ssl-btn');
    const sslStatus = modal.querySelector('.sv-xr-ssl-status');
    if (sslBtn) {
      sslBtn.addEventListener('click', async () => {
        sslBtn.disabled = true;
        sslBtn.style.opacity = '0.7';
        sslBtn.textContent = 'Generating certificate…';
        if (sslStatus) sslStatus.textContent = '';
        try {
          const r = await fetch('/api/ssl/enable', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
          const d = await r.json().catch(() => ({}));
          if (!r.ok || !d.ok) {
            throw new Error(d.error || ('HTTP ' + r.status));
          }
          if (sslStatus) sslStatus.textContent = 'HTTPS listener on port ' + d.https_port + ' — redirecting…';
          sslBtn.textContent = '✓ Redirecting to HTTPS';
          const target = 'https://' + location.hostname + ':' + d.https_port + location.pathname + location.search + location.hash;
          // Small delay so the user sees the confirmation.
          setTimeout(() => { location.href = target; }, 900);
        } catch (err) {
          console.error('[RagnarSkyViewVR] SSL enable failed', err);
          if (sslStatus) sslStatus.innerHTML = '<span style="color:#fca5a5;">Failed: ' + (err && err.message ? err.message : err) + '</span>';
          sslBtn.disabled = false;
          sslBtn.style.opacity = '1';
          sslBtn.textContent = '🔐 Retry generating SSL';
        }
      });
    }
    console.log('[RagnarSkyViewVR] not available:', {
      isSecureContext: window.isSecureContext,
      hasXR: hasXR,
      reason: reason,
      userAgent: navigator.userAgent
    });
  }

  function ensureStatusOverlay() {
    if (statusOverlay) return statusOverlay;
    statusOverlay = document.createElement('div');
    statusOverlay.style.cssText = 'position:fixed;inset:0;z-index:100005;background:rgba(1,4,10,.88);display:flex;align-items:center;justify-content:center;color:#dbeafe;font-family:system-ui,-apple-system,sans-serif;font-size:14px;letter-spacing:.04em;';
    statusOverlay.innerHTML =
      '<div style="text-align:center;">' +
        '<div style="font-size:28px;margin-bottom:14px;">🥽</div>' +
        '<div class="sv-xr-msg" style="opacity:.85;">Preparing VR scene…</div>' +
        '<div style="margin-top:12px;font-size:11px;color:#7f93ad;">Put on your headset — a VR session prompt will appear.</div>' +
      '</div>';
    document.body.appendChild(statusOverlay);
    return statusOverlay;
  }

  function setStatus(msg) {
    if (!statusOverlay) return;
    const el = statusOverlay.querySelector('.sv-xr-msg');
    if (el) el.textContent = msg;
  }

  function removeStatusOverlay() {
    if (statusOverlay) { statusOverlay.remove(); statusOverlay = null; }
  }

  function exit() {
    if (session) { try { session.end(); } catch (_) {} }
    onSessionEnd();
  }

  function showLaunchPanel(snapshot, onGo) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;z-index:100010;background:rgba(1,4,10,.82);display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,-apple-system,sans-serif;backdrop-filter:blur(6px);';
    const posLine = (snapshot && typeof snapshot.lat === 'number')
      ? snapshot.lat.toFixed(3) + ', ' + snapshot.lon.toFixed(3) + ' · ' + ((snapshot.sky || []).length) + ' sats'
      : 'no GPS fix — using fallback position';
    modal.innerHTML =
      '<div style="max-width:440px;width:100%;background:linear-gradient(180deg,#081426,#02050d);color:#e2e8f0;border:1px solid rgba(125,211,252,.35);border-radius:14px;padding:22px 24px;box-shadow:0 22px 60px rgba(0,0,0,.6);">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">' +
          '<div style="font-size:24px;">🥽</div>' +
          '<h3 style="margin:0;color:#7dd3fc;font-size:16px;letter-spacing:.06em;text-transform:uppercase;">Enter Ragnar Observatory VR</h3>' +
        '</div>' +
        '<p style="margin:6px 0 14px;font-size:12px;color:#9fb0c3;line-height:1.5;">Put on your headset. Trigger a satellite, planet, or bright star to inspect it. Grip / menu to exit.</p>' +
        '<div style="font-size:11px;color:#7f93ad;background:rgba(2,6,15,.6);border:1px solid rgba(125,211,252,.14);border-radius:8px;padding:8px 10px;margin-bottom:14px;font-family:ui-monospace,monospace;">' + posLine + '</div>' +
        '<label class="sv-xr-toggle" style="display:flex;align-items:center;justify-content:space-between;gap:14px;background:rgba(3,10,22,.7);border:1px solid rgba(125,211,252,.2);border-radius:10px;padding:12px 14px;cursor:pointer;user-select:none;">' +
          '<span>' +
            '<div style="color:#e0f2fe;font-size:13px;font-weight:600;">Passthrough (see real sky)</div>' +
            '<div style="color:#7f93ad;font-size:11px;margin-top:2px;">Overlays the observatory on the real world (Quest 3 AR mode).</div>' +
          '</span>' +
          '<span class="sv-xr-switch" style="position:relative;width:46px;height:26px;border-radius:999px;background:' + (passthrough ? 'linear-gradient(180deg,#0ea5e9,#0369a1)' : '#334155') + ';flex:0 0 auto;transition:background .2s;">' +
            '<span class="sv-xr-knob" style="position:absolute;top:3px;left:' + (passthrough ? '23px' : '3px') + ';width:20px;height:20px;border-radius:999px;background:#f8fafc;transition:left .2s;box-shadow:0 2px 6px rgba(0,0,0,.4);"></span>' +
          '</span>' +
        '</label>' +
        '<div style="display:flex;justify-content:flex-end;gap:10px;margin-top:18px;">' +
          '<button type="button" class="sv-xr-cancel" style="background:transparent;color:#94a3b8;border:1px solid rgba(148,163,184,.3);border-radius:8px;padding:9px 16px;cursor:pointer;font-weight:600;">Cancel</button>' +
          '<button type="button" class="sv-xr-go" style="background:linear-gradient(180deg,#0ea5e9,#0369a1);color:#fff;border:none;border-radius:8px;padding:9px 20px;cursor:pointer;font-weight:600;letter-spacing:.03em;">Enter VR</button>' +
        '</div>' +
      '</div>';
    const toggle = modal.querySelector('.sv-xr-toggle');
    const track = modal.querySelector('.sv-xr-switch');
    const knob = modal.querySelector('.sv-xr-knob');
    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      passthrough = !passthrough;
      try { localStorage.setItem('ragnar.skyview.xr.passthrough', passthrough ? '1' : '0'); } catch (_) {}
      track.style.background = passthrough ? 'linear-gradient(180deg,#0ea5e9,#0369a1)' : '#334155';
      knob.style.left = passthrough ? '23px' : '3px';
    });
    modal.querySelector('.sv-xr-cancel').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
    modal.querySelector('.sv-xr-go').addEventListener('click', () => {
      modal.remove();
      onGo();
    });
    document.body.appendChild(modal);
  }

  function onSessionEnd() {
    if (renderer) {
      try { renderer.setAnimationLoop(null); } catch (_) {}
      try { renderer.dispose(); } catch (_) {}
      const c = renderer.domElement;
      if (c && c.parentNode) c.parentNode.removeChild(c);
    }
    session = null; renderer = null; scene = null; camera = null;
    baseGroup = null; pointables = []; controllers = []; rayLines = [];
    raycaster = null; infoPanel = null; hoveredObject = null;
    skyDomeMesh = null;
    removeStatusOverlay();
  }

  function enter(snapshot) {
    if (session) return;
    currentSnapshot = snapshot || {};
    if (!navigator.xr) {
      showXrUnavailableModal('navigator.xr is missing.');
      return;
    }
    showLaunchPanel(snapshot, () => startSession(snapshot));
  }

  async function startSession(snapshot) {
    if (session) return;
    ensureStatusOverlay();
    // We used to gate on isSessionSupported() here but Meta Quest Browser
    // reports false negatives for immersive-ar on some builds. Just try the
    // session — the requestSession() error tells us what actually failed.
    let sessionMode = passthrough ? 'immersive-ar' : 'immersive-vr';
    let vrSupported = false, arSupported = false;
    try { vrSupported = await navigator.xr.isSessionSupported('immersive-vr'); } catch (_) {}
    try { arSupported = await navigator.xr.isSessionSupported('immersive-ar'); } catch (_) {}
    console.log('[RagnarSkyViewVR] support probe', { vrSupported, arSupported, requested: sessionMode });
    if (!vrSupported && !arSupported) {
      removeStatusOverlay();
      showXrUnavailableModal('Neither immersive-ar nor immersive-vr is reported as supported.');
      return;
    }
    if (passthrough && !arSupported && vrSupported) {
      passthrough = false;
      sessionMode = 'immersive-vr';
      setStatus('Passthrough unavailable — falling back to opaque VR.');
    }
    setStatus('Loading 3D engine…');
    try { await loadThree(); } catch (err) {
      console.error('[RagnarSkyViewVR] loadThree failed', err);
      removeStatusOverlay();
      showXrUnavailableModal('Failed to load three.js from ' + THREE_URL + ' — ' + ((err && err.message) || err));
      return;
    }
    setStatus('Building sky…');
    const [catalog, constLines] = await Promise.all([
      loadJSON(CATALOG_URL, catalogRef),
      loadJSON(CONST_URL, constLinesRef)
    ]);

    const lat = (snapshot && typeof snapshot.lat === 'number') ? snapshot.lat : 45;
    const lon = (snapshot && typeof snapshot.lon === 'number') ? snapshot.lon : 0;
    const date = (snapshot && snapshot.date instanceof Date) ? snapshot.date : new Date();

    const canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:fixed;inset:0;z-index:100000;';
    document.body.appendChild(canvas);
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: passthrough });
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.xr.enabled = true;
    if (passthrough) renderer.setClearColor(0x000000, 0);

    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(80, window.innerWidth / window.innerHeight, 0.1, 2000);
    camera.position.set(0, 1.6, 0);

    if (!passthrough) {
      skyDomeMesh = buildSkyDome();
      scene.add(skyDomeMesh);
    }
    if (catalog) scene.add(buildStars(catalog, lat, lon, date));
    if (constLines) {
      const cl = buildConstellationLines(constLines, lat, lon, date);
      if (cl) scene.add(cl);
    }
    scene.add(buildPlanets(lat, lon, date));
    scene.add(buildSatellites(snapshot && snapshot.sky));
    if (!passthrough) scene.add(buildCompass());
    else scene.add(buildCompassAR());

    infoPanel = buildInfoPanel();
    scene.add(infoPanel);

    // Controllers.
    for (let i = 0; i < 2; i++) {
      const ctl = renderer.xr.getController(i);
      ctl.addEventListener('selectstart', onSelectStart);
      ctl.addEventListener('connected', (ev) => { ctl.userData._inputSource = ev.data; });
      ctl.addEventListener('disconnected', () => { ctl.userData._inputSource = null; });
      const g = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0), new THREE.Vector3(0, 0, -40)]);
      const m = new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.65 });
      const line = new THREE.Line(g, m);
      ctl.add(line);
      const puck = new THREE.Mesh(
        new THREE.SphereGeometry(0.02, 12, 8),
        new THREE.MeshBasicMaterial({ color: 0x7dd3fc })
      );
      ctl.add(puck);
      scene.add(ctl);
      controllers.push(ctl);
      rayLines.push(line);
    }

    raycaster = new THREE.Raycaster();

    setStatus('Requesting ' + (passthrough ? 'AR passthrough' : 'VR') + ' session…');
    let xrSession;
    try {
      const opts = { optionalFeatures: ['local-floor', 'bounded-floor', 'hand-tracking'] };
      xrSession = await navigator.xr.requestSession(sessionMode, opts);
    } catch (err) {
      onSessionEnd();
      showXrUnavailableModal('The browser refused the XR session (' + (err && err.message || err) + ').');
      return;
    }
    session = xrSession;
    session.addEventListener('end', onSessionEnd);
    await renderer.xr.setSession(session);
    removeStatusOverlay();

    renderer.setAnimationLoop(() => {
      for (const ctl of controllers) if (ctl.visible !== false) highlightAlong(ctl);
      renderer.render(scene, camera);
    });
  }

  window.RagnarSkyViewVR = { enter, exit };
})();
