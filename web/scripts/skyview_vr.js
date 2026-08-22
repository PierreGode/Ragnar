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
  const DEEP_SKY_URL = '/web/vendor/deep_sky.json';
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
  let catalogCache = null, constLinesCache = null, deepSkyCache = null;
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
  let skyGroup = null;
  let skyRotationY = 0;
  try {
    const v = parseFloat(localStorage.getItem('ragnar.skyview.xr.rotY'));
    if (isFinite(v)) skyRotationY = v;
  } catch (_) {}
  let userZoom = 1;
  const ZOOM_MIN = 1, ZOOM_MAX = 5;
  let zoomable = [];
  let billboards = [];

  function makeYLockedBillboard(map, sizeX, sizeY, color) {
    const mat = new THREE.MeshBasicMaterial({
      map: map || null,
      color: color != null ? color : 0xffffff,
      transparent: true,
      depthWrite: false,
      side: THREE.DoubleSide
    });
    const mesh = new THREE.Mesh(new THREE.PlaneGeometry(sizeX, sizeY == null ? sizeX : sizeY), mat);
    mesh.userData._billboard = true;
    billboards.push(mesh);
    return mesh;
  }

  function updateBillboards() {
    if (!camera) return;
    const cam = camera.getWorldPosition(new THREE.Vector3());
    const tmp = new THREE.Vector3();
    const up = new THREE.Vector3(0, 1, 0);
    const m = new THREE.Matrix4();
    const right = new THREE.Vector3();
    const trueUp = new THREE.Vector3();
    const fwd = new THREE.Vector3();
    for (const bb of billboards) {
      if (!bb.parent || bb.visible === false) continue;
      bb.getWorldPosition(tmp);
      fwd.copy(cam).sub(tmp);
      if (fwd.lengthSq() < 1e-6) continue;
      fwd.normalize();
      right.crossVectors(up, fwd);
      if (right.lengthSq() < 1e-6) right.set(1, 0, 0); else right.normalize();
      trueUp.crossVectors(fwd, right);
      m.makeBasis(right, trueUp, fwd);
      const q = new THREE.Quaternion().setFromRotationMatrix(m);
      if (bb.parent) {
        const pq = bb.parent.getWorldQuaternion(new THREE.Quaternion()).invert();
        bb.quaternion.copy(pq.multiply(q));
      } else {
        bb.quaternion.copy(q);
      }
    }
  }
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
  const deepSkyRef = { get value() { return deepSkyCache; }, set value(v) { deepSkyCache = v; } };

  // ---- Scene builders ------------------------------------------------
  function buildStars(catalog, lat, lon, date) {
    const positions = [], colors = [], sizes = [];
    const meta = [];
    const colTable = catalog.colors || [];
    for (const st of catalog.stars) {
      const [ra, dec, mag, cidx, name, cons] = st;
      const p = raDecToAltAz(ra, dec, lat, lon, date);
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

  function buildDeepSky(deepSky, lat, lon, date) {
    const group = new THREE.Group();
    if (!deepSky || !Array.isArray(deepSky.objects)) return group;
    const typeNames = deepSky.type_names || {};
    for (const o of deepSky.objects) {
      const [ra, dec, mag, id, name, type, dim] = o;
      const p = raDecToAltAz(ra, dec, lat, lon, date);
      const pos = altAzToVec(p.az, p.alt, R_STARS - 15);
      const iconColor = type && type.startsWith('g') ? 0xf9a8d4 : (type === 'oc' ? 0xbef264 : (type === 'gc' ? 0xfcd34d : 0xc4b5fd));
      // Small dashed ring so DSOs read differently from stars.
      const geom = new THREE.RingGeometry(3.0, 3.6, 24);
      const mat = new THREE.MeshBasicMaterial({ color: iconColor, transparent: true, opacity: 0.85, side: THREE.DoubleSide, depthWrite: false });
      const ring = new THREE.Mesh(geom, mat);
      ring.position.copy(pos);
      ring.lookAt(pos.clone().multiplyScalar(2));
      ring.userData = { kind: 'dso', id, name, dtype: typeNames[type] || type, mag, ra, dec, alt: p.alt, az: p.az, color: iconColor, dim };
      pointables.push(ring);
      zoomable.push(ring);
      group.add(ring);
      // Show a label for the brighter Messier objects so the sky doesn't get
      // overrun with tiny text.
      if (mag != null && mag < 7) {
        const label = makeLabelSprite(name || id, '#c4b5fd');
        label.scale.set(18, 4.5, 1);
        label.position.copy(pos).multiplyScalar(1.02);
        group.add(label);
      }
    }
    return group;
  }

  function buildConstellationLines(constLines, lat, lon, date) {
    const positions = [];
    for (const cid in constLines.lines) {
      for (const seg of constLines.lines[cid]) {
        let prev = null;
        for (let i = 0; i < seg.length; i++) {
          const [ra, dec] = seg[i];
          const p = raDecToAltAz(ra, dec, lat, lon, date);
          const v = altAzToVec(p.az, p.alt, R_STARS - 5);
          if (prev) {
            positions.push(prev.x, prev.y, prev.z, v.x, v.y, v.z);
          }
          prev = v;
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
    const bb = makeYLockedBillboard(tex, 30, 7.5);
    bb.material.depthTest = false;
    bb.renderOrder = 900;
    return bb;
  }

  // ---- Procedural planet textures ------------------------------------
  const _textureCache = {};

  function _paintBands(ctx, W, H, bands) {
    for (const b of bands) {
      const y0 = b.y * H, y1 = (b.y + b.h) * H;
      const grad = ctx.createLinearGradient(0, y0, 0, y1);
      grad.addColorStop(0, b.c1);
      grad.addColorStop(1, b.c2);
      ctx.fillStyle = grad;
      ctx.fillRect(0, y0, W, y1 - y0);
    }
  }

  function _paintSpot(ctx, W, H, x, y, r, color, opacity) {
    ctx.save();
    ctx.globalAlpha = opacity != null ? opacity : 0.7;
    const grad = ctx.createRadialGradient(x * W, y * H, 0, x * W, y * H, r * H);
    grad.addColorStop(0, color);
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.ellipse(x * W, y * H, r * H * 1.4, r * H, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  }

  function _paintPoles(ctx, W, H, color) {
    const grad1 = ctx.createLinearGradient(0, 0, 0, H * 0.18);
    grad1.addColorStop(0, color);
    grad1.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = grad1; ctx.fillRect(0, 0, W, H * 0.18);
    const grad2 = ctx.createLinearGradient(0, H * 0.82, 0, H);
    grad2.addColorStop(0, 'rgba(255,255,255,0)');
    grad2.addColorStop(1, color);
    ctx.fillStyle = grad2; ctx.fillRect(0, H * 0.82, W, H * 0.18);
  }

  function _paintNoise(ctx, W, H, amount) {
    const img = ctx.getImageData(0, 0, W, H);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
      const n = (Math.random() - 0.5) * amount;
      d[i] = Math.max(0, Math.min(255, d[i] + n));
      d[i + 1] = Math.max(0, Math.min(255, d[i + 1] + n));
      d[i + 2] = Math.max(0, Math.min(255, d[i + 2] + n));
    }
    ctx.putImageData(img, 0, 0);
  }

  const PLANET_IMAGE_PATHS = {
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

  function planetImageTexture(name) {
    const key = '__img_' + name;
    if (_textureCache[key]) return _textureCache[key];
    const path = PLANET_IMAGE_PATHS[name];
    if (!path) return null;
    const loader = new THREE.TextureLoader();
    const tex = loader.load(path);
    tex.anisotropy = 8;
    _textureCache[key] = tex;
    return tex;
  }

  function planetTexture(name) {
    if (_textureCache[name]) return _textureCache[name];
    const W = 512, H = 256;
    const canvas = document.createElement('canvas');
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext('2d');

    if (name === 'Sun') {
      const grad = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, H * 0.7);
      grad.addColorStop(0, '#fffbe6');
      grad.addColorStop(0.35, '#ffd76a');
      grad.addColorStop(0.7, '#f59e0b');
      grad.addColorStop(1, '#c2410c');
      ctx.fillStyle = grad; ctx.fillRect(0, 0, W, H);
      for (let i = 0; i < 32; i++) {
        _paintSpot(ctx, W, H, Math.random(), Math.random(), 0.04 + Math.random() * 0.08, 'rgba(255,255,220,0.35)', 0.4);
      }
      _paintNoise(ctx, W, H, 14);
    } else if (name === 'Mercury') {
      ctx.fillStyle = '#8a7663'; ctx.fillRect(0, 0, W, H);
      for (let i = 0; i < 60; i++) {
        const x = Math.random(), y = Math.random(), r = 0.02 + Math.random() * 0.09;
        _paintSpot(ctx, W, H, x, y, r, i % 2 ? 'rgba(60,50,40,1)' : 'rgba(180,160,140,1)', 0.55);
      }
      _paintNoise(ctx, W, H, 26);
    } else if (name === 'Venus') {
      _paintBands(ctx, W, H, [
        { y: 0, h: 0.3, c1: '#f8e6bb', c2: '#f0d494' },
        { y: 0.3, h: 0.4, c1: '#f0d494', c2: '#e2b872' },
        { y: 0.7, h: 0.3, c1: '#e2b872', c2: '#c99a52' }
      ]);
      for (let i = 0; i < 20; i++) {
        _paintSpot(ctx, W, H, Math.random(), 0.2 + Math.random() * 0.6, 0.05 + Math.random() * 0.1, 'rgba(255,240,200,0.6)', 0.5);
      }
      _paintNoise(ctx, W, H, 8);
    } else if (name === 'Mars') {
      _paintBands(ctx, W, H, [
        { y: 0, h: 0.5, c1: '#c96844', c2: '#b04d2c' },
        { y: 0.5, h: 0.5, c1: '#b04d2c', c2: '#8f3818' }
      ]);
      _paintSpot(ctx, W, H, 0.35, 0.55, 0.15, 'rgba(70,30,20,1)', 0.65);
      _paintSpot(ctx, W, H, 0.75, 0.45, 0.12, 'rgba(90,45,25,1)', 0.6);
      _paintSpot(ctx, W, H, 0.15, 0.35, 0.08, 'rgba(60,25,15,1)', 0.55);
      _paintPoles(ctx, W, H, 'rgba(240,220,200,0.9)');
      _paintNoise(ctx, W, H, 18);
    } else if (name === 'Jupiter') {
      _paintBands(ctx, W, H, [
        { y: 0.00, h: 0.10, c1: '#a67c52', c2: '#c9a37a' },
        { y: 0.10, h: 0.08, c1: '#ecd6b0', c2: '#d3b085' },
        { y: 0.18, h: 0.10, c1: '#b98858', c2: '#8f6740' },
        { y: 0.28, h: 0.10, c1: '#e7cea3', c2: '#c9a37a' },
        { y: 0.38, h: 0.14, c1: '#b98858', c2: '#a17547' },
        { y: 0.52, h: 0.12, c1: '#e7cea3', c2: '#d3b085' },
        { y: 0.64, h: 0.10, c1: '#a67c52', c2: '#c9a37a' },
        { y: 0.74, h: 0.10, c1: '#ecd6b0', c2: '#d3b085' },
        { y: 0.84, h: 0.16, c1: '#8f6740', c2: '#6c4d2c' }
      ]);
      _paintSpot(ctx, W, H, 0.65, 0.62, 0.06, 'rgba(190,70,50,1)', 0.85);
      _paintNoise(ctx, W, H, 10);
    } else if (name === 'Saturn') {
      _paintBands(ctx, W, H, [
        { y: 0.00, h: 0.20, c1: '#d9c188', c2: '#e6cf9a' },
        { y: 0.20, h: 0.20, c1: '#e6cf9a', c2: '#f5dfa8' },
        { y: 0.40, h: 0.20, c1: '#f5dfa8', c2: '#e6cf9a' },
        { y: 0.60, h: 0.20, c1: '#e6cf9a', c2: '#d0b781' },
        { y: 0.80, h: 0.20, c1: '#d0b781', c2: '#a89162' }
      ]);
      _paintNoise(ctx, W, H, 6);
    } else if (name === 'Uranus') {
      const grad = ctx.createLinearGradient(0, 0, 0, H);
      grad.addColorStop(0, '#c6ecf5');
      grad.addColorStop(0.5, '#a7ddec');
      grad.addColorStop(1, '#7fbfd3');
      ctx.fillStyle = grad; ctx.fillRect(0, 0, W, H);
      _paintNoise(ctx, W, H, 4);
    } else if (name === 'Neptune') {
      const grad = ctx.createLinearGradient(0, 0, 0, H);
      grad.addColorStop(0, '#4f7dc0');
      grad.addColorStop(0.5, '#3762a8');
      grad.addColorStop(1, '#254e94');
      ctx.fillStyle = grad; ctx.fillRect(0, 0, W, H);
      _paintSpot(ctx, W, H, 0.4, 0.55, 0.07, 'rgba(15,25,60,1)', 0.7);
      _paintNoise(ctx, W, H, 5);
    } else if (name === 'Moon') {
      ctx.fillStyle = '#c9c6bd'; ctx.fillRect(0, 0, W, H);
      const maria = [
        { x: 0.45, y: 0.35, r: 0.14 }, { x: 0.55, y: 0.42, r: 0.10 },
        { x: 0.35, y: 0.55, r: 0.09 }, { x: 0.62, y: 0.58, r: 0.11 },
        { x: 0.28, y: 0.42, r: 0.07 }
      ];
      for (const m of maria) _paintSpot(ctx, W, H, m.x, m.y, m.r, 'rgba(80,80,90,1)', 0.75);
      for (let i = 0; i < 120; i++) {
        _paintSpot(ctx, W, H, Math.random(), Math.random(), 0.005 + Math.random() * 0.015,
          Math.random() > 0.5 ? 'rgba(180,180,175,1)' : 'rgba(90,90,90,1)', 0.6);
      }
      _paintNoise(ctx, W, H, 14);
    } else {
      ctx.fillStyle = '#888'; ctx.fillRect(0, 0, W, H);
    }
    const tex = new THREE.CanvasTexture(canvas);
    tex.anisotropy = 4;
    _textureCache[name] = tex;
    return tex;
  }

  function buildSunGlow(radius) {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 256;
    const ctx = canvas.getContext('2d');
    const grad = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
    grad.addColorStop(0, 'rgba(255,240,170,0.85)');
    grad.addColorStop(0.25, 'rgba(255,190,80,0.55)');
    grad.addColorStop(0.6, 'rgba(255,120,20,0.18)');
    grad.addColorStop(1, 'rgba(255,80,0,0)');
    ctx.fillStyle = grad; ctx.fillRect(0, 0, 256, 256);
    const tex = new THREE.CanvasTexture(canvas);
    const bb = makeYLockedBillboard(tex, radius * 6, radius * 6);
    bb.material.blending = THREE.AdditiveBlending;
    return bb;
  }

  function buildSaturnRings(radius) {
    const canvas = document.createElement('canvas');
    canvas.width = 512; canvas.height = 32;
    const ctx = canvas.getContext('2d');
    for (let x = 0; x < 512; x++) {
      const t = x / 512;
      let a = 0.4 + 0.5 * Math.sin(t * 20) * Math.sin(t * 8);
      if (t < 0.15 || t > 0.95) a *= 0.2;
      if (Math.abs(t - 0.55) < 0.03) a *= 0.15;
      const shade = 210 + Math.round(Math.sin(t * 30) * 20);
      ctx.fillStyle = 'rgba(' + shade + ',' + (shade - 20) + ',' + (shade - 60) + ',' + Math.max(0, Math.min(1, a)) + ')';
      ctx.fillRect(x, 0, 1, 32);
    }
    const tex = new THREE.CanvasTexture(canvas);
    const inner = radius * 1.35, outer = radius * 2.4;
    const geom = new THREE.RingGeometry(inner, outer, 96, 1);
    // Map the texture radially across the ring.
    const pos = geom.attributes.position;
    const uv = geom.attributes.uv;
    const v3 = new THREE.Vector3();
    for (let i = 0; i < pos.count; i++) {
      v3.fromBufferAttribute(pos, i);
      const r = v3.length();
      uv.setXY(i, (r - inner) / (outer - inner), 0.5);
    }
    const mat = new THREE.MeshBasicMaterial({ map: tex, side: THREE.DoubleSide, transparent: true, depthWrite: false });
    const ring = new THREE.Mesh(geom, mat);
    ring.rotation.x = Math.PI / 2;
    ring.rotation.z = 26.7 * D2R;
    return ring;
  }

  function makePlanetSprite(name, sizeWorld) {
    const tex = planetImageTexture(name);
    return makeYLockedBillboard(tex, sizeWorld, sizeWorld);
  }

  function buildPlanets(lat, lon, date) {
    const group = new THREE.Group();
    // Sun.
    const sun = sunSky(date, lat, lon);
    {
      const sunSize = 22;
      const sSpr = makePlanetSprite('Sun', sunSize);
      const pos = altAzToVec(sun.az, sun.alt, R_PLANETS);
      sSpr.position.copy(pos);
      sSpr.userData = { kind: 'sun', name: 'Sun', alt: sun.alt, az: sun.az };
      pointables.push(sSpr);
      zoomable.push(sSpr);
      group.add(sSpr);
      const glow = buildSunGlow(sunSize * 0.55);
      glow.position.copy(pos);
      zoomable.push(glow);
      group.add(glow);
      const label = makeLabelSprite('Sun', '#ffdf7e');
      label.position.copy(altAzToVec(sun.az, sun.alt - 2.5, R_PLANETS * 1.01));
      group.add(label);
    }
    // Moon.
    const moon = moonSky(date, lat, lon);
    {
      const mSpr = makePlanetSprite('Moon', 16);
      const pos = altAzToVec(moon.az, moon.alt, R_PLANETS);
      mSpr.position.copy(pos);
      mSpr.userData = { kind: 'moon', name: 'Moon', alt: moon.alt, az: moon.az, illum: moon.illum };
      pointables.push(mSpr);
      zoomable.push(mSpr);
      group.add(mSpr);
      const label = makeLabelSprite('Moon', '#e2e8f0');
      label.position.copy(altAzToVec(moon.az, moon.alt - 2.5, R_PLANETS * 1.01));
      group.add(label);
    }
    // Planets.
    const planets = planetSkyPositions(date, lat, lon);
    for (const p of planets) {
      const sz = p.size * 2.2;
      const spr = makePlanetSprite(p.name, sz);
      const pos = altAzToVec(p.az, p.alt, R_PLANETS);
      spr.position.copy(pos);
      spr.userData = { kind: 'planet', name: p.name, alt: p.alt, az: p.az, ra: p.ra, dec: p.dec };
      pointables.push(spr);
      zoomable.push(spr);
      group.add(spr);
      const label = makeLabelSprite(p.name, '#f5d58a');
      label.position.copy(altAzToVec(p.az, p.alt - 2.5, R_PLANETS * 1.01));
      group.add(label);
    }
    return group;
  }

  // ---- ISS (International Space Station) -----------------------------
  let issMesh = null, issLabel = null, issRefreshMs = 0, issState = null;
  const ISS_URL = '/api/iss/position';

  function buildISSModel() {
    const g = new THREE.Group();
    const truss = new THREE.Mesh(
      new THREE.BoxGeometry(4.6, 0.5, 0.5),
      new THREE.MeshBasicMaterial({ color: 0xdedede })
    );
    g.add(truss);
    for (let side = -1; side <= 1; side += 2) {
      for (let i = 0; i < 2; i++) {
        const panel = new THREE.Mesh(
          new THREE.PlaneGeometry(1.9, 4.0),
          new THREE.MeshBasicMaterial({ color: 0x1e3a8a, side: THREE.DoubleSide })
        );
        panel.position.set(side * (1.0 + i * 2.0), 0, 0);
        g.add(panel);
      }
    }
    const modules = new THREE.Mesh(
      new THREE.CylinderGeometry(0.55, 0.55, 1.9, 16),
      new THREE.MeshBasicMaterial({ color: 0xe0e6ee })
    );
    modules.rotation.z = Math.PI / 2;
    g.add(modules);
    // Radiator arrays on top/bottom
    for (let s = -1; s <= 1; s += 2) {
      const rad = new THREE.Mesh(
        new THREE.PlaneGeometry(2.4, 0.9),
        new THREE.MeshBasicMaterial({ color: 0xfdf6e3, side: THREE.DoubleSide })
      );
      rad.position.set(0, s * 0.9, 0);
      g.add(rad);
    }
    // Scale up so ISS reads clearly at R_SATS distance.
    g.scale.setScalar(1.4);
    return g;
  }

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

  async function refreshISS(obsLat, obsLon) {
    if (obsLat == null || obsLon == null) return;
    try {
      const r = await fetch(ISS_URL, { cache: 'no-store' });
      if (!r.ok) {
        console.warn('[RagnarSkyViewVR] ISS fetch HTTP', r.status);
        return;
      }
      const d = await r.json();
      if (d && d.error) {
        console.warn('[RagnarSkyViewVR] ISS upstream error', d.error);
        return;
      }
      const sky = issSkyFromLatLon(d.latitude, d.longitude, d.altitude, obsLat, obsLon);
      issState = { lat: d.latitude, lon: d.longitude, alt_km: d.altitude, velocity: d.velocity, ...sky };
      if (issMesh) {
        issMesh.visible = true;
        if (issLabel) issLabel.visible = true;
        const pos = altAzToVec(sky.az, sky.el, R_SATS);
        issMesh.position.copy(pos);
        issMesh.lookAt(pos.clone().multiplyScalar(2));
        if (issLabel) issLabel.position.copy(pos).multiplyScalar(1.08);
        issMesh.userData.iss = issState;
      }
    } catch (_) {}
  }

  function buildISS(obsLat, obsLon) {
    const g = new THREE.Group();
    issMesh = buildISSModel();
    issMesh.userData = { kind: 'iss', name: 'ISS' };
    issMesh.visible = false;
    pointables.push(issMesh);
    zoomable.push(issMesh);
    g.add(issMesh);
    issLabel = makeLabelSprite('ISS', '#a7f3d0');
    issLabel.visible = false;
    g.add(issLabel);
    refreshISS(obsLat, obsLon);
    return g;
  }

  const SAT_IMG = '/web/vendor/sky/sat/satellite.png';
  let _satTexture = null;
  function satTexture() {
    if (_satTexture) return _satTexture;
    _satTexture = new THREE.TextureLoader().load(SAT_IMG);
    _satTexture.anisotropy = 4;
    return _satTexture;
  }

  function buildSatModel(color) {
    const g = new THREE.Group();
    const spr = makeYLockedBillboard(satTexture(), 7, 7);
    g.add(spr);
    // Tiny constellation-colored dot below the sprite so you can still tell
    // GPS from GLONASS from Galileo etc. at a glance.
    const tag = makeYLockedBillboard(null, 1.4, 1.4, color);
    tag.position.set(0, -3.6, 0);
    g.add(tag);
    return g;
  }

  function buildSatellites(sky) {
    const group = new THREE.Group();
    if (!sky || !sky.length) return group;
    for (const s of sky) {
      if (s.az == null || s.elev == null) continue;
      // Only render sats the receiver is actually locked onto — anything with
      // SNR=0 is either obstructed by the environment (buildings, balcony
      // wall, etc.) or below the tracking threshold, so it shouldn't appear.
      if (!(typeof s.snr === 'number' && s.snr > 0)) continue;
      const color = SAT_COLORS[s.constellation] || 0x94a3b8;
      const model = buildSatModel(color);
      const pos = altAzToVec(s.az, s.elev, R_SATS);
      model.position.copy(pos);
      model.userData = { kind: 'sat', sat: s, alt: s.elev, az: s.az };
      pointables.push(model);
      zoomable.push(model);
      group.add(model);
      const label = makeLabelSprite(
        (s.constellation || 'sat') + (s.prn != null ? ' ' + s.prn : ''),
        '#' + color.toString(16).padStart(6, '0')
      );
      label.scale.set(20, 5, 1);
      // Place the label ~2.5° below the satellite along the sphere.
      label.position.copy(altAzToVec(s.az, s.elev - 2.5, R_SATS * 1.01));
      group.add(label);
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
    // Horizon ring — semi-transparent so it doesn't block below-horizon view.
    const ringGeom = new THREE.RingGeometry(R_COMPASS - 1, R_COMPASS + 1, 128);
    ringGeom.rotateX(-Math.PI / 2);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.28, side: THREE.DoubleSide });
    group.add(new THREE.Mesh(ringGeom, ringMat));
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
    const mesh = new THREE.Mesh(new THREE.PlaneGeometry(1.6, 0.9), mat);
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
    } else if (d.kind === 'iss') {
      accent = '#a7f3d0';
      title = '🛰 International Space Station';
      const s = d.iss || issState || {};
      lines = [
        'Elevation ' + (s.el != null ? fmtDeg(s.el, 1) : '—'),
        'Azimuth ' + (s.az != null ? fmtDeg(s.az, 1) + ' ' + cardinal(s.az) : '—'),
        'Range ' + (s.range_km != null ? s.range_km.toFixed(0) + ' km' : '—'),
        'Altitude ' + (s.alt_km != null ? s.alt_km.toFixed(0) + ' km' : '—'),
        'Speed ' + (s.velocity != null ? s.velocity.toFixed(0) + ' km/h' : '—')
      ];
    } else if (d.kind === 'dso') {
      accent = '#c4b5fd';
      title = '◇ ' + (d.name || d.id);
      lines = [
        'Catalog ' + (d.id || '—'),
        'Type ' + (d.dtype || '—'),
        'Magnitude ' + (d.mag != null ? d.mag.toFixed(1) : '—'),
        'Elevation ' + fmtDeg(d.alt, 1),
        'Azimuth ' + fmtDeg(d.az, 1) + ' ' + cardinal(d.az)
      ];
      if (d.dim) lines.push('Dimensions ' + d.dim);
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
    // Place the panel ~1.6m in front of the controller, facing the head.
    const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion);
    const headPos = new THREE.Vector3().setFromMatrixPosition(camera.matrixWorld);
    infoPanel.position.copy(ctl.position).addScaledVector(dir, 1.6);
    infoPanel.lookAt(headPos);
    infoPanel.visible = true;
    if (infoPanel.userData._hideTimer) clearTimeout(infoPanel.userData._hideTimer);
    infoPanel.userData._hideTimer = setTimeout(() => {
      if (infoPanel) infoPanel.visible = false;
    }, 6000);
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
      if (o.visible === false) continue;
      tmp.copy(o.getWorldPosition(new THREE.Vector3())).sub(origin);
      const t = tmp.dot(dir);
      if (t <= 0) continue;
      const projX = t * dir.x, projY = t * dir.y, projZ = t * dir.z;
      const dx = tmp.x - projX, dy = tmp.y - projY, dz = tmp.z - projZ;
      const perp = Math.sqrt(dx * dx + dy * dy + dz * dz);
      // The angular tolerance (rad) — scale by 8 deg for planets/sats, 5 deg for stars.
      const kind = o.userData && o.userData.kind;
      const tolDeg = kind === 'star' ? 3.5
        : (kind === 'iss' ? 4
        : (kind === 'planet' || kind === 'sun' || kind === 'moon' ? 5
        : (kind === 'dso' ? 3 : 6)));
      const tol = t * Math.tan(tolDeg * D2R);
      if (perp > tol) continue;
      const score = perp / (tol || 1);
      if (score < bestScore) { bestScore = score; best = o; }
    }
    return best;
  }

  function onSqueezeStart(ev) {
    if (!camera || !skyGroup) return;
    // Get the head's forward direction on the horizontal plane, then rotate
    // skyGroup so its local -Z (astronomical north) points that way.
    const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(camera.quaternion);
    forward.y = 0;
    if (forward.lengthSq() < 1e-6) return;
    forward.normalize();
    skyRotationY = Math.atan2(-forward.x, -forward.z);
    skyGroup.rotation.y = skyRotationY;
    try { localStorage.setItem('ragnar.skyview.xr.rotY', String(skyRotationY)); } catch (_) {}
    // Haptic pulse + brief on-panel confirmation.
    const ctl = ev.target;
    try {
      const src = ctl && ctl.userData && ctl.userData._inputSource;
      const act = src && src.gamepad && src.gamepad.hapticActuators && src.gamepad.hapticActuators[0];
      if (act && act.pulse) act.pulse(0.8, 120);
    } catch (_) {}
    if (infoPanel && ctl) {
      drawInfoPanel(infoPanel, '🧭 Sky aligned', ['This direction is now north.', 'Fine-tune with right thumbstick.'], '#86efac');
      const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion);
      const headPos = new THREE.Vector3().setFromMatrixPosition(camera.matrixWorld);
      infoPanel.position.copy(ctl.position).addScaledVector(dir, 1.6);
      infoPanel.lookAt(headPos);
      infoPanel.visible = true;
      if (infoPanel.userData._hideTimer) clearTimeout(infoPanel.userData._hideTimer);
      infoPanel.userData._hideTimer = setTimeout(() => { if (infoPanel) infoPanel.visible = false; }, 2200);
    }
  }

  function onSelectStart(ev) {
    const ctl = ev.target;
    const origin = new THREE.Vector3().setFromMatrixPosition(ctl.matrixWorld);
    const dir = new THREE.Vector3(0, 0, -1).applyQuaternion(ctl.quaternion).normalize();
    const solidHit = pickAlongRay(origin, dir);
    const starHit = pickStar(origin, dir);
    // Prefer the solid object (sat/planet) if the ray is close to it; otherwise
    // fall back to the brightest on-axis star.
    if (solidHit) {
      showInfoFor(solidHit, ctl);
    } else if (starHit) {
      showInfoFor({ userData: starHit.meta }, ctl);
    } else {
      if (infoPanel) infoPanel.visible = false;
    }
  }

  function pickStar(origin, dir) {
    if (!scene) return null;
    let starObj = null;
    scene.traverse(o => { if (o.isPoints && o.userData && o.userData.stars) starObj = o; });
    if (!starObj) return null;
    // Transform world-space ray into star cloud's local frame (i.e. skyGroup).
    starObj.updateWorldMatrix(true, false);
    const inv = new THREE.Matrix4().copy(starObj.matrixWorld).invert();
    const lo = origin.clone().applyMatrix4(inv);
    const ld = dir.clone().transformDirection(inv).normalize();
    let bestScore = Infinity, best = null;
    const meta = starObj.userData.stars;
    const sorted = meta.slice().sort((a, b) => a.mag - b.mag).slice(0, 250);
    const tmp = new THREE.Vector3();
    for (const m of sorted) {
      tmp.copy(altAzToVec(m.az, m.alt, R_STARS)).sub(lo);
      const t = tmp.dot(ld);
      if (t <= 0) continue;
      const dx = tmp.x - t * ld.x, dy = tmp.y - t * ld.y, dz = tmp.z - t * ld.z;
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
    const prevHover = ctl.userData._hover;
    if (hit !== prevHover) {
      if (prevHover && prevHover.userData._origColor != null && !isHoveredByOtherController(prevHover, ctl)) {
        prevHover.material.color.setHex(prevHover.userData._origColor);
      }
      if (hit && hit.material && hit.material.color) {
        if (hit.userData._origColor == null) hit.userData._origColor = hit.material.color.getHex();
        hit.material.color.setHex(0xffffff);
      }
      ctl.userData._hover = hit;
    }
    const reticle = ctl.userData._reticle;
    if (reticle) {
      if (hit) {
        reticle.position.copy(hit.getWorldPosition(new THREE.Vector3()));
        reticle.lookAt(origin);
        reticle.visible = true;
      } else {
        reticle.visible = false;
      }
    }
  }

  function isHoveredByOtherController(obj, notCtl) {
    for (const c of controllers) if (c !== notCtl && c.userData._hover === obj) return true;
    return false;
  }

  function applyZoom() {
    for (const o of zoomable) {
      if (o.userData._baseScale == null) o.userData._baseScale = o.scale.x;
      o.scale.setScalar(o.userData._baseScale * userZoom);
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
        '<p style="margin:6px 0 4px;font-size:12px;color:#9fb0c3;line-height:1.55;"><b style="color:#dbeafe;">Controls</b> (right hand):</p>' +
        '<ul style="margin:0 0 10px 16px;padding:0;font-size:12px;color:#9fb0c3;line-height:1.6;">' +
          '<li>Thumbstick X: rotate sky · Thumbstick Y: zoom (1–5×)</li>' +
          '<li><b style="color:#86efac;">Grip / squeeze</b>: face real-world north and squeeze — the sky snaps to your head direction (saves).</li>' +
          '<li>Trigger: inspect the object your ray points at.</li>' +
        '</ul>' +
        '<p style="margin:0 0 14px;font-size:11px;color:#7f93ad;line-height:1.55;">Only satellites the receiver is actively tracking (SNR&nbsp;&gt;&nbsp;0) are shown — obstructed sats stay hidden.</p>' +
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
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:18px;">' +
          '<button type="button" class="sv-xr-reset-rot" style="background:transparent;color:#7f93ad;border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:7px 12px;cursor:pointer;font-size:11px;">Reset alignment</button>' +
          '<div style="display:flex;gap:10px;">' +
            '<button type="button" class="sv-xr-cancel" style="background:transparent;color:#94a3b8;border:1px solid rgba(148,163,184,.3);border-radius:8px;padding:9px 16px;cursor:pointer;font-weight:600;">Cancel</button>' +
            '<button type="button" class="sv-xr-go" style="background:linear-gradient(180deg,#0ea5e9,#0369a1);color:#fff;border:none;border-radius:8px;padding:9px 20px;cursor:pointer;font-weight:600;letter-spacing:.03em;">Enter VR</button>' +
          '</div>' +
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
    const resetBtn = modal.querySelector('.sv-xr-reset-rot');
    if (resetBtn) resetBtn.addEventListener('click', () => {
      skyRotationY = 0;
      try { localStorage.setItem('ragnar.skyview.xr.rotY', '0'); } catch (_) {}
      resetBtn.textContent = '✓ Alignment reset';
      resetBtn.style.color = '#86efac';
      setTimeout(() => { resetBtn.textContent = 'Reset alignment'; resetBtn.style.color = '#7f93ad'; }, 1400);
    });
    document.body.appendChild(modal);
  }

  function onSessionEnd() {
    try { localStorage.setItem('ragnar.skyview.xr.rotY', String(skyRotationY)); } catch (_) {}
    if (renderer) {
      try { renderer.setAnimationLoop(null); } catch (_) {}
      try { renderer.dispose(); } catch (_) {}
      const c = renderer.domElement;
      if (c && c.parentNode) c.parentNode.removeChild(c);
    }
    session = null; renderer = null; scene = null; camera = null;
    baseGroup = null; pointables = []; controllers = []; rayLines = [];
    zoomable = []; userZoom = 1; billboards = [];
    raycaster = null; infoPanel = null; hoveredObject = null;
    skyDomeMesh = null; skyGroup = null;
    issMesh = null; issLabel = null; issState = null;
    removeStatusOverlay();
  }

  function enter(snapshot) {
    if (session) return;
    currentSnapshot = snapshot || {};
    // On insecure origin (plain HTTP), transparently promote to HTTPS. The
    // /api/ssl/enable endpoint is idempotent — reuses an existing cert and
    // listener, so re-invocation costs nothing.
    if (!window.isSecureContext) {
      _promoteToHttps();
      return;
    }
    if (!navigator.xr) {
      showXrUnavailableModal('navigator.xr is missing.');
      return;
    }
    showLaunchPanel(snapshot, () => startSession(snapshot));
  }

  async function _promoteToHttps() {
    const toast = document.createElement('div');
    toast.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:100010;background:linear-gradient(180deg,#081426,#02050d);border:1px solid rgba(125,211,252,.35);border-radius:12px;padding:16px 22px;color:#dbeafe;font-family:system-ui,-apple-system,sans-serif;font-size:13px;letter-spacing:.03em;box-shadow:0 22px 60px rgba(0,0,0,.6);text-align:center;';
    toast.innerHTML = '<div style="font-size:22px;margin-bottom:8px;">🔐</div><div class="sv-xr-toast-msg">Switching to HTTPS…</div>';
    document.body.appendChild(toast);
    const setMsg = (m) => { const el = toast.querySelector('.sv-xr-toast-msg'); if (el) el.textContent = m; };
    try {
      const r = await fetch('/api/ssl/enable', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || !d.ok) throw new Error(d.error || ('HTTP ' + r.status));
      setMsg(d.already_running ? 'Redirecting to HTTPS…' : 'SSL ready — redirecting…');
      const target = 'https://' + location.hostname + ':' + d.https_port + location.pathname + location.search + location.hash;
      setTimeout(() => { location.href = target; }, d.already_running ? 250 : 700);
    } catch (err) {
      console.error('[RagnarSkyViewVR] auto-promote to HTTPS failed', err);
      toast.remove();
      showXrUnavailableModal('Automatic HTTPS bootstrap failed: ' + (err && err.message || err));
    }
  }

  async function startSession(snapshot) {
    if (session) return;
    try {
      await _startSessionImpl(snapshot);
    } catch (err) {
      console.error('[RagnarSkyViewVR] startSession crashed', err);
      onSessionEnd();
      showXrUnavailableModal('VR startup failed: ' + ((err && err.message) || err));
    }
  }

  async function _startSessionImpl(snapshot) {
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
    const [catalog, constLines, deepSky] = await Promise.all([
      loadJSON(CATALOG_URL, catalogRef),
      loadJSON(CONST_URL, constLinesRef),
      loadJSON(DEEP_SKY_URL, deepSkyRef)
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

    skyGroup = new THREE.Group();
    skyGroup.rotation.y = skyRotationY;
    scene.add(skyGroup);
    if (!passthrough) {
      skyDomeMesh = buildSkyDome();
      skyGroup.add(skyDomeMesh);
    }
    if (catalog) skyGroup.add(buildStars(catalog, lat, lon, date));
    if (constLines) {
      const cl = buildConstellationLines(constLines, lat, lon, date);
      if (cl) skyGroup.add(cl);
    }
    if (deepSky) skyGroup.add(buildDeepSky(deepSky, lat, lon, date));
    skyGroup.add(buildPlanets(lat, lon, date));
    skyGroup.add(buildSatellites(snapshot && snapshot.sky));
    skyGroup.add(buildISS(lat, lon));
    if (!passthrough) skyGroup.add(buildCompass());
    else skyGroup.add(buildCompassAR());

    infoPanel = buildInfoPanel();
    scene.add(infoPanel);

    // Controllers.
    for (let i = 0; i < 2; i++) {
      const ctl = renderer.xr.getController(i);
      ctl.addEventListener('selectstart', onSelectStart);
      ctl.addEventListener('squeezestart', onSqueezeStart);
      ctl.addEventListener('connected', (ev) => { ctl.userData._inputSource = ev.data; });
      ctl.addEventListener('disconnected', () => { ctl.userData._inputSource = null; });
      const g = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0), new THREE.Vector3(0, 0, -R_STARS)]);
      const m = new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.55 });
      const line = new THREE.Line(g, m);
      ctl.add(line);
      const puck = new THREE.Mesh(
        new THREE.SphereGeometry(0.015, 12, 8),
        new THREE.MeshBasicMaterial({ color: 0x7dd3fc })
      );
      ctl.add(puck);
      // Reticle floating at the point the ray is currently aimed at.
      const reticle = new THREE.Mesh(
        new THREE.RingGeometry(1.6, 2.4, 24),
        new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.85, side: THREE.DoubleSide, depthTest: false })
      );
      reticle.renderOrder = 998;
      reticle.visible = false;
      ctl.userData._reticle = reticle;
      scene.add(reticle);
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

    let lastFrameTime = null;
    let saveThrottle = 0;
    let issTicker = 30000;
    renderer.setAnimationLoop((now) => {
      if (lastFrameTime == null) lastFrameTime = now;
      const dtSec = Math.min(0.1, (now - lastFrameTime) / 1000);
      lastFrameTime = now;
      issTicker += dtSec * 1000;
      if (issTicker >= 30000) {
        issTicker = 0;
        refreshISS(lat, lon);
      }

      // Right thumbstick: X = rotate sky (fine-tune), Y = zoom.
      if (session && session.inputSources && skyGroup) {
        let stickRX = 0, stickRY = 0;
        for (const src of session.inputSources) {
          if (!src.gamepad || src.handedness !== 'right') continue;
          const axes = src.gamepad.axes || [];
          stickRX = axes.length >= 3 ? (axes[2] || 0) : (axes[0] || 0);
          stickRY = axes.length >= 4 ? (axes[3] || 0) : (axes[1] || 0);
        }
        if (Math.abs(stickRX) > 0.15) {
          skyRotationY -= stickRX * dtSec * 1.5;
          skyGroup.rotation.y = skyRotationY;
          saveThrottle += dtSec;
          if (saveThrottle > 0.5) {
            saveThrottle = 0;
            try { localStorage.setItem('ragnar.skyview.xr.rotY', String(skyRotationY)); } catch (_) {}
          }
        }
        if (Math.abs(stickRY) > 0.15) {
          userZoom -= stickRY * dtSec * 2.2;
          userZoom = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, userZoom));
          applyZoom();
        }
      }

      for (const ctl of controllers) if (ctl.visible !== false) highlightAlong(ctl);
      updateBillboards();
      renderer.render(scene, camera);
    });
  }

  window.RagnarSkyViewVR = { enter, exit };
})();
