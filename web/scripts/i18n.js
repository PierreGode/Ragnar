(function () {
    'use strict';
    if (window.RagnarI18n) return;

    var SUPPORTED = ['en', 'es', 'fr', 'de'];
    var NATIVE_NAMES = { en: 'English', es: 'Español', fr: 'Français', de: 'Deutsch' };
    var ATTRS = ['placeholder', 'title', 'aria-label', 'alt', 'data-tooltip', 'data-label', 'label'];
    var OBSERVED_ATTRS = ATTRS.concat(['value']);
    var SKIP_TAGS = { script: 1, style: 1, code: 1, pre: 1, textarea: 1, kbd: 1, samp: 1, noscript: 1, template: 1 };
    var PHRASING = {
        a: 1, abbr: 1, b: 1, bdi: 1, bdo: 1, br: 1, cite: 1, code: 1, data: 1, dfn: 1, em: 1, i: 1, kbd: 1,
        mark: 1, q: 1, s: 1, samp: 1, small: 1, span: 1, strong: 1, sub: 1, sup: 1, time: 1, u: 1, 'var': 1, wbr: 1
    };
    var EXCLUDE_SEL = 'script,style,code,pre,textarea,kbd,samp,noscript,template,[translate="no"],.notranslate,' +
        '[contenteditable=""],[contenteditable="true"],.xterm';
    var BUTTON_INPUT = { button: 1, submit: 1, reset: 1 };
    var WS = /\s+/g;
    var WS_CHAR = /\s/;
    var LETTER = /[A-Za-zÀ-ɏ]/;
    var PH_SPLIT = /\{(\d+)\}/;
    var PH_ALL = /\{(\d+)\}/g;
    var DECOR = /^([^A-Za-z0-9À-ɏ"'(\[{¿¡<]{1,4}\s+)([\s\S]+)$/;
    var MAX_TEXT = 4000;
    var SAME = {};

    var boot = window.__RAGNAR_I18N__ || {};
    var version = String(boot.v || '1');
    var lang = 'en';
    var packs = {};
    var textRec = new WeakMap();
    var attrRec = new WeakMap();
    var groupRec = new WeakMap();
    var observer = null;
    var observing = false;
    var touched = false;
    var listeners = [];
    var pendingLoads = {};

    function normalize(s) { return s.replace(WS, ' '); }

    function edges(s) {
        var a = 0, b = s.length;
        while (a < b && WS_CHAR.test(s.charAt(a))) a++;
        while (b > a && WS_CHAR.test(s.charAt(b - 1))) b--;
        return [s.slice(0, a), s.slice(a, b), s.slice(b)];
    }

    function midWord(lit) {
        var words = lit.split(' ');
        for (var i = 1; i < words.length - 1; i++) {
            if (words[i].length >= 3 && LETTER.test(words[i])) return words[i];
        }
        return null;
    }

    function placeholderList(s) {
        var out = [];
        s.replace(PH_ALL, function (m, n) { out.push(+n); return m; });
        return out.sort(function (a, b) { return a - b; });
    }

    function samePlaceholders(key, val) {
        var a = placeholderList(key), b = placeholderList(val);
        if (a.length !== b.length) return false;
        for (var i = 0; i < a.length; i++) if (a[i] !== b[i] || (i && a[i] === a[i - 1])) return false;
        return true;
    }

    function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

    function trieNode() { return { c: Object.create(null), t: null }; }

    function trieInsert(root, str, tpl) {
        var n = root;
        for (var i = 0; i < str.length; i++) {
            var ch = str.charAt(i);
            n = n.c[ch] || (n.c[ch] = trieNode());
        }
        (n.t || (n.t = [])).push(tpl);
    }

    function trieCollect(root, s, fromEnd, out) {
        var n = root, len = s.length;
        for (var i = 0; i < len; i++) {
            n = n.c[s.charAt(fromEnd ? len - 1 - i : i)];
            if (!n) return;
            if (n.t) for (var j = 0; j < n.t.length; j++) out.push(n.t[j]);
        }
    }

    var NOT_LETTER = '[^A-Za-z\\u00C0-\\u024F\\s]';
    var ENDS_LETTER = /[A-Za-zÀ-ɏ]$/;
    var STARTS_LETTER = /^[A-Za-zÀ-ɏ]/;

    // A placeholder glued to letters ("{0}d", "{0}ms") only captures a
    // non-letter edge, so unit templates match "5d" but never cut into words.
    function captureGroup(before, after, last) {
        var left = ENDS_LETTER.test(before), right = STARTS_LETTER.test(after);
        if (left && right) return '(' + NOT_LETTER + '(?:[\\s\\S]*?' + NOT_LETTER + ')?)';
        if (right) return '([\\s\\S]*?' + NOT_LETTER + ')';
        if (left) return last ? '(' + NOT_LETTER + '[\\s\\S]*)' : '(' + NOT_LETTER + '[\\s\\S]*?)';
        return last ? '([\\s\\S]+)' : '([\\s\\S]+?)';
    }

    function compile(dict) {
        var exact = new Map(), rev = new Map(), known = new Set();
        var pre = trieNode(), suf = trieNode(), midIdx = new Map(), midScan = [];
        var keys = Object.keys(dict || {});
        for (var k = 0; k < keys.length; k++) {
            var key = keys[k], val = dict[key];
            if (typeof val !== 'string' || !val) continue;
            var same = val === key;
            var hasPh = key.indexOf('{') !== -1 && PH_SPLIT.test(key);
            if (!same && (hasPh || val.indexOf('{') !== -1) && !samePlaceholders(key, val)) continue;
            exact.set(key, val);
            if (same) known.add(key);
            else {
                var nv = normalize(val).trim();
                if (nv && nv.indexOf(' ') !== -1 && !rev.has(nv)) rev.set(nv, key);
            }
            if (!hasPh) continue;
            var parts = key.split(/(\{\d+\})/);
            var lits = [], src = '^';
            for (var i = 0; i < parts.length; i++) {
                if (i % 2) src += captureGroup(parts[i - 1], parts[i + 1], i === parts.length - 2 && parts[parts.length - 1] === '');
                else { src += escapeRe(parts[i]); lits.push(parts[i]); }
            }
            var tpl = { src: src + '$', rx: null, out: val, same: same, weight: lits.join('').length, mid: null,
                count: parts.length === 3 && !parts[0] && /^\s+[^\s{}]+$/.test(parts[2]) };
            var first = lits[0], last = lits[lits.length - 1];
            if (first) trieInsert(pre, first, tpl);
            else if (last) trieInsert(suf, last.split('').reverse().join(''), tpl);
            else {
                var longest = '';
                for (var j = 0; j < lits.length; j++) if (lits[j].length > longest.length) longest = lits[j];
                tpl.mid = longest;
                var w = midWord(longest);
                if (w) { var bucket = midIdx.get(w); if (bucket) bucket.push(tpl); else midIdx.set(w, [tpl]); }
                else midScan.push(tpl);
            }
        }
        return { exact: exact, rev: rev, known: known, pre: pre, suf: suf, midIdx: midIdx, midScan: midScan };
    }

    function pack() { return lang === 'en' ? null : packs[lang] || null; }

    function byWeight(a, b) { return b.weight - a.weight; }

    function firstMatch(cands, n) {
        if (cands.length > 1) cands.sort(byWeight);
        for (var j = 0; j < cands.length; j++) {
            var t = cands[j];
            if (!t.rx) t.rx = new RegExp(t.src);
            var m = t.rx.exec(n);
            // "{0} hosts" is a count: never let it rewrite "Home Network"-style names.
            if (m && t.count && !/\d/.test(m[1])) continue;
            if (m) return { out: t.out, m: m, same: t.same };
        }
        return null;
    }

    // Leading-text templates win: "Last scan: {0}" over "{0} minutes ago".
    function templateHit(p, n) {
        var cands = [];
        trieCollect(p.pre, n, false, cands);
        var hit = cands.length ? firstMatch(cands, n) : null;
        if (hit) return hit;
        cands = [];
        trieCollect(p.suf, n, true, cands);
        hit = cands.length ? firstMatch(cands, n) : null;
        if (hit) return hit;
        cands = [];
        if (p.midIdx.size) {
            var words = n.split(' ');
            for (var w = 0; w < words.length; w++) {
                var bucket = p.midIdx.get(words[w]);
                if (!bucket) continue;
                for (var b = 0; b < bucket.length; b++) {
                    if (cands.indexOf(bucket[b]) === -1 && n.indexOf(bucket[b].mid) !== -1) cands.push(bucket[b]);
                }
            }
        }
        for (var i = 0; i < p.midScan.length; i++) if (n.indexOf(p.midScan[i].mid) !== -1) cands.push(p.midScan[i]);
        return cands.length ? firstMatch(cands, n) : null;
    }

    function captureText(p, c, depth) {
        var e = edges(c);
        if (!e[1] || !LETTER.test(e[1])) return c;
        var n = normalize(e[1]);
        var v = p.exact.get(n);
        if (v === undefined && depth < 1) {
            var hit = templateHit(p, n);
            if (hit) v = fill(p, hit, depth + 1);
        }
        return v === undefined || v === null ? c : e[0] + v + e[2];
    }

    function fill(p, hit, depth) {
        if (hit.same) return hit.m[0];
        return hit.out.replace(PH_ALL, function (x, i) {
            var c = hit.m[+i + 1];
            return c === undefined ? x : captureText(p, c, depth);
        });
    }

    function lookupPlain(p, n) {
        var v = p.exact.get(n);
        if (v !== undefined) return v;
        var hit = templateHit(p, n);
        return hit ? fill(p, hit, 0) : null;
    }

    function lookup(p, n) {
        var v = lookupPlain(p, n);
        if (v !== null) return v;
        var d = DECOR.exec(n);
        if (d) {
            v = lookupPlain(p, d[2]);
            if (v !== null) return d[1] + v;
        }
        if (n.length > 2 && n.charAt(n.length - 1) === ':') {
            v = lookupPlain(p, n.slice(0, -1).replace(/\s+$/, ''));
            if (v !== null) return v + ':';
        }
        return null;
    }

    function perLine(p, core) {
        var lines = core.split('\n'), any = false;
        for (var i = 0; i < lines.length; i++) {
            var e = edges(lines[i]);
            if (!e[1] || !LETTER.test(e[1])) continue;
            var v = lookup(p, normalize(e[1]));
            if (v !== null) { lines[i] = e[0] + v + e[2]; any = true; }
        }
        return any ? lines.join('\n') : null;
    }

    function translateWith(p, s) {
        if (!p || !s || s.length > MAX_TEXT) return null;
        var e = edges(s);
        var core = e[1];
        if (!core || !LETTER.test(core)) return null;
        var v = lookup(p, normalize(core));
        if (v === null && core.indexOf('\n') !== -1) v = perLine(p, core);
        return v === null ? null : e[0] + v + e[2];
    }

    function translate(s) { return translateWith(pack(), s); }

    function isEnglishKey(n) {
        for (var code in packs) {
            var p = packs[code];
            if (p.exact.has(n) || p.known.has(n)) return true;
        }
        return false;
    }

    // Single words are never reverse-mapped: they collide with hostnames and SSIDs.
    function reverseNormalized(n) {
        if (n.indexOf(' ') === -1 || isEnglishKey(n)) return null;
        var cur = pack();
        if (cur) { var k = cur.rev.get(n); if (k !== undefined) return k; }
        for (var code in packs) {
            if (packs[code] === cur) continue;
            var k2 = packs[code].rev.get(n);
            if (k2 !== undefined) return k2;
        }
        return null;
    }

    function reverse(s) {
        if (s.length > MAX_TEXT) return null;
        var e = edges(s);
        if (!e[1] || !LETTER.test(e[1])) return null;
        var k = reverseNormalized(normalize(e[1]));
        return k === null ? null : e[0] + k + e[2];
    }

    function knownKey(p, key) {
        return !!p && (p.exact.has(key) || p.known.has(key) || templateHit(p, key) !== null);
    }

    function skippedElement(el) {
        var tag = el.localName;
        if (SKIP_TAGS[tag]) return true;
        if (el.getAttribute('translate') === 'no') return true;
        var ce = el.getAttribute('contenteditable');
        if (ce === '' || ce === 'true') return true;
        var cl = el.classList;
        return !!cl && (cl.contains('notranslate') || cl.contains('xterm'));
    }

    function insideExcluded(node) {
        var p = node.nodeType === 1 ? node : node.parentElement;
        return !!(p && p.closest && p.closest(EXCLUDE_SEL));
    }

    function isGroup(el) {
        if (el.nodeType !== 1 || skippedElement(el)) return false;
        var hasText = false, hasPhrase = false;
        for (var c = el.firstChild; c; c = c.nextSibling) {
            var t = c.nodeType;
            if (t === 3) { if (!hasText && /\S/.test(c.data)) hasText = true; }
            else if (t === 1) { if (PHRASING[c.localName]) hasPhrase = true; else return false; }
            else if (t !== 8) return false;
        }
        return hasText && hasPhrase;
    }

    function processText(t) {
        var cur = t.data;
        var rec = textRec.get(t);
        var src;
        if (rec && cur === rec.out) {
            if (rec.lang === lang) return;
            src = rec.src;
        } else {
            if (!LETTER.test(cur)) { if (rec) textRec.delete(t); return; }
            src = cur;
        }
        var out = translate(src);
        if (out === null && src === cur) {
            var en = reverse(cur);
            if (en !== null) { src = en; out = translate(en); }
        }
        if (out === null) out = src;
        if (out !== cur) t.data = out;
        if (out !== src) { textRec.set(t, { src: src, out: out, lang: lang }); touched = true; }
        else if (rec) textRec.delete(t);
    }

    function processAttr(el, name) {
        if (name === 'value' && !(el.localName === 'input' && BUTTON_INPUT[(el.getAttribute('type') || '').toLowerCase()])) return;
        var cur = el.getAttribute(name);
        var recs = attrRec.get(el);
        var rec = recs && recs[name];
        if (cur === null) { if (rec) delete recs[name]; return; }
        var src;
        if (rec && cur === rec.out) {
            if (rec.lang === lang) return;
            src = rec.src;
        } else {
            if (!LETTER.test(cur)) { if (rec) delete recs[name]; return; }
            src = cur;
        }
        var out = translate(src);
        if (out === null && src === cur) {
            var en = reverse(cur);
            if (en !== null) { src = en; out = translate(en); }
        }
        if (out === null) out = src;
        if (out !== cur) el.setAttribute(name, out);
        if (out !== src) {
            if (!recs) { recs = {}; attrRec.set(el, recs); }
            recs[name] = { src: src, out: out, lang: lang };
            touched = true;
        } else if (rec) delete recs[name];
    }

    function processAttrs(el) {
        if (!el.hasAttributes()) return;
        for (var i = 0; i < ATTRS.length; i++) if (el.hasAttribute(ATTRS[i])) processAttr(el, ATTRS[i]);
        if (el.localName === 'input' && el.hasAttribute('value')) processAttr(el, 'value');
    }

    function sameChildren(el, list) {
        var c = el.firstChild, i = 0;
        for (; c; c = c.nextSibling, i++) if (list[i] !== c) return false;
        return i === list.length;
    }

    function setChildren(el, nodes) {
        while (el.firstChild) el.removeChild(el.firstChild);
        for (var i = 0; i < nodes.length; i++) el.appendChild(nodes[i]);
    }

    function buildGroupState(el, p) {
        var s = '', els = [], src = [];
        for (var c = el.firstChild; c; c = c.nextSibling) {
            src.push(c);
            if (c.nodeType === 3) {
                var r = textRec.get(c);
                if (r && c.data === r.out) { c.data = r.src; textRec.delete(c); }
                s += c.data;
            } else if (c.nodeType === 1) {
                s += '{' + els.length + '}';
                els.push(c);
            }
        }
        var e = edges(s);
        var key = normalize(e[1]);
        var st = { key: key, els: els, src: src, lead: e[0], trail: e[2], out: null, lang: null };
        if (LETTER.test(key) && key.length <= MAX_TEXT && !knownKey(p, key)) {
            var en = reverseNormalized(key);
            if (en !== null && placeholderList(en).length === els.length) { st.key = en; st.src = null; }
        }
        return st;
    }

    function pushText(segs, text) {
        if (!text) return;
        var last = segs.length - 1;
        if (last >= 0 && typeof segs[last] === 'string') segs[last] += text;
        else segs.push(text);
    }

    function groupSegments(p, st) {
        var key = st.key, nEls = st.els.length;
        var out = p.exact.get(key), hit = null;
        if (out === undefined) {
            hit = templateHit(p, key);
            if (!hit) return null;
            if (hit.same) return SAME;
            out = hit.out;
        } else if (out === key) {
            return SAME;
        }
        var segs = [], used = [], i;
        for (i = 0; i < nEls; i++) used.push(0);
        var parts = out.split(PH_SPLIT);
        for (i = 0; i < parts.length; i++) {
            if (!(i % 2)) { pushText(segs, parts[i]); continue; }
            var idx = +parts[i];
            if (!hit) {
                if (idx >= nEls) return null;
                segs.push(idx); used[idx]++;
                continue;
            }
            var cap = hit.m[idx + 1];
            if (cap === undefined) return null;
            var cparts = cap.split(PH_SPLIT);
            if (cparts.length === 1) { pushText(segs, captureText(p, cap, 0)); continue; }
            for (var j = 0; j < cparts.length; j++) {
                if (!(j % 2)) { pushText(segs, cparts[j]); continue; }
                var e = +cparts[j];
                if (e >= nEls) return null;
                segs.push(e); used[e]++;
            }
        }
        for (i = 0; i < nEls; i++) if (used[i] !== 1) return null;
        return segs;
    }

    function nodesFromSegments(st, segs) {
        var nodes = [];
        if (st.lead && typeof segs[0] !== 'string') nodes.push(document.createTextNode(st.lead));
        for (var i = 0; i < segs.length; i++) {
            var s = segs[i];
            if (typeof s === 'number') { nodes.push(st.els[s]); continue; }
            if (i === 0) s = st.lead + s.replace(/^\s+/, '');
            if (i === segs.length - 1) s = s.replace(/\s+$/, '') + st.trail;
            nodes.push(document.createTextNode(s));
        }
        if (st.trail && typeof segs[segs.length - 1] !== 'string') nodes.push(document.createTextNode(st.trail));
        return nodes;
    }

    function englishSegments(st) {
        var segs = [], parts = st.key.split(PH_SPLIT);
        for (var i = 0; i < parts.length; i++) {
            if (i % 2) segs.push(+parts[i]);
            else pushText(segs, parts[i]);
        }
        return segs;
    }

    function processGroup(el) {
        var p = pack();
        var rec = groupRec.get(el);
        var st;
        if (rec && sameChildren(el, rec.out)) {
            if (rec.lang === lang) return;
            st = rec;
        } else {
            st = buildGroupState(el, p);
        }
        var segs = p && LETTER.test(st.key) ? groupSegments(p, st) : null;
        if (segs === SAME) {
            if (st === rec) {
                setChildren(el, st.src || nodesFromSegments(st, englishSegments(st)));
                groupRec.delete(el);
            } else if (!st.src) {
                setChildren(el, nodesFromSegments(st, englishSegments(st)));
            }
            return;
        }
        if (segs) {
            var nodes = nodesFromSegments(st, segs);
            setChildren(el, nodes);
            st.out = nodes;
            st.lang = lang;
            groupRec.set(el, st);
            touched = true;
            return;
        }
        if (st === rec) {
            setChildren(el, st.src || nodesFromSegments(st, englishSegments(st)));
            groupRec.delete(el);
            if (!p) return;
        } else if (!st.src) {
            setChildren(el, nodesFromSegments(st, englishSegments(st)));
        }
        for (var c = el.firstChild; c; c = c.nextSibling) if (c.nodeType === 3) processText(c);
    }

    function processSubtree(node) {
        if (node.nodeType === 3) {
            var parent = node.parentNode;
            if (parent && parent.nodeType === 1 && isGroup(parent)) processGroup(parent);
            else processText(node);
            return;
        }
        if (node.nodeType !== 1 || skippedElement(node)) return;
        processAttrs(node);
        var group = isGroup(node);
        if (group) processGroup(node);
        var c = node.firstChild;
        while (c) {
            var next = c.nextSibling;
            if (c.nodeType === 1) processSubtree(c);
            else if (c.nodeType === 3 && !group) processText(c);
            c = next;
        }
    }

    function onMutations(records) {
        if (lang === 'en' && !touched) return;
        var seen = new Set();
        for (var i = 0; i < records.length; i++) {
            var r = records[i], tgt = r.target;
            if (r.type === 'childList') {
                if (tgt.nodeType === 1 && !seen.has(tgt) && tgt.isConnected && isGroup(tgt) && !insideExcluded(tgt)) {
                    seen.add(tgt);
                    processGroup(tgt);
                }
                var added = r.addedNodes;
                for (var j = 0; j < added.length; j++) {
                    var n = added[j];
                    if (seen.has(n) || !n.isConnected) continue;
                    seen.add(n);
                    if (n.nodeType === 3) {
                        var par = n.parentNode;
                        if (seen.has(par)) continue;
                        if (insideExcluded(n)) continue;
                        if (par.nodeType === 1 && isGroup(par)) { seen.add(par); processGroup(par); }
                        else processText(n);
                    } else if (n.nodeType === 1) {
                        if (n.parentElement && insideExcluded(n.parentElement)) continue;
                        processSubtree(n);
                    }
                }
            } else if (r.type === 'characterData') {
                if (seen.has(tgt) || !tgt.isConnected) continue;
                seen.add(tgt);
                var pa = tgt.parentNode;
                if (!pa || seen.has(pa) || insideExcluded(tgt)) continue;
                if (pa.nodeType === 1 && isGroup(pa)) { seen.add(pa); processGroup(pa); }
                else processText(tgt);
            } else if (r.type === 'attributes') {
                if (!tgt.isConnected || insideExcluded(tgt)) continue;
                processAttr(tgt, r.attributeName);
            }
        }
        if (observer) observer.takeRecords();
    }

    function startObserving() {
        if (observing || typeof MutationObserver === 'undefined') return;
        if (!observer) observer = new MutationObserver(onMutations);
        observer.observe(document.documentElement, {
            childList: true, subtree: true, characterData: true,
            attributes: true, attributeFilter: OBSERVED_ATTRS
        });
        observing = true;
    }

    function stopObserving() {
        if (!observing) return;
        observer.takeRecords();
        observer.disconnect();
        observing = false;
    }

    function fullPass() {
        if (lang === 'en' && !touched) return;
        processSubtree(document.documentElement);
        if (observer) observer.takeRecords();
    }

    function register(code, dict) {
        if (SUPPORTED.indexOf(code) === -1 || code === 'en') return;
        packs[code] = compile(dict);
    }

    function loadPack(code) {
        if (code === 'en' || packs[code]) return Promise.resolve();
        if (pendingLoads[code]) return pendingLoads[code];
        var url = '/scripts/i18n/' + code + '.json?v=' + encodeURIComponent(version);
        pendingLoads[code] = fetch(url, { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (dict) { register(code, dict); })
            .finally(function () { delete pendingLoads[code]; });
        return pendingLoads[code];
    }

    function notify() {
        for (var i = 0; i < listeners.length; i++) {
            try { listeners[i](lang); } catch (e) { /* ignore */ }
        }
        try { window.dispatchEvent(new CustomEvent('ragnar:languagechange', { detail: { lang: lang } })); } catch (e) { /* ignore */ }
    }

    function applyLanguage(code) {
        lang = code;
        try { document.documentElement.setAttribute('lang', code); } catch (e) { /* ignore */ }
        if (code !== 'en') startObserving();
        fullPass();
        if (code === 'en') stopObserving();
        var frames = document.getElementsByTagName('iframe');
        for (var i = 0; i < frames.length; i++) {
            try {
                var w = frames[i].contentWindow;
                if (w && w.RagnarI18n && w.RagnarI18n !== api) w.RagnarI18n.setLanguage(code, { persist: false });
            } catch (e) { /* ignore */ }
        }
        notify();
    }

    function persist(code) {
        return fetch('/api/i18n/language', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ language: code })
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (body) {
                if (!r.ok || body.success === false) throw new Error(body.error || ('HTTP ' + r.status));
                return body;
            });
        });
    }

    function remember(code) {
        try { localStorage.setItem('ragnar.lang', code); } catch (e) { /* ignore */ }
    }

    function setLanguage(code, opts) {
        opts = opts || {};
        code = String(code || '').toLowerCase();
        if (SUPPORTED.indexOf(code) === -1) return Promise.reject(new Error('Unsupported language: ' + code));
        return loadPack(code).then(function () {
            if (code !== lang) applyLanguage(code);
            remember(code);
            if (opts.persist === false) return { success: true, language: code };
            return persist(code);
        });
    }

    function syncFromServer() {
        return fetch('/api/i18n/language', { credentials: 'same-origin', cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                var code = d && d.language;
                if (code && code !== lang && SUPPORTED.indexOf(code) !== -1) return setLanguage(code, { persist: false });
            })
            .catch(function () { /* ignore */ });
    }

    function sourceText(node) {
        if (!node) return '';
        if (node.nodeType === 3) {
            var r = textRec.get(node);
            return r && node.data === r.out ? r.src : node.data;
        }
        if (node.nodeType !== 1) return '';
        var g = groupRec.get(node);
        if (g && sameChildren(node, g.out)) {
            if (g.src) {
                var s0 = '';
                for (var i = 0; i < g.src.length; i++) s0 += sourceText(g.src[i]);
                return s0;
            }
            return g.lead + g.key.replace(PH_ALL, function (m, k) { return sourceText(g.els[+k]); }) + g.trail;
        }
        var s = '';
        for (var c = node.firstChild; c; c = c.nextSibling) s += sourceText(c);
        return s;
    }

    function wrapDialog(name) {
        var native = window[name];
        if (typeof native !== 'function') return;
        window[name] = function (message) {
            var args = Array.prototype.slice.call(arguments);
            if (lang !== 'en' && args.length && message !== undefined && message !== null) {
                var s = String(message);
                var out = translate(s);
                if (out !== null) args[0] = out;
            }
            return native.apply(window, args);
        };
    }

    var api = {
        get lang() { return lang; },
        languages: SUPPORTED.slice(),
        names: NATIVE_NAMES,
        t: function (s) {
            if (s === undefined || s === null) return s;
            var out = translate(String(s));
            return out === null ? String(s) : out;
        },
        setLanguage: setLanguage,
        source: sourceText,
        onChange: function (fn) { if (typeof fn === 'function') listeners.push(fn); },
        refresh: fullPass,
        register: register,
        sync: syncFromServer
    };
    window.RagnarI18n = api;

    ['alert', 'confirm', 'prompt'].forEach(wrapDialog);

    if (boot.dict && boot.lang && boot.lang !== 'en') register(boot.lang, boot.dict);
    boot.dict = null;
    if (boot.lang && packs[boot.lang]) {
        lang = boot.lang;
        try { document.documentElement.setAttribute('lang', lang); } catch (e) { /* ignore */ }
        startObserving();
        fullPass();
    }

    function onReady() {
        fullPass();
        if (!boot.lang) syncFromServer();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
    else onReady();

    window.addEventListener('storage', function (e) {
        if (e.key === 'ragnar.lang' && e.newValue && e.newValue !== lang) {
            setLanguage(e.newValue, { persist: false }).catch(function () { /* ignore */ });
        }
    });
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible') syncFromServer();
    });
})();
