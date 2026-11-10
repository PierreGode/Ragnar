#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const acorn = require('acorn');
const { parseDocument } = require('htmlparser2');

const ROOT = path.resolve(__dirname, '..', '..');
const PACK_DIR = path.join(ROOT, 'web', 'scripts', 'i18n');
const LANGS = ['es', 'fr', 'de'];

const HTML_FILES = ['web/index_modern.html', 'web/login.html', 'web/wifi_config.html',
    'web/captive_portal.html', 'web/wardrive_mobile.html', 'web/observatory.html'];
const JS_FILES = ['web/scripts/ragnar_modern.js', 'web/scripts/ragnar_rtlsdr.js',
    'web/scripts/skyview.js', 'web/scripts/skyview_vr.js'];
const JS_DIRS = ['web/rusense', 'web/observatory/js'];

// Key rules below must stay identical to web/scripts/i18n.js.
const SKIP_TAGS = new Set(['script', 'style', 'code', 'pre', 'textarea', 'kbd', 'samp', 'noscript', 'template']);
const PHRASING = new Set(['a', 'abbr', 'b', 'bdi', 'bdo', 'br', 'cite', 'code', 'data', 'dfn', 'em', 'i', 'kbd',
    'mark', 'q', 's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr']);
const ATTRS = ['placeholder', 'title', 'aria-label', 'alt', 'data-tooltip', 'data-label', 'label'];
const LETTER = /[A-Za-zÀ-ɏ]/;

const TEXT_PH = '';
const TEXT_PH_END = '';
const EL_PH = '';
const EL_PH_END = '';
const TEXT_PH_RE = /(\d+)/g;

const catalog = new Map();

function norm(s) { return s.replace(/\s+/g, ' ').trim(); }

function literalOf(key) { return key.replace(/\{\d+\}/g, ' '); }

function junk(key) {
    const lit = literalOf(key);
    if (!LETTER.test(lit)) return true;
    if (/\b\d*(px|pt|em)\b[^.]*\b(sans-serif|serif|monospace)\b/.test(key)) return true;
    if (/^[\w.-]*(:(\{\d+\}|[\w.-]+))+$/.test(key) && !/\s/.test(key)) return true;
    if (/^[?&][\w-]+=/.test(key) || /[?&][\w-]+=(\{\d+\})?&/.test(key)) return true;
    if (/^style="/.test(key) || (/[a-z-]+\s*:\s*[^;]+;/.test(key) && /\b(rgba?|px|solid|border|background|margin|padding)\b/.test(key))) return true;
    if (/\b(vec[234]|mat[34]|gl_\w+|uniform|varying|sampler2D)\b/.test(key)) return true;
    if (/\b(attribute|precision)\s+(float|int|mediump|highp|lowp)\b|\bfloat\s+\w+\s*=|\bmix\(/.test(key)) return true;
    if (/^(rgba?|hsla?)\(/.test(key) || /^(translate|rotate|scale|matrix)[XYZ3d]*\(/.test(key)) return true;
    return false;
}

function acceptKey(key) {
    if (!key || junk(key)) return false;
    if (!/\{\d+\}/.test(key)) return true;
    const lit = literalOf(key).replace(/[^A-Za-zÀ-ɏ ]/g, '').trim();
    if (!lit) return false;
    if (/^\{\d+\}/.test(key) && /\{\d+\}$/.test(key)) {
        return lit.split(/\s+/).filter(w => w.length > 1).length >= 2;
    }
    return true;
}

function add(key, kind, ref, ctx) {
    if (!acceptKey(key)) return;
    let e = catalog.get(key);
    if (!e) { e = { kinds: new Set(), refs: new Set(), ctx: new Set() }; catalog.set(key, e); }
    e.kinds.add(kind);
    if (e.refs.size < 4) e.refs.add(ref);
    if (ctx && ctx !== key && e.ctx.size < 2) e.ctx.add(ctx.slice(0, 300));
}

function finishKey(raw, isGroup) {
    let s = raw;
    let prev;
    do { prev = s; s = s.replace(/(\d+)\s*(\d+)/g, TEXT_PH + '$1' + TEXT_PH_END); } while (s !== prev);
    s = norm(s);
    const map = new Map();
    const re = isGroup ? /(\d+)|(\d+)/g : TEXT_PH_RE;
    return s.replace(re, (m, t, e) => {
        const id = t !== undefined ? 't' + t : 'e' + e;
        if (!map.has(id)) map.set(id, map.size);
        return '{' + map.get(id) + '}';
    });
}

function excludedEl(el) {
    if (!el || el.type === 'root') return false;
    if (SKIP_TAGS.has((el.name || '').toLowerCase())) return true;
    const a = el.attribs || {};
    if (a.translate === 'no') return true;
    if (a.contenteditable === 'true' || a.contenteditable === '') return true;
    return !!(a.class && /(^|\s)(notranslate|xterm)(\s|$)/.test(a.class));
}

function isGroup(el) {
    if (excludedEl(el)) return false;
    let hasText = false, hasPhrase = false;
    for (const c of el.children || []) {
        if (c.type === 'text') { if (/\S/.test(c.data)) hasText = true; }
        else if (c.type === 'comment') continue;
        else if (c.type === 'tag' || c.type === 'script' || c.type === 'style') {
            if (PHRASING.has(c.name.toLowerCase())) hasPhrase = true; else return false;
        } else return false;
    }
    return hasText && hasPhrase;
}

function plainText(el) {
    let s = '';
    for (const c of el.children || []) {
        if (c.type === 'text') s += c.data;
        else if (c.type === 'tag') s += ' ' + plainText(c) + ' ';
    }
    return s;
}

function groupSkeleton(el) {
    let s = '', n = 0;
    for (const c of el.children) {
        if (c.type === 'text') s += c.data;
        else if (c.type === 'tag' || c.type === 'script' || c.type === 'style') s += EL_PH + (n++) + EL_PH_END;
    }
    return s;
}

function walkHtml(node, ref, inJs) {
    if (node.type === 'tag' || node.type === 'script' || node.type === 'style') {
        if (excludedEl(node)) {
            if (node.name === 'script' && !inJs) {
                const code = (node.children || []).map(c => c.data || '').join('');
                const type = (node.attribs && node.attribs.type) || '';
                if (code.trim() && (!type || /javascript|module/.test(type))) extractJs(code, ref + '<script>');
            }
            return;
        }
        const a = node.attribs || {};
        for (const at of ATTRS) if (a[at] !== undefined) add(finishKey(a[at], false), 'attr', ref, null);
        if (node.name === 'input' && /^(button|submit|reset)$/i.test(a.type || '') && a.value !== undefined) {
            add(finishKey(a.value, false), 'attr', ref, null);
        }
        if (!inJs) for (const at of Object.keys(a)) if (/^on[a-z]+$/.test(at) && a[at]) extractJs(a[at], ref + '@' + at);
    }
    if (node.type !== 'tag' && node.type !== 'root') return;
    if ((node.type === 'tag' || inJs) && isGroup(node)) {
        add(finishKey(groupSkeleton(node), true), 'group', ref, norm(plainText(node)));
        for (const c of node.children) if (c.type === 'tag') walkHtml(c, ref, inJs);
        return;
    }
    const ctx = node.type === 'tag' ? norm(plainText(node)) : null;
    for (const c of node.children || []) {
        if (c.type === 'text') add(finishKey(c.data, false), 'text', ref, ctx);
        else walkHtml(c, ref, inJs);
    }
}

function extractHtml(html, ref, inJs) {
    walkHtml(parseDocument(html, { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true }), ref, inJs);
}

const DISPLAY_PROPS = new Set(['textContent', 'innerText', 'innerHTML', 'outerHTML', 'title', 'placeholder', 'label', 'alt', 'text', 'ariaLabel']);
const NON_DISPLAY_CALLEES = new Set([
    'getElementById', 'querySelector', 'querySelectorAll', 'getElementsByClassName', 'getElementsByTagName', 'closest', 'matches',
    'add', 'remove', 'toggle', 'contains', 'replace', 'addEventListener', 'removeEventListener', 'dispatchEvent',
    'getAttribute', 'removeAttribute', 'hasAttribute', 'fetch', 'networkAwareFetch', 'fetchAPI', 'postAPI', 'getItem', 'setItem',
    'removeItem', 'log', 'warn', 'error', 'debug', 'info', 'trace', 'parse', 'stringify', 'split', 'join', 'match', 'matchAll',
    'test', 'exec', 'search', 'startsWith', 'endsWith', 'includes', 'indexOf', 'lastIndexOf', 'createElement', 'createElementNS',
    'parseInt', 'parseFloat', 'require', 'emit', 'on', 'off', 'once', 'open', 'send', 'setRequestHeader', 'postMessage',
    'Date', 'RegExp', 'encodeURIComponent', 'decodeURIComponent', 'toLocaleString', 'toLocaleDateString', 'toLocaleTimeString',
    'padStart', 'padEnd', 'localeCompare', 'getPropertyValue', 'setProperty', 'attr', 'style', 'classed', 'select', 'selectAll',
    'insert', 'scrollIntoView', 'focus', 'blur', 'replaceAll', 'normalize', 'charAt', 'charCodeAt', 'slice', 'substring', 'substr',
    'Worker', 'importScripts', 'setTimeout', 'setInterval', 'Function', 'eval', 'Symbol', 'define', 'get', 'has', 'delete', 'set'
]);
const NON_DISPLAY_KEYS = new Set(['class', 'className', 'cls', 'color', 'colour', 'icon', 'type', 'id', 'key', 'url', 'href', 'src',
    'path', 'method', 'endpoint', 'api', 'action', 'mode', 'kind', 'value', 'val', 'bg', 'fg', 'border', 'tone', 'badge', 'dot',
    'ring', 'css', 'style', 'tag', 'el', 'elementId', 'selector', 'event', 'field', 'unit', 'fmt', 'format', 'pattern', 'regex',
    're', 'stroke', 'fill', 'textColor', 'bgColor', 'iconClass', 'hex', 'rgb', 'emoji', 'sym', 'symbol', 'code', 'cmd', 'command',
    'bin', 'pkg', 'package', 'tool', 'module', 'file', 'filename', 'ext', 'mime', 'contentType', 'accept', 'target', 'rel', 'role',
    'state', 'font']);
const DISPLAY_KEYS = new Set(['label', 'title', 'text', 'message', 'msg', 'desc', 'description', 'hint', 'placeholder', 'tooltip',
    'tip', 'short', 'long', 'summary', 'detail', 'details', 'reason', 'caption', 'heading', 'header', 'help', 'note', 'notes', 'name',
    'subtitle', 'sub', 'blurb', 'explain', 'explanation', 'why', 'what', 'how', 'fix', 'advice', 'recommendation', 'button', 'btn',
    'confirm', 'prompt', 'empty', 'emptyText', 'loading', 'error', 'warning', 'success', 'info', 'verdict', 'meaning', 'impact',
    'risk', 'nextStep', 'next', 'display', 'displayName', 'legend', 'question', 'answer', 'body', 'html', 'content', 'status',
    'statusText', 'line', 'lines', 'headline', 'lede', 'intro', 'footer', 'remedy', 'mitigation', 'cause', 'effect', 'result',
    'outcome']);
const DISPLAY_CALL_RE = /^(alert|confirm|prompt|showNotification|addConsoleMessage|notify|toast|showToast|setManualActionHelper|_ndBusy|setStatus|showError|showSuccess|showMessage|showWarning|showInfo)$/i;
const DISPLAY_CALL_HINT = /(Notif|Toast|Message|Status|Label|Text|Title|Hint|Banner|Error|Warn|Busy|Msg|Note|Caption|Tooltip|Summary)/;
const MAX_VARIANTS = 12;

function isStr(n) { return n && n.type === 'Literal' && typeof n.value === 'string'; }

function isStringy(n) {
    if (!n) return false;
    if (isStr(n) || n.type === 'TemplateLiteral') return true;
    return n.type === 'BinaryExpression' && n.operator === '+' && (isStringy(n.left) || isStringy(n.right));
}

function yieldsString(n) {
    if (isStringy(n)) return true;
    if (n.type === 'ConditionalExpression') return yieldsString(n.consequent) || yieldsString(n.alternate);
    if (n.type === 'LogicalExpression') return yieldsString(n.right);
    return false;
}

function product(a, b) {
    const out = [];
    for (const x of a) for (const y of b) { out.push(x.concat(y)); if (out.length >= MAX_VARIANTS) return out; }
    return out;
}

function flatten(n, opaque, ph) {
    if (isStr(n)) return [[{ lit: n.value }]];
    if (n.type === 'TemplateLiteral') {
        let acc = [[]];
        n.quasis.forEach((q, i) => {
            const cooked = q.value.cooked == null ? q.value.raw : q.value.cooked;
            acc = acc.map(v => v.concat([{ lit: cooked }]));
            if (i < n.expressions.length) acc = product(acc, inner(n.expressions[i], opaque, ph));
        });
        return acc;
    }
    if (n.type === 'BinaryExpression' && n.operator === '+' && isStringy(n)) {
        return product(inner(n.left, opaque, ph), inner(n.right, opaque, ph));
    }
    return inner(n, opaque, ph);
}

function inner(n, opaque, ph) {
    if (isStringy(n)) return flatten(n, opaque, ph);
    if (n.type === 'ConditionalExpression' && (yieldsString(n.consequent) || yieldsString(n.alternate))) {
        opaque.push(n.test);
        const branch = b => {
            if (yieldsString(b)) return inner(b, opaque, ph);
            opaque.push(b);
            return [[{ ph: ph.next++ }]];
        };
        return branch(n.consequent).concat(branch(n.alternate)).slice(0, MAX_VARIANTS);
    }
    if (n.type === 'LogicalExpression' && yieldsString(n.right)) {
        opaque.push(n.left);
        return [[{ ph: ph.next++ }]].concat(inner(n.right, opaque, ph)).slice(0, MAX_VARIANTS);
    }
    opaque.push(n);
    return [[{ ph: ph.next++ }]];
}

function partsToString(parts) {
    return parts.map(p => (p.lit !== undefined ? p.lit : TEXT_PH + p.ph + TEXT_PH_END)).join('');
}

function looksHtml(s) { return /<\/?[a-zA-Z][^<>]*>|<br\s*\/?>/.test(s); }

function naturalLanguage(s, displayed) {
    const t = norm(s.replace(TEXT_PH_RE, ' X '));
    if (!LETTER.test(t.replace(/\bX\b/g, ''))) return false;
    if (/^(https?:|wss?:|\/|\.\.?\/|#[\w-]|data:|mailto:|blob:)/i.test(t) || /\/api\//.test(t)) return false;
    if (/[{};]\s*$|=>|\$\{|^\s*[\[{(]|function\s*\(|\breturn\b.*;/.test(t)) return false;
    if (/^[\w.-]+\.(js|css|png|jpg|svg|json|html|py|sh|csv|txt|log|ico|woff2?|gz|zip|pcap|pcapng|kml|gpx)$/i.test(t)) return false;
    if (/^[a-z]+\/[a-z0-9.+-]+$/i.test(t)) return false;
    const tokens = t.split(' ');
    if (tokens.every(tok => /^[a-z0-9!:\-\[\]\/\.%#_()&>~+*=,]+$/.test(tok)) && tokens.some(tok => /[-:]/.test(tok)) && !/[A-Z]/.test(t)) return false;
    if (/^[.#][\w-]+([\s>.#:\[][\w\-\s>.#:\[\]="'()*]*)?$/.test(t) || /^\[[\w-]+(=[^\]]*)?\]$/.test(t)) return false;
    if (tokens.length === 1) {
        const w = tokens[0];
        if (w.length < 2) return false;
        if (/^[a-z][a-z0-9]*([_-][a-z0-9]+)+$/.test(w) || /^[a-z]+[A-Z]\w*$/.test(w)) return false;
        if (!displayed && (/^[A-Z0-9_]{2,}$/.test(w) || /^[a-z][a-z0-9]*$/.test(w) || /^\d/.test(w))) return false;
    }
    const letters = (t.match(/[A-Za-zÀ-ɏ]/g) || []).length;
    return !(letters / t.length < 0.45 && tokens.length < 3);
}

function propName(m) {
    if (!m || m.type !== 'MemberExpression') return null;
    if (!m.computed && m.property.type === 'Identifier') return m.property.name;
    if (m.computed && isStr(m.property)) return m.property.value;
    return null;
}

function calleeName(c) {
    if (!c) return null;
    if (c.type === 'Identifier') return c.name;
    return propName(c);
}

function context(parent, node) {
    if (!parent) return 'neutral';
    switch (parent.type) {
        case 'BinaryExpression':
            return ['===', '!==', '==', '!=', 'in', 'instanceof'].includes(parent.operator) ? 'skip' : 'neutral';
        case 'SwitchCase': return parent.test === node ? 'skip' : 'neutral';
        case 'Property': {
            if (parent.key === node) return parent.computed ? 'skip' : 'key';
            const k = parent.key && (parent.key.name || parent.key.value);
            if (k && NON_DISPLAY_KEYS.has(k)) return 'skip';
            return k && DISPLAY_KEYS.has(k) ? 'display' : 'neutral';
        }
        case 'MemberExpression':
        case 'ImportDeclaration': case 'ExportAllDeclaration': case 'ExportNamedDeclaration':
            return 'skip';
        case 'CallExpression': case 'NewExpression': {
            const name = calleeName(parent.callee);
            if (name === 'setAttribute') {
                const an = parent.arguments[0];
                return parent.arguments.indexOf(node) > 0 && isStr(an) && ATTRS.includes(an.value) ? 'display' : 'skip';
            }
            if (name && NON_DISPLAY_CALLEES.has(name)) return 'skip';
            if (name && (DISPLAY_CALL_RE.test(name) || DISPLAY_CALL_HINT.test(name))) return 'display';
            if (name === 'Error' || name === 'TypeError' || name === 'createTextNode' || name === 'text' || name === 'html'
                || name === 'append' || name === 'prepend' || name === 'after' || name === 'before' || name === 'replaceWith') return 'display';
            return 'neutral';
        }
        case 'AssignmentExpression': {
            if (parent.left === node) return 'skip';
            const pn = propName(parent.left);
            if (pn && DISPLAY_PROPS.has(pn)) return 'display';
            if (pn && /^(className|id|src|href|type|value|name|cssText|display|width|height|color|background|transform|opacity|onclick|font)$/.test(pn)) return 'skip';
            if (parent.left.type === 'MemberExpression' && propName(parent.left.object) === 'style') return 'skip';
            return 'neutral';
        }
        default: return 'neutral';
    }
}

function handleRoot(n, parent, ref) {
    const opaque = [];
    const variants = flatten(n, opaque, { next: 0 });
    const ctx = context(parent, n);
    const where = ref + ':' + (n.loc ? n.loc.start.line : 0);
    if (ctx === 'key') {
        if (isStr(n) && /^[A-Z]/.test(n.value) && /[a-z]/.test(n.value) && !/^[\w.]+(-[\w.]+)+$/.test(n.value)
            && naturalLanguage(n.value, false)) {
            add(finishKey(n.value, false), 'js', where, null);
        }
    } else if (ctx !== 'skip') {
        for (const parts of variants) {
            const s = partsToString(parts);
            if (looksHtml(s)) { extractHtml(s, where, true); continue; }
            const displayed = ctx === 'display';
            for (const line of s.split('\n')) {
                if (naturalLanguage(line, displayed)) add(finishKey(line, false), 'js', where, null);
            }
        }
    }
    for (const o of opaque) visit(o, n, ref);
}

function visit(n, parent, ref) {
    if (!n || typeof n.type !== 'string') return;
    if (isStringy(n)) { handleRoot(n, parent, ref); return; }
    for (const key of Object.keys(n)) {
        if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
        const v = n[key];
        if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string') visit(c, n, ref); }
        else if (v && typeof v.type === 'string') visit(v, n, ref);
    }
}

function extractJs(code, ref) {
    const opts = { ecmaVersion: 'latest', allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, locations: true };
    let ast;
    try { ast = acorn.parse(code, Object.assign({ sourceType: 'script' }, opts)); }
    catch (e) {
        try { ast = acorn.parse(code, Object.assign({ sourceType: 'module' }, opts)); }
        catch (e2) { console.error(`skipped ${ref}: ${e2.message}`); return; }
    }
    visit(ast, null, ref);
}

function listJs(dir) {
    const out = [];
    for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
        const p = dir + '/' + e.name;
        if (e.isDirectory()) out.push(...listJs(p));
        else if (e.name.endsWith('.js')) out.push(p);
    }
    return out.sort();
}

function extractBackend() {
    const script = path.join(__dirname, 'extract_backend.py');
    for (const py of ['python3', 'python']) {
        try {
            const out = execFileSync(py, [script, ROOT], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
            const found = JSON.parse(out);
            for (const [key, refs] of Object.entries(found)) for (const r of refs) add(key, 'backend', r, null);
            return true;
        } catch (e) {
            if (e.code !== 'ENOENT') { console.error(`backend extraction failed (${py}): ${e.message}`); return false; }
        }
    }
    console.error('backend extraction skipped: no python3/python on PATH');
    return false;
}

function buildCatalog() {
    for (const f of HTML_FILES) extractHtml(fs.readFileSync(path.join(ROOT, f), 'utf8'), f, false);
    for (const f of JS_FILES.concat(...JS_DIRS.map(listJs))) extractJs(fs.readFileSync(path.join(ROOT, f), 'utf8'), f);
    extractBackend();
    const out = {};
    for (const key of [...catalog.keys()].sort()) {
        const e = catalog.get(key);
        out[key] = { kinds: [...e.kinds], refs: [...e.refs], ctx: [...e.ctx] };
    }
    return out;
}

function readPack(lang) {
    const p = path.join(PACK_DIR, lang + '.json');
    return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : {};
}

function writePack(lang, pack) {
    const sorted = {};
    for (const k of Object.keys(pack).sort()) sorted[k] = pack[k];
    fs.writeFileSync(path.join(PACK_DIR, lang + '.json'), JSON.stringify(sorted, null, 1) + '\n');
}

function main() {
    const args = process.argv.slice(2);
    const opt = name => { const i = args.indexOf(name); return i === -1 ? null : (args[i + 1] || ''); };
    const cat = buildCatalog();
    const keys = Object.keys(cat);
    if (opt('--catalog') !== null) {
        fs.writeFileSync(opt('--catalog'), JSON.stringify(cat, null, 1));
        console.log(`wrote ${keys.length} keys to ${opt('--catalog')}`);
    }
    const missingDir = opt('--missing');
    for (const lang of LANGS) {
        const pack = readPack(lang);
        const missing = keys.filter(k => typeof pack[k] !== 'string');
        const stale = Object.keys(pack).filter(k => !cat[k]);
        console.log(`${lang}: ${keys.length - missing.length}/${keys.length} translated, ${missing.length} missing, ${stale.length} unused`);
        if (missingDir) {
            fs.mkdirSync(missingDir, { recursive: true });
            const m = {};
            for (const k of missing) m[k] = cat[k];
            fs.writeFileSync(path.join(missingDir, lang + '.missing.json'), JSON.stringify(m, null, 1));
        }
        if (args.includes('--prune') && stale.length) {
            for (const k of stale) delete pack[k];
            writePack(lang, pack);
            console.log(`${lang}: pruned ${stale.length} unused entries`);
        }
    }
}

main();
