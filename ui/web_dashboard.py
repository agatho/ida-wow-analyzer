"""
Interactive Web-Based Analysis Dashboard for TC WoW Analyzer.

Serves analysis results from the SQLite knowledge DB in a rich, interactive
web UI.  Uses only Python stdlib (http.server + threading) so there are no
external dependencies.  The server runs in a daemon thread so the IDA UI
stays responsive.

Entry points:
    start_web_dashboard(session, port=8421)
    stop_web_dashboard()
    is_dashboard_running() -> bool
"""

import http.server
import json
import os
import re
import sqlite3
import threading
import time
import webbrowser
from html import escape as html_escape
from urllib.parse import urlparse, parse_qs

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_server = None           # type: http.server.HTTPServer | None
_server_thread = None    # type: threading.Thread | None
_db_path = None          # type: str | None
_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def start_web_dashboard(session, port=8421):
    """Start the dashboard web server and open a browser.

    Args:
        session: PluginSession with an open KnowledgeDB at session.db.
        port: TCP port to listen on (will try port, port+1, ... port+9).
    """
    global _server, _server_thread, _db_path

    with _lock:
        if _server is not None:
            msg_warn("Web dashboard is already running — opening browser")
            _open_browser(_server.server_address[1])
            return

        if session.db is None:
            msg_error("Cannot start web dashboard: no database loaded")
            return

        _db_path = session.db.path

        # Try a range of ports in case the default is occupied
        bound = False
        for offset in range(10):
            try_port = port + offset
            try:
                srv = http.server.HTTPServer(
                    ("127.0.0.1", try_port), _DashboardHandler
                )
                _server = srv
                bound = True
                break
            except OSError:
                msg_warn(f"Port {try_port} in use, trying next...")

        if not bound:
            msg_error(f"Could not bind to any port in range "
                      f"{port}..{port + 9}")
            return

        actual_port = _server.server_address[1]
        _server_thread = threading.Thread(
            target=_server.serve_forever,
            name="TCWoWDashboard",
            daemon=True,
        )
        _server_thread.start()
        msg_info(f"Web dashboard started at http://127.0.0.1:{actual_port}/")
        _open_browser(actual_port)


def stop_web_dashboard():
    """Stop the dashboard web server if running."""
    global _server, _server_thread, _db_path

    with _lock:
        if _server is None:
            return
        msg_info("Stopping web dashboard...")
        _server.shutdown()
        _server = None
        _server_thread = None
        _db_path = None


def is_dashboard_running() -> bool:
    """Return True if the web dashboard server is alive."""
    with _lock:
        return _server is not None


# ═══════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════

def _open_browser(port):
    """Fire-and-forget browser open on a tiny thread."""
    threading.Thread(
        target=lambda: webbrowser.open(f"http://127.0.0.1:{port}/"),
        daemon=True,
    ).start()


def _get_db_connection():
    """Open a fresh read-only SQLite connection for the current request.

    Each request gets its own connection for thread safety.
    """
    if _db_path is None:
        return None
    conn = sqlite3.connect(_db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA query_only=ON")
    return conn


def _rows_to_dicts(rows):
    """Convert a list of sqlite3.Row objects into plain dicts."""
    return [dict(r) for r in rows]


def _safe_json(obj):
    """Serialize *obj* to JSON, handling non-standard types."""
    def _default(o):
        if isinstance(o, bytes):
            return o.hex()
        return str(o)
    return json.dumps(obj, default=_default, ensure_ascii=False)


def _kv_get(conn, key, default=None):
    """Read a single value from the kv_store."""
    row = conn.execute(
        "SELECT value FROM kv_store WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return row["value"]


def _table_count(conn, table):
    """Return row count for *table*."""
    try:
        row = conn.execute(f"SELECT COUNT(*) AS cnt FROM {table}").fetchone()
        return row["cnt"] if row else 0
    except Exception:
        return 0


def _get_all_stats(conn):
    """Return a dict of every table count plus derived metrics."""
    tables = [
        "functions", "opcodes", "jam_types", "db2_tables",
        "vtables", "vtable_entries", "lua_api", "update_fields",
        "annotations", "strings", "diffing",
    ]
    stats = {}
    for t in tables:
        stats[t] = _table_count(conn, t)

    # KV-derived counters
    kv_count = _table_count(conn, "kv_store")
    stats["kv_entries"] = kv_count

    # Opcode direction breakdown
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM opcodes WHERE direction='CMSG'"
        ).fetchone()
        stats["cmsg_count"] = row["cnt"] if row else 0
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM opcodes WHERE direction='SMSG'"
        ).fetchone()
        stats["smsg_count"] = row["cnt"] if row else 0
    except Exception:
        stats["cmsg_count"] = 0
        stats["smsg_count"] = 0

    # System function counts
    try:
        rows = conn.execute(
            "SELECT system, COUNT(*) AS cnt FROM functions "
            "WHERE system IS NOT NULL GROUP BY system ORDER BY cnt DESC"
        ).fetchall()
        stats["systems"] = {r["system"]: r["cnt"] for r in rows}
    except Exception:
        stats["systems"] = {}

    stats["total"] = sum(
        stats.get(t, 0) for t in tables
    )
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# Embedded HTML / CSS / JS
# ═══════════════════════════════════════════════════════════════════════════

_CSS = r"""
:root {
    --bg-base:      #1e1e2e;
    --bg-surface:   #313244;
    --bg-overlay:   #45475a;
    --bg-mantle:    #181825;
    --bg-crust:     #11111b;
    --text:         #cdd6f4;
    --text-sub:     #a6adc8;
    --text-dim:     #585b70;
    --blue:         #89b4fa;
    --lavender:     #b4befe;
    --mauve:        #cba6f7;
    --green:        #a6e3a1;
    --yellow:       #f9e2af;
    --peach:        #fab387;
    --red:          #f38ba8;
    --teal:         #94e2d5;
    --sky:          #89dceb;
    --sapphire:     #74c7ec;
    --flamingo:     #f2cdcd;
    --rosewater:    #f5e0dc;
}
*,*::before,*::after{box-sizing:border-box}
html{font-size:14px}
body{
    margin:0;padding:0;
    background:var(--bg-base);color:var(--text);
    font-family:'Segoe UI','Inter',system-ui,sans-serif;
    line-height:1.55;
}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline;color:var(--lavender)}
h1,h2,h3{margin:0 0 .5em;font-weight:600}
h1{font-size:1.6rem}
h2{font-size:1.25rem;color:var(--lavender)}
h3{font-size:1.05rem;color:var(--mauve)}

/* ── Layout ────────────────────────────────── */
.app{display:flex;flex-direction:column;min-height:100vh}
.topbar{
    display:flex;align-items:center;gap:16px;
    padding:10px 24px;background:var(--bg-crust);
    border-bottom:1px solid var(--bg-overlay);
    position:sticky;top:0;z-index:100;
}
.topbar .brand{font-weight:700;font-size:1.1rem;color:var(--mauve);white-space:nowrap}
.topbar .brand span{color:var(--text-dim);font-weight:400;font-size:.85rem;margin-left:8px}
.nav{display:flex;gap:4px;flex-wrap:wrap}
.nav a{
    padding:6px 14px;border-radius:6px;font-size:.85rem;
    transition:background .15s,color .15s;color:var(--text-sub);
}
.nav a:hover{background:var(--bg-surface);color:var(--text);text-decoration:none}
.nav a.active{background:var(--bg-surface);color:var(--mauve);font-weight:600}
.search-box{margin-left:auto;position:relative}
.search-box input{
    padding:7px 12px 7px 32px;width:280px;
    background:var(--bg-surface);border:1px solid var(--bg-overlay);
    color:var(--text);border-radius:6px;font-size:.85rem;
    outline:none;transition:border-color .15s;
}
.search-box input:focus{border-color:var(--blue)}
.search-box svg{position:absolute;left:9px;top:50%;transform:translateY(-50%);opacity:.5}
.main{padding:24px;flex:1;max-width:1600px;margin:0 auto;width:100%}

/* ── Cards ─────────────────────────────────── */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:24px}
.card{
    background:var(--bg-surface);border-radius:10px;padding:16px 18px;
    border:1px solid transparent;transition:border-color .2s;
}
.card:hover{border-color:var(--bg-overlay)}
.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim);margin-bottom:4px}
.card .value{font-size:1.75rem;font-weight:700;line-height:1.2}
.card .sub{font-size:.8rem;color:var(--text-sub);margin-top:2px}

/* ── Meter ─────────────────────────────────── */
.meter-wrap{margin-bottom:24px}
.meter{height:22px;background:var(--bg-overlay);border-radius:11px;overflow:hidden;position:relative}
.meter .fill{height:100%;border-radius:11px;transition:width .6s ease}
.meter .label-over{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:.75rem;font-weight:600}

/* ── Tables ────────────────────────────────── */
.tbl-wrap{overflow-x:auto;margin-bottom:24px;border-radius:8px;border:1px solid var(--bg-overlay)}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:8px 12px;text-align:left}
th{
    background:var(--bg-overlay);position:sticky;top:0;z-index:1;
    cursor:pointer;user-select:none;font-weight:600;
    white-space:nowrap;
}
th:hover{color:var(--blue)}
th .sort-arrow{margin-left:4px;font-size:.65rem;opacity:.5}
th .sort-arrow.active{opacity:1;color:var(--blue)}
tr{border-bottom:1px solid var(--bg-overlay)}
tr:last-child{border-bottom:none}
tr:hover{background:rgba(137,180,250,.06)}
td.mono{font-family:'Cascadia Code','Fira Code',monospace;font-size:.8rem}
td.clickable{cursor:pointer;color:var(--blue)}
td.clickable:hover{text-decoration:underline}

/* ── Score colors ──────────────────────────── */
.sc-good{color:var(--green)}
.sc-ok{color:var(--teal)}
.sc-warn{color:var(--yellow)}
.sc-poor{color:var(--peach)}
.sc-bad{color:var(--red)}

/* ── Code blocks ───────────────────────────── */
pre{
    background:var(--bg-mantle);padding:14px 16px;border-radius:8px;
    overflow-x:auto;font-size:.82rem;line-height:1.5;
    border:1px solid var(--bg-overlay);
}
code{font-family:'Cascadia Code','Fira Code','Consolas',monospace}
.kw{color:var(--mauve);font-weight:600}
.ty{color:var(--yellow)}
.fn{color:var(--blue)}
.st{color:var(--green)}
.cm{color:var(--text-dim);font-style:italic}
.nu{color:var(--peach)}
.pp{color:var(--flamingo)}

/* ── Diff ──────────────────────────────────── */
.diff-add{background:rgba(166,227,161,.1);color:var(--green)}
.diff-del{background:rgba(243,139,168,.1);color:var(--red)}

/* ── Tags ──────────────────────────────────── */
.tag{
    display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;
    font-weight:600;margin-right:4px;
}
.tag-cmsg{background:rgba(137,180,250,.15);color:var(--blue)}
.tag-smsg{background:rgba(203,166,247,.15);color:var(--mauve)}
.tag-matched{background:rgba(166,227,161,.15);color:var(--green)}
.tag-unknown{background:rgba(249,226,175,.15);color:var(--yellow)}
.tag-new{background:rgba(148,226,213,.15);color:var(--teal)}
.tag-removed{background:rgba(243,139,168,.15);color:var(--red)}

/* ── Detail panel ──────────────────────────── */
.detail-panel{
    background:var(--bg-surface);border-radius:10px;
    padding:20px 24px;margin-bottom:24px;
    border:1px solid var(--bg-overlay);
}
.detail-panel .section{margin-bottom:18px}
.detail-panel .section:last-child{margin-bottom:0}
.detail-grid{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;font-size:.85rem}
.detail-grid .lbl{color:var(--text-dim);font-weight:600}

/* ── Tabs ──────────────────────────────────── */
.tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:2px solid var(--bg-overlay);padding-bottom:0}
.tabs button{
    background:none;border:none;color:var(--text-sub);padding:8px 16px;
    cursor:pointer;font-size:.85rem;border-bottom:2px solid transparent;
    margin-bottom:-2px;transition:all .15s;
}
.tabs button:hover{color:var(--text)}
.tabs button.active{color:var(--mauve);border-bottom-color:var(--mauve);font-weight:600}
.tab-content{display:none}
.tab-content.active{display:block}

/* ── Graph (SVG) ───────────────────────────── */
.graph-container{
    background:var(--bg-mantle);border-radius:8px;
    border:1px solid var(--bg-overlay);
    overflow:auto;min-height:400px;position:relative;
}
.graph-container svg{display:block}
.graph-node{cursor:pointer}
.graph-node circle{transition:r .2s}
.graph-node:hover circle{r:8}
.graph-edge{stroke:var(--bg-overlay);stroke-width:1.2}
.graph-label{font-size:10px;fill:var(--text-sub);pointer-events:none}

/* ── Loading / Empty ───────────────────────── */
.loading{text-align:center;padding:40px;color:var(--text-dim)}
.loading::after{content:'';display:inline-block;width:20px;height:20px;border:2px solid var(--text-dim);border-top-color:transparent;border-radius:50%;animation:spin .6s linear infinite;margin-left:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:40px;color:var(--text-dim);font-style:italic}

/* ── Responsive ────────────────────────────── */
@media(max-width:900px){
    .topbar{flex-wrap:wrap;padding:8px 12px}
    .search-box{margin-left:0;width:100%;order:10}
    .search-box input{width:100%}
    .main{padding:12px}
    .cards{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
}
"""

_JS = r"""
/* ═══════════════════════════════════════════════════════════════════════ */
/* TC WoW Analyzer — Dashboard JS (embedded, no dependencies)           */
/* ═══════════════════════════════════════════════════════════════════════ */

const API = '';  // same origin
let _cache = {};

/* ── Fetch helper ──────────────────────────── */
async function api(endpoint) {
    const key = endpoint;
    if (_cache[key]) return _cache[key];
    try {
        const r = await fetch(API + endpoint);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        _cache[key] = data;
        return data;
    } catch (e) {
        console.error('API error:', endpoint, e);
        return null;
    }
}

function clearCache(prefix) {
    if (!prefix) { _cache = {}; return; }
    for (const k of Object.keys(_cache)) {
        if (k.startsWith(prefix)) delete _cache[k];
    }
}

/* ── DOM helpers ───────────────────────────── */
const $ = (s, p) => (p || document).querySelector(s);
const $$ = (s, p) => [...(p || document).querySelectorAll(s)];
const el = (tag, attrs, ...children) => {
    const e = document.createElement(tag);
    if (attrs) for (const [k,v] of Object.entries(attrs)) {
        if (k === 'class') e.className = v;
        else if (k === 'html') e.innerHTML = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v);
    }
    for (const c of children) {
        if (typeof c === 'string') e.appendChild(document.createTextNode(c));
        else if (c) e.appendChild(c);
    }
    return e;
};

/* ── Formatting ────────────────────────────── */
function fmtNum(n) {
    if (n == null) return '-';
    return Number(n).toLocaleString();
}
function fmtAddr(a) {
    if (a == null) return '-';
    if (typeof a === 'string') return a;
    return '0x' + a.toString(16).toUpperCase();
}
function scoreClass(s) {
    if (s == null) return '';
    if (s >= 80) return 'sc-good';
    if (s >= 65) return 'sc-ok';
    if (s >= 50) return 'sc-warn';
    if (s >= 30) return 'sc-poor';
    return 'sc-bad';
}
function scoreTag(s) {
    if (s == null) return '<span class="sc-bad">-</span>';
    return `<span class="${scoreClass(s)}">${s.toFixed?s.toFixed(1):s}%</span>`;
}
function dirTag(d) {
    return d === 'CMSG'
        ? '<span class="tag tag-cmsg">CMSG</span>'
        : '<span class="tag tag-smsg">SMSG</span>';
}
function statusTag(s) {
    const cls = ({matched:'tag-matched',unknown:'tag-unknown','new':'tag-new',removed:'tag-removed'})[s] || 'tag-unknown';
    return `<span class="tag ${cls}">${s||'unknown'}</span>`;
}

/* ── Syntax highlighting (basic C++) ───────── */
function highlightCpp(code) {
    if (!code) return '';
    let h = code
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/(\/\/[^\n]*)/g, '<span class="cm">$1</span>')
        .replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="cm">$1</span>')
        .replace(/("(?:[^"\\]|\\.)*")/g, '<span class="st">$1</span>')
        .replace(/\b(void|int|uint8|uint16|uint32|uint64|int8|int16|int32|int64|float|double|bool|char|auto|const|static|class|struct|enum|typedef|typename|template|namespace|return|if|else|for|while|do|switch|case|break|continue|default|try|catch|throw|new|delete|using|virtual|override|public|private|protected|nullptr|true|false|this)\b/g, '<span class="kw">$1</span>')
        .replace(/\b(Player|WorldSession|WorldPacket|Creature|Unit|Map|ObjectGuid|ByteBuffer|std::\w+|TC_LOG_\w+)\b/g, '<span class="ty">$1</span>')
        .replace(/\b(\d+\.?\d*[fFuUlL]*)\b/g, '<span class="nu">$1</span>')
        .replace(/(#\s*\w+[^\n]*)/g, '<span class="pp">$1</span>');
    return h;
}

/* ── Sorting ───────────────────────────────── */
function makeSortable(table) {
    const ths = $$('th', table);
    let sortCol = -1, sortAsc = true;
    const tbody = $('tbody', table);
    if (!tbody) return;
    ths.forEach((th, i) => {
        th.innerHTML += ' <span class="sort-arrow">&#9650;</span>';
        th.addEventListener('click', () => {
            if (sortCol === i) sortAsc = !sortAsc;
            else { sortCol = i; sortAsc = true; }
            ths.forEach(t => { const a = $('.sort-arrow',t); if(a){a.className='sort-arrow';a.innerHTML='&#9650;'} });
            const arrow = $('.sort-arrow', th);
            arrow.className = 'sort-arrow active';
            arrow.innerHTML = sortAsc ? '&#9650;' : '&#9660;';
            const rows = [...tbody.querySelectorAll('tr')];
            rows.sort((a,b) => {
                let va = a.children[i]?.textContent?.trim() || '';
                let vb = b.children[i]?.textContent?.trim() || '';
                const na = parseFloat(va.replace(/[,%]/g,''));
                const nb = parseFloat(vb.replace(/[,%]/g,''));
                if (!isNaN(na) && !isNaN(nb)) return sortAsc ? na-nb : nb-na;
                return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
            });
            rows.forEach(r => tbody.appendChild(r));
        });
    });
}

/* ── Router ────────────────────────────────── */
const routes = {};
function registerRoute(hash, loader) { routes[hash] = loader; }
function navigate(hash) {
    window.location.hash = hash;
    loadRoute(hash);
}
function loadRoute(hash) {
    hash = hash || window.location.hash || '#overview';
    if (!hash.startsWith('#')) hash = '#' + hash;
    $$('.nav a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === hash));
    const loader = routes[hash] || routes['#overview'];
    const main = $('#content');
    if (main && loader) {
        main.innerHTML = '<div class="loading">Loading</div>';
        loader(main).catch(e => {
            main.innerHTML = `<div class="empty">Error: ${e.message}</div>`;
        });
    }
}
window.addEventListener('hashchange', () => loadRoute());

/* ── Debounced search ──────────────────────── */
let _searchTimeout;
function onSearchInput(e) {
    clearTimeout(_searchTimeout);
    _searchTimeout = setTimeout(() => {
        const q = e.target.value.trim();
        if (q.length >= 2) {
            navigate('#search=' + encodeURIComponent(q));
        }
    }, 350);
}

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Overview                                                       */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#overview', async (container) => {
    const stats = await api('/api/stats');
    if (!stats) { container.innerHTML = '<div class="empty">No data available</div>'; return; }

    let html = '<h1>Analysis Overview</h1>';

    // Summary cards
    html += '<div class="cards">';
    const cards = [
        ['Opcodes',      fmtNum(stats.opcodes),      `${fmtNum(stats.cmsg_count)} CMSG / ${fmtNum(stats.smsg_count)} SMSG`],
        ['Functions',    fmtNum(stats.functions),    'Analyzed functions'],
        ['JAM Types',    fmtNum(stats.jam_types),     'Message type layouts'],
        ['DB2 Tables',   fmtNum(stats.db2_tables),    'Client data stores'],
        ['VTables',      fmtNum(stats.vtables),       `${fmtNum(stats.vtable_entries)} entries`],
        ['Lua API',      fmtNum(stats.lua_api),       'Exported API functions'],
        ['UpdateFields', fmtNum(stats.update_fields), 'Object descriptors'],
        ['Strings',      fmtNum(stats.strings),       'Cataloged strings'],
        ['Annotations',  fmtNum(stats.annotations),   'IDB annotations'],
        ['Diff Records', fmtNum(stats.diffing),       'Cross-build matches'],
    ];
    for (const [label, value, sub] of cards) {
        html += `<div class="card"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
    }
    html += '</div>';

    // Coverage meter (KV entries as proxy for how many analyzers ran)
    const analyzerCount = stats.kv_entries || 0;
    const estimatedTotal = 40;  // rough estimate of all analyzers
    const pct = Math.min(100, Math.round((analyzerCount / estimatedTotal) * 100));
    const meterColor = pct >= 75 ? 'var(--green)' : pct >= 40 ? 'var(--yellow)' : 'var(--red)';
    html += '<div class="meter-wrap">';
    html += `<h2>Analysis Coverage</h2>`;
    html += `<div style="font-size:.85rem;color:var(--text-sub);margin-bottom:6px">${analyzerCount} analyzer results stored (est. ${estimatedTotal} total)</div>`;
    html += `<div class="meter"><div class="fill" style="width:${pct}%;background:${meterColor}"></div><div class="label-over">${pct}%</div></div>`;
    html += '</div>';

    // Systems breakdown
    if (stats.systems && Object.keys(stats.systems).length > 0) {
        html += '<h2>Functions by System</h2>';
        html += '<div class="tbl-wrap"><table><thead><tr><th>System</th><th>Functions</th><th>Coverage</th></tr></thead><tbody>';
        const totalFuncs = stats.functions || 1;
        const sorted = Object.entries(stats.systems).sort((a,b) => b[1]-a[1]);
        for (const [sys, cnt] of sorted) {
            const pctSys = ((cnt / totalFuncs) * 100).toFixed(1);
            html += `<tr><td>${sys}</td><td>${fmtNum(cnt)}</td><td><div class="meter" style="height:14px;width:200px;display:inline-block;vertical-align:middle"><div class="fill" style="width:${pctSys}%;background:var(--blue)"></div></div> ${pctSys}%</td></tr>`;
        }
        html += '</tbody></table></div>';
    }

    // Total records
    html += `<div style="text-align:right;font-size:.8rem;color:var(--text-dim);margin-top:12px">Total records: ${fmtNum(stats.total)}</div>`;

    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Opcodes                                                        */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#opcodes', async (container) => {
    const data = await api('/api/opcodes');
    if (!data || !data.length) { container.innerHTML = '<div class="empty">No opcodes found. Run opcode analysis first.</div>'; return; }

    let html = `<h1>Opcodes (${data.length})</h1>`;
    html += `<div style="margin-bottom:12px"><input type="text" class="search" id="opcode-filter" placeholder="Filter opcodes..." style="padding:7px 12px;background:var(--bg-surface);border:1px solid var(--bg-overlay);color:var(--text);border-radius:6px;width:300px"></div>`;
    html += '<div class="tbl-wrap"><table id="opcode-table"><thead><tr>';
    html += '<th>Direction</th><th>Index</th><th>Wire</th><th>TC Name</th><th>Handler</th><th>JAM Type</th><th>Status</th>';
    html += '</tr></thead><tbody>';
    for (const op of data) {
        const idx = op.internal_index != null ? '0x' + op.internal_index.toString(16).toUpperCase() : '-';
        const wire = op.wire_opcode != null ? '0x' + op.wire_opcode.toString(16).toUpperCase() : '-';
        const handler = op.handler_ea ? fmtAddr(op.handler_ea) : '-';
        const tcName = op.tc_name || '<em>unknown</em>';
        html += `<tr data-filter="${(op.tc_name||'').toLowerCase()} ${(op.jam_type||'').toLowerCase()} ${(op.direction||'').toLowerCase()}">`;
        html += `<td>${dirTag(op.direction)}</td>`;
        html += `<td class="mono">${idx}</td>`;
        html += `<td class="mono">${wire}</td>`;
        html += `<td class="clickable" onclick="navigate('#handler/${encodeURIComponent(op.tc_name||'')}')">${tcName}</td>`;
        html += `<td class="mono">${handler}</td>`;
        html += `<td>${op.jam_type||'-'}</td>`;
        html += `<td>${statusTag(op.status)}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table></div>';

    container.innerHTML = html;
    makeSortable(document.getElementById('opcode-table'));

    // Filter
    document.getElementById('opcode-filter').addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        $$('#opcode-table tbody tr').forEach(tr => {
            tr.style.display = tr.dataset.filter.includes(q) ? '' : 'none';
        });
    });
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Conformance                                                    */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#conformance', async (container) => {
    const data = await api('/api/conformance');
    if (!data) { container.innerHTML = '<div class="empty">No conformance data. Run conformance analysis first.</div>'; return; }

    let html = `<h1>Conformance Scores</h1>`;

    // Summary
    html += '<div class="cards">';
    html += `<div class="card"><div class="label">Handlers Scored</div><div class="value">${fmtNum(data.total_handlers)}</div></div>`;
    html += `<div class="card"><div class="label">Average Score</div><div class="value ${scoreClass(data.average_score)}">${data.average_score!=null?data.average_score.toFixed(1)+'%':'-'}</div></div>`;
    html += '</div>';

    // System scores
    if (data.system_scores && Object.keys(data.system_scores).length) {
        html += '<h2>By System</h2>';
        html += '<div class="tbl-wrap"><table><thead><tr><th>System</th><th>Avg Score</th><th>Min</th><th>Max</th><th>Handlers</th></tr></thead><tbody>';
        for (const [sys, s] of Object.entries(data.system_scores).sort((a,b)=>a[1].average_score-b[1].average_score)) {
            html += `<tr>`;
            html += `<td>${sys}</td>`;
            html += `<td>${scoreTag(s.average_score)}</td>`;
            html += `<td>${scoreTag(s.min_score)}</td>`;
            html += `<td>${scoreTag(s.max_score)}</td>`;
            html += `<td>${s.handler_count}</td>`;
            html += '</tr>';
        }
        html += '</tbody></table></div>';
    }

    // Per-handler table
    if (data.handlers && data.handlers.length) {
        html += `<h2>Per-Handler Scores (${data.handlers.length})</h2>`;
        html += '<div class="tbl-wrap"><table id="conf-table"><thead><tr>';
        html += '<th>Handler</th><th>Score</th><th>Calls</th><th>Branches</th><th>Validation</th><th>Size</th><th>Address</th>';
        html += '</tr></thead><tbody>';
        for (const h of data.handlers) {
            html += `<tr>`;
            html += `<td class="clickable" onclick="navigate('#handler/${encodeURIComponent(h.tc_name)}')">${h.tc_name}</td>`;
            html += `<td>${scoreTag(h.score)}</td>`;
            html += `<td>${scoreTag(h.call_score)}</td>`;
            html += `<td>${scoreTag(h.branch_score)}</td>`;
            html += `<td>${scoreTag(h.validation_score)}</td>`;
            html += `<td>${scoreTag(h.size_score)}</td>`;
            html += `<td class="mono">${h.handler_ea||'-'}</td>`;
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        setTimeout(() => makeSortable(document.getElementById('conf-table')), 0);
    }

    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Handler Detail                                                 */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#handler', async (container) => {
    // Extract handler name from hash: #handler/CMSG_SOMETHING
    const parts = window.location.hash.split('/');
    const name = decodeURIComponent(parts.slice(1).join('/'));
    if (!name) { container.innerHTML = '<div class="empty">No handler specified</div>'; return; }

    const data = await api('/api/handler/' + encodeURIComponent(name));
    if (!data) { container.innerHTML = `<div class="empty">No data found for handler: ${name}</div>`; return; }

    let html = `<h1>${name}</h1>`;
    html += '<div class="detail-panel">';

    // Basic info grid
    html += '<div class="section"><h3>Basic Info</h3><div class="detail-grid">';
    const fields = [
        ['Direction', data.direction],
        ['Internal Index', data.internal_index != null ? fmtAddr(data.internal_index) : '-'],
        ['Wire Opcode', data.wire_opcode != null ? fmtAddr(data.wire_opcode) : '-'],
        ['Handler Address', data.handler_ea ? fmtAddr(data.handler_ea) : '-'],
        ['Deserializer', data.deserializer_ea ? fmtAddr(data.deserializer_ea) : '-'],
        ['JAM Type', data.jam_type || '-'],
        ['Status', data.status || 'unknown'],
    ];
    for (const [l,v] of fields) {
        html += `<div class="lbl">${l}</div><div>${v}</div>`;
    }
    html += '</div></div>';

    // Tabs for sub-data
    const tabDefs = [];
    if (data.wire_format) tabDefs.push(['wire', 'Wire Format', renderWireFormat(data.wire_format)]);
    if (data.constraints && data.constraints.length) tabDefs.push(['constraints', 'Constraints', renderConstraints(data.constraints)]);
    if (data.behavioral_spec) tabDefs.push(['behavior', 'Behavioral Spec', renderBehavior(data.behavioral_spec)]);
    if (data.conformance) tabDefs.push(['conf', 'Conformance', renderConformanceDetail(data.conformance)]);
    if (data.taint_flows && data.taint_flows.length) tabDefs.push(['taint', 'Taint Flows', renderTaintFlows(data.taint_flows)]);
    if (data.scaffold) tabDefs.push(['scaffold', 'Scaffold Code', `<pre><code>${highlightCpp(data.scaffold)}</code></pre>`]);
    if (data.decompilation) tabDefs.push(['decomp', 'Decompilation', `<pre><code>${highlightCpp(data.decompilation)}</code></pre>`]);
    if (data.alignment_diff) tabDefs.push(['align', 'TC Alignment', renderAlignmentDiff(data.alignment_diff)]);
    if (data.constants && data.constants.length) tabDefs.push(['const', 'Constants', renderConstants(data.constants)]);

    if (tabDefs.length) {
        html += '<div class="tabs">';
        tabDefs.forEach(([id, label], i) => {
            html += `<button class="${i===0?'active':''}" onclick="switchTab(this,'${id}')">${label}</button>`;
        });
        html += '</div>';
        tabDefs.forEach(([id, , content], i) => {
            html += `<div class="tab-content ${i===0?'active':''}" id="tab-${id}">${content}</div>`;
        });
    }

    html += '</div>';  // detail-panel
    container.innerHTML = html;
});

function switchTab(btn, id) {
    const parent = btn.parentElement.parentElement;
    $$('.tabs button', parent).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    $$('.tab-content', parent).forEach(tc => tc.classList.toggle('active', tc.id === 'tab-' + id));
}

function renderWireFormat(wf) {
    if (typeof wf === 'string') return `<pre><code>${highlightCpp(wf)}</code></pre>`;
    if (!wf.fields || !wf.fields.length) return '<div class="empty">No wire format fields</div>';
    let h = '<div class="tbl-wrap"><table><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Size</th><th>Notes</th></tr></thead><tbody>';
    wf.fields.forEach((f, i) => {
        h += `<tr><td>${i}</td><td class="mono">${f.name||'-'}</td><td>${f.type||'-'}</td><td>${f.size||'-'}</td><td>${f.notes||''}</td></tr>`;
    });
    h += '</tbody></table></div>';
    return h;
}

function renderConstraints(constraints) {
    let h = '<div class="tbl-wrap"><table><thead><tr><th>Field</th><th>Check</th><th>Value</th><th>Action</th></tr></thead><tbody>';
    for (const c of constraints) {
        h += `<tr><td class="mono">${c.field||'-'}</td><td>${c.check||'-'}</td><td class="mono">${c.value!=null?c.value:'-'}</td><td>${c.action||'-'}</td></tr>`;
    }
    h += '</tbody></table></div>';
    return h;
}

function renderBehavior(spec) {
    if (typeof spec === 'string') return `<pre>${spec}</pre>`;
    let h = '';
    if (spec.paths) {
        h += '<h3>Behavioral Paths</h3><ul>';
        for (const p of spec.paths) {
            h += `<li><strong>${p.name || 'Path'}</strong>: ${p.description || JSON.stringify(p)}</li>`;
        }
        h += '</ul>';
    }
    if (spec.side_effects) {
        h += '<h3>Side Effects</h3><ul>';
        for (const se of spec.side_effects) {
            h += `<li>${typeof se === 'string' ? se : JSON.stringify(se)}</li>`;
        }
        h += '</ul>';
    }
    if (!h) h = `<pre>${JSON.stringify(spec, null, 2)}</pre>`;
    return h;
}

function renderConformanceDetail(conf) {
    if (typeof conf === 'number') return `<div style="font-size:2rem;font-weight:700" class="${scoreClass(conf)}">${conf.toFixed(1)}%</div>`;
    let h = '<div class="detail-grid">';
    for (const [k,v] of Object.entries(conf)) {
        h += `<div class="lbl">${k}</div><div>${typeof v === 'number' ? scoreTag(v) : v}</div>`;
    }
    h += '</div>';
    return h;
}

function renderTaintFlows(flows) {
    let h = '<div class="tbl-wrap"><table><thead><tr><th>Source</th><th>Sink</th><th>Path</th></tr></thead><tbody>';
    for (const f of flows) {
        h += `<tr><td class="mono">${f.source||'-'}</td><td class="mono">${f.sink||'-'}</td><td>${f.path||'-'}</td></tr>`;
    }
    h += '</tbody></table></div>';
    return h;
}

function renderAlignmentDiff(diff) {
    if (typeof diff === 'string') {
        const lines = diff.split('\n').map(line => {
            if (line.startsWith('+')) return `<span class="diff-add">${line}</span>`;
            if (line.startsWith('-')) return `<span class="diff-del">${line}</span>`;
            return line;
        });
        return `<pre><code>${lines.join('\n')}</code></pre>`;
    }
    return `<pre>${JSON.stringify(diff, null, 2)}</pre>`;
}

function renderConstants(constants) {
    let h = '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Value</th><th>Usage</th></tr></thead><tbody>';
    for (const c of constants) {
        h += `<tr><td class="mono">${c.name||'-'}</td><td class="mono">${c.value!=null?c.value:'-'}</td><td>${c.usage||'-'}</td></tr>`;
    }
    h += '</tbody></table></div>';
    return h;
}

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Handlers                                                       */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#handlers', async (container) => {
    const data = await api('/api/handlers');
    if (!data || !data.length) { container.innerHTML = '<div class="empty">No handler data</div>'; return; }

    let html = `<h1>Handlers (${data.length})</h1>`;
    html += `<div style="margin-bottom:12px"><input type="text" class="search" id="handler-filter" placeholder="Filter handlers..." style="padding:7px 12px;background:var(--bg-surface);border:1px solid var(--bg-overlay);color:var(--text);border-radius:6px;width:300px"></div>`;
    html += '<div class="tbl-wrap"><table id="handler-table"><thead><tr>';
    html += '<th>Name</th><th>Direction</th><th>Handler EA</th><th>JAM Type</th><th>Status</th><th>Analyzers</th>';
    html += '</tr></thead><tbody>';
    for (const h of data) {
        const aCount = h.analyzer_count || 0;
        html += `<tr data-filter="${(h.tc_name||'').toLowerCase()}">`;
        html += `<td class="clickable" onclick="navigate('#handler/${encodeURIComponent(h.tc_name||'')}')">${h.tc_name||'<em>unknown</em>'}</td>`;
        html += `<td>${dirTag(h.direction)}</td>`;
        html += `<td class="mono">${h.handler_ea ? fmtAddr(h.handler_ea) : '-'}</td>`;
        html += `<td>${h.jam_type||'-'}</td>`;
        html += `<td>${statusTag(h.status)}</td>`;
        html += `<td>${aCount}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
    makeSortable(document.getElementById('handler-table'));

    document.getElementById('handler-filter').addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        $$('#handler-table tbody tr').forEach(tr => {
            tr.style.display = tr.dataset.filter.includes(q) ? '' : 'none';
        });
    });
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Systems                                                        */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#systems', async (container) => {
    const data = await api('/api/systems');
    if (!data || !Object.keys(data).length) { container.innerHTML = '<div class="empty">No system data</div>'; return; }

    let html = '<h1>Systems</h1>';

    for (const [system, info] of Object.entries(data).sort((a,b) => (b[1].function_count||0) - (a[1].function_count||0))) {
        html += '<div class="detail-panel">';
        html += `<h2>${system}</h2>`;
        html += '<div class="detail-grid">';
        html += `<div class="lbl">Functions</div><div>${fmtNum(info.function_count)}</div>`;
        if (info.opcode_count != null) html += `<div class="lbl">Opcodes</div><div>${fmtNum(info.opcode_count)}</div>`;
        if (info.conformance_avg != null) html += `<div class="lbl">Conformance Avg</div><div>${scoreTag(info.conformance_avg)}</div>`;
        if (info.subsystems && info.subsystems.length) {
            html += `<div class="lbl">Subsystems</div><div>${info.subsystems.join(', ')}</div>`;
        }
        html += '</div>';

        if (info.top_functions && info.top_functions.length) {
            html += '<details style="margin-top:10px"><summary style="cursor:pointer;color:var(--blue)">Top Functions</summary>';
            html += '<div class="tbl-wrap" style="margin-top:8px"><table><thead><tr><th>Name</th><th>Address</th><th>Confidence</th></tr></thead><tbody>';
            for (const f of info.top_functions) {
                html += `<tr><td>${f.name||fmtAddr(f.ea)}</td><td class="mono">${fmtAddr(f.ea)}</td><td>${f.confidence||'-'}</td></tr>`;
            }
            html += '</tbody></table></div></details>';
        }
        html += '</div>';
    }

    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Call Graph                                                     */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#callgraph', async (container) => {
    const data = await api('/api/call-graph');
    if (!data || !data.nodes || !data.nodes.length) {
        container.innerHTML = '<div class="empty">No call graph data. Run call graph analysis first.</div>';
        return;
    }

    let html = '<h1>Call Graph</h1>';
    html += `<div style="margin-bottom:12px;font-size:.85rem;color:var(--text-sub)">${data.nodes.length} nodes, ${data.edges?data.edges.length:0} edges</div>`;

    // Render as SVG with simple force-directed layout approximation
    const W = 1400, H = 800;
    const nodes = data.nodes.slice(0, 300);  // cap for performance
    const edges = (data.edges || []).slice(0, 600);

    // Assign positions in a grid with jitter
    const cols = Math.ceil(Math.sqrt(nodes.length));
    const cellW = W / (cols + 1);
    const cellH = H / (Math.ceil(nodes.length / cols) + 1);

    // Build node ID map
    const nodeMap = {};
    nodes.forEach((n, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        n._x = cellW * (col + 0.5) + (Math.sin(i * 2.1) * cellW * 0.3);
        n._y = cellH * (row + 0.5) + (Math.cos(i * 3.7) * cellH * 0.3);
        nodeMap[n.id || n.ea || i] = n;
    });

    // Color by system
    const systemColors = {};
    const palette = ['#89b4fa','#cba6f7','#a6e3a1','#f9e2af','#fab387','#f38ba8','#94e2d5','#89dceb','#74c7ec','#f2cdcd','#b4befe','#f5e0dc'];
    let ci = 0;
    nodes.forEach(n => {
        if (n.system && !systemColors[n.system]) {
            systemColors[n.system] = palette[ci % palette.length];
            ci++;
        }
    });

    let svg = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">`;

    // Edges
    for (const e of edges) {
        const src = nodeMap[e.source || e.from];
        const dst = nodeMap[e.target || e.to];
        if (src && dst) {
            svg += `<line class="graph-edge" x1="${src._x}" y1="${src._y}" x2="${dst._x}" y2="${dst._y}"/>`;
        }
    }

    // Nodes
    for (const n of nodes) {
        const color = systemColors[n.system] || '#585b70';
        const r = Math.max(4, Math.min(10, (n.degree || 1)));
        const label = n.name || n.label || '';
        const shortLabel = label.length > 20 ? label.slice(0, 18) + '..' : label;
        svg += `<g class="graph-node">`;
        svg += `<circle cx="${n._x}" cy="${n._y}" r="${r}" fill="${color}" opacity="0.8"/>`;
        if (shortLabel) {
            svg += `<text class="graph-label" x="${n._x + r + 3}" y="${n._y + 3}">${shortLabel}</text>`;
        }
        svg += `</g>`;
    }
    svg += '</svg>';

    // Legend
    html += '<div style="margin-bottom:8px;display:flex;gap:12px;flex-wrap:wrap">';
    for (const [sys, color] of Object.entries(systemColors)) {
        html += `<span style="font-size:.8rem"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${color};margin-right:4px;vertical-align:middle"></span>${sys}</span>`;
    }
    html += '</div>';

    html += `<div class="graph-container">${svg}</div>`;
    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Scaffolds                                                      */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#scaffolds', async (container) => {
    const data = await api('/api/scaffolds');
    if (!data || !Object.keys(data).length) {
        container.innerHTML = '<div class="empty">No scaffold code generated yet.</div>';
        return;
    }

    let html = `<h1>Generated Scaffolds (${Object.keys(data).length})</h1>`;
    for (const [name, code] of Object.entries(data)) {
        html += '<div class="detail-panel">';
        html += `<h3>${name}</h3>`;
        html += `<pre><code>${highlightCpp(typeof code === 'string' ? code : JSON.stringify(code, null, 2))}</code></pre>`;
        html += '</div>';
    }
    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Wire Formats                                                   */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#wireformats', async (container) => {
    const opcodes = await api('/api/opcodes');
    if (!opcodes) { container.innerHTML = '<div class="empty">No data</div>'; return; }

    // Filter to those with JAM type
    const withJam = opcodes.filter(o => o.jam_type);

    let html = `<h1>Wire Formats (${withJam.length} JAM types)</h1>`;
    html += '<div class="tbl-wrap"><table id="wire-table"><thead><tr>';
    html += '<th>JAM Type</th><th>Direction</th><th>Opcode</th><th>Field Count</th><th>Wire Size</th><th>Status</th>';
    html += '</tr></thead><tbody>';
    for (const o of withJam) {
        html += `<tr>`;
        html += `<td class="clickable" onclick="navigate('#handler/${encodeURIComponent(o.tc_name||'')}')">${o.jam_type}</td>`;
        html += `<td>${dirTag(o.direction)}</td>`;
        html += `<td class="mono">${o.tc_name||'-'}</td>`;
        html += `<td>${o.field_count||'-'}</td>`;
        html += `<td>${o.wire_size ? o.wire_size + ' B' : '-'}</td>`;
        html += `<td>${statusTag(o.jam_status || o.status)}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
    makeSortable(document.getElementById('wire-table'));
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Constraints                                                    */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#constraints', async (container) => {
    const data = await api('/api/constraints');
    if (!data || !data.length) { container.innerHTML = '<div class="empty">No constraint data. Run validation extractor first.</div>'; return; }

    let html = `<h1>Parameter Constraints (${data.length})</h1>`;
    html += '<div class="tbl-wrap"><table id="constraint-table"><thead><tr>';
    html += '<th>Handler</th><th>Field</th><th>Check</th><th>Value</th><th>Action</th></tr></thead><tbody>';
    for (const c of data) {
        html += `<tr>`;
        html += `<td class="clickable" onclick="navigate('#handler/${encodeURIComponent(c.handler||'')}')">${c.handler||'-'}</td>`;
        html += `<td class="mono">${c.field||'-'}</td>`;
        html += `<td>${c.check||'-'}</td>`;
        html += `<td class="mono">${c.value!=null?c.value:'-'}</td>`;
        html += `<td>${c.action||'-'}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
    makeSortable(document.getElementById('constraint-table'));
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Route: Search                                                         */
/* ═══════════════════════════════════════════════════════════════════════ */
registerRoute('#search', async (container) => {
    const hash = window.location.hash;
    const m = hash.match(/#search=(.+)/);
    const q = m ? decodeURIComponent(m[1]) : '';
    if (!q) { container.innerHTML = '<div class="empty">Enter a search query</div>'; return; }

    // Also set the search box value
    const input = document.getElementById('global-search');
    if (input) input.value = q;

    const data = await api('/api/search?q=' + encodeURIComponent(q));
    if (!data) { container.innerHTML = '<div class="empty">Search failed</div>'; return; }

    let total = 0;
    let html = `<h1>Search Results: "${q}"</h1>`;

    if (data.opcodes && data.opcodes.length) {
        total += data.opcodes.length;
        html += `<h2>Opcodes (${data.opcodes.length})</h2>`;
        html += '<div class="tbl-wrap"><table><thead><tr><th>Direction</th><th>TC Name</th><th>JAM Type</th><th>Status</th></tr></thead><tbody>';
        for (const o of data.opcodes) {
            html += `<tr><td>${dirTag(o.direction)}</td><td class="clickable" onclick="navigate('#handler/${encodeURIComponent(o.tc_name||'')}')">${o.tc_name||'-'}</td><td>${o.jam_type||'-'}</td><td>${statusTag(o.status)}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (data.functions && data.functions.length) {
        total += data.functions.length;
        html += `<h2>Functions (${data.functions.length})</h2>`;
        html += '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>System</th><th>Address</th><th>Confidence</th></tr></thead><tbody>';
        for (const f of data.functions) {
            html += `<tr><td>${f.name||fmtAddr(f.ea)}</td><td>${f.system||'-'}</td><td class="mono">${fmtAddr(f.ea)}</td><td>${f.confidence||'-'}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (data.strings && data.strings.length) {
        total += data.strings.length;
        html += `<h2>Strings (${data.strings.length})</h2>`;
        html += '<div class="tbl-wrap"><table><thead><tr><th>Value</th><th>System</th><th>Address</th><th>Xrefs</th></tr></thead><tbody>';
        for (const s of data.strings) {
            html += `<tr><td style="max-width:500px;overflow:hidden;text-overflow:ellipsis">${s.value||'-'}</td><td>${s.system||'-'}</td><td class="mono">${fmtAddr(s.ea)}</td><td>${s.xref_count||0}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (data.handlers && data.handlers.length) {
        total += data.handlers.length;
        html += `<h2>Handlers (${data.handlers.length})</h2>`;
        html += '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Direction</th><th>Status</th></tr></thead><tbody>';
        for (const h of data.handlers) {
            html += `<tr><td class="clickable" onclick="navigate('#handler/${encodeURIComponent(h.tc_name||'')}')">${h.tc_name||'-'}</td><td>${dirTag(h.direction)}</td><td>${statusTag(h.status)}</td></tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (total === 0) {
        html += '<div class="empty">No results found</div>';
    }

    container.innerHTML = html;
});

/* ═══════════════════════════════════════════════════════════════════════ */
/* Boot                                                                  */
/* ═══════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
    loadRoute();
});
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TC WoW Analyzer Dashboard</title>
    <style>
{css}
    </style>
</head>
<body>
<div class="app">
    <div class="topbar">
        <div class="brand">TC WoW Analyzer<span>Dashboard</span></div>
        <div class="nav">
            <a href="#overview">Overview</a>
            <a href="#opcodes">Opcodes</a>
            <a href="#conformance">Conformance</a>
            <a href="#handlers">Handlers</a>
            <a href="#systems">Systems</a>
            <a href="#callgraph">Call Graph</a>
            <a href="#scaffolds">Scaffolds</a>
            <a href="#wireformats">Wire Formats</a>
            <a href="#constraints">Constraints</a>
        </div>
        <div class="search-box">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="global-search" placeholder="Search opcodes, functions, strings..." oninput="onSearchInput(event)">
        </div>
    </div>
    <div class="main" id="content">
        <div class="loading">Loading</div>
    </div>
</div>
<script>
{js}
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════
# Request handler
# ═══════════════════════════════════════════════════════════════════════════

class _DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Handle dashboard HTTP requests."""

    # Suppress default stderr logging
    def log_message(self, format, *args):
        pass

    # ── Helpers ─────────────────────────────────

    def _send_json(self, obj, status=200):
        body = _safe_json(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, message):
        self._send_json({"error": message}, status)

    # ── Routing ─────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # Static routes
        if path == "/":
            return self._handle_index()
        if path == "/api/stats":
            return self._handle_api_stats()
        if path == "/api/opcodes":
            return self._handle_api_opcodes()
        if path == "/api/conformance":
            return self._handle_api_conformance()
        if path == "/api/handlers":
            return self._handle_api_handlers()
        if path == "/api/call-graph":
            return self._handle_api_call_graph()
        if path == "/api/systems":
            return self._handle_api_systems()
        if path == "/api/scaffolds":
            return self._handle_api_scaffolds()
        if path == "/api/constraints":
            return self._handle_api_constraints()
        if path == "/api/search":
            q = qs.get("q", [""])[0]
            return self._handle_api_search(q)

        # Dynamic: /api/handler/<name>
        m = re.match(r"^/api/handler/(.+)$", path)
        if m:
            name = m.group(1)
            # URL-decode
            from urllib.parse import unquote
            name = unquote(name)
            return self._handle_api_handler(name)

        self._send_error(404, "Not found")

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── Route Implementations ──────────────────

    def _handle_index(self):
        page = _HTML_TEMPLATE.format(css=_CSS, js=_JS)
        self._send_html(page)

    def _handle_api_stats(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            stats = _get_all_stats(conn)
            self._send_json(stats)
        finally:
            conn.close()

    def _handle_api_opcodes(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            rows = conn.execute(
                "SELECT * FROM opcodes ORDER BY direction, internal_index"
            ).fetchall()
            result = _rows_to_dicts(rows)

            # Enrich with JAM type info where available
            jam_cache = {}
            for r in result:
                jt = r.get("jam_type")
                if jt and jt not in jam_cache:
                    jam_row = conn.execute(
                        "SELECT field_count, wire_size, status FROM jam_types "
                        "WHERE name = ?", (jt,)
                    ).fetchone()
                    jam_cache[jt] = dict(jam_row) if jam_row else {}
                if jt and jt in jam_cache:
                    r["field_count"] = jam_cache[jt].get("field_count")
                    r["wire_size"] = jam_cache[jt].get("wire_size")
                    r["jam_status"] = jam_cache[jt].get("status")

            self._send_json(result)
        finally:
            conn.close()

    def _handle_api_conformance(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            report = _kv_get(conn, "conformance_report")
            if report is None:
                return self._send_json({})
            self._send_json(report)
        finally:
            conn.close()

    def _handle_api_handlers(self):
        """Return all opcodes enriched with cross-analyzer data counts."""
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            rows = conn.execute(
                "SELECT * FROM opcodes WHERE tc_name IS NOT NULL "
                "ORDER BY direction, tc_name"
            ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                tc_name = d.get("tc_name", "")
                # Count how many KV entries reference this handler
                count = 0
                for suffix in [
                    f"behavioral_spec:{tc_name}",
                    f"constants:{tc_name}",
                    f"spec_verification:{tc_name}",
                ]:
                    if _kv_get(conn, suffix) is not None:
                        count += 1
                # Check conformance report for this handler
                conf_report = _kv_get(conn, "conformance_report")
                if conf_report and isinstance(conf_report, dict):
                    handlers_list = conf_report.get("handlers", [])
                    for h in handlers_list:
                        if h.get("tc_name") == tc_name:
                            count += 1
                            break
                d["analyzer_count"] = count
                result.append(d)
            self._send_json(result)
        finally:
            conn.close()

    def _handle_api_handler(self, name):
        """Return unified view of a single handler across all analyzers."""
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            # Base opcode info
            row = conn.execute(
                "SELECT * FROM opcodes WHERE tc_name = ?", (name,)
            ).fetchone()
            if row is None:
                return self._send_json({"error": "Handler not found", "tc_name": name})
            result = dict(row)

            # JAM type details and wire format
            jt = result.get("jam_type")
            if jt:
                jam_row = conn.execute(
                    "SELECT * FROM jam_types WHERE name = ?", (jt,)
                ).fetchone()
                if jam_row:
                    jam = dict(jam_row)
                    fields_json = jam.get("fields_json")
                    if fields_json:
                        try:
                            fields = json.loads(fields_json)
                            result["wire_format"] = {
                                "fields": fields,
                                "wire_size": jam.get("wire_size"),
                            }
                        except (json.JSONDecodeError, TypeError):
                            pass

            # Behavioral spec
            spec = _kv_get(conn, f"behavioral_spec:{name}")
            if spec:
                result["behavioral_spec"] = spec

            # Constants
            constants = _kv_get(conn, f"constants:{name}")
            if constants:
                result["constants"] = constants if isinstance(constants, list) else []

            # Conformance
            conf_report = _kv_get(conn, "conformance_report")
            if conf_report and isinstance(conf_report, dict):
                for h in conf_report.get("handlers", []):
                    if h.get("tc_name") == name:
                        result["conformance"] = h
                        break

            # Binary-TC alignment
            alignment = _kv_get(conn, "binary_tc_alignment")
            if alignment and isinstance(alignment, dict):
                handler_diffs = alignment.get("handler_diffs", {})
                if name in handler_diffs:
                    result["alignment_diff"] = handler_diffs[name]

            # Taint analysis
            taint = _kv_get(conn, "taint_analysis")
            if taint and isinstance(taint, dict):
                handler_taint = taint.get("handlers", {})
                if name in handler_taint:
                    flows = handler_taint[name]
                    result["taint_flows"] = flows if isinstance(flows, list) else []

            # Scaffold code
            scaffolds = _kv_get(conn, "scaffolds")
            if scaffolds and isinstance(scaffolds, dict) and name in scaffolds:
                result["scaffold"] = scaffolds[name]

            # Spec verification
            verification = _kv_get(conn, f"spec_verification:{name}")
            if verification:
                result["verification"] = verification

            # Validation constraints
            validation = _kv_get(conn, "validation_constraints")
            if validation and isinstance(validation, dict):
                handler_constraints = validation.get(name)
                if handler_constraints:
                    result["constraints"] = handler_constraints if isinstance(
                        handler_constraints, list
                    ) else []

            self._send_json(result)
        finally:
            conn.close()

    def _handle_api_call_graph(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            cga = _kv_get(conn, "call_graph_analytics")
            if cga and isinstance(cga, dict):
                # Return pre-computed graph data
                nodes = cga.get("nodes", [])
                edges = cga.get("edges", [])
                self._send_json({"nodes": nodes, "edges": edges})
                return

            # Fallback: build minimal graph from functions + opcodes
            nodes = []
            edges = []

            # Get functions that have system labels
            funcs = conn.execute(
                "SELECT ea, name, system, confidence FROM functions "
                "WHERE system IS NOT NULL ORDER BY confidence DESC LIMIT 200"
            ).fetchall()

            for f in funcs:
                nodes.append({
                    "id": f["ea"],
                    "ea": f["ea"],
                    "name": f["name"] or f"0x{f['ea']:X}",
                    "system": f["system"],
                    "degree": max(1, (f["confidence"] or 0) // 10),
                })

            # Opcodes as edges to their handlers
            opcodes = conn.execute(
                "SELECT tc_name, handler_ea FROM opcodes "
                "WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
            ).fetchall()

            handler_eas = {n["id"] for n in nodes}
            for op in opcodes:
                hea = op["handler_ea"]
                if hea in handler_eas:
                    # Create an opcode node pointing to handler
                    opid = hash(op["tc_name"]) & 0xFFFFFFFF
                    nodes.append({
                        "id": opid,
                        "name": op["tc_name"],
                        "system": "opcode",
                        "degree": 2,
                    })
                    edges.append({"source": opid, "target": hea})

            self._send_json({"nodes": nodes, "edges": edges})
        finally:
            conn.close()

    def _handle_api_systems(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            result = {}

            # Functions per system
            rows = conn.execute(
                "SELECT system, subsystem, COUNT(*) as cnt "
                "FROM functions WHERE system IS NOT NULL "
                "GROUP BY system, subsystem ORDER BY system, cnt DESC"
            ).fetchall()

            for r in rows:
                sys = r["system"]
                if sys not in result:
                    result[sys] = {
                        "function_count": 0,
                        "subsystems": [],
                        "top_functions": [],
                    }
                result[sys]["function_count"] += r["cnt"]
                sub = r["subsystem"]
                if sub and sub not in result[sys]["subsystems"]:
                    result[sys]["subsystems"].append(sub)

            # Top functions per system
            for sys in result:
                top = conn.execute(
                    "SELECT ea, name, confidence FROM functions "
                    "WHERE system = ? ORDER BY confidence DESC LIMIT 10",
                    (sys,)
                ).fetchall()
                result[sys]["top_functions"] = _rows_to_dicts(top)

            # Opcode counts per system
            opcodes = conn.execute(
                "SELECT tc_name FROM opcodes WHERE tc_name IS NOT NULL"
            ).fetchall()
            for op in opcodes:
                tc = op["tc_name"]
                # Infer system from opcode name pattern: CMSG_HOUSING_XXX -> Housing
                parts = tc.replace("CMSG_", "").replace("SMSG_", "").split("_")
                if parts:
                    inferred = parts[0].capitalize()
                    if inferred in result:
                        result[inferred]["opcode_count"] = (
                            result[inferred].get("opcode_count", 0) + 1
                        )

            # Conformance averages per system
            conf = _kv_get(conn, "conformance_report")
            if conf and isinstance(conf, dict):
                sys_scores = conf.get("system_scores", {})
                for sys, data in sys_scores.items():
                    if sys in result:
                        result[sys]["conformance_avg"] = data.get("average_score")

            self._send_json(result)
        finally:
            conn.close()

    def _handle_api_scaffolds(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            scaffolds = _kv_get(conn, "scaffolds")
            if scaffolds and isinstance(scaffolds, dict):
                self._send_json(scaffolds)
                return

            # Fallback: search kv_store for scaffold-related keys
            rows = conn.execute(
                "SELECT key, value FROM kv_store WHERE key LIKE '%scaffold%'"
            ).fetchall()
            result = {}
            for r in rows:
                try:
                    val = json.loads(r["value"])
                except (json.JSONDecodeError, TypeError):
                    val = r["value"]
                result[r["key"]] = val

            self._send_json(result)
        finally:
            conn.close()

    def _handle_api_constraints(self):
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            # Try dedicated KV key first
            constraints = _kv_get(conn, "validation_constraints")
            if constraints and isinstance(constraints, dict):
                flat = []
                for handler_name, clist in constraints.items():
                    if isinstance(clist, list):
                        for c in clist:
                            if isinstance(c, dict):
                                c["handler"] = handler_name
                                flat.append(c)
                self._send_json(flat)
                return

            # Fallback: look for validation_extractor results
            ve = _kv_get(conn, "validation_extractor")
            if ve and isinstance(ve, dict):
                flat = []
                for handler_name, data in ve.items():
                    checks = data if isinstance(data, list) else data.get(
                        "checks", []
                    ) if isinstance(data, dict) else []
                    for c in checks:
                        if isinstance(c, dict):
                            c["handler"] = handler_name
                            flat.append(c)
                self._send_json(flat)
                return

            self._send_json([])
        finally:
            conn.close()

    def _handle_api_search(self, query):
        if not query or len(query) < 2:
            return self._send_json({"opcodes": [], "functions": [],
                                     "strings": [], "handlers": []})
        conn = _get_db_connection()
        if not conn:
            return self._send_error(500, "Database not available")
        try:
            like = f"%{query}%"
            limit = 50

            # Search opcodes
            opcodes = conn.execute(
                "SELECT * FROM opcodes WHERE tc_name LIKE ? OR jam_type LIKE ? "
                "ORDER BY tc_name LIMIT ?",
                (like, like, limit)
            ).fetchall()

            # Search functions
            functions = conn.execute(
                "SELECT ea, name, system, confidence FROM functions "
                "WHERE name LIKE ? ORDER BY confidence DESC LIMIT ?",
                (like, limit)
            ).fetchall()

            # Search strings
            strings = conn.execute(
                "SELECT ea, value, system, xref_count FROM strings "
                "WHERE value LIKE ? ORDER BY xref_count DESC LIMIT ?",
                (like, limit)
            ).fetchall()

            # De-dup opcodes → handlers
            seen = set()
            handlers = []
            for o in opcodes:
                tn = o["tc_name"]
                if tn and tn not in seen:
                    seen.add(tn)
                    handlers.append(dict(o))

            result = {
                "opcodes": _rows_to_dicts(opcodes),
                "functions": _rows_to_dicts(functions),
                "strings": _rows_to_dicts(strings),
                "handlers": handlers,
            }
            self._send_json(result)
        finally:
            conn.close()
