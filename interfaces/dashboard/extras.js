/* ZAHRA Dashboard Extras — Risk Scores, Attack Graph, Notifications, Reports
 * Self-contained: injects its own UI if the host page lacks it, and opens a
 * dedicated WebSocket to /ws/attack so live events are received independently
 * of the main dashboard script (which loads before this file).
 */
(function () {
    'use strict';

    // ── 1. WebSocket tap (defensive: catches connection sockets too) ────────
    const _origWS = window.WebSocket;
    const _listeners = [];
    window.WebSocket = function (url, protocols) {
        const ws = protocols !== undefined ? new _origWS(url, protocols) : new _origWS(url);
        ws.addEventListener('message', (e) => {
            _listeners.forEach((fn) => { try { fn(e); } catch (_) {} });
        });
        return ws;
    };
    window.WebSocket.prototype = _origWS.prototype;
    window.WebSocket.CONNECTING = _origWS.CONNECTING;
    window.WebSocket.OPEN = _origWS.OPEN;
    window.WebSocket.CLOSING = _origWS.CLOSING;
    window.WebSocket.CLOSED = _origWS.CLOSED;
    Object.defineProperty(window.WebSocket, 'name', { value: 'WebSocket' });

    // ── 2. Styles ────────────────────────────────────────────────────────────
    const css = `
    #zx-extras { margin: 18px 0; }
    .zx-card { background: rgba(10, 14, 12, .82); border: 1px solid #00ff3c33;
        border-radius: 12px; padding: 16px; margin-bottom: 16px;
        box-shadow: 0 0 18px #00ff3c14; }
    .zx-card h3 { color: #00ff3c; margin: 0 0 10px; font-size: 15px;
        letter-spacing: .08em; text-transform: uppercase; }
    .zx-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    table.zx-findings { width: 100%; border-collapse: collapse; font-size: 13px; }
    table.zx-findings th { text-align: left; color: #9df5b5; border-bottom: 1px solid #00ff3c33;
        padding: 6px 8px; }
    table.zx-findings td { padding: 6px 8px; border-bottom: 1px solid #ffffff0d; color: #cfe; }
    .zx-risk { font-weight: 700; }
    .zx-risk.critical, .zx-risk.high { color: #ff4d4d; }
    .zx-risk.medium { color: #ffb020; }
    .zx-risk.low { color: #ffe14d; }
    .zx-risk.info { color: #35d07f; }
    tr.zx-sev-critical, tr.zx-sev-high { background: #ff4d4d14; }
    tr.zx-sev-medium { background: #ffb02010; }
    tr.zx-sev-low { background: #ffe14d08; }
    .zx-btn { background: #00ff3c1a; color: #00ff3c; border: 1px solid #00ff3c55;
        border-radius: 8px; padding: 8px 14px; cursor: pointer; font-weight: 600; }
    .zx-btn:hover { background: #00ff3c2e; }
    #zx-graph { width: 100%; height: 420px; border: 1px solid #00ff3c22;
        border-radius: 10px; background: #050807; }
    #zx-flash { position: fixed; inset: 0; pointer-events: none; opacity: 0;
        background: radial-gradient(ellipse at center, #ff4d4d33 0%, #ff000055 100%);
        transition: opacity .25s; z-index: 9998; }
    #zx-toasts { position: fixed; right: 16px; top: 16px; z-index: 9999;
        display: flex; flex-direction: column; gap: 8px; }
    .zx-toast { background: #160b0b; border: 1px solid #ff4d4d; color: #ffd9d9;
        border-radius: 10px; padding: 10px 14px; min-width: 260px;
        box-shadow: 0 0 14px #ff4d4d44; font-size: 13px; }
    .zx-toast b { color: #ff8080; }
    .zx-switch { display: inline-flex; align-items: center; gap: 6px;
        color: #9df5b5; font-size: 13px; cursor: pointer; }
    .zx-muted { color: #6fa07f; font-size: 12px; }
    `;
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);

    // ── 3. UI injection (defensive: works even if host page lacks containers) ─
    let _host = null;
    function ensureHost() {
        if (_host && document.body.contains(_host)) return _host;
        _host = document.getElementById('zx-extras');
        if (!_host) {
            _host = document.createElement('div');
            _host.id = 'zx-extras';
            _host.innerHTML = `
              <div class="zx-card" id="zx-card-risk">
                <h3>Findings — Risk Scored</h3>
                <div class="zx-row" style="margin-bottom:8px">
                  <button class="zx-btn" id="zx-btn-report">⬇ Download Report</button>
                  <label class="zx-switch"><input type="checkbox" id="zx-notif-toggle"
                        style="accent-color:#00ff3c"> Critical notifications</label>
                  <span class="zx-muted" id="zx-notif-status"></span>
                </div>
                <table class="zx-findings"><thead>
                  <tr><th>Severity</th><th>Risk</th><th>CVE</th>
                      <th>Description</th><th>Agent</th></tr>
                </thead><tbody id="zx-findings-body"></tbody></table>
              </div>
              <div class="zx-card" id="zx-card-graph">
                <h3>Attack Graph (live)</h3>
                <div id="zx-graph"></div>
              </div>
              <div id="zx-flash"></div><div id="zx-toasts"></div>`;
            const main = document.querySelector('main') ||
                         document.querySelector('.container') || document.body;
            main.appendChild(_host);
        }
        return _host;
    }

    // ── 4. Notification state ─────────────────────────────────────────────────
    let _notifOn = false;
    let _notifSettings = { webhook_url: '', sound: true, visual: true };
    let _ws = null; // self-contained WebSocket client for live attack events

    function loadNotifSettings() {
        fetch('/api/notifications/status').then(r => r.json()).then(d => {
            _notifSettings = Object.assign(_notifSettings, d.settings || d);
            _notifOn = !!(_notifSettings.enabled || d.enabled);
            const t = document.getElementById('zx-notif-toggle');
            if (t) t.checked = _notifOn;
            const s = document.getElementById('zx-notif-status');
            if (s) s.textContent = _notifOn ? 'ON' : 'OFF';
        }).catch(() => {});
    }

    function saveNotifSettings() {
        _notifSettings.enabled = _notifOn;
        fetch('/api/notifications/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(_notifSettings),
        }).catch(() => {});
    }

    function beep() {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const o = ctx.createOscillator(), g = ctx.createGain();
            o.type = 'square'; o.frequency.value = 880;
            o.connect(g); g.connect(ctx.destination);
            g.gain.setValueAtTime(0.08, ctx.currentTime);
            o.start(); o.stop(ctx.currentTime + 0.18);
            setTimeout(() => ctx.close(), 400);
        } catch (_) {}
    }

    function flash() {
        const f = document.getElementById('zx-flash');
        if (!f) return;
        f.style.opacity = '1';
        setTimeout(() => { f.style.opacity = '0'; }, 500);
    }

    function toast(sev, text) {
        const box = document.getElementById('zx-toasts');
        if (!box) return;
        const t = document.createElement('div');
        t.className = 'zx-toast';
        t.innerHTML = `<b>${(sev || 'ALERT').toUpperCase()}</b> — ${text}`;
        box.appendChild(t);
        setTimeout(() => t.remove(), 8000);
    }

    function alertCritical(f) {
        if (!_notifOn) return;
        const sev = String(f.severity || '').toLowerCase();
        if (sev !== 'critical' && sev !== 'high') return;
        const msg = f.description || f.finding_type || 'Critical finding detected';
        toast(sev, msg);
        if (_notifSettings.visual !== false) flash();
        if (_notifSettings.sound !== false) beep();
    }

    // ── 5. Attack graph (vis-network via CDN, lazy-loaded once) ───────────────
    const _graph = { net: null, nodes: null, edges: null, seen: {} };
    const _SEV_COLOR_NODE = { critical: '#ff4d4d', high: '#ff7a45',
        medium: '#ffb020', low: '#ffe14d', info: '#35d07f' };

    function loadVis(cb) {
        if (window.vis && window.vis.Network) return cb();
        const s = document.createElement('script');
        s.src = 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.js';
        s.onload = cb; s.onerror = cb;
        document.head.appendChild(s);
    }

    function ensureGraph() {
        if (_graph.net || !window.vis) return;
        _graph.nodes = new vis.DataSet([]);
        _graph.edges = new vis.DataSet([]);
        _graph.net = new vis.Network(document.getElementById('zx-graph'), {
            nodes: _graph.nodes, edges: _graph.edges,
        }, {
            physics: { stabilization: true, solver: 'forceAtlas2Based' },
            interaction: { hover: true, dragView: true },
        });
    }

    function addNode(id, label, color, shape) {
        if (_graph.seen[id] || !_graph.nodes) return;
        _graph.seen[id] = true;
        _graph.nodes.add({ id, label, color: { background: color, border: color },
            font: { color: '#eaffea' }, shape: shape || 'dot' });
    }

    function addEdge(from, to, color) {
        if (!_graph.edges) return;
        const key = from + '→' + to;
        if (_graph.seen[key]) return;
        _graph.seen[key] = true;
        _graph.edges.add({ from, to, color: { color: color, highlight: color },
            arrows: 'to' });
    }

    function graphUpdate(msg) {
        const target = msg.target || (msg.data && msg.data.target) || 'unknown';
        const tid = 'target:' + target;
        addNode(tid, '🎯 ' + target, '#00ff3c', 'star');
        if (!_graph.nodes) return;
        ensureGraph();

        const type = String(msg.event || msg.type || '').toLowerCase();
        const d = msg.data || msg;

        if (type.includes('port') || d.finding_type === 'open_port') {
            const port = d.port || (String(d.description || '').match(/\b(\d{2,5})\/(tcp|udp)\b/) || [])[1];
            if (port) {
                const pid = 'port:' + target + ':' + port;
                addNode(pid, ':' + port, '#4da6ff', 'ellipse');
                addEdge(tid, pid, '#4da6ff');
            }
        }
        if (type.includes('finding') || d.finding_type) {
            const sev = String(d.severity || 'info').toLowerCase();
            const fid = 'vuln:' + (d.id || d.cve || d.finding_type || Math.random());
            addNode(fid, '⚠ ' + (d.cve || d.finding_type || sev),
                _SEV_COLOR_NODE[sev] || '#ffb020');
            const anchor = (d.port ? 'port:' + target + ':' + d.port : tid);
            addEdge(anchor, fid, _SEV_COLOR_NODE[sev] || '#ffb020');
        }
        if (type.includes('exploit') && type.includes('success')) {
            const xid = 'exploit:' + (d.id || Math.random());
            addNode(xid, '✔ exploited', '#35d07f', 'diamond');
            addEdge(tid, xid, '#35d07f');
        }
    }
// __ZX2__

    // ── 6. Findings table (risk-scored, colour-coded rows) ────────────────────
    function riskColor(score) {
        if (score == null) return '#6fa07f';
        if (score >= 0.75) return '#ff4d4d';
        if (score >= 0.5) return '#ffb020';
        if (score >= 0.25) return '#ffe14d';
        return '#35d07f';
    }

    function scoreFinding(f) {
        // Prefer the server-side RiskEngine score when present
        if (f && typeof f.risk_score === 'number') {
            return { risk_score: f.risk_score, risk_level: f.risk_level,
                risk_color: f.risk_color };
        }
        try {
            if (window.__zxRiskScore) return window.__zxRiskScore(f);
        } catch (_) {}
        // client-side fallback heuristic aligned with core/risk_engine.py bands
        const sev = String(f.severity || 'info').toLowerCase();
        return { risk_score: ({ critical: 0.95, high: 0.8, medium: 0.5,
            low: 0.25, info: 0.05 })[sev] ?? 0.1 };
    }

    function refreshFindings() {
        const tbody = document.getElementById('zx-findings-body');
        if (!tbody) return;
        fetch('/memory/findings').then(r => r.json()).then(d => {
            const rows = Array.isArray(d) ? d : (d.findings || d.items || []);
            rows.sort((a, b) => scoreFinding(b).risk_score - scoreFinding(a).risk_score);
            tbody.innerHTML = '';
            rows.slice(0, 50).forEach(f => {
                const r = scoreFinding(f);
                const sev = String(f.severity || 'info').toLowerCase();
                const c = r.risk_color || riskColor(r.risk_score);
                const label = r.risk_level
                    ? String(r.risk_level).toUpperCase() : (sev || '').toUpperCase();
                const tr = document.createElement('tr');
                tr.className = 'zx-sev-' + sev;
                tr.innerHTML =
                    '<td><span class="zx-risk ' + sev + '">' + label + '</span></td>' +
                    '<td class="zx-risk" style="color:' + c + '">' +
                    r.risk_score.toFixed(2) + '</td>' +
                    '<td>' + (f.cve || '—') + '</td>' +
                    '<td>' + String(f.description || f.finding_type || '')
                        .slice(0, 110) + '</td>' +
                    '<td>' + (f.agent_name || '—') + '</td>';
                tbody.appendChild(tr);
                alertCritical(f);
            });
        }).catch(() => {});
    }
// __ZX3__

    // ── 7. Download report + notifications toggle ─────────────────────────────
    function wireButtons() {
        const btn = document.getElementById('zx-btn-report');
        if (btn && !btn.dataset.zxWired) {
            btn.dataset.zxWired = '1';
            btn.addEventListener('click', () => {
                fetch('/api/reports').then(r => r.json()).then(d => {
                    const reports = d.reports || d || [];
                    const latest = Array.isArray(reports) && reports.length
                        ? (reports[0].name || reports[0]) : null;
                    if (latest) {
                        window.open('/api/reports/' + encodeURIComponent(latest), '_blank');
                    } else {
                        toast('info', 'No reports yet — run a campaign first.');
                    }
                }).catch(() => toast('info', 'Report endpoint unavailable.'));
            });
        }
        const tog = document.getElementById('zx-notif-toggle');
        if (tog && !tog.dataset.zxWired) {
            tog.dataset.zxWired = '1';
            tog.addEventListener('change', () => {
                _notifOn = tog.checked;
                const s = document.getElementById('zx-notif-status');
                if (s) s.textContent = _notifOn ? 'ON' : 'OFF';
                saveNotifSettings();
            });
        }
    }

    // ── 8. Bootstrap (self-contained WebSocket — independent of script.js) ─────
    function onWSMessage(e) {
        try {
            const msg = JSON.parse(e.data);
            graphUpdate(msg);
            if (String(msg.event || msg.type || '').toLowerCase().includes('finding')) {
                refreshFindings();
            }
        } catch (_) { /* non-JSON frames are ignored */ }
    }

    function connectWS() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        try {
            const ws = new WebSocket(proto + '//' + location.host + '/ws/attack');
            ws.onopen = () => { _ws = ws; };
            ws.onmessage = (e) => onWSMessage(e);
            ws.onclose = () => { _ws = null; setTimeout(connectWS, 4000); };
            ws.onerror = () => { try { ws.close(); } catch (_) {} };
        } catch (_) {}
    }

    function init() {
        ensureHost();
        wireButtons();
        loadNotifSettings();
        refreshFindings();
        loadVis(ensureGraph);
        connectWS();
        setInterval(refreshFindings, 15000); // periodic refresh + alert sweep
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

