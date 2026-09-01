// ZAHRA Dashboard — Command Center UI Controller

class ZAHRADashboard {
    constructor() {
        this.ws = null;
        this.campaignId = null;
        this.agents = {};
        this.findings = [];
        this.campaigns = [];
        this.events = [];
        this.graph = null;
        this.graphNodes = new Map();
        this.graphEdges = new Map();
        this.sparkData = { campaigns: [], findings: [], agents: [], rag: [] };
        this.sparkCharts = {};
        this.init();
    }

    init() {
        this.aiSession = 'dash-' + Math.random().toString(36).slice(2, 10);
        this.initWebGLBackground();
        this.attachAuthListeners();
        this.connectWebSocket();
        this.attachEventListeners();
        this.attachNavEnhancements();
        this.initDatabaseExplorer();
        this.initAIViews();
        this.initChat();
        this.loadPlatformStatus();
        this.loadHistoricalFindings();
        this.initSparklines();
        this.initAttackGraph();
        this.initTheme();
        this.initScheduler();
        this.initSwarmControl();
        this.initNotifications();
    }

    initWebGLBackground() {
        // Three.js matrix: green-neon point cloud with a scrolling Z rain.
        const canvas = document.getElementById('bg-canvas');
        if (!canvas || typeof THREE === 'undefined') return;

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 2000);
        camera.position.z = 60;

        const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
        renderer.setPixelRatio(window.devicePixelRatio <= 1.5 ? window.devicePixelRatio : 1.5);
        renderer.setClearColor(0x000000, 0);

        const group = new THREE.Group();
        scene.add(group);

        const COUNT = 1800;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(COUNT * 3);
        const velocities = new Float32Array(COUNT);
        const rng = Math.random;

        for (let i = 0; i < COUNT; i++) {
            positions[i * 3] = (rng() - 0.5) * 120;
            positions[i * 3 + 1] = (rng() - 0.5) * 70;
            positions[i * 3 + 2] = rng() * 40 - 20;
            velocities[i] = 0.08 + rng() * 0.22;
        }
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('velocity', new THREE.BufferAttribute(velocities, 1));

        const material = new THREE.PointsMaterial({
            color: 0x00ff3c,
            size: 0.28,
            sizeAttenuation: true,
            transparent: true,
            opacity: 0.82,
            depthWrite: false,
            blending: THREE.AdditiveBlending,
        });
        const points = new THREE.Points(geometry, material);
        group.add(points);

        // occasional connection lines (matrix web)
        const lineMaterial = new THREE.LineBasicMaterial({ color: 0x00ff3c, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending });

        const onResize = () => {
            const w = window.innerWidth, h = window.innerHeight;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
            renderer.setScissorTest(false);
        };
        window.addEventListener('resize', onResize);
        onResize();

        const clock = new THREE.Clock();
        const animate = () => {
            requestAnimationFrame(animate);
            const dt = clock.getDelta();
            const pos = geometry.attributes.position.array;
            const vel = geometry.attributes.velocity.array;

            for (let i = 0; i < COUNT; i++) {
                pos[i * 3 + 2] += vel[i] * dt * 25;            // fall / scroll deeper (Z)
                if (pos[i * 3 + 2] > 40) {
                    pos[i * 3] = (rng() - 0.5) * 120;
                    pos[i * 3 + 1] = (rng() - 0.5) * 70;
                    pos[i * 3 + 2] = -20;
                }
            }
            geometry.attributes.position.needsUpdate = true;
            points.rotation.y = clock.elapsedTime * 0.02;
            renderer.render(scene, camera);
        };
        animate();
    }

    attachAuthListeners() {
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');

        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        if (signupForm) {
            signupForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleSignup();
            });
        }
    }

    handleLogin() {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;

        if (!email || !password) {
            alert('Please enter both email and password');
            return;
        }

        localStorage.setItem('zahra-authenticated', 'true');
        this.showDashboard();
    }

    handleSignup() {
        const name = document.getElementById('signup-name').value;
        const email = document.getElementById('signup-email').value;
        const password = document.getElementById('signup-password').value;
        const confirm = document.getElementById('signup-confirm').value;

        if (!name || !email || !password || !confirm) {
            alert('Please fill all fields');
            return;
        }

        if (password !== confirm) {
            alert('Passwords do not match');
            return;
        }

        localStorage.setItem('zahra-authenticated', 'true');
        this.showDashboard();
    }

    showDashboard() {
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        const dashboard = document.getElementById('dashboard');

        if (loginForm) loginForm.classList.remove('active');
        if (signupForm) signupForm.classList.remove('active');
        if (dashboard) dashboard.classList.remove('hidden');
    }

    socialLogin(provider) {
        alert(`${provider} login would be implemented here with OAuth`);
    }

    showLogin() {
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        if (signupForm) signupForm.classList.remove('active');
        if (loginForm) loginForm.classList.add('active');
    }

    showSignup() {
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        if (loginForm) loginForm.classList.remove('active');
        if (signupForm) signupForm.classList.add('active');
    }

    logout() {
        localStorage.removeItem('zahra-authenticated');
        location.reload();
    }

    addActivity(text) {
        const feed = document.getElementById('activityFeed');
        if (!feed) return;
        const now = new Date().toLocaleTimeString();
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-time">${now}</span>
            <span class="activity-text">${this.escapeHtml(text)}</span>
        `;
        feed.insertBefore(item, feed.firstChild);
        if (feed.children.length > 50) feed.removeChild(feed.lastChild);
    }

    async doSearch(deep = false) {
        const input = document.getElementById('searchInput');
        const resultsDiv = document.getElementById('searchResults');
        const loading = document.getElementById('searchLoading');
        const query = input ? input.value.trim() : '';
        if (!query || !resultsDiv) return;

        resultsDiv.innerHTML = '';
        if (loading) loading.classList.remove('hidden');

        try {
            // 1) RAG memory (local knowledge) — High confidence
            let local = [];
            try {
                const r = await fetch(`/api/agent/rag/recent?limit=40`);
                const d = await r.json();
                const entries = d.entries || [];
                const q = query.toLowerCase();
                local = entries.filter(e => (e.content || '').toLowerCase().includes(q)).slice(0, 5);
            } catch (e) { local = []; }

            // 2) OSINT / web search (Agent-Reach + fallback engines)
            let web = [];
            try {
                const r = await fetch(`/api/agent/search?q=${encodeURIComponent(query)}`, { signal: AbortSignal.timeout(25000) });
                web = (await r.json()).results || [];
            } catch (e) { web = []; }

            const cards = [];
            local.forEach(e => {
                const txt = (e.content || '').slice(0, 240);
                cards.push(`<div class="result-card">
                    <a href="#" onclick="return false;">${this.escapeHtml((e.content || '').slice(0, 120))}</a>
                    <div class="result-snippet">${this.escapeHtml(txt)}</div>
                    <div class="result-meta">
                        <span class="confidence high">High</span>
                        <span class="source-badge rag">📚 RAG memory</span>
                    </div>
                </div>`);
            });
            web.forEach((item, i) => {
                const conf = i < 2 ? 'High' : i < 5 ? 'Medium' : 'Low';
                cards.push(`<div class="result-card">
                    <a href="${this.escapeHtml(item.url || '#')}" target="_blank" rel="noopener">${this.escapeHtml((item.title || item.url || 'OSINT result').slice(0, 130))}</a>
                    <div class="result-snippet">${this.escapeHtml((item.snippet || '').slice(0, 220))}</div>
                    <div class="result-meta">
                        <span class="confidence ${conf.toLowerCase()}">${conf}</span>
                        <span class="source-badge osint">🌐 ${this.escapeHtml(item.engine || 'web')}</span>
                    </div>
                </div>`);
            });

            if (!cards.length) {
                resultsDiv.innerHTML = '<div class="empty">No results found. Try a different query.</div>';
            } else {
                resultsDiv.innerHTML = cards.join('');
            }
            this.addActivity(`Search: "${query}" — ${local.length} RAG, ${web.length} OSINT`);
            const last = document.getElementById('lastSearch');
            if (last) last.textContent = `Last: "${query}"`;
        } catch (err) {
            resultsDiv.innerHTML = '<div class="empty">Search failed. See server logs.</div>';
            this.addActivity(`Search failed: ${err}`);
        } finally {
            if (loading) loading.classList.add('hidden');
        }
    }

    executeSearch() {
        this.doSearch(false);
    }

    executeDeepSearch() {
        this.doSearch(true);
    }

    clearResults() {
        const resultsDiv = document.getElementById('searchResults');
        const input = document.getElementById('searchInput');
        if (resultsDiv) resultsDiv.innerHTML = '';
        if (input) input.value = '';
        const last = document.getElementById('lastSearch');
        if (last) last.textContent = 'No recent searches';
        this.addActivity('Results cleared');
    }

    connectWebSocket() {
        const wsUrl = `ws://${window.location.host}/ws/attack`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.updateConnectionStatus(true);
            this.log('system', 'Connected to ZAHRA server');
        };

        this.ws.onmessage = (event) => {
            let data;
            try {
                data = JSON.parse(event.data);
            } catch {
                return;
            }
            this.handleMessage(data);
        };

        this.ws.onclose = () => {
            this.updateConnectionStatus(false);
            this.log('error', 'Disconnected from server. Reconnecting...');
            setTimeout(() => this.connectWebSocket(), 3000);
        };

        this.ws.onerror = () => {
            this.log('error', 'WebSocket error');
        };
    }

    handleMessage(data) {
        this.events.push(data);
        if (this.events.length > 200) this.events.shift();

        switch (data.type) {
            case 'system':
                this.log('system', data.message);
                break;
            case 'campaign_created':
                this.campaignId = data.campaign_id;
                this.log('success', `Campaign created: ${data.campaign_id}`);
                this.log('info', `Target: ${data.target}`);
                this.resetAgents();
                break;
            case 'campaign_starting':
                this.log('info', 'Starting campaign execution...');
                break;
            case 'agent_started':
                this.updateAgentStatus(data.agent, 'running');
                this.log('info', `${data.agent} started`);
                this.addGraphNode(data.agent, 'running');
                break;
            case 'tool_used':
                this.log('command', `Executing: ${data.detail}`);
                this.addGraphEdge(data.agent || 'orchestrator', data.detail || 'tool');
                break;
            case 'agent_finished':
                this.updateAgentStatus(data.agent, 'done');
                this.log('success', `${data.agent} completed: ${data.detail}`);
                this.addGraphNode(data.agent, 'done');
                break;
            case 'campaign_completed':
                this.log('success', 'Campaign completed!');
                this.loadPlatformStatus();
                this.loadCampaigns();
                break;
            case 'finding':
                this.addFinding(data.data);
                break;
            case 'critical_alert':
                this.showToast('critical',
                    `CRITICAL FINDING (${(data.severity || 'high').toUpperCase()})`,
                    `${data.agent || 'agent'}: ${data.description || data.detail || ''}`);
                this.notifyDesktop('ZAHRA — Critical finding!',
                    `${data.agent || 'agent'}: ${(data.description || data.detail || '').slice(0, 120)}`);
                break;
            case 'scheduled_run':
                this.showToast('info', 'SCHEDULED CAMPAIGN',
                    `${data.command} → ${data.campaign_id || ''} (${data.findings || 0} findings, ${data.status || ''})`);
                this.log('info', `Scheduled run: ${data.command} → ${data.findings || 0} findings`);
                this.loadCampaigns();
                break;
            case 'error':
                this.log('error', data.message);
                break;
            default:
                if (data.agent && data.detail) {
                    this.log('info', `${data.agent}: ${data.detail}`);
                }
                break;
        }
    }

    updateConnectionStatus(connected) {
        const pairs = [
            ['connectionDot', 'connectionText'],
            ['connectionDotTop', 'connectionTextTop']
        ];
        pairs.forEach(([dotId, textId]) => {
            const dot = document.getElementById(dotId);
            const text = document.getElementById(textId);
            if (!dot) return;
            if (connected) {
                dot.classList.remove('offline');
                dot.classList.add('online');
            } else {
                dot.classList.remove('online');
                dot.classList.add('offline');
            }
            if (text) text.textContent = connected ? 'Connected' : 'Disconnected';
        });
    }

    updateAgentStatus(agentName, status) {
        const agentMap = {
            'coordinator_agent': 'coordinator',
            'recon_agent': 'recon',
            'scan_agent': 'scan',
            'exploit_agent': 'exploit',
            'c2_agent': 'c2',
            'mitm_agent': 'mitm'
        };

        const agentId = agentMap[agentName] || agentName;
        if (!agentId) return;

        const row = document.querySelector(`.agent-row[data-agent="${agentId}"]`);
        if (row) {
            const dot = row.querySelector('.agent-dot');
            const text = row.querySelector('.agent-status-text');
            if (dot) dot.className = `agent-dot ${status}`;
            if (text) text.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }
        this.updateNavAgentBadge();

        const card = document.getElementById(`agent-${agentId}`);
        if (card) {
            card.classList.remove('idle', 'running', 'done', 'blocked');
            card.classList.add(status);
            const statusText = card.querySelector('.status-text');
            const statusIndicator = card.querySelector('.status-indicator');
            if (statusText) statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
            if (statusIndicator) statusIndicator.className = `status-indicator ${status}`;
        }
    }

    addFinding(finding) {
        this.findings.push(finding);
        this.renderFindings();
        this.updateKPI();
        this.pushSpark('findings');
    }

    updateNavAgentBadge() {
        const badge = document.getElementById('navAgentsBadge');
        if (!badge) return;
        const busy = document.querySelectorAll('.agent-row .agent-dot.running, .agent-row .agent-dot.done').length;
        badge.textContent = busy;
        badge.hidden = busy === 0;
    }

    attachNavEnhancements() {
        const rail = document.getElementById('tacticalRail');
        const railToggle = document.getElementById('railToggle');
        const icoClose = '<svg class="w-4 h-4 inline-block" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/><path d="m16 15-3-3 3-3"/></svg>';
        const icoOpen = '<svg class="w-4 h-4 inline-block" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/><path d="m14 9 3 3-3 3"/></svg>';
        if (rail && railToggle) {
            railToggle.innerHTML = icoClose;
            railToggle.addEventListener('click', () => {
                rail.classList.toggle('rail-collapsed');
                railToggle.innerHTML = rail.classList.contains('rail-collapsed') ? icoOpen : icoClose;
            });
        }

        const wsTrigger = document.getElementById('wsTrigger');
        const wsMenu = document.getElementById('wsMenu');
        if (wsTrigger && wsMenu) {
            wsTrigger.addEventListener('click', (e) => {
                e.stopPropagation();
                wsMenu.classList.toggle('hidden');
            });
            document.addEventListener('click', (e) => {
                if (!wsMenu.classList.contains('hidden') && !wsMenu.contains(e.target)) {
                    wsMenu.classList.add('hidden');
                }
            });
            wsMenu.querySelectorAll('.ws-option[data-ws]').forEach(opt => {
                opt.addEventListener('click', () => {
                    const name = opt.dataset.ws;
                    const wsName = document.getElementById('wsName');
                    if (wsName) wsName.textContent = name;
                    wsMenu.querySelectorAll('.ws-option[data-ws]').forEach(o => o.classList.remove('selected'));
                    opt.classList.add('selected');
                    wsMenu.classList.add('hidden');
                });
            });
        }

        const navSearch = document.getElementById('navSearch');
        if (navSearch) {
            const runSearch = () => {
                this.switchView('overview');
                const t = document.getElementById('targetInput');
                if (t) { t.focus(); t.select(); }
            };
            navSearch.addEventListener('click', (e) => {
                e.preventDefault();
                runSearch();
            });
            document.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                    e.preventDefault();
                    runSearch();
                }
            });
        }
    }

    loadHistoricalFindings() {
        fetch('/memory/findings')
            .then(res => res.json())
            .then(list => {
                if (Array.isArray(list) && list.length) {
                    this.findings = list.slice(-20);
                    this.renderFindings();
                    this.updateKPI();
                }
            })
            .catch(() => {});
    }

    renderFindings() {
        const tbody = document.getElementById('findingsBody');
        if (!tbody) return;

        if (this.findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty">No findings yet</td></tr>';
            return;
        }

        tbody.innerHTML = this.findings.slice(-10).reverse().map(f => `
            <tr>
                <td><span class="pill ${f.severity || 'info'}">${(f.severity || 'INFO').toUpperCase()}</span></td>
                <td>${f.finding_type || 'info'}</td>
                <td>${f.description || ''}</td>
                <td>${f.agent_name || 'unknown'}</td>
                <td>${Math.round((f.confidence || 0) * 100)}%</td>
            </tr>
        `).join('');
    }

    updateKPI() {
        const count = document.getElementById('kpiFindings');
        if (count) count.textContent = this.findings.length;
    }

    initSparklines() {
        ['campaigns', 'findings', 'agents', 'rag'].forEach((key, i) => {
            const el = document.getElementById(`spark${key.charAt(0).toUpperCase() + key.slice(1)}`);
            if (el) this.renderSparkline(el, key);
        });
    }

    pushSpark(key) {
        const el = document.getElementById(`spark${key.charAt(0).toUpperCase() + key.slice(1)}`);
        if (el) this.renderSparkline(el, key);
    }

    renderSparkline(el, key) {
        const base = {
            campaigns: parseInt(document.getElementById('kpiCampaigns')?.textContent || '0', 10),
            findings: this.findings.length,
            agents: 6,
            rag: parseInt(document.getElementById('kpiRag')?.textContent || '0', 10)
        }[key] || 0;

        const current = this.sparkData[key];
        current.push(base);
        if (current.length > 24) current.shift();

        const w = el.clientWidth || 120;
        const h = el.clientHeight || 30;
        const max = Math.max(...current, 1);
        const min = Math.min(...current, 0);
        const range = (max - min) || 1;
        const pts = current.map((v, i) => {
            const x = (i / (current.length - 1)) * w;
            const y = h - ((v - min) / range) * h;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
        }).join(' ');

        const color = key === 'agents' ? '#7ae2ff' : '#c6ff00';
        el.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
            <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" opacity="0.9" />
            <polygon points="0,${h} ${pts} ${w},${h}" fill="${color}" opacity="0.08" />
        </svg>`;
    }

    loadPlatformStatus() {
        fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                const campaigns = document.getElementById('kpiCampaigns');
                if (campaigns && data.campaigns !== undefined) campaigns.textContent = data.campaigns;

                const memory = data.memory || {};
                const rag = memory.rag || {};
                const ragEl = document.getElementById('kpiRag');
                if (ragEl && rag.total !== undefined) ragEl.textContent = rag.total;

                this.loadCampaigns();
            })
            .catch(() => {});

        this.loadAIStatus();
    }

    loadCampaigns() {
        fetch('/api/campaigns')
            .then(res => res.json())
            .then(data => {
                this.campaigns = data.campaigns || [];
                const tbody = document.getElementById('campaignsBody');
                if (!tbody) return;

                if (this.campaigns.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty">No campaigns yet</td></tr>';
                    return;
                }

                tbody.innerHTML = this.campaigns.map(c => `
                    <tr>
                        <td>${(c.id || '').slice(0, 8)}</td>
                        <td>${c.target || ''}</td>
                        <td>${c.intent || ''}</td>
                        <td><span class="pill ${c.status || 'info'}">${(c.status || 'INFO').toUpperCase()}</span></td>
                        <td>${c.findings_count || 0}</td>
                    </tr>
                `).join('');
            })
            .catch(() => {});
    }

    initAIViews() {
        const thinkBtn = document.getElementById('aiThinkBtn');
        if (thinkBtn) {
            thinkBtn.addEventListener('click', () => {
                const input = document.getElementById('aiTaskInput');
                const task = input.value.trim();
                if (!task) return;
                const convBox = document.getElementById('aiConvBox');
                const output = document.getElementById('aiThinkOutput');
                if (convBox) this.appendAiTurn('user', task);
                input.value = '';
                if (output) {
                    output.hidden = false;
                    output.textContent = 'Thinking...';
                }
                fetch('/api/agent/think', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task, session: this.aiSession })
                })
                .then(res => res.json())
                .then(data => {
                    if (convBox) {
                        const reply = data.analysis || data.command || data.reasoning ||
                            data.response || (data.error ? `Error: ${data.error}` : JSON.stringify(data));
                        this.appendAiTurn('ai', reply, data.action);
                    }
                    if (output) output.textContent = JSON.stringify(data, null, 2);
                })
                .catch(err => {
                    if (convBox) this.appendAiTurn('ai', `Error: ${err}`);
                    if (output) output.textContent = `Error: ${err}`;
                });
            });
        }

        const resetBtn = document.getElementById('aiConvReset');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                const box = document.getElementById('aiConvBox');
                if (box) box.innerHTML = '';
                fetch('/api/agent/think/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session: this.aiSession })
                }).catch(() => {});
            });
        }

        const ragBtn = document.getElementById('ragSearchBtn');
        if (ragBtn) {
            ragBtn.addEventListener('click', () => {
                const query = document.getElementById('ragSearchInput').value.trim();
                if (!query) return;
                const results = document.getElementById('ragResults');
                results.innerHTML = '<div class="empty">Searching...</div>';
                fetch(`/api/agent/rag/recent?limit=50`)
                    .then(res => res.json())
                    .then(data => {
                        const entries = data.entries || [];
                        const filtered = entries.filter(e =>
                            (e.content || '').toLowerCase().includes(query.toLowerCase())
                        );
                        if (filtered.length === 0) {
                            results.innerHTML = '<div class="empty">No results found</div>';
                            return;
                        }
                        results.innerHTML = filtered.map(e => `
                            <div class="rag-result">
                                <span class="rag-category">[${e.category}]</span>
                                <div>${e.content}</div>
                                <span class="rag-score">${new Date((e.timestamp || 0) * 1000).toLocaleString()}</span>
                            </div>
                        `).join('');
                    })
                    .catch(err => {
                        results.innerHTML = `<div class="empty">Error: ${err}</div>`;
                    });
            });
        }
    }

    appendAiTurn(role, text, intent = '') {
        const box = document.getElementById('aiConvBox');
        if (!box) return;
        const div = document.createElement('div');
        div.className = `chat-msg ${role === 'user' ? 'user' : 'bot'}`;
        let html = '';
        if (intent) html += `<span class="intent-tag">${this.escapeHtml(intent)}</span>`;
        html += this.escapeHtml(text);
        div.innerHTML = html;
        box.appendChild(div);
        box.scrollTop = box.scrollHeight;
    }

    loadAIStatus() {
        fetch('/api/agent/status')
            .then(res => res.json())
            .then(data => {
                const set = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val;
                };
                set('aiBackend', data.backend || '—');
                set('aiModel', data.model || '—');
                set('aiRag', data.rag_enabled ? 'Enabled' : 'Disabled');
                set('aiWeb', data.web_search_enabled ? 'Enabled' : 'Disabled');
                set('aiBackend2', data.backend || '—');
                set('aiModel2', data.model || '—');
                set('aiRag2', data.rag_enabled ? 'Enabled' : 'Disabled');
                set('aiWeb2', data.web_search_enabled ? 'Enabled' : 'Disabled');
                set('setBackend', data.backend || '—');
                set('setModel', data.model || '—');
                set('setRag', data.rag_enabled ? 'Enabled' : 'Disabled');
                set('setWeb', data.web_search_enabled ? 'Enabled' : 'Disabled');

                const kpiRag = document.getElementById('kpiRag');
                if (kpiRag && data.rag) kpiRag.textContent = data.rag.total_entries || 0;

                const badge = document.getElementById('modelStatus');
                const text = document.getElementById('modelStatusText');
                if (badge && text) {
                    const backend = data.backend || 'offline';
                    const online = backend !== 'offline';
                    badge.classList.toggle('online', online);
                    badge.classList.toggle('offline', !online);
                    text.textContent = online
                        ? `Model: ${data.model || backend} (${backend})`
                        : 'Model: offline';
                }
            })
            .catch(() => {
                const badge = document.getElementById('modelStatus');
                const text = document.getElementById('modelStatusText');
                if (badge && text) {
                    badge.classList.add('offline');
                    badge.classList.remove('online');
                    text.textContent = 'Model: unreachable';
                }
            });
    }

    initDatabaseExplorer() {
        this.loadDbTables();

        const refreshBtn = document.getElementById('dbRefreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadDbTables());
        }

        const select = document.getElementById('dbTableSelect');
        if (select) {
            select.addEventListener('change', (e) => {
                const table = e.target.value;
                if (table) {
                    this.loadDbTableData(table);
                } else {
                    document.getElementById('dbTableHead').innerHTML = '';
                    document.getElementById('dbTableBody').innerHTML = '<tr><td colspan="5" class="empty">Select a table to view data</td></tr>';
                }
            });
        }
    }

    loadDbTables() {
        fetch('/api/db/tables')
            .then(res => res.json())
            .then(data => {
                const select = document.getElementById('dbTableSelect');
                if (!select) return;
                const current = select.value;
                select.innerHTML = '<option value="">Select table...</option>';
                (data.tables || []).forEach(table => {
                    const opt = document.createElement('option');
                    opt.value = table;
                    opt.textContent = table;
                    select.appendChild(opt);
                });
                if (current && (data.tables || []).includes(current)) {
                    select.value = current;
                    this.loadDbTableData(current);
                }
            })
            .catch(() => {});
    }

    loadDbTableData(table) {
        fetch(`/api/db/table/${encodeURIComponent(table)}`)
            .then(res => res.json())
            .then(data => {
                const head = document.getElementById('dbTableHead');
                const body = document.getElementById('dbTableBody');
                if (!head || !body) return;

                const columns = data.columns || [];
                const rows = data.rows || [];

                head.innerHTML = `<tr>${columns.map(c => `<th>${c}</th>`).join('')}</tr>`;

                if (rows.length === 0) {
                    body.innerHTML = `<tr><td colspan="${columns.length || 1}" class="empty">No data in table</td></tr>`;
                    return;
                }

                body.innerHTML = rows.map(row => `
                    <tr>${columns.map(c => `<td>${row[c] !== null && row[c] !== undefined ? row[c] : ''}</td>`).join('')}</tr>
                `).join('');
            })
            .catch(() => {
                document.getElementById('dbTableBody').innerHTML = '<tr><td colspan="5" class="empty">Failed to load table data</td></tr>';
            });
    }

    initAttackGraph() {
        this.loadBlackboard().then(() => {
            this.renderGraph();
        });
    }

    loadBlackboard() {
        return fetch('/api/blackboard')
            .then(res => res.json())
            .then(data => {
                const findings = data.findings || [];
                findings.forEach(f => {
                    this.addGraphNode(f.agent || 'unknown', 'idle', f.target || 'target');
                });
                this.renderGraph();
            })
            .catch(() => {});
    }

    addGraphNode(agent, status = 'idle', label) {
        const id = agent || 'unknown';
        if (!this.graphNodes.has(id)) {
            this.graphNodes.set(id, {
                id,
                label: label ? `${agent} → ${label}` : agent,
                status
            });
        } else {
            this.graphNodes.get(id).status = status;
        }
        if (this.graph) this.renderGraph();
    }

    addGraphEdge(from, label) {
        const edgeId = `${from}-${label}`;
        if (!this.graphEdges.has(edgeId)) {
            this.graphEdges.set(edgeId, { from, to: label, id: edgeId, label });
        }
        if (this.graph) this.renderGraph();
    }

    renderGraph() {
        const container = document.getElementById('attackGraph');
        if (!container) return;
        if (typeof vis === 'undefined') {
            container.innerHTML = '<div class="empty">Attack graph requires vis-network (CDN unavailable).</div>';
            return;
        }

        const nodes = Array.from(this.graphNodes.values()).map(n => ({
            id: n.id,
            label: n.label || n.id,
            color: n.status === 'running' ? '#ffb42e' : n.status === 'done' ? '#c6ff00' : '#7ae2ff',
            shape: 'dot',
            size: n.status === 'running' ? 22 : 16
        }));

        Object.keys(this.agents).forEach(a => {
            if (!nodes.some(n => n.id === a)) {
                nodes.push({ id: a, label: a, color: '#47576a', shape: 'dot', size: 14 });
            }
        });

        const edges = Array.from(this.graphEdges.values()).map(e => ({
            from: e.from,
            to: e.to,
            label: e.label,
            arrows: { to: { enabled: true, scaleFactor: 0.5 } },
            color: { color: 'rgba(198,255,0,0.4)', highlight: '#c6ff00' }
        }));

        const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
        const options = {
            nodes: {
                font: { color: '#e8eef6', size: 12, face: 'IBM Plex Mono' },
                borderWidth: 1,
                borderWidthSelected: 2
            },
            edges: {
                font: { color: '#6d7d8c', size: 10, face: 'IBM Plex Mono', align: 'middle' },
                smooth: { type: 'continuous', roundness: 0.4 }
            },
            physics: {
                enabled: true,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 120 }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        this.graph = new vis.Network(container, data, options);
    }

    log(type, message) {
        const terminals = document.querySelectorAll('.terminal-content');
        if (!terminals.length) return;
        const timestamp = new Date().toLocaleTimeString();

        terminals.forEach(terminal => {
            const line = document.createElement('div');
            line.className = `terminal-line ${type}`;
            line.innerHTML = `
                <span class="timestamp">[${timestamp}]</span>
                <span class="message"></span>
            `;
            line.querySelector('.message').textContent = message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        });

        this.pushSpark('agents');
    }

    sendCommand(action) {
        let target = document.getElementById('targetInput').value.trim();
        if (!target) {
            target = '127.0.0.1';
            this.log('info', 'No target specified, using default 127.0.0.1');
        }

        const command = `${action} ${target}`;

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                command: command,
                auto_run: true
            }));
            this.log('info', `Sending command: ${command}`);
            this.switchView('agents');
        } else {
            this.log('error', 'Not connected to server');
        }
    }

    resetAgents() {
        Object.keys(this.agents).forEach(agent => {
            this.updateAgentStatus(agent, 'idle');
        });
        this.findings = [];
        this.renderFindings();
        this.updateKPI();
    }

    initChat() {
        const sendBtn = document.getElementById('chatSendBtn');
        const input = document.getElementById('chatInput');
        const clearBtn = document.getElementById('chatClearBtn');
        if (!sendBtn || !input) return;
        const chat = this;

        const send = () => {
            const text = input.value.trim();
            if (!text) return;
            chat.appendChatMsg('user', text);
            input.value = '';
            chat.setChatStatus('زهرة تفكر...');
            fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, history: [] })
            })
            .then(res => res.json())
            .then(data => {
                chat.setChatStatus('');
                chat.appendChatMsg('bot', data.reply || 'No reply', data.intent, data.sources);
            })
            .catch(err => {
                chat.setChatStatus('');
                chat.appendChatMsg('bot', `خطأ: ${err}`);
            });
        };

        sendBtn.addEventListener('click', send);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                document.getElementById('chatMessages').innerHTML = '';
            });
        }
        this.appendChatMsg('bot', 'أهلاً! أنا زهرة 🤖 اسألني عن أي موضوع تقني (RAG من ملفاتك)، أو اطلب أمرًا: scan 127.0.0.1 / assess <target> / ابحث عن <مصطلح>', 'help');
    }

    appendChatMsg(role, text, intent = '', sources = []) {
        const box = document.getElementById('chatMessages');
        if (!box) return;
        const div = document.createElement('div');
        div.className = `chat-msg ${role}`;
        let html = '';
        if (intent) html += `<span class="intent-tag">${intent}</span>`;
        html += this.escapeHtml(text);
        div.innerHTML = html;
        if (sources && sources.length) {
            const src = document.createElement('div');
            src.className = 'src-list';
            src.innerHTML = sources.slice(0, 5).map(s =>
                `<div>• ${this.escapeHtml(s.type || 'src')}: ${this.escapeHtml((s.title || s.name || s.command || '').slice(0, 90))}</div>`
            ).join('');
            div.appendChild(src);
        }
        box.appendChild(div);
        box.scrollTop = box.scrollHeight;
    }

    setChatStatus(text) {
        const el = document.getElementById('chatStatus');
        if (el) el.textContent = text;
    }

    escapeHtml(str) {
        return String(str || '')
            .replace(/\x26/g, '&a' + 'mp;')
            .replace(/\x3C/g, '&l' + 't;')
            .replace(/\x3E/g, '&g' + 't;')
            .replace(/\x22/g, '&q' + 'uot;')
            .replace(/\x27/g, '&#0' + '39;');
    }

    attachEventListeners() {
        document.querySelectorAll('.nav-link[data-view]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const view = link.dataset.view;
                this.switchView(view);
            });
        });

        document.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                this.sendCommand(action);
            });
        });

        const fullBtn = document.getElementById('btnFullSwarm');
        if (fullBtn) {
            fullBtn.addEventListener('click', () => this.sendCommand('full'));
        }

        const clearBtn = document.getElementById('clearTerminal');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                document.querySelectorAll('.terminal-content').forEach(t => { t.innerHTML = ''; });
            });
        }

        const clearLiveBtn = document.getElementById('clearTerminalLive');
        if (clearLiveBtn) {
            clearLiveBtn.addEventListener('click', () => {
                document.querySelectorAll('.terminal-content').forEach(t => { t.innerHTML = ''; });
            });
        }

        ['btnExportReport', 'btnExportReport2'].forEach(id => {
            const b = document.getElementById(id);
            if (b) b.addEventListener('click', () => this.exportReport('html'));
        });
        const jsonBtn = document.getElementById('btnExportJson');
        if (jsonBtn) jsonBtn.addEventListener('click', () => this.exportReport('json'));

        const targetInput = document.getElementById('targetInput');
        if (targetInput) {
            targetInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.sendCommand('full');
                }
            });
        }
    }

    initTheme() {
        const saved = localStorage.getItem('zahra-theme');
        if (saved === 'light') this.applyTheme('light');
        const btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', () => {
            const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
            this.applyTheme(next);
        });
    }

    applyTheme(theme) {
        if (theme === 'light') {
            document.documentElement.dataset.theme = 'light';
        } else {
            delete document.documentElement.dataset.theme;
        }
        localStorage.setItem('zahra-theme', theme);
    }

    showToast(kind, title, message) {
        const stack = document.getElementById('toastStack');
        if (!stack) return;
        const toast = document.createElement('div');
        toast.className = `toast ${kind}`;
        toast.innerHTML = `
            <span class="t-close" title="dismiss">&times;</span>
            <span class="t-title">${this.escapeHtml(title)}</span>
            <span>${this.escapeHtml(message)}</span>`;
        toast.querySelector('.t-close').addEventListener('click', () => toast.remove());
        stack.appendChild(toast);
        setTimeout(() => toast.remove(), 9000);
    }

    initNotifications() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    notifyDesktop(title, body) {
        try {
            if ('Notification' in window && Notification.permission === 'granted') {
                new Notification(title, { body, tag: 'zahra-alert' });
            }
        } catch (e) { /* ignore */ }
    }

    initScheduler() {
        fetch('/api/scheduler/config')
            .then(res => res.json())
            .then(cfg => this.renderScheduler(cfg))
            .catch(() => {});

        const toggle = document.getElementById('schedToggle');
        if (toggle) toggle.addEventListener('click', () => {
            const on = !toggle.classList.contains('on');
            this.postScheduler({ enabled: on });
        });
        const save = document.getElementById('schedSave');
        if (save) save.addEventListener('click', () => {
            this.postScheduler({
                interval_seconds: parseInt(document.getElementById('schedInterval').value || '3600', 10),
                command: document.getElementById('schedCommand').value.trim() || 'full 127.0.0.1'
            });
        });
        const runNow = document.getElementById('schedRunNow');
        if (runNow) runNow.addEventListener('click', () => {
            this.log('command', 'Triggering scheduled campaign now...');
            fetch('/api/scheduler/run-now', { method: 'POST' })
                .then(res => res.json())
                .then(d => {
                    if (d.started) {
                        this.log('success', `Scheduled campaign started: ${d.campaign_id}`);
                        this.showToast('success', 'CAMPAIGN STARTED', `${d.command} → ${d.campaign_id}`);
                    } else {
                        this.log('error', `Scheduled run failed: ${d.error || 'unknown'}`);
                    }
                })
                .catch(e => this.log('error', `Scheduler: ${e}`));
        });
    }

    postScheduler(body) {
        fetch('/api/scheduler/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(res => res.json())
        .then(cfg => this.renderScheduler(cfg))
        .catch(() => {});
    }

    renderScheduler(cfg) {
        const toggle = document.getElementById('schedToggle');
        if (toggle) toggle.classList.toggle('on', !!cfg.enabled);
        const interval = document.getElementById('schedInterval');
        if (interval && cfg.interval_seconds) interval.value = cfg.interval_seconds;
        const command = document.getElementById('schedCommand');
        if (command && cfg.command) command.value = cfg.command;
        const set = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };
        set('schedRuns', cfg.runs || 0);
        set('schedErrors', cfg.errors || 0);
        set('schedLast', cfg.last_run ? new Date(cfg.last_run * 1000).toLocaleTimeString() : '—');
        set('schedNext', cfg.next_run ? new Date(cfg.next_run * 1000).toLocaleTimeString() : '—');
    }

    initSwarmControl() {
        this.loadAgentsFull();

        document.querySelectorAll('.ag-deploy').forEach(btn => {
            btn.addEventListener('click', () => {
                const agent = btn.dataset.agent;
                const input = document.querySelector(`.ag-target[data-agent="${agent}"]`);
                const target = (input ? input.value.trim() : '') || '127.0.0.1';
                this.log('command', `Deploying ${agent} → ${target}`);
                fetch(`/api/agents/${agent}/deploy`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                })
                .then(res => res.json())
                .then(f => {
                    const msg = f.error || f.description || `${agent} deployed`;
                    this.log('info', `${agent}: ${msg}`);
                    this.showToast('success', 'AGENT DEPLOYED', `${agent} → ${target}`);
                    this.loadAgentsFull();
                    this.loadAgentLogs(agent, true);
                })
                .catch(e => this.log('error', `${agent} deploy failed: ${e}`));
            });
        });

        document.querySelectorAll('.ag-toggle').forEach(btn => {
            btn.addEventListener('click', () => {
                const agent = btn.dataset.agent;
                const enabled = btn.dataset.enabled !== '1';
                fetch(`/api/agents/${agent}/enabled`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled })
                })
                .then(res => res.json())
                .then(d => {
                    if (d.error) return this.log('error', d.error);
                    btn.dataset.enabled = enabled ? '1' : '0';
                    btn.textContent = enabled ? 'ENABLED' : 'DISABLED';
                    btn.classList.toggle('!bg-[#ff2d55]/20', !enabled);
                    this.log('info', `${agent} ${enabled ? 'ENABLED' : 'DISABLED'}`);
                })
                .catch(e => this.log('error', `Toggle failed: ${e}`));
            });
        });

        document.querySelectorAll('.ag-iters').forEach(inp => {
            inp.addEventListener('change', () => {
                this.postAgentConfig(inp.dataset.agent, { iterations: parseInt(inp.value || '10', 10) });
            });
        });
        document.querySelectorAll('.ag-rps').forEach(inp => {
            inp.addEventListener('change', () => {
                this.postAgentConfig(inp.dataset.agent, { rps: parseFloat(inp.value || '0') });
            });
        });

        document.querySelectorAll('.ag-logs').forEach(btn => {
            btn.addEventListener('click', () => this.loadAgentLogs(btn.dataset.agent));
        });
    }

    postAgentConfig(agent, body) {
        let url = `/api/agents/${agent}/`;
        let payload = {};
        if (body.iterations !== undefined) {
            url += 'max-iterations';
            payload = { iterations: body.iterations };
        } else {
            url += 'rate-limit';
            payload = { rps: body.rps };
        }
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(d => {
            if (d.error) return this.log('error', `${agent}: ${d.error}`);
            this.log('info', `${agent}: ${JSON.stringify(d)}`);
        })
        .catch(e => this.log('error', `${agent} config failed: ${e}`));
    }

    loadAgentsFull() {
        fetch('/api/agents')
            .then(res => res.json())
            .then(data => {
                (data.agents || []).forEach(a => {
                    const btn = document.querySelector(`.ag-toggle[data-agent="${a.name}"]`);
                    if (btn) {
                        btn.dataset.enabled = a.enabled ? '1' : '0';
                        btn.textContent = a.enabled ? 'ENABLED' : 'DISABLED';
                        btn.classList.toggle('!bg-[#ff2d55]/20', !a.enabled);
                    }
                    const iters = document.querySelector(`.ag-iters[data-agent="${a.name}"]`);
                    if (iters) iters.value = a.max_iterations;
                    const rps = document.querySelector(`.ag-rps[data-agent="${a.name}"]`);
                    if (rps) rps.value = a.rate_limit || 0;
                    const card = document.getElementById(`agent-${a.name.replace('_agent', '')}`);
                    if (card) {
                        card.classList.remove('idle', 'running', 'done', 'blocked');
                        card.classList.add(a.enabled ? 'idle' : 'blocked');
                        const statusText = card.querySelector('.status-text');
                        const statusIndicator = card.querySelector('.status-indicator');
                        if (statusText) statusText.textContent = a.enabled ? 'Idle' : 'Disabled';
                        if (statusIndicator) statusIndicator.className = `status-indicator ${a.enabled ? 'idle' : 'blocked'}`;
                    }
                });
            })
            .catch(() => {});
    }

    loadAgentLogs(agent, open = false) {
        fetch(`/api/agents/${agent}/logs`)
            .then(res => res.json())
            .then(data => {
                const box = document.getElementById(`log-${agent}`);
                if (!box) return;
                const logs = data.logs || [];
                box.innerHTML = logs.length
                    ? logs.slice(-50).map(l => {
                        const t = new Date(l.ts * 1000).toLocaleTimeString();
                        return `<div>[${t}] [${l.level}] ${this.escapeHtml(l.message)}</div>`;
                      }).join('')
                    : '<div>No activity yet</div>';
                box.hidden = !open ? !box.hidden : false;
                box.scrollTop = box.scrollHeight;
            })
            .catch(() => {});
    }

    exportReport(format) {
        window.open(`/api/reports/export?format=${format}`, '_blank');
    }

    switchView(view) {
        document.querySelectorAll('.nav-link[data-view]').forEach(link => {
            link.classList.toggle('active', link.dataset.view === view);
        });

        document.querySelectorAll('.view').forEach(v => {
            v.classList.remove('active');
        });
        const target = document.getElementById(`view-${view}`);
        if (target) target.classList.add('active');

        const title = document.getElementById('pageTitle');
        if (title) {
            const names = {
                'overview': 'Overview',
                'agents': 'Agents',
                'campaigns': 'Campaigns',
                'database': 'Database',
                'ai-agent': 'AI Brain',
                'rag-memory': 'RAG Memory',
                'attack-graph': 'Attack Graph',
                'terminal': 'Terminal',
                'settings': 'Settings'
            };
            title.textContent = names[view] || view;
        }

        if (view === 'attack-graph') {
            this.renderGraph();
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new ZAHRADashboard();
});
