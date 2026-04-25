/* SOC Dashboard — main JS */
'use strict';

let STATE = { hosts: [], alerts: [], techniques: [], graph: null, scanMeta: {} };
const DANGEROUS_PORTS = new Set([21,22,23,25,53,135,139,445,512,513,514,1433,1521,3306,3389,4444,5900,6379,8080,27017]);

// ── NAVIGATION ────────────────────────────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`panel-${name}`).classList.add('active');
  event.currentTarget.classList.add('active');
  if (name === 'graph' && STATE.graph) renderGraph(STATE.graph);
}

// ── UPLOAD ────────────────────────────────────────────────────────────────────
function dropFile(event, type) {
  event.preventDefault();
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const input = document.getElementById(type === 'nmap' ? 'nmap-file' : 'pcap-file');
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  uploadFile(type);
}

async function uploadFile(type) {
  const isNmap = type === 'nmap';
  const input = document.getElementById(isNmap ? 'nmap-file' : 'pcap-file');
  const statusEl = document.getElementById(isNmap ? 'nmap-status' : 'pcap-status');
  if (!input.files[0]) return;

  const fd = new FormData();
  fd.append('file', input.files[0]);
  statusEl.innerHTML = `<span class="soc-spinner"></span>Uploading...`;

  try {
    const url = isNmap ? '/api/upload/nmap' : '/api/upload/wireshark';
    const res = await fetch(url, { method: 'POST', body: fd });
    const data = await res.json();

    if (data.error) { statusEl.innerHTML = `<span class="text-danger">${data.error}</span>`; return; }

    statusEl.innerHTML = `<span class="text-success"><i class="bi bi-check-circle me-1"></i>Loaded successfully</span>`;

    if (isNmap) {
      STATE.hosts = data.hosts || [];
      STATE.alerts = data.alerts || [];
      STATE.techniques = data.techniques || [];
      STATE.graph = data.graph || null;
      STATE.scanMeta = data.scan_meta || {};
      updateStats(data.alert_summary);
      renderHosts();
      renderAlerts();
      renderMitre();
      renderCVEs();
      document.getElementById('scan-status').textContent =
        `${STATE.scanMeta.total_hosts || 0} hosts • ${STATE.scanMeta.scan_time?.slice(0,10) || 'now'}`;
    } else {
      renderWireshark(data);
    }
  } catch (e) {
    statusEl.innerHTML = `<span class="text-danger">Error: ${e.message}</span>`;
  }
}

// ── STATS BAR ─────────────────────────────────────────────────────────────────
function updateStats(alertSummary) {
  const sev = alertSummary?.severity_breakdown || {};
  document.getElementById('s-hosts').textContent = STATE.hosts.length;
  document.getElementById('s-critical').textContent = sev.CRITICAL || 0;
  document.getElementById('s-high').textContent = sev.HIGH || 0;
  document.getElementById('s-medium').textContent = sev.MEDIUM || 0;
  document.getElementById('s-techniques').textContent = new Set(STATE.techniques.map(t => t.technique_id)).size;
  const totalCVEs = STATE.hosts.reduce((s, h) => s + (h.cves?.length || 0), 0);
  document.getElementById('s-cves').textContent = totalCVEs;

  const badge = document.getElementById('alert-badge');
  if (STATE.alerts.length) {
    badge.textContent = STATE.alerts.length;
    badge.classList.remove('d-none');
  }
}

// ── HOSTS ─────────────────────────────────────────────────────────────────────
function renderHosts(filter = '') {
  const container = document.getElementById('hosts-table-container');
  const filtered = STATE.hosts.filter(h =>
    !filter || h.ip.includes(filter) || (h.hostname || '').toLowerCase().includes(filter.toLowerCase())
  );

  if (!filtered.length) {
    container.innerHTML = '<p class="text-muted text-center py-4">No hosts match filter.</p>';
    return;
  }

  const rows = filtered.map(h => {
    const risk = h.risk_score || 0;
    const riskColor = risk >= 70 ? '#dc3545' : risk >= 40 ? '#fd7e14' : '#238636';
    const cveCount = h.cves?.length || 0;
    const maxCVSS = h.max_cvss || 0;

    return `<tr style="cursor:pointer" onclick="showHostDetail('${h.ip}')">
      <td><code class="text-info">${h.ip}</code></td>
      <td class="text-muted">${h.hostname !== h.ip ? h.hostname : '-'}</td>
      <td>${h.os?.name ? h.os.name.slice(0,30) : '<span class="text-muted">Unknown</span>'}</td>
      <td>${h.open_port_count || 0}</td>
      <td>
        <div class="d-flex align-items-center gap-2">
          <div class="risk-bar" style="width:60px">
            <div class="risk-fill" style="width:${risk}%;background:${riskColor}"></div>
          </div>
          <span style="color:${riskColor};font-weight:600">${risk}</span>
        </div>
      </td>
      <td>${maxCVSS > 0 ? `<span class="sev-badge sev-${cvssToSev(maxCVSS)}">${maxCVSS.toFixed(1)}</span>` : '-'}</td>
      <td>${cveCount > 0 ? `<span class="text-warning">${cveCount}</span>` : '-'}</td>
      <td><i class="bi bi-chevron-right text-muted"></i></td>
    </tr>`;
  }).join('');

  container.innerHTML = `
    <table class="soc-table">
      <thead><tr>
        <th>IP Address</th><th>Hostname</th><th>OS</th>
        <th>Open Ports</th><th>Risk Score</th><th>Max CVSS</th><th>CVEs</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function filterHosts() {
  renderHosts(document.getElementById('host-filter').value);
}

function showHostDetail(ip) {
  const host = STATE.hosts.find(h => h.ip === ip);
  if (!host) return;

  const openPorts = host.ports?.filter(p => p.state === 'open') || [];
  const portTags = openPorts.map(p => {
    const cls = DANGEROUS_PORTS.has(p.port) ? 'dangerous' : '';
    return `<span class="port-tag ${cls}">${p.port}/${p.service}</span>`;
  }).join('');

  const cveRows = (host.cves || []).slice(0, 10).map(c => `
    <tr>
      <td><a href="${c.url}" target="_blank" class="text-info">${c.cve_id}</a></td>
      <td><span class="sev-badge sev-${c.severity}">${c.severity}</span></td>
      <td><strong>${c.cvss_score.toFixed(1)}</strong></td>
      <td class="text-muted" style="font-size:0.78rem">${c.description}</td>
    </tr>`).join('');

  const techniques = STATE.techniques.filter(t => t.host === ip);
  const techHtml = techniques.map(t => `
    <div class="d-flex align-items-center gap-2 mb-1">
      <span class="mitre-id">${t.technique_id}</span>
      <span class="text-muted">${t.technique_name}</span>
      <span class="tactic-badge">${t.tactic_name}</span>
    </div>`).join('');

  const alerts = STATE.alerts.filter(a => a.host_ip === ip);
  const alertHtml = alerts.map(a => `
    <div class="alert-card ${a.severity} py-2 px-3 mb-2">
      <span class="sev-badge sev-${a.severity} me-2">${a.severity}</span>
      <strong>${a.rule_name}</strong>
      <p class="mb-1 mt-1 text-muted small">${a.description}</p>
      <div class="small text-muted">${a.mitigations?.map(m => `• ${m}`).join('<br>') || ''}</div>
    </div>`).join('');

  document.getElementById('modal-host-title').innerHTML =
    `<code class="text-info">${ip}</code> — ${host.hostname !== ip ? host.hostname : 'Host Detail'}`;

  document.getElementById('modal-host-body').innerHTML = `
    <div class="row g-3">
      <div class="col-md-6">
        <h6 class="text-muted">System Info</h6>
        <table class="soc-table"><tbody>
          <tr><td class="text-muted">IP</td><td><code>${host.ip}</code></td></tr>
          <tr><td class="text-muted">Hostname</td><td>${host.hostname || '-'}</td></tr>
          <tr><td class="text-muted">MAC</td><td>${host.mac || '-'}</td></tr>
          <tr><td class="text-muted">OS</td><td>${host.os?.name || 'Unknown'}</td></tr>
          <tr><td class="text-muted">Risk Score</td><td><strong>${host.risk_score}/100</strong></td></tr>
        </tbody></table>
        <h6 class="text-muted mt-3">Open Ports</h6>
        <div>${portTags || '<span class="text-muted">None</span>'}</div>
      </div>
      <div class="col-md-6">
        <h6 class="text-muted">Alerts (${alerts.length})</h6>
        ${alertHtml || '<p class="text-muted">No alerts</p>'}
        <h6 class="text-muted mt-3">MITRE Techniques</h6>
        ${techHtml || '<p class="text-muted">None</p>'}
      </div>
      <div class="col-12">
        <h6 class="text-muted">CVE Findings</h6>
        ${cveRows ? `<table class="soc-table"><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>${cveRows}</tbody></table>` : '<p class="text-muted">No CVEs found</p>'}
      </div>
    </div>`;

  new bootstrap.Modal(document.getElementById('hostModal')).show();
}

// ── ALERTS ────────────────────────────────────────────────────────────────────
function renderAlerts() {
  const container = document.getElementById('alerts-container');
  if (!STATE.alerts.length) {
    container.innerHTML = '<p class="text-success text-center py-5"><i class="bi bi-shield-check me-2"></i>No alerts triggered.</p>';
    return;
  }

  const cards = STATE.alerts.map(a => `
    <div class="alert-card ${a.severity}">
      <div class="d-flex justify-content-between align-items-center mb-1">
        <div class="d-flex align-items-center gap-2">
          <span class="sev-badge sev-${a.severity}">${a.severity}</span>
          <strong>${a.rule_name}</strong>
          <span class="text-muted small">${a.rule_id}</span>
        </div>
        <code class="text-info small">${a.host_ip}</code>
      </div>
      <p class="mb-1 text-muted">${a.description}</p>
      <div class="small text-muted mt-1">
        <i class="bi bi-tools me-1"></i>${a.mitigations?.slice(0,2).join(' • ') || ''}
      </div>
    </div>`).join('');

  container.innerHTML = cards;
}

// ── MITRE ─────────────────────────────────────────────────────────────────────
function renderMitre() {
  const container = document.getElementById('mitre-container');
  if (!STATE.techniques.length) {
    container.innerHTML = '<p class="text-muted text-center py-5">No techniques mapped.</p>';
    return;
  }

  const grouped = {};
  STATE.techniques.forEach(t => {
    if (!grouped[t.tactic_name]) grouped[t.tactic_name] = [];
    if (!grouped[t.tactic_name].find(x => x.technique_id === t.technique_id && x.host === t.host))
      grouped[t.tactic_name].push(t);
  });

  const html = Object.entries(grouped).map(([tactic, techs]) => `
    <div class="mb-3">
      <h6 class="text-muted mb-2"><span class="tactic-badge">${tactic}</span></h6>
      ${techs.map(t => `
        <div class="mitre-card">
          <div class="d-flex align-items-center gap-2 flex-wrap">
            <a href="${t.url}" target="_blank" class="mitre-id text-decoration-none">${t.technique_id}</a>
            <span>${t.technique_name}</span>
            <span class="text-muted small ms-auto">Port ${t.triggered_by_port} • ${t.host}</span>
          </div>
        </div>`).join('')}
    </div>`).join('');

  container.innerHTML = html;
}

// ── CVEs ──────────────────────────────────────────────────────────────────────
function renderCVEs() {
  const container = document.getElementById('cves-container');
  const allCVEs = STATE.hosts.flatMap(h =>
    (h.cves || []).map(c => ({ ...c, host_ip: h.ip }))
  ).sort((a, b) => b.cvss_score - a.cvss_score);

  if (!allCVEs.length) {
    container.innerHTML = '<p class="text-muted text-center py-5">No CVEs found (NVD lookup requires internet access).</p>';
    return;
  }

  const rows = allCVEs.slice(0, 50).map(c => `
    <tr>
      <td><a href="${c.url}" target="_blank" class="text-info text-decoration-none">${c.cve_id}</a></td>
      <td><span class="sev-badge sev-${c.severity}">${c.severity}</span></td>
      <td><strong>${c.cvss_score.toFixed(1)}</strong></td>
      <td><code class="text-info small">${c.host_ip}</code></td>
      <td class="text-muted" style="font-size:0.78rem">${c.description}</td>
    </tr>`).join('');

  container.innerHTML = `
    <table class="soc-table">
      <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Host</th><th>Description</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── ATTACK GRAPH ──────────────────────────────────────────────────────────────
function renderGraph(graphData) {
  const container = document.getElementById('attack-graph');
  if (!graphData?.nodes?.length) {
    container.innerHTML = '<p class="text-muted text-center pt-5">No graph data. Upload a scan first.</p>';
    return;
  }

  const nodes = new vis.DataSet(graphData.nodes);
  const edges = new vis.DataSet(graphData.edges);

  const options = {
    nodes: { font: { color: '#e6edf3', size: 11 }, borderWidth: 1, borderWidthSelected: 3 },
    edges: { font: { color: '#7d8590', size: 9, background: 'rgba(13,17,23,0.7)' }, smooth: { type: 'dynamic' } },
    groups: {
      attacker: { color: { background: '#dc3545', border: '#ff6b81' }, shape: 'triangle', size: 35 },
      host: { color: { background: '#1c2128', border: '#30363d' }, shape: 'box' },
      service: { color: { background: '#1f3a5f', border: '#1f6feb' }, shape: 'ellipse' },
      technique: { color: { background: '#2d1f47', border: '#6f42c1' }, shape: 'diamond' },
    },
    physics: { stabilization: { iterations: 150 }, barnesHut: { gravitationalConstant: -3000 } },
    interaction: { hover: true, tooltipDelay: 100 },
    layout: { improvedLayout: true },
  };

  container.innerHTML = '';
  new vis.Network(container, { nodes, edges }, options);
}

// ── WIRESHARK ─────────────────────────────────────────────────────────────────
function renderWireshark(data) {
  const container = document.getElementById('wireshark-container');
  if (data.error) { container.innerHTML = `<p class="text-danger">${data.error}</p>`; return; }

  const sum = data.summary || {};
  const susp = data.suspicious || [];
  const conv = data.conversations || [];

  const protoRows = Object.entries(sum.protocol_breakdown || {}).map(([p, c]) =>
    `<tr><td>${p}</td><td>${c}</td></tr>`).join('');

  const suspCards = susp.map(s => `
    <div class="alert-card ${s.severity} py-2 px-3 mb-2">
      <span class="sev-badge sev-${s.severity} me-2">${s.type}</span>
      ${s.description}
      <span class="ms-2 text-muted small">${s.src} → ${s.dst}:${s.port}</span>
    </div>`).join('');

  container.innerHTML = `
    <div class="row g-3">
      <div class="col-md-4">
        <div class="bg-dark rounded p-3 border border-secondary">
          <h6 class="text-muted">Packet Summary</h6>
          <div class="stat-value">${sum.total_packets?.toLocaleString() || 0}</div>
          <div class="stat-label">Total Packets</div>
          <hr class="border-secondary">
          <table class="soc-table mt-2"><thead><tr><th>Protocol</th><th>Count</th></tr></thead>
          <tbody>${protoRows}</tbody></table>
        </div>
      </div>
      <div class="col-md-8">
        <h6 class="text-muted">Suspicious Activity (${susp.length})</h6>
        ${suspCards || '<p class="text-success"><i class="bi bi-shield-check me-1"></i>No suspicious activity detected</p>'}
        <h6 class="text-muted mt-3">Top Conversations</h6>
        <table class="soc-table">
          <thead><tr><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes</th></tr></thead>
          <tbody>${conv.slice(0,10).map(c =>
            `<tr><td><code>${c.src}</code></td><td><code>${c.dst}</code></td>
             <td>${c.packets}</td><td>${(c.bytes/1024).toFixed(1)} KB</td></tr>`
          ).join('')}</tbody>
        </table>
      </div>
    </div>`;
}

// ── AI ANALYST ────────────────────────────────────────────────────────────────
async function runAIAnalysis() {
  const btn = document.getElementById('ai-btn');
  const container = document.getElementById('ai-report-container');
  btn.disabled = true;
  btn.innerHTML = '<span class="soc-spinner"></span> Analyzing with Claude...';
  container.innerHTML = '<p class="text-muted p-3">Claude is reading your scan data...</p>';

  try {
    const res = await fetch('/api/ai/analyze', { method: 'POST' });
    const data = await res.json();
    if (data.error) { container.innerHTML = `<p class="text-danger p-3">${data.error}</p>`; }
    else { container.innerHTML = marked.parse(data.report); }
  } catch (e) {
    container.innerHTML = `<p class="text-danger p-3">Error: ${e.message}</p>`;
  }
  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-play-fill me-1"></i> Run AI Analysis';
}

async function askAI() {
  const input = document.getElementById('ai-question');
  const container = document.getElementById('ai-answer');
  const q = input.value.trim();
  if (!q) return;

  container.innerHTML = '<p class="text-muted p-3"><span class="soc-spinner"></span> Thinking...</p>';
  try {
    const res = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q })
    });
    const data = await res.json();
    container.innerHTML = data.error
      ? `<p class="text-danger p-3">${data.error}</p>`
      : marked.parse(data.answer);
  } catch (e) {
    container.innerHTML = `<p class="text-danger p-3">Error: ${e.message}</p>`;
  }
}

async function runThreatHunt() {
  const btn = document.getElementById('hunt-btn');
  const container = document.getElementById('hunt-container');
  btn.disabled = true;
  btn.innerHTML = '<span class="soc-spinner"></span> Generating...';
  container.innerHTML = '<p class="text-muted p-3">Generating Sigma/KQL/SPL hunt queries...</p>';

  try {
    const res = await fetch('/api/ai/hunt', { method: 'POST' });
    const data = await res.json();
    container.innerHTML = data.error
      ? `<p class="text-danger p-3">${data.error}</p>`
      : marked.parse(data.queries);
  } catch (e) {
    container.innerHTML = `<p class="text-danger p-3">Error: ${e.message}</p>`;
  }
  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-search me-1"></i> Generate Hunt Queries';
}

// ── SAMPLE LOADER ─────────────────────────────────────────────────────────────
async function loadSample(type) {
  const btnMap = { nmap: 'btn-sample-nmap', wireshark: 'btn-sample-pcap', both: 'btn-sample-both' };
  const btn = document.getElementById(btnMap[type]);
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="soc-spinner"></span> Loading...';

  try {
    if (type === 'nmap' || type === 'both') {
      const res = await fetch('/api/load/sample', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'nmap'})
      });
      const data = await res.json();
      if (data.error) { alert(data.error); return; }
      STATE.hosts = data.hosts || [];
      STATE.alerts = data.alerts || [];
      STATE.techniques = data.techniques || [];
      STATE.graph = data.graph || null;
      STATE.scanMeta = data.scan_meta || {};
      updateStats(data.alert_summary);
      renderHosts();
      renderAlerts();
      renderMitre();
      renderCVEs();
      document.getElementById('scan-status').textContent =
        `${data.scan_meta.total_hosts} hosts • sample scan`;
      document.getElementById('nmap-status').innerHTML =
        '<span class="text-success"><i class="bi bi-check-circle me-1"></i>Sample scan loaded</span>';
    }

    if (type === 'wireshark' || type === 'both') {
      const res = await fetch('/api/load/sample', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'wireshark'})
      });
      const data = await res.json();
      if (data.error) { alert(data.error); return; }
      renderWireshark(data);
      document.getElementById('pcap-status').innerHTML =
        '<span class="text-success"><i class="bi bi-check-circle me-1"></i>Sample capture loaded</span>';
    }

    // Navigate to the best panel for what was loaded
    if (type === 'nmap') {
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      document.getElementById('panel-hosts').classList.add('active');
    } else if (type === 'wireshark') {
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      document.getElementById('panel-wireshark').classList.add('active');
    } else {
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      document.getElementById('panel-alerts').classList.add('active');
    }

  } catch (e) {
    alert('Error: ' + e.message);
  }

  btn.disabled = false;
  btn.innerHTML = orig;
}

// ── EXPORT ────────────────────────────────────────────────────────────────────
function exportJSON() { window.location.href = '/api/export/json'; }
function exportPDF()  { window.location.href = '/api/export/pdf'; }

async function clearSession() {
  await fetch('/api/session/clear', { method: 'POST' });
  STATE = { hosts: [], alerts: [], techniques: [], graph: null, scanMeta: {} };
  ['s-hosts','s-critical','s-high','s-medium','s-techniques','s-cves'].forEach(id =>
    document.getElementById(id).textContent = '0');
  document.getElementById('scan-status').textContent = 'No scan loaded';
  document.getElementById('alert-badge').classList.add('d-none');
  document.getElementById('hosts-table-container').innerHTML = '<p class="text-muted text-center py-5">Upload a scan to see hosts.</p>';
  document.getElementById('alerts-container').innerHTML = '<p class="text-muted text-center py-5">Upload a scan to see alerts.</p>';
  document.getElementById('mitre-container').innerHTML = '<p class="text-muted text-center py-5">Upload a scan to see techniques.</p>';
  document.getElementById('cves-container').innerHTML = '<p class="text-muted text-center py-5">Upload a scan to see CVEs.</p>';
  document.getElementById('attack-graph').innerHTML = '';
  document.getElementById('ai-report-container').innerHTML = '';
  document.getElementById('ai-answer').innerHTML = '';
  document.getElementById('hunt-container').innerHTML = '';
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function cvssToSev(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0)    return 'LOW';
  return 'NONE';
}
