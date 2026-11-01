const API = '/api';

let currentIncidentId = null;
let playbackFrames = [];
let playbackTimer = null;
let isPlaying = false;
let cyGraph = null;

// ─────────────────── CYTOSCAPE GRAPH INIT ────────────────────
function initGraph() {
  cyGraph = cytoscape({
    container: document.getElementById('cy-container'),
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'font-size': '9px',
          'font-family': 'JetBrains Mono, monospace',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': '4px',
          'color': '#94a3b8',
          'width': '28px',
          'height': '28px',
          'background-color': '#1e40af',
          'border-width': '2px',
          'border-color': '#1e3a8a',
        }
      },
      {
        selector: 'node[type="external"]',
        style: {
          'background-color': '#ef4444',
          'border-color': '#7f1d1d',
          'shape': 'triangle',
          'width': '24px',
          'height': '24px',
        }
      },
      {
        selector: 'node[type="crown_jewel"]',
        style: {
          'background-color': '#eab308',
          'border-color': '#713f12',
          'width': '36px',
          'height': '36px',
          'border-width': '3px',
          'shadow-blur': '15px',
          'shadow-color': '#eab308',
          'shadow-opacity': 0.8,
        }
      },
      {
        selector: 'node[zone="mgmt"]',
        style: {
          'background-color': '#a855f7',
          'border-color': '#581c87',
          'width': '32px',
          'height': '32px',
        }
      },
      {
        selector: 'node[isolated="true"]',
        style: {
          'background-color': '#475569',
          'border-color': '#334155',
          'opacity': 0.4,
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#38bdf8',
          'border-width': '3px',
        }
      },
      {
        selector: 'edge',
        style: {
          'width': '1.5px',
          'line-color': '#334155',
          'target-arrow-color': '#334155',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.7,
          'arrow-scale': 0.9,
        }
      },
      {
        selector: 'edge[severity="critical"], edge[severity="high"], edge[severity="HIGH"], edge[severity="CRITICAL"]',
        style: {
          'line-color': '#ef4444',
          'target-arrow-color': '#ef4444',
          'opacity': 1,
          'width': '2.5px',
        }
      },
      {
        selector: 'edge.playback-active',
        style: {
          'line-color': '#f97316',
          'target-arrow-color': '#f97316',
          'width': '3px',
          'opacity': 1,
        }
      },
      {
        selector: 'edge.bypass-route',
        style: {
          'line-color': '#eab308',
          'target-arrow-color': '#eab308',
          'width': '3px',
          'line-style': 'dashed',
        }
      }
    ],
    layout: { name: 'cose', animate: false }
  });

  cyGraph.on('tap', 'node', function(evt) {
    const node = evt.target;
    populateIsolateDropdown(node.id());
    document.getElementById('select-isolate-node').value = node.id();
  });
}

// ─────────────────── RENDER GRAPH ────────────────────
function renderIncidentGraph(graphData) {
  if (!cyGraph || !graphData) return;
  cyGraph.elements().remove();
  
  const elements = [
    ...graphData.nodes.map(n => ({ data: n.data })),
    ...graphData.edges.map(e => ({ data: e.data }))
  ];
  cyGraph.add(elements);
  cyGraph.layout({
    name: 'cose',
    animate: true,
    animationDuration: 500,
    idealEdgeLength: 120,
    nodeRepulsion: 8000,
    numIter: 1000,
    padding: 40,
    randomize: false,
  }).run();
}

// ─────────────────── INCIDENT LIST ────────────────────
async function loadIncidents() {
  try {
    const res = await fetch(`${API}/incidents`);
    const data = await res.json();
    const container = document.getElementById('incident-list-container');
    const countBadge = document.getElementById('incident-count-badge');
    countBadge.textContent = data.total_incidents;

    if (!data.incidents || data.incidents.length === 0) {
      container.innerHTML = '<div style="padding: 20px; color: #64748b; font-size: 12px;">No incidents found. Click "Re-Scan Dataset" to run the pipeline.</div>';
      return;
    }

    container.innerHTML = '';
    data.incidents.forEach(inc => {
      const sev = inc.severity || 'HIGH';
      const sevClass = sev === 'CRITICAL' ? 'badge-critical' : sev === 'HIGH' ? 'badge-high' : 'badge-medium';
      const riskColor = inc.risk_score >= 85 ? '#ef4444' : inc.risk_score >= 65 ? '#f97316' : '#eab308';
      
      const card = document.createElement('div');
      card.className = 'incident-card';
      card.dataset.id = inc.id;
      card.innerHTML = `
        <div class="card-top">
          <span class="card-id">${inc.id}</span>
          <span class="badge ${sevClass}">${sev}</span>
        </div>
        <div class="card-title">${inc.title}</div>
        <div class="card-metrics">
          <span style="color: ${riskColor}; font-weight: 700;">Risk: ${inc.risk_score}/100</span>
          <span>${inc.total_raw_alerts_merged?.toLocaleString() || 0} raw alerts merged</span>
          <span>${(inc.financial_exposure_usd / 1e6).toFixed(1)}M exposed</span>
        </div>
        <div style="margin-top: 6px; font-size: 10px; color: #475569; font-family: monospace;">
          ${(inc.techniques || []).join(' → ')}
        </div>
      `;
      card.addEventListener('click', () => selectIncident(inc.id));
      container.appendChild(card);
    });

    if (data.incidents.length > 0) {
      selectIncident(data.incidents[0].id);
    }
  } catch (err) {
    console.error('Failed to load incidents:', err);
    document.getElementById('incident-list-container').innerHTML = '<div style="padding:20px;color:#ef4444;font-size:12px;">Failed to connect to API. Is the server running?</div>';
  }
}

// ─────────────────── SELECT INCIDENT ────────────────────
async function selectIncident(id) {
  currentIncidentId = id;
  document.querySelectorAll('.incident-card').forEach(c => c.classList.remove('active'));
  const card = document.querySelector(`.incident-card[data-id="${id}"]`);
  if (card) card.classList.add('active');

  try {
    const [pathRes, reportRes, remRes, lookRes, playRes] = await Promise.all([
      fetch(`${API}/incidents/${id}/path`),
      fetch(`${API}/incidents/${id}/report`),
      fetch(`${API}/incidents/${id}/remediation`),
      fetch(`${API}/incidents/${id}/path`),
      fetch(`${API}/incidents/${id}/playback`)
    ]);

    const incident = await pathRes.json();
    const reports = await reportRes.json();
    const remediation = await remRes.json();
    const playback = await playRes.json();

    updateBanner(incident);
    renderIncidentGraph(incident.graph);
    populateIsolateDropdown(null, incident.nodes);
    renderReports(reports);
    renderRemediation(remediation);
    renderLookAhead(incident.look_ahead);
    setupPlayback(playback);

  } catch (err) {
    console.error('Failed to load incident details:', err);
  }
}

// ─────────────────── BANNER UPDATE ────────────────────
function updateBanner(incident) {
  const sev = incident.severity || 'HIGH';
  const sevEl = document.getElementById('banner-severity');
  sevEl.textContent = sev;
  sevEl.className = `badge badge-${sev.toLowerCase()}`;

  document.getElementById('banner-title').textContent = incident.title || 'Attack Incident';
  document.getElementById('banner-raw-merged').textContent = (incident.total_raw_alerts_merged || 0).toLocaleString();
  document.getElementById('banner-risk-score').textContent = `${incident.risk_score || '--'} / 100`;

  const exp = incident.financial_exposure_usd || 0;
  document.getElementById('banner-exposure').textContent = exp > 0 ? `$${(exp / 1e6).toFixed(1)}M` : '—';
}

// ─────────────────── POPULATE ISOLATE DROPDOWN ────────────────────
function populateIsolateDropdown(selected, nodes) {
  const sel = document.getElementById('select-isolate-node');
  if (nodes) {
    sel.innerHTML = '<option value="">Select node to isolate...</option>';
    nodes.forEach(n => {
      const opt = document.createElement('option');
      opt.value = n;
      opt.textContent = n;
      sel.appendChild(opt);
    });
  }
  if (selected) sel.value = selected;
}

// ─────────────────── BLAST RADIUS SIMULATION ────────────────────
document.getElementById('btn-isolate-simulate').addEventListener('click', async () => {
  const nodeId = document.getElementById('select-isolate-node').value;
  if (!nodeId || !currentIncidentId) {
    alert('Please select an incident and a node to isolate.');
    return;
  }

  const res = await fetch(`${API}/incidents/${currentIncidentId}/simulate-isolate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_id: nodeId })
  });
  const data = await res.json();

  if (cyGraph) {
    cyGraph.getElementById(nodeId).data('isolated', 'true');
    
    (data.active_bypass_routes || []).forEach(route => {
      (route.bypass_route || []).forEach((n, i, arr) => {
        if (i < arr.length - 1) {
          const edges = cyGraph.edges(`[source="${arr[i]}"][target="${arr[i+1]}"]`);
          edges.addClass('bypass-route');
        }
      });
    });
  }

  const contained = data.containment_successful;
  const simBox = document.getElementById('sim-result-box');
  const simIcon = document.getElementById('sim-icon');
  const simTitle = document.getElementById('sim-title');
  const simDesc = document.getElementById('sim-desc');

  simIcon.textContent = contained ? '✓' : '⚠';
  simBox.style.background = contained ? 'rgba(16,185,129,0.12)' : 'rgba(234,179,8,0.12)';
  simBox.style.borderColor = contained ? '#10b981' : '#eab308';
  simTitle.textContent = contained ? 'CONTAINMENT SUCCESS' : `PARTIAL — ${data.active_bypass_routes.length} Bypass Route(s) Remain`;
  simDesc.textContent = data.simulation_verdict;
  simBox.style.display = 'flex';
});

document.getElementById('btn-reset-graph').addEventListener('click', () => {
  document.getElementById('sim-result-box').style.display = 'none';
  document.getElementById('select-isolate-node').value = '';
  if (cyGraph) {
    cyGraph.nodes().data('isolated', 'false');
    cyGraph.edges().removeClass('bypass-route');
    cyGraph.edges().removeClass('playback-active');
  }
});

// ─────────────────── REPORTS ────────────────────
function renderReports(reports) {
  const boardRoom = document.getElementById('boardroom-report-content');
  const soc = document.getElementById('soc-report-content');
  boardRoom.innerHTML = markdownToHtml(reports.boardroom_summary || '');
  soc.innerHTML = markdownToHtml(reports.soc_technical_report || '');
}

function markdownToHtml(md) {
  return md
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/^## (.+)$/gm, '<h2>$2</h2>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>(\n)?)+/g, s => `<ul>${s}</ul>`)
    .replace(/\|(.+)\|/g, s => {
      const cells = s.split('|').filter(c => c.trim()).map(c => `<td style="padding:3px 6px;border:1px solid #1e293b;">${c.trim()}</td>`);
      return `<tr>${cells.join('')}</tr>`;
    })
    .replace(/(<tr>.*<\/tr>(\n)?)+/g, s => `<table style="font-size:10px;border-collapse:collapse;width:100%;margin-bottom:8px;">${s}</table>`)
    .replace(/\n/g, '<br>');
}

// ─────────────────── REMEDIATION CODE ────────────────────
function renderRemediation(data) {
  const playbooks = data.playbooks || {};
  document.getElementById('code-fortigate').textContent = playbooks.fortigate_cli || '# No data';
  document.getElementById('code-powershell').textContent = playbooks.powershell || '# No data';
  document.getElementById('code-cisco').textContent = playbooks.cisco_ios || '! No data';
}

function copyCode(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = event.target;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
}

// ─────────────────── LOOK-AHEAD REACHABILITY ────────────────────
function renderLookAhead(data) {
  const el = document.getElementById('lookahead-content');
  if (!data) { el.innerHTML = '<div class="placeholder-text">No reachability data.</div>'; return; }

  const cjRisks = data.crown_jewels_at_risk || [];
  const reachable = data.next_reachable_assets || [];

  let html = `
    <div style="font-size:11px;color:#94a3b8;margin-bottom:12px;">${data.look_ahead_summary || ''}</div>
  `;

  if (cjRisks.length > 0) {
    html += `<div style="font-size:12px;font-weight:700;color:#ef4444;margin-bottom:8px;">⚠ Crown Jewels at Risk</div>`;
    cjRisks.forEach(cj => {
      const urgColor = cj.urgency === 'IMMEDIATE' ? '#ef4444' : '#f97316';
      html += `
        <div style="background:#12192c;border:1px solid #1e293b;border-left:3px solid ${urgColor};border-radius:6px;padding:10px;margin-bottom:8px;">
          <div style="font-family:monospace;font-size:11px;font-weight:700;color:${urgColor};">${cj.urgency} — ${cj.hops_away} hop(s) away</div>
          <div style="font-size:10px;color:#94a3b8;margin-top:4px;">Crown Jewel: <code style="color:#eab308;">${cj.crown_jewel}</code></div>
          ${cj.path ? `<div style="font-size:10px;color:#64748b;margin-top:4px;">Path: ${cj.path.join(' → ')}</div>` : ''}
        </div>
      `;
    });
  }

  if (reachable.length > 0) {
    html += `<div style="font-size:12px;font-weight:700;color:#94a3b8;margin:12px 0 8px;">Next Lateral Targets</div>`;
    reachable.slice(0, 5).forEach(r => {
      html += `
        <div style="background:#12192c;border:1px solid #1e293b;border-radius:6px;padding:8px;margin-bottom:6px;">
          <div style="font-family:monospace;font-size:10px;font-weight:700;color:#38bdf8;">${r.hostname || r.target_node}</div>
          <div style="font-size:10px;color:#64748b;">${r.role} — <span style="color:#94a3b8;">${r.zone}</span></div>
        </div>
      `;
    });
  }

  el.innerHTML = html || '<div class="placeholder-text">No reachable assets identified.</div>';
}

// ─────────────────── TEMPORAL PLAYBACK ────────────────────
function setupPlayback(data) {
  playbackFrames = data.frames || [];
  const slider = document.getElementById('playback-slider');
  slider.max = Math.max(0, playbackFrames.length - 1);
  slider.value = 0;
  document.getElementById('playback-step-badge').textContent = `Step 0 / ${playbackFrames.length}`;
  document.getElementById('playback-caption').textContent = 'Temporal Attack Playback — Drag slider to inspect step-by-step';
  if (isPlaying) { clearInterval(playbackTimer); isPlaying = false; }
}

document.getElementById('playback-slider').addEventListener('input', function() {
  const idx = parseInt(this.value);
  renderPlaybackFrame(idx);
});

document.getElementById('btn-play-pause').addEventListener('click', function() {
  if (!playbackFrames.length) return;
  if (isPlaying) {
    clearInterval(playbackTimer);
    isPlaying = false;
  } else {
    isPlaying = true;
    let idx = parseInt(document.getElementById('playback-slider').value);
    playbackTimer = setInterval(() => {
      if (idx >= playbackFrames.length - 1) { clearInterval(playbackTimer); isPlaying = false; return; }
      idx++;
      document.getElementById('playback-slider').value = idx;
      renderPlaybackFrame(idx);
    }, 600);
  }
});

function renderPlaybackFrame(idx) {
  if (!playbackFrames[idx] || !cyGraph) return;
  const frame = playbackFrames[idx];
  
  document.getElementById('playback-step-badge').textContent = `Step ${idx + 1} / ${playbackFrames.length}`;
  document.getElementById('playback-caption').textContent = frame.caption || '';

  cyGraph.edges().removeClass('playback-active');
  
  (frame.cumulative_nodes || []).forEach(nid => {
    const n = cyGraph.getElementById(nid);
    if (n) n.style('opacity', 1);
  });

  const active = frame.active_edge;
  if (active) {
    const edges = cyGraph.edges(`[source="${active.source}"][target="${active.target}"]`);
    edges.addClass('playback-active');
  }
}

// ─────────────────── SIGMA RULES ────────────────────
async function loadRules() {
  try {
    const res = await fetch(`${API}/rules`);
    const data = await res.json();
    const box = document.getElementById('rules-list-box');
    box.innerHTML = '';
    (data.rules || []).forEach(r => {
      const div = document.createElement('div');
      div.style.cssText = 'background:#12192c;border:1px solid #1e293b;border-radius:6px;padding:10px;margin-bottom:8px;';
      div.innerHTML = `
        <div style="font-size:11px;font-weight:700;color:#38bdf8;">${r.title || r.id}</div>
        <div style="font-size:10px;color:#64748b;margin-top:3px;">${r.mitre?.technique_id} · ${r.mitre?.tactic} · <span style="color:${r.mitre?.severity === 'CRITICAL' ? '#ef4444' : '#f97316'}">${r.mitre?.severity}</span></div>
      `;
      box.appendChild(div);
    });
  } catch (err) {
    console.error('Failed to load rules', err);
  }
}

document.getElementById('btn-save-rule').addEventListener('click', async () => {
  const name = document.getElementById('new-rule-name').value.trim();
  const yaml = document.getElementById('new-rule-yaml').value.trim();
  if (!name || !yaml) { alert('Please provide a filename and YAML content.'); return; }

  const params = new URLSearchParams({ filename: name, yaml_content: yaml });
  const res = await fetch(`${API}/rules?${params}`, { method: 'POST' });
  const data = await res.json();
  if (data.status === 'SUCCESS') {
    alert(`Rule "${name}" saved and compiled!`);
    document.getElementById('new-rule-name').value = '';
    document.getElementById('new-rule-yaml').value = '';
    loadRules();
  } else {
    alert('Error: ' + JSON.stringify(data));
  }
});

// ─────────────────── PIPELINE RUN ────────────────────
document.getElementById('btn-run-pipeline').addEventListener('click', async () => {
  const btn = document.getElementById('btn-run-pipeline');
  btn.disabled = true;
  btn.textContent = '⟳ Scanning...';
  try {
    const res = await fetch(`${API}/pipeline/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ memory_limit: '6GB' })
    });
    const data = await res.json();
    alert(`Pipeline complete!\n${data.raw_alerts_merged?.toLocaleString()} raw alerts merged → ${data.aggregated_attack_steps?.toLocaleString()} attack steps\nTime: ${data.total_processing_time_seconds}s | Parquet: ${data.parquet_size_mb} MB`);
    loadIncidents();
    loadRules();
  } catch (err) {
    alert('Pipeline error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Re-Scan Dataset';
  }
});

// ─────────────────── TABS ────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab)?.classList.add('active');
    if (btn.dataset.tab === 'tab-agents' && currentIncidentId) {
      loadAgentStatus(currentIncidentId);
    }
  });
});

// ─────────────────── LANGGRAPH MULTI-AGENT UI ────────────────────
async function loadAgentStatus(incidentId) {
  const box = document.getElementById('agents-roster-box');
  if (!box) return;
  box.innerHTML = '<div style="color: #94a3b8; font-size: 12px; padding: 12px;">Loading LangGraph multi-agent state...</div>';

  try {
    const res = await fetch(`${API}/agents/status/${incidentId}`);
    const data = await res.json();
    renderAgentStatus(data);
  } catch (err) {
    box.innerHTML = `<div style="color: #ef4444; font-size: 12px;">Failed to load agents: ${err.message}</div>`;
  }
}

function renderAgentStatus(data) {
  const box = document.getElementById('agents-roster-box');
  const approvalBox = document.getElementById('agent-approval-box');
  const approvalDesc = document.getElementById('agent-approval-desc');
  if (!box) return;

  // Handle human approval status
  if (data.human_approval_required && approvalBox) {
    approvalBox.style.display = 'block';
    const rec = data.defense_plan_data?.recommended_containment_strategy || 'Quarantine critical pivot nodes';
    approvalDesc.innerHTML = `Proposed action: <strong>${rec}</strong>. Affects hosts: <code>${(data.defense_plan_data?.hosts_to_isolate || []).join(', ')}</code>.`;
  } else if (approvalBox) {
    approvalBox.style.display = 'none';
  }

  const AGENTS_SPEC = [
    { name: 'Investigation Agent', role: 'Primary Incident Investigator', icon: '🔍', key: 'investigation_findings' },
    { name: 'Attack Path Reconstruction Agent', role: 'Lateral Movement & Provenance', icon: '🕸️', key: 'attack_path_data' },
    { name: 'Threat Intelligence Agent', role: 'IOC & Threat Actor Enrichment', icon: '🛡️', key: 'threat_intel_data' },
    { name: 'Predictive Attack Agent', role: 'Next-Hop & Crown Jewel Reachability', icon: '🔮', key: 'predictions_data' },
    { name: 'Defense Optimization Agent', role: 'Containment Strategy & Vertex Cut', icon: '⚡', key: 'defense_plan_data' },
    { name: 'Forensics and Evidence Agent', role: 'Chronological Audit Ledger', icon: '📜', key: 'forensics_report_data' },
    { name: 'Response Governance and Validation Agent', role: 'Policy & Safety Validation', icon: '⚖️', key: 'governance_validation_data' }
  ];

  const completed = new Set(data.completed_agents || []);

  box.innerHTML = AGENTS_SPEC.map(spec => {
    const isDone = completed.has(spec.name);
    const agentData = data[spec.key];
    const summaryText = agentData?.summary || agentData?.incident_summary || 'Waiting for supervisor dispatch...';

    return `
      <div style="background: #1e293b; border: 1px solid ${isDone ? '#3b82f6' : '#334155'}; border-radius: 6px; padding: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <div style="display: flex; items-center; gap: 6px;">
            <span style="font-size: 14px;">${spec.icon}</span>
            <span style="font-weight: 600; font-size: 12px; color: ${isDone ? '#f8fafc' : '#94a3b8'};">${spec.name}</span>
          </div>
          <span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; background: ${isDone ? 'rgba(16, 185, 129, 0.2)' : 'rgba(148, 163, 184, 0.2)'}; color: ${isDone ? '#34d399' : '#94a3b8'};">
            ${isDone ? 'COMPLETED' : 'PENDING'}
          </span>
        </div>
        <div style="font-size: 11px; color: #64748b; margin-bottom: 6px;">${spec.role}</div>
        <div style="font-size: 11px; color: #cbd5e1; background: #0f172a; padding: 6px 8px; border-radius: 4px; line-height: 1.4;">
          ${summaryText}
        </div>
      </div>
    `;
  }).join('');
}

document.getElementById('btn-run-agents')?.addEventListener('click', async () => {
  if (!currentIncidentId) return;
  const btn = document.getElementById('btn-run-agents');
  btn.disabled = true;
  btn.textContent = '⏳ Orchestrating...';
  try {
    const res = await fetch(`${API}/agents/investigate/${currentIncidentId}`, { method: 'POST' });
    const data = await res.json();
    await loadAgentStatus(currentIncidentId);
  } catch (err) {
    alert(`Failed to run LangGraph agents: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Run 7-Agent Investigation';
  }
});

document.getElementById('btn-approve-containment')?.addEventListener('click', async () => {
  if (!currentIncidentId) return;
  await fetch(`${API}/agents/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incident_id: currentIncidentId, decision: 'APPROVED' })
  });
  document.getElementById('agent-approval-box').style.display = 'none';
  alert('Containment strategy formally approved by SOC Commander. Action logged to audit ledger.');
});

document.getElementById('btn-reject-containment')?.addEventListener('click', async () => {
  if (!currentIncidentId) return;
  await fetch(`${API}/agents/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incident_id: currentIncidentId, decision: 'REJECTED' })
  });
  document.getElementById('agent-approval-box').style.display = 'none';
  alert('Containment rejected. Supervisor notified.');
});

// ─────────────────── BOOTSTRAP ────────────────────
window.addEventListener('DOMContentLoaded', () => {
  initGraph();
  loadIncidents();
  loadRules();
});

window.copyCode = copyCode;
