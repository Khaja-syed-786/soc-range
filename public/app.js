// SOC Simulator front end — vanilla JS, no external libraries.
'use strict';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtTs = ts => ts ? new Date(ts).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';
const fmtDur = s => s == null ? '-' : s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}m` : `${(s / 3600).toFixed(1)}h`;
const SEV_COLOR = { low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' };
const VERDICT_LABEL = { true_positive: 'True positive', false_positive: 'False positive', benign: 'Benign' };
const IOC_TYPE = { ip: 'IP', domain: 'Domain', hash: 'Hash' };
const shortIoc = v => v.length > 28 ? `${v.slice(0, 6)}…${v.slice(-16)}` : v;
// Clickable indicator: opens it on the IOC Lookup page. Red when it is on the intel list.
const iocLink = x => `<a class="ioc-chip ${x.onIntel ? 'bad' : ''}" href="#ioc?v=${encodeURIComponent(x.value)}"
  title="${esc(x.value)}${x.onIntel ? ' (on the threat intel list)' : ''}"><span class="muted">${IOC_TYPE[x.type]}</span> <span class="mono">${esc(shortIoc(x.value))}</span></a>`;

let META = null;
let PLAYBOOKS = [];
let selectedAlert = null;
let selectedCase = null;
let searchPage = 0;

async function api(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-SocSim': '1', ...(opts.headers || {}) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = err ? 'err' : '';
  t.style.display = 'block';
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.style.display = 'none'; }, 3500);
}

// ---------- routing ----------
function show(view) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  ({ dashboard: loadDashboard, alerts: loadAlerts, cases: loadCases, search: runSearch, ioc: loadIoc, mitre: loadMitre,
    exercise: loadExercise, handover: loadHandover, rules: loadRules, generator: loadGenerator }[view] || (() => {}))();
}
const currentView = () => (location.hash || '#dashboard').slice(1).split('?')[0];
const hashParam = k => new URLSearchParams(location.hash.split('?')[1] || '').get(k);
window.addEventListener('hashchange', () => show(currentView()));

// ---------- charts (tiny SVG helpers) ----------
function barChart(el, items, colorFn) {
  const max = Math.max(1, ...items.map(i => i.value));
  el.innerHTML = items.map(i => `<div class="hbar"><span>${esc(i.label)}</span>
    <div><div class="bar" style="width:${(i.value / max) * 100}%;background:${colorFn ? colorFn(i) : 'var(--accent)'}"></div></div>
    <span class="n">${i.value}</span></div>`).join('') || '<p class="muted">No data</p>';
}

function lineChart(el, points) {
  const W = 900, H = 160, P = 28;
  const max = Math.max(1, ...points.map(p => p.count));
  const x = i => P + (i * (W - 2 * P)) / Math.max(1, points.length - 1);
  const y = v => H - P - (v / max) * (H - 2 * P);
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p.count)}`).join(' ');
  const area = `${path} L${x(points.length - 1)},${H - P} L${x(0)},${H - P} Z`;
  const labels = points.map((p, i) => i % 3 === 0
    ? `<text x="${x(i)}" y="${H - 8}" text-anchor="middle">${new Date(p.ts).getHours().toString().padStart(2, '0')}:00</text>` : '').join('');
  const dots = points.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.count)}" r="3" fill="var(--accent)"><title>${fmtTs(p.ts)}: ${p.count}</title></circle>`).join('');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="none" style="height:${H}px">
    <line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" stroke="var(--line)"/>
    <text x="4" y="${y(max) + 4}">${max}</text><text x="4" y="${H - P + 4}">0</text>
    <path d="${area}" fill="rgba(47,180,255,.12)"/><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2"/>
    ${dots}${labels}</svg>`;
}

// ---------- dashboard ----------
async function loadDashboard() {
  const s = await api('/api/stats');
  $('#kOpen').textContent = s.open;
  $('#kNew').textContent = s.byStatus.New;
  $('#kClosed').textContent = s.closed;
  $('#kCases').textContent = s.openCases;
  $('#kMttd').textContent = fmtDur(s.mttdSeconds);
  $('#kMttr').textContent = fmtDur(s.mttrSeconds);
  $('#kEvents').textContent = s.eventCount.toLocaleString();
  barChart($('#chSeverity'), ['critical', 'high', 'medium', 'low'].map(k => ({ label: k, value: s.bySeverity[k] })), i => SEV_COLOR[i.label]);
  barChart($('#chStatus'), [
    { label: 'New', value: s.byStatus.New, c: 'var(--accent)' },
    { label: 'Investigating', value: s.byStatus.Investigating, c: 'var(--medium)' },
    { label: 'Closed', value: s.byStatus.Closed, c: 'var(--muted)' }], i => i.c);
  lineChart($('#chTime'), s.alertsPerHour);
  barChart($('#chHosts'), s.topHosts.map(h => ({ label: h.name, value: h.count })));
  barChart($('#chUsers'), s.topUsers.map(u => ({ label: u.name, value: u.count })));
}

// ---------- alerts ----------
async function loadAlerts() {
  const p = new URLSearchParams({ status: $('#fStatus').value, severity: $('#fSeverity').value, assignee: $('#fAssignee').value, mitre: $('#fMitre').value });
  const list = await api(`/api/alerts?${p}`);
  $('#alertCount').textContent = `${list.length} alerts`;
  $('#alertTable tbody').innerHTML = list.map(a => `<tr data-id="${a.id}" class="${a.id === selectedAlert ? 'selected' : ''}">
    <td class="mono">${a.id}</td><td><span class="sev ${a.severity}">${a.severity}</span></td>
    <td>${esc(a.title)}${a.count > 1 ? ` <span class="muted">(${a.count} events)</span>` : ''}</td>
    <td class="mono">${esc(a.key)}</td><td class="mono">${esc(a.mitre)}</td>
    <td><span class="st ${a.status}">${a.status}</span>${a.verdict ? ` <span class="muted">${VERDICT_LABEL[a.verdict]}</span>` : ''}</td>
    <td>${esc(a.assignee) || '<span class="muted">-</span>'}</td><td class="mono">${fmtTs(a.createdTs)}</td></tr>`).join('');
}

$('#alertTable tbody').addEventListener('click', e => {
  const tr = e.target.closest('tr');
  if (tr) openAlert(Number(tr.dataset.id));
});
['#fStatus', '#fSeverity', '#fAssignee', '#fMitre'].forEach(s => $(s).addEventListener('change', loadAlerts));

async function openAlert(id) {
  selectedAlert = id;
  document.querySelectorAll('#alertTable tr').forEach(tr => tr.classList.toggle('selected', Number(tr.dataset.id) === id));
  const [a, allCases] = await Promise.all([api(`/api/alerts/${id}`), api('/api/cases')]);
  const openCases = allCases.filter(c => c.status !== 'Closed');
  const opt = (vals, cur, labels = {}) => vals.map(v => `<option value="${esc(v)}" ${v === cur ? 'selected' : ''}>${esc(labels[v] || v || '-')}</option>`).join('');
  $('#alertDetail').innerHTML = `
    <h2>#${a.id} ${esc(a.title)}</h2>
    <div><span class="sev ${a.severity}">${a.severity}</span>${a.ruleSeverity && a.ruleSeverity !== a.severity ? ` <span class="muted">(rule said ${esc(a.ruleSeverity)})</span>` : ''} <span class="st ${a.status}">${a.status}</span>
      <a class="mono" href="https://attack.mitre.org/techniques/${esc(a.mitre.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"
        title="Opens MITRE's public site in your browser (the app itself never connects out)">${esc(a.mitre)}</a></div>
    <p class="muted">${esc(a.description)}</p>
    <div class="kv">
      <div>Entity</div><div class="mono">${esc(a.key)}</div>
      <div>Rule</div><div class="mono">${esc(a.ruleId)}</div>
      <div>First event</div><div class="mono">${fmtTs(a.firstEventTs)}</div>
      <div>Alert created</div><div class="mono">${fmtTs(a.createdTs)}</div>
      <div>Last event</div><div class="mono">${fmtTs(a.lastEventTs)}</div>
      <div>Acknowledged</div><div class="mono">${fmtTs(a.ackTs)}</div>
      <div>Closed</div><div class="mono">${fmtTs(a.closedTs)}</div>
    </div>
    <h3 class="muted">Indicators (${a.iocs.length}) <span class="muted">&middot; click one to look it up</span></h3>
    <div class="ioc-chips">${a.iocs.map(iocLink).join('') || '<span class="muted">None in the stored events.</span>'}</div>
    <div class="row">
      <label>Status <select id="dStatus">${opt(META.statuses, a.status)}</select></label>
      <label>Assignee <select id="dAssignee">${opt(['', ...META.analysts], a.assignee)}</select></label>
      <label>Verdict <select id="dVerdict">${opt(['', ...META.verdicts], a.verdict || '', VERDICT_LABEL)}</select></label>
      <label title="How bad it would be if real. You can raise or lower what the rule set.">Severity <select id="dSev">${opt(META.severities, a.severity)}</select></label>
      <button id="dSave">Save</button>
    </div>
    <div class="row" id="dCaseRow">${a.caseId
      ? `In incident case <a href="#cases" id="dCaseLink">Case #${a.caseId} &rarr;</a>`
      : `<select id="dCaseSel"><option value="">New case</option>${openCases.map(c => `<option value="${c.id}">#${c.id} ${esc(c.title)}</option>`).join('')}</select>
         <button id="dEscalate" class="ghost">Escalate to case</button>`}</div>
    ${playbookHtml(a)}
    <h3 class="muted">Related events (${a.events.length}) <a href="#search" id="dSearch">open in Log Search &rarr;</a></h3>
    <table><tbody>${a.events.slice(0, 50).map(e => `<tr><td class="mono">${fmtTs(e.ts)}</td><td>${esc(e.source)} ${esc(e.eventId || '')}</td>
      <td class="mono">${esc(e.host)}</td><td class="mono">${esc(e.user || '')}</td><td>${esc(e.message)}${e.targetUser ? ` &rarr; <b>${esc(e.targetUser)}</b>` : ''}${e.dstIp ? ` &rarr; ${esc(e.dstIp)}` : ''}${e.srcIp && e.source === 'winsec' ? ` <span class="muted">from ${esc(e.srcIp)}</span>` : ''}${eventExtras(e)}</td></tr>`).join('')}</tbody></table>
    ${a.events.length < a.relatedEventIds.length ? `<p class="muted">${a.relatedEventIds.length - a.events.length} older events were trimmed by the event cap.</p>` : ''}
    <h3 class="muted">Alert notes</h3>
    ${a.notes.map(n => `<div class="note"><span class="muted mono">${fmtTs(n.ts)} &middot; ${esc(n.author)}</span><br>${esc(n.text)}</div>`).join('') || '<p class="muted">No notes yet. Write down what you checked and why.</p>'}
    <textarea id="dNote" placeholder="Add an investigation note..."></textarea>
    <div class="row"><button id="dAddNote">Add note</button></div>`;

  $('#dSave').onclick = async () => {
    try {
      // Verdict and assignee first so a "Closed" status passes the verdict check
      await api(`/api/alerts/${id}`, { method: 'PATCH', body: { assignee: $('#dAssignee').value, verdict: $('#dVerdict').value || null, severity: $('#dSev').value } });
      await api(`/api/alerts/${id}`, { method: 'PATCH', body: { status: $('#dStatus').value } });
      toast('Alert updated');
    } catch (e) { toast(e.message, true); }
    openAlert(id); loadAlerts(); refreshBadge();
  };
  $('#dAddNote').onclick = async () => {
    try {
      await api(`/api/alerts/${id}/notes`, { method: 'POST', body: { author: $('#dAssignee').value || 'analyst', text: $('#dNote').value } });
      openAlert(id);
    } catch (e) { toast(e.message, true); }
  };
  if (a.caseId) $('#dCaseLink').onclick = () => { selectedCase = a.caseId; };
  else $('#dEscalate').onclick = async () => {
    try {
      const c = await api(`/api/alerts/${id}/escalate`, { method: 'POST', body: { caseId: Number($('#dCaseSel').value) || null } });
      toast(`Alert added to case #${c.id}`);
      selectedCase = c.id;
      openAlert(id); loadAlerts(); refreshBadge();
    } catch (e) { toast(e.message, true); }
  };
  bindPlaybook(a, () => openAlert(id));
  $('#dSearch').onclick = ev => {
    ev.preventDefault();
    const f = $('#searchForm');
    f.reset();
    f.ids.value = a.relatedEventIds.join(',');
    searchPage = 0;
    location.hash = '#search';
  };
}

// ---------- playbooks (shown inside alert detail) ----------
function playbookHtml(a) {
  const pb = a.playbook && PLAYBOOKS.find(p => p.id === a.playbook.id);
  if (!pb) return '<h3 class="muted">Playbook</h3><p class="muted">No playbook for this rule.</p>';
  const done = a.playbook.steps.filter(s => s.done).length;
  return `<h3 class="muted">Playbook: ${esc(pb.name)} <span class="mono">(${done}/${pb.steps.length})</span></h3>
    <div class="pb-progress"><div style="width:${(done / pb.steps.length) * 100}%"></div></div>
    ${pb.steps.map((s, i) => {
      const st = a.playbook.steps[i] || {};
      return `<div class="pb-step ${st.done ? 'done' : ''}">
        <label><input type="checkbox" data-pb-step="${i}" ${st.done ? 'checked' : ''}><span class="pb-title">${i + 1}. ${esc(s.title)}</span></label>
        <div class="pb-help muted">${esc(s.help || '')}${st.doneTs ? ` &middot; done ${fmtTs(st.doneTs)}` : ''}</div>
        <input type="text" data-pb-note="${i}" value="${esc(st.note || '')}" placeholder="Step note (saved when you leave the box)">
      </div>`;
    }).join('')}`;
}

function bindPlaybook(a, reload) {
  const save = async (i, body) => {
    try { await api(`/api/alerts/${a.id}/playbook/${i}`, { method: 'PATCH', body }); }
    catch (e) { toast(e.message, true); }
  };
  document.querySelectorAll('[data-pb-step]').forEach(el => {
    el.onchange = async () => { await save(el.dataset.pbStep, { done: el.checked }); reload(); };
  });
  document.querySelectorAll('[data-pb-note]').forEach(el => {
    el.onchange = () => save(el.dataset.pbNote, { note: el.value }).then(() => toast('Step note saved'));
  });
}

// ---------- cases ----------
async function loadCases() {
  const p = new URLSearchParams({ status: $('#cStatusF').value });
  const list = await api(`/api/cases?${p}`);
  $('#caseCount').textContent = `${list.length} cases`;
  $('#caseTable tbody').innerHTML = list.map(c => `<tr data-id="${c.id}" class="${c.id === selectedCase ? 'selected' : ''}">
    <td class="mono">${c.id}</td><td><span class="sev ${c.severity}">${c.severity}</span></td><td>${esc(c.title)}</td>
    <td><span class="phase ${c.status}">${esc(c.status)}</span></td><td>${esc(c.owner) || '<span class="muted">-</span>'}</td>
    <td class="mono">${c.alertIds.length}</td><td class="mono">${fmtTs(c.createdTs)}</td></tr>`).join('') ||
    '<tr><td colspan="7" class="muted">No cases yet. Open an alert and click "Escalate to case".</td></tr>';
  if (selectedCase) openCase(selectedCase, true);
}
$('#caseTable tbody').addEventListener('click', e => {
  const tr = e.target.closest('tr[data-id]');
  if (tr) openCase(Number(tr.dataset.id));
});
$('#cStatusF').addEventListener('change', loadCases);
$('#cNew').onclick = async () => {
  const title = prompt('Case title:', 'New incident');
  if (!title) return;
  try { const c = await api('/api/cases', { method: 'POST', body: { title } }); selectedCase = c.id; loadCases(); refreshBadge(); }
  catch (e) { toast(e.message, true); }
};

const TL_LABEL = { event: 'Event', alert: 'Alert', note: 'Note', status: 'Case update', ioc: 'IOC' };

async function openCase(id, keepScroll = false) {
  selectedCase = id;
  document.querySelectorAll('#caseTable tr').forEach(tr => tr.classList.toggle('selected', Number(tr.dataset.id) === id));
  let c;
  try { c = await api(`/api/cases/${id}`); } catch (e) { selectedCase = null; return; }
  const box = $('#caseDetail');
  const scroll = box.scrollTop;
  const opt = (vals, cur) => vals.map(v => `<option value="${esc(v)}" ${v === cur ? 'selected' : ''}>${esc(v || '-')}</option>`).join('');
  const curIdx = META.casePhases.indexOf(c.status);
  const closed = c.status === 'Closed';
  box.innerHTML = `
    <h2>Case #${c.id} ${esc(c.title)}</h2>
    <div><span class="sev ${c.severity}">${c.severity}</span> <span class="phase ${c.status}">${esc(c.status)}</span>
      <span class="muted">opened ${fmtTs(c.createdTs)}${c.closedTs ? ` &middot; closed ${fmtTs(c.closedTs)}` : ''}</span></div>
    <div class="stepper" title="NIST incident response lifecycle - click a phase to move the case">
      ${META.casePhases.map((ph, i) => `<button data-phase="${esc(ph)}" class="${closed || i < curIdx ? 'past' : i === curIdx ? 'cur' : ''}">${i + 1}. ${esc(ph)}</button>`).join('')}
    </div>
    <div class="row">
      <label>Owner <select id="cOwner">${opt(['', ...META.analysts], c.owner)}</select></label>
      <label>Severity <select id="cSev">${opt(META.severities, c.severity)}</select></label>
      <button id="cSave">Save</button>
    </div>
    <h3 class="muted">Linked alerts (${c.alerts.length})</h3>
    <table><tbody>${c.alerts.map(a => `<tr data-alert="${a.id}"><td class="mono">#${a.id}</td><td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td>${esc(a.title)}</td><td class="mono">${esc(a.key)}</td><td><span class="st ${a.status}">${a.status}</span></td>
      <td class="mono">${a.playbook ? `${a.playbook.steps.filter(s => s.done).length}/${a.playbook.steps.length}` : ''}</td></tr>`).join('') ||
      '<tr><td class="muted">No alerts linked. Use "Escalate to case" on an alert.</td></tr>'}</tbody></table>
    <h3 class="muted">Indicators of compromise (${c.iocs.length})</h3>
    ${c.iocs.map(x => `<div class="ioc-row">${iocLink(x)} <span class="muted">${esc(x.note)}</span>
      ${closed ? '' : `<button class="ghost x" data-ioc-del="${esc(x.value)}" title="Remove from case">&times;</button>`}</div>`).join('') ||
      '<p class="muted">None yet. Record the IPs, domains and hashes involved, or use "Add to case" on the IOC Lookup page.</p>'}
    ${closed ? '' : `<div class="row"><input id="cIocVal" placeholder="IP, domain or hash" size="28">
      <input id="cIocNote" placeholder="Why it matters (optional)" size="28"> <button id="cIocAdd" class="ghost">Add IOC</button></div>`}
    <h3 class="muted">Timeline (${c.timeline.length})</h3>
    <div class="tl">${c.timeline.map((t, i) => `<div class="tl-item ${t.kind}" data-tl="${i}">
      <span class="tl-kind">${TL_LABEL[t.kind]}</span> <span class="mono muted">${fmtTs(t.ts)}</span>
      ${t.author ? `<span class="muted">&middot; ${esc(t.author)}</span>` : ''}
      ${t.event ? `<span class="mono muted">&middot; ${esc(t.event.host)}${t.event.user ? ' / ' + esc(t.event.user) : ''}</span>` : ''}
      <div>${t.severity ? `<span class="sev ${t.severity}">${t.severity}</span> ` : ''}${esc(t.text)}</div>
    </div>`).join('')}</div>
    <h3 class="muted">Case notes</h3>
    <textarea id="cNote" placeholder="Add a note (what you found, what you did)..."></textarea>
    <div class="row"><button id="cAddNote">Add note</button></div>
    <h3 class="muted">Final summary ${closed ? '' : '<span class="muted">(required before closing)</span>'}</h3>
    <textarea id="cSummary" placeholder="What happened, impact, root cause, actions taken, lessons learned...">${esc(c.summary)}</textarea>
    <div class="row">
      <button id="cSaveSummary" class="ghost">Save summary</button>
      ${closed ? `<button id="cReopen" class="ghost">Reopen (Post-incident)</button>` : `<button id="cClose" class="danger">Close case</button>`}
    </div>`;
  if (keepScroll) box.scrollTop = scroll;

  const patch = async body => {
    try { await api(`/api/cases/${id}`, { method: 'PATCH', body }); toast('Case updated'); }
    catch (e) { toast(e.message, true); }
    openCase(id, true); loadCaseList(); refreshBadge();
  };
  box.querySelectorAll('[data-phase]').forEach(b => { b.onclick = () => patch({ status: b.dataset.phase }); });
  $('#cSave').onclick = () => patch({ owner: $('#cOwner').value, severity: $('#cSev').value });
  $('#cSaveSummary').onclick = () => patch({ summary: $('#cSummary').value });
  if (closed) $('#cReopen').onclick = () => patch({ status: 'Post-incident' });
  else $('#cClose').onclick = () => {
    if (!confirm('Close this case? Open linked alerts will be closed too.')) return;
    patch({ summary: $('#cSummary').value, status: 'Closed' });
  };
  $('#cAddNote').onclick = async () => {
    try {
      await api(`/api/cases/${id}/notes`, { method: 'POST', body: { author: $('#cOwner').value || 'analyst', text: $('#cNote').value } });
      openCase(id, true);
    } catch (e) { toast(e.message, true); }
  };
  box.querySelectorAll('[data-alert]').forEach(tr => {
    tr.onclick = () => { location.hash = '#alerts'; openAlert(Number(tr.dataset.alert)); };
  });
  if (!closed) $('#cIocAdd').onclick = async () => {
    try {
      await api(`/api/cases/${id}/iocs`, { method: 'POST', body: { value: $('#cIocVal').value, note: $('#cIocNote').value } });
      toast('IOC added to case'); openCase(id, true);
    } catch (e) { toast(e.message, true); }
  };
  box.querySelectorAll('[data-ioc-del]').forEach(b => {
    b.onclick = async () => {
      try { await api(`/api/cases/${id}/iocs/${encodeURIComponent(b.dataset.iocDel)}`, { method: 'DELETE' }); openCase(id, true); }
      catch (e) { toast(e.message, true); }
    };
  });
  box.querySelectorAll('.tl-item.event').forEach(el => {
    el.onclick = () => {
      const pre = el.querySelector('pre');
      if (pre) return pre.remove();
      el.insertAdjacentHTML('beforeend', `<pre>${esc(JSON.stringify(c.timeline[el.dataset.tl].event, null, 2))}</pre>`);
    };
  });
}
// Refresh just the list (avoid re-rendering the detail while someone is typing)
async function loadCaseList() {
  const keep = selectedCase; selectedCase = null;
  await loadCases(); selectedCase = keep;
  document.querySelectorAll('#caseTable tr').forEach(tr => tr.classList.toggle('selected', Number(tr.dataset.id) === keep));
}

// ---------- search ----------
async function runSearch() {
  const f = $('#searchForm');
  const p = new URLSearchParams();
  for (const k of ['source', 'host', 'user', 'eventId', 'q', 'ids']) if (f[k].value) p.set(k, f[k].value.trim());
  if (f.from.value) p.set('from', new Date(f.from.value).getTime());
  if (f.to.value) p.set('to', new Date(f.to.value).getTime());
  p.set('page', searchPage);
  const r = await api(`/api/events?${p}`);
  $('#searchInfo').textContent = `${r.total.toLocaleString()} matching events${f.ids.value ? ' (showing events linked to an alert — Clear to reset)' : ''}`;
  const pages = Math.max(1, Math.ceil(r.total / r.size));
  $('#pgInfo').textContent = `page ${searchPage + 1} / ${pages}`;
  $('#pgPrev').disabled = searchPage === 0;
  $('#pgNext').disabled = searchPage + 1 >= pages;
  $('#eventTable tbody').innerHTML = r.events.map(e => `<tr title="${esc(JSON.stringify(e, null, 1))}">
    <td class="mono">${fmtTs(e.ts)}</td><td>${esc(e.source)}</td><td class="mono">${esc(e.eventId || e.action || '')}</td>
    <td class="mono">${esc(e.host)}</td><td class="mono">${esc(e.user || '')}${e.targetUser ? ` &rarr; ${esc(e.targetUser)}` : ''}</td>
    <td class="mono">${esc(e.srcIp || '')}</td><td class="mono">${esc(e.dstIp ? `${e.dstIp}:${e.dstPort}` : e.domain || '')}</td>
    <td>${esc(e.message)}${e.reason ? ` <span class="muted">(${esc(e.reason)})</span>` : ''}${eventExtras(e)}</td></tr>`).join('');
}

// Details analysts need without opening the raw JSON: EDR process/signer, change references
function eventExtras(e) {
  return (e.process && e.source === 'edr' && e.action === 'detected' ? ` <span class="mono muted">${esc(e.process)}</span>` : '') +
    (e.signer ? ` <span class="muted">signed by ${esc(e.signer)}</span>` : '') +
    (e.changeRef && e.source !== 'change' ? ` <span class="muted">(change ${esc(e.changeRef)})</span>` : '') +
    (e.source === 'mail' && e.spf ? ` <span class="muted">SPF ${esc(e.spf)}, ${esc(e.recipients)} recipient(s)</span>` : '') +
    (e.source === 'mail' && e.domainAgeDays != null ? ` <span class="muted">(domain ${esc(e.domainAgeDays)} days old)</span>` : '') +
    (e.source === 'winsec' && e.logonType ? ` <span class="muted">type ${esc(e.logonType)}</span>` : '');
}
$('#searchForm').addEventListener('submit', e => { e.preventDefault(); searchPage = 0; runSearch(); });
$('#searchClear').onclick = () => { $('#searchForm').reset(); $('#searchForm').ids.value = ''; searchPage = 0; runSearch(); };
$('#pgPrev').onclick = () => { searchPage = Math.max(0, searchPage - 1); runSearch(); };
$('#pgNext').onclick = () => { searchPage++; runSearch(); };

// Open Log Search with filters set (pivot from another screen)
function searchFor({ host = '', user = '', q = '' }) {
  const f = $('#searchForm');
  f.reset(); f.ids.value = '';
  f.host.value = host;
  f.user.value = user;
  if (user && f.user.value !== user) q = user; // not in the dropdown (e.g. SYSTEM): keyword search instead
  f.q.value = q;
  searchPage = 0;
  if (currentView() === 'search') runSearch(); else location.hash = '#search';
}

// ---------- IOC lookup ----------
const IOC_EXAMPLES = ['203.0.113.66', 'c2-beacon.example', '192.0.2.10', '198.51.100.20',
  '000000000000000000000000000000000000000000000000fa4e000000000001'];
const iocHelp = () => `<h3>What is an IOC?</h3>
  <p class="muted">An Indicator of Compromise is a concrete clue: an IP address, a domain name or a file hash.
  Look one up to see whether threat intel knows it, where it shows up in your logs (sightings), and which
  alerts and cases involve it. Following one clue to the next is called <b>pivoting</b>.</p>
  <p class="muted">Try one:</p><div class="ioc-chips">${IOC_EXAMPLES.map(v => `<a class="ioc-chip" href="#ioc?v=${encodeURIComponent(v)}"><span class="mono">${esc(shortIoc(v))}</span></a>`).join('')}</div>`;

async function loadIoc() {
  loadIntel();
  const v = hashParam('v');
  if (v) { $('#iocValue').value = v; lookupIoc(v); }
  else if (!$('#iocResult').innerHTML.trim()) $('#iocResult').innerHTML = iocHelp();
}

async function lookupIoc(value) {
  const box = $('#iocResult');
  let r, openCases;
  try { [r, openCases] = await Promise.all([api(`/api/ioc?value=${encodeURIComponent(value)}`), api('/api/cases')]); }
  catch (e) { box.innerHTML = `<div class="verdict warn">${esc(e.message)}</div>${iocHelp()}`; return; }
  openCases = openCases.filter(c => c.status !== 'Closed');
  const s = r.sightings;
  const pivots = (list, kind) => list.slice(0, 8).map(x => `<a href="#search" data-pivot-${kind}="${esc(x.name)}" class="mono">${esc(x.name)}</a> <span class="muted">(${x.count})</span>`).join(', ') || '-';
  box.innerHTML = `
    <h2 class="mono wrap">${esc(r.value)}</h2>
    <div class="muted">${IOC_TYPE[r.type]} &middot; ${esc(r.about)}</div>
    ${r.intel ? `<div class="verdict bad">On the threat intel list: ${esc(r.intel.note)}</div>`
      : '<div class="verdict">Not on the threat intel list. That does not prove it is safe: check the sightings below.</div>'}
    <div class="row">
      ${r.intel ? '' : '<button id="iAddIntel" class="ghost">Add to intel list</button>'}
      ${openCases.length ? `<select id="iCaseSel">${openCases.map(c => `<option value="${c.id}">Case #${c.id} ${esc(c.title)}</option>`).join('')}</select>
        <button id="iAddCase" class="ghost">Add to case</button>` : '<span class="muted">No open cases to add it to.</span>'}
      <button id="iSearch" class="ghost">Search logs for it</button>
    </div>
    <h3 class="muted">Sightings in stored events</h3>
    <div class="kv">
      <div>Events</div><div class="mono">${s.count.toLocaleString()}</div>
      <div>First seen</div><div class="mono">${fmtTs(s.firstTs)}</div>
      <div>Last seen</div><div class="mono">${fmtTs(s.lastTs)}</div>
      <div>Hosts</div><div>${pivots(s.hosts, 'host')}</div>
      <div>Users</div><div>${pivots(s.users, 'user')}</div>
      <div>Log sources</div><div class="mono">${s.sources.map(x => `${esc(x.name)} (${x.count})`).join(', ') || '-'}</div>
    </div>
    ${s.count ? '' : '<p class="muted">Never seen in the stored events (the oldest events are trimmed by the event cap).</p>'}
    <h3 class="muted">Related alerts (${r.alerts.length})</h3>
    <table><tbody>${r.alerts.slice(0, 50).map(a => `<tr data-ioc-alert="${a.id}"><td class="mono">#${a.id}</td><td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td>${esc(a.title)}</td><td><span class="st ${a.status}">${a.status}</span>${a.verdict ? ` <span class="muted">${VERDICT_LABEL[a.verdict]}</span>` : ''}</td>
      <td class="mono">${fmtTs(a.createdTs)}</td></tr>`).join('') || '<tr><td class="muted">None</td></tr>'}</tbody></table>
    <h3 class="muted">Related cases (${r.cases.length})</h3>
    <table><tbody>${r.cases.map(c => `<tr data-ioc-case="${c.id}"><td class="mono">#${c.id}</td><td><span class="sev ${c.severity}">${c.severity}</span></td>
      <td>${esc(c.title)}</td><td><span class="phase ${c.status}">${esc(c.status)}</span></td>
      <td class="muted">${c.hasIoc ? 'recorded as IOC' : 'via alert'}</td></tr>`).join('') || '<tr><td class="muted">None</td></tr>'}</tbody></table>
    <h3 class="muted">Latest events (${s.latest.length} of ${s.count.toLocaleString()})</h3>
    <table><tbody>${s.latest.map(e => `<tr title="${esc(JSON.stringify(e, null, 1))}"><td class="mono">${fmtTs(e.ts)}</td><td>${esc(e.source)} ${esc(e.eventId || '')}</td>
      <td class="mono">${esc(e.host)}</td><td class="mono">${esc(e.user || '')}</td><td>${esc(e.message)}</td></tr>`).join('')}</tbody></table>`;

  box.querySelectorAll('[data-pivot-host]').forEach(a => { a.onclick = ev => { ev.preventDefault(); searchFor({ host: a.dataset.pivotHost }); }; });
  box.querySelectorAll('[data-pivot-user]').forEach(a => { a.onclick = ev => { ev.preventDefault(); searchFor({ user: a.dataset.pivotUser }); }; });
  box.querySelectorAll('[data-ioc-alert]').forEach(tr => { tr.onclick = () => { location.hash = '#alerts'; openAlert(Number(tr.dataset.iocAlert)); }; });
  box.querySelectorAll('[data-ioc-case]').forEach(tr => { tr.onclick = () => { selectedCase = Number(tr.dataset.iocCase); location.hash = '#cases'; }; });
  $('#iSearch').onclick = () => searchFor({ q: r.value });
  if (!r.intel) $('#iAddIntel').onclick = async () => {
    const note = prompt('Intel note (why is this bad?):', 'Added by analyst (training)');
    if (note === null) return;
    try { await api('/api/intel', { method: 'POST', body: { value: r.value, note } }); toast('Added to intel list. Lookup rules use it for new events.'); loadIntel(); lookupIoc(r.value); }
    catch (e) { toast(e.message, true); }
  };
  if (openCases.length) $('#iAddCase').onclick = async () => {
    const note = prompt('Why does this indicator matter for the case? (optional)', '');
    if (note === null) return;
    try { const c = await api(`/api/cases/${$('#iCaseSel').value}/iocs`, { method: 'POST', body: { value: r.value, note } }); toast(`Added to case #${c.id}`); lookupIoc(r.value); }
    catch (e) { toast(e.message, true); }
  };
}
$('#iocForm').addEventListener('submit', e => {
  e.preventDefault();
  const v = $('#iocValue').value.trim();
  const target = `#ioc?v=${encodeURIComponent(v)}`;
  if (location.hash === target) lookupIoc(v); else location.hash = target;
});

async function loadIntel() {
  $('#intelText').value = JSON.stringify(await api('/api/intel'), null, 2);
}
$('#intelReload').onclick = loadIntel;
$('#intelSave').onclick = async () => {
  try {
    await api('/api/intel', { method: 'PUT', body: JSON.parse($('#intelText').value) });
    toast('Intel saved. Lookup rules use it for new events.');
    loadIntel();
  } catch (e) { toast(e.message, true); }
};

// ---------- MITRE ATT&CK heatmap ----------
let MITRE = null;
let mitreMode = 'coverage';
let mitreSel = null;

async function loadMitre() {
  MITRE = await api(`/api/mitre?hours=${$('#mHours').value}`);
  renderMitre();
}

function renderMitre() {
  const m = MITRE;
  const activity = mitreMode === 'activity';
  $('#mMode').querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.mode === mitreMode));
  $('#mHours').style.display = activity ? '' : 'none';
  const period = $('#mHours').selectedOptions[0].text.toLowerCase();
  $('#mSummary').textContent = activity
    ? `${m.summary.withAlerts} techniques with alerts (${period})`
    : `${m.summary.covered} of ${m.summary.techniques} techniques have at least one enabled rule`;
  $('#mLegend').innerHTML = activity
    ? 'Number = alerts in the period (darker red = more). Dashed border = no enabled rule, so this attack would go unseen.'
    : 'Number = enabled detection rules (darker green = more). Dashed border = <b>coverage gap</b>: no enabled rule detects this technique.';

  const val = c => (activity ? c.alerts.total : c.coverage);
  const max = Math.max(1, ...[...m.techniques, ...m.other].map(val));
  const rgb = activity ? '244,63,94' : '52,211,153';
  const cell = c => {
    const n = val(c);
    const tip = activity
      ? `${c.alerts.total} alerts: ${c.alerts.true_positive} TP, ${c.alerts.false_positive} FP, ${c.alerts.benign} benign, ${c.alerts.open} open`
      : `${c.coverage} enabled rule(s)${c.rules.length > c.coverage ? `, ${c.rules.length - c.coverage} disabled` : ''}`;
    return `<div class="m-cell ${c.coverage ? '' : 'gap'} ${mitreSel === c.id ? 'sel' : ''}" data-tech="${esc(c.id)}"
      style="${n ? `background:rgba(${rgb},${(0.18 + 0.62 * n / max).toFixed(2)})` : ''}" title="${esc(tip)}">
      <div class="m-top"><span class="mono">${esc(c.id)}</span><span class="m-n">${n}</span></div><div class="m-name">${esc(c.name)}</div></div>`;
  };
  const cols = m.tactics.map(t => ({ name: t.name, cells: m.techniques.filter(c => c.tactics.includes(t.id)) }));
  if (m.other.length) cols.push({ name: 'Other (not in catalogue)', cells: m.other });
  $('#mGrid').style.gridTemplateColumns = `repeat(${cols.length}, minmax(130px, 1fr))`;
  $('#mGrid').innerHTML = cols.map(col => `<div class="m-col">
    <div class="m-head">${esc(col.name)}<div class="muted">${col.cells.filter(c => c.coverage).length}/${col.cells.length} covered</div></div>
    ${col.cells.map(cell).join('')}</div>`).join('');
  if (mitreSel) mitreDetail(mitreSel);
}

function mitreDetail(id) {
  const c = [...MITRE.techniques, ...MITRE.other].find(x => x.id === id);
  if (!c) return;
  mitreSel = id;
  document.querySelectorAll('.m-cell').forEach(el => el.classList.toggle('sel', el.dataset.tech === id));
  const known = MITRE.techniques.includes(c);
  const tactics = c.tactics.map(t => MITRE.tactics.find(x => x.id === t)?.name || t).join(', ');
  $('#mDetail').innerHTML = `
    <h3>${esc(c.id)} &middot; ${esc(c.name)}</h3>
    <div class="muted">Tactic${c.tactics.length > 1 ? 's' : ''}: ${esc(tactics)}
      ${known ? ` &middot; <a href="https://attack.mitre.org/techniques/${esc(c.id)}/" target="_blank" rel="noopener noreferrer"
        title="Opens MITRE's public site in your browser (the app itself never connects out)">MITRE page</a>` : ''}</div>
    <h3 class="muted">Detection rules (${c.rules.length})</h3>
    ${c.rules.length ? `<table><tbody>${c.rules.map(r => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.name)}</td>
      <td class="mono">${esc(r.technique)}</td><td>${r.enabled ? '<span class="st New">enabled</span>' : '<span class="st Closed">disabled</span>'}</td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">No rule detects this technique. This is a <b>coverage gap</b>: if an attacker used it, no alert would fire.</p>'}
    ${c.subs.length ? `<p class="muted">Sub-techniques: ${c.subs.map(s => `<span class="mono">${esc(s.id)}</span> ${esc(s.name)} (${s.rules} rules, ${s.alerts} alerts)`).join('; ')}</p>` : ''}
    <h3 class="muted">Alerts (${esc($('#mHours').selectedOptions[0].text.toLowerCase())})</h3>
    <div class="kv">
      <div>Total</div><div class="mono">${c.alerts.total}</div>
      <div>Open</div><div class="mono">${c.alerts.open}</div>
      <div>True positive</div><div class="mono">${c.alerts.true_positive}</div>
      <div>False positive</div><div class="mono">${c.alerts.false_positive}</div>
      <div>Benign</div><div class="mono">${c.alerts.benign}</div>
    </div>
    <button id="mToAlerts" class="ghost">Show all alerts for ${esc(c.id)} in the Alert Queue &rarr;</button>`;
  $('#mToAlerts').onclick = () => {
    const sel = $('#fMitre');
    if (![...sel.options].some(o => o.value === c.id)) sel.insertAdjacentHTML('beforeend', `<option value="${esc(c.id)}">${esc(c.id)}</option>`);
    sel.value = c.id;
    $('#fStatus').value = '';
    location.hash = '#alerts';
  };
}
$('#mGrid').addEventListener('click', e => {
  const el = e.target.closest('[data-tech]');
  if (el) mitreDetail(el.dataset.tech);
});
$('#mMode').addEventListener('click', e => {
  if (!e.target.dataset.mode) return;
  mitreMode = e.target.dataset.mode;
  renderMitre();
});
$('#mHours').addEventListener('change', loadMitre);

// ---------- exercise (scenario mode with scoring) ----------
let EX = { running: false };
let exShown = null; // id of the scorecard on screen (null = latest)
const OUTCOME = { submitted: 'submitted', timeout: 'time ran out (auto-submitted)', abandoned: 'abandoned', interrupted: 'interrupted' };
const HEADLINE_CLASS = { 'Correct call': 'good', 'Partly right': 'warn', 'Over-escalated': 'warn', 'Unfinished': 'warn', 'Missed incident': 'bad', 'No alert yet': 'bad' };
const SC_ICON = { got: '&#10003;', partial: '&#9680;', missed: '&#10007;', 'n/a': '&ndash;' };
const mmss = ms => `${String(Math.floor(ms / 60000)).padStart(2, '0')}:${String(Math.floor(ms / 1000) % 60).padStart(2, '0')}`;

async function refreshExercise() {
  const was = EX.running;
  EX = await api('/api/exercise');
  renderBanner();
  if (was && !EX.running) {
    toast('Exercise finished and scored. See the Exercise screen.');
    exShown = null;
    if (currentView() === 'exercise') loadExercise();
  }
}

// Countdown in the header (all screens) and on the Exercise screen
function renderBanner() {
  $('#exBanner').hidden = !EX.running;
  if (!EX.running) return;
  const left = Math.max(0, EX.deadlineTs - Date.now());
  $('#exClock').textContent = `${mmss(left)} left`;
  if ($('#exTimer')) $('#exTimer').textContent = mmss(left);
  // The server auto-submits at the deadline; pick up the result shortly after
  if (!left && !renderBanner.wait) renderBanner.wait = setTimeout(() => { renderBanner.wait = null; refreshExercise().catch(() => {}); }, 2500);
}

async function loadExercise() {
  const [cur, hist] = await Promise.all([api('/api/exercise'), api('/api/exercises')]);
  EX = cur;
  renderExControl();
  renderBanner();
  renderExHistory(hist);
  const x = exShown ? hist.find(h => h.id === exShown) : !cur.running && hist[0];
  if (x) renderScorecard(x);
  else $('#exCard').innerHTML = `<p class="muted">${cur.running ? 'The scorecard is shown when you submit.' : 'Your scorecard appears here after you submit.'}</p>`;
}

function renderExControl() {
  const box = $('#exControl');
  if (!EX.running) {
    box.innerHTML = `<h3>Start an exercise</h3>
      <p class="muted">The simulator injects one scenario into the live noise. Work it like any other alert (triage, playbook, notes,
        verdict, severity, a case if it is a real incident), then click <b>Submit</b>. You are scored on the verdict, severity,
        whether you escalated (or rightly did not), linking related alerts into one case, MTTA, MTTR, playbook steps and notes.
        Some scenarios are harmless: the right call is to <i>not</i> escalate.</p>
      <div class="row">
        <label>Scenario <select id="exScenario"><option value="random">Random (hidden)</option>
          <optgroup label="Pick one (not hidden)">${META.scenarios.map(s => `<option value="${esc(s.key)}">${esc(s.name)}</option>`).join('')}</optgroup></select></label>
        <label>Time limit <select id="exMinutes">${META.exerciseMinutes.map(m => `<option value="${m}" ${m === META.exerciseDefaultMinutes ? 'selected' : ''}>${m} min</option>`).join('')}</select></label>
        <button type="button" id="exStart">Start</button>
      </div>
      <p class="muted">While it runs, auto-scenarios are paused and manual injection is off (background noise continues).</p>`;
    $('#exStart').onclick = async () => {
      try {
        await api('/api/exercise/start', { method: 'POST', body: { scenario: $('#exScenario').value, minutes: Number($('#exMinutes').value) } });
        exShown = null;
        toast('Exercise started. Find the new alert(s) in the Alert Queue.');
        loadExercise(); refreshBadge();
      } catch (e) { toast(e.message, true); }
    };
    return;
  }
  box.innerHTML = `<h3>Exercise running</h3>
    <div class="ex-timer mono" id="exTimer">${mmss(Math.max(0, EX.deadlineTs - Date.now()))}</div>
    <div class="muted">${EX.name ? `Scenario: <b>${esc(EX.name)}</b>` : 'Scenario hidden: find it in the Alert Queue.'}
      Started ${fmtTs(EX.startedTs)}, ${EX.minutes} min limit. At 00:00 it is submitted automatically.</div>
    <ol class="ex-steps">
      <li>Find the new alert(s) in the <a href="#alerts">Alert Queue</a>. Some arrive as late logs with an older timestamp.</li>
      <li>Acknowledge quickly: set it to <b>Investigating</b> or escalate it (this stops the MTTA clock).</li>
      <li>Investigate: work the playbook, pivot in Log Search and IOC Lookup, and write notes as you go.</li>
      <li>Decide: verdict and severity. Open a case only for a real incident, and put related alerts in the <b>same</b> case.</li>
      <li>Close the alert(s), or the case, then Submit (this stops the MTTR clock).</li>
    </ol>
    <div class="row"><button type="button" id="exSubmit">Submit for scoring</button> <button type="button" id="exAbandon" class="ghost">Abandon</button></div>`;
  $('#exSubmit').onclick = submitExercise;
  $('#exAbandon').onclick = async () => {
    if (!confirm('Abandon this exercise? It is recorded without a score.')) return;
    try { const r = await api('/api/exercise/abandon', { method: 'POST', body: {} }); exShown = r.id; EX = { running: false }; loadExercise(); }
    catch (e) { toast(e.message, true); }
  };
}

async function submitExercise() {
  if (!confirm('Submit this exercise for scoring now?')) return;
  try {
    const r = await api('/api/exercise/submit', { method: 'POST', body: {} });
    EX = { running: false }; renderBanner();
    exShown = r.id;
    toast(`Scored: ${r.score}/100 (${r.headline})`);
    if (currentView() === 'exercise') loadExercise(); else location.hash = '#exercise';
  } catch (e) { toast(e.message, true); }
}
$('#exBannerSubmit').onclick = submitExercise;

function renderScorecard(x) {
  const a = x.answer;
  const secs = Math.round((x.endedTs - x.startedTs) / 1000);
  const act = x.actions;
  $('#exCard').innerHTML = `
    <div class="sc-head">
      <div class="sc-score ${HEADLINE_CLASS[x.headline] || ''}">${x.score == null ? '&ndash;' : x.score}<span>/100</span></div>
      <div><h2>${esc(x.headline)}</h2>
        <div class="muted">Exercise #${x.id} &middot; ${x.mode === 'random' ? 'random (hidden)' : 'picked from the list'} &middot;
          ${fmtTs(x.startedTs)} &rarr; ${fmtTs(x.endedTs)} (${fmtDur(secs)}) &middot; ${esc(OUTCOME[x.outcome] || x.outcome)}</div>
        <div>Scenario: <b>${esc(x.name)}</b> &middot; expected verdict: <b>${esc(VERDICT_LABEL[a.verdict])}</b></div>
        ${x.reason ? `<div class="muted">${esc(x.reason)}</div>` : ''}</div>
    </div>
    ${x.criteria.length ? `<table class="sc-table"><thead><tr><th></th><th>Criterion</th><th>Points</th><th>You</th><th>Expected</th><th>Why</th></tr></thead>
      <tbody>${x.criteria.map(c => `<tr class="sc-${c.status === 'n/a' ? 'na' : c.status}"><td class="sc-ic">${SC_ICON[c.status]}</td><td>${esc(c.label)}</td>
        <td class="mono">${c.credit == null ? 'n/a' : `${c.points}/${c.max}`}</td><td>${esc(c.given)}</td><td>${esc(c.expected)}</td><td>${esc(c.why)}</td></tr>`).join('')}</tbody></table>` : ''}
    <div class="grid sc-reveal">
      <div><h3>What it was</h3><p>${esc(a.explain)}</p>
        <h3>Clues you could have spotted</h3><ul>${a.clues.map(c => `<li>${esc(c)}</li>`).join('')}</ul></div>
      <div><h3>Alerts from this exercise (${x.alerts.length})</h3>
        <table><tbody>${x.alerts.map(al => `<tr data-ex-alert="${al.id}"><td class="mono">#${al.id}</td><td><span class="sev ${al.severity}">${al.severity}</span></td>
          <td>${esc(al.title)}</td><td class="mono">${esc(al.key)}</td><td>${al.verdict ? VERDICT_LABEL[al.verdict] : '<span class="muted">no verdict</span>'}</td>
          <td class="mono">${al.caseId ? `case #${al.caseId}` : ''}</td></tr>`).join('') || '<tr><td class="muted">None appeared.</td></tr>'}</tbody></table>
        ${act ? `<h3>What you did</h3><div class="kv">
          <div>Verdict</div><div>${esc([...new Set(act.verdicts.map(v => VERDICT_LABEL[v] || 'none'))].join(', '))}</div>
          <div>Severity</div><div>${esc(act.severity)}</div>
          <div>Case</div><div>${act.caseIds.length ? act.caseIds.map(id => `#${id}`).join(', ') : 'none'}</div>
          <div>MTTA</div><div class="mono">${fmtDur(act.mttaSeconds == null ? null : Math.round(act.mttaSeconds))}</div>
          <div>MTTR</div><div class="mono">${fmtDur(act.mttrSeconds == null ? null : Math.round(act.mttrSeconds))}</div>
          <div>Playbook</div><div class="mono">${act.stepsDone}/${act.stepsTotal}</div>
          <div>Notes</div><div class="mono">${act.notes}</div></div>` : ''}
      </div>
    </div>`;
  $('#exCard').querySelectorAll('[data-ex-alert]').forEach(tr => {
    tr.onclick = () => { location.hash = '#alerts'; openAlert(Number(tr.dataset.exAlert)).catch(e => toast(e.message, true)); };
  });
  document.querySelectorAll('#exHistory tr').forEach(tr => tr.classList.toggle('selected', Number(tr.dataset.ex) === x.id));
}

function renderExHistory(hist) {
  const shown = exShown || (!EX.running && hist[0]?.id);
  $('#exHistory tbody').innerHTML = hist.map(h => `<tr data-ex="${h.id}" class="${h.id === shown ? 'selected' : ''}">
    <td class="mono">${h.id}</td><td class="mono">${fmtTs(h.startedTs)}</td><td>${esc(h.name)}</td><td>${h.mode === 'random' ? 'hidden' : 'picked'}</td>
    <td>${esc(h.headline)}</td><td class="mono">${h.score ?? '-'}</td><td class="mono">${fmtDur(Math.round((h.endedTs - h.startedTs) / 1000))}</td></tr>`).join('') ||
    '<tr><td colspan="7" class="muted">No exercises yet.</td></tr>';
  const scored = hist.filter(h => h.score != null).slice(0, 30).reverse(); // oldest first
  scoreChart($('#exChart'), scored);
  const weak = META.exerciseCriteria.map(c => {
    const credits = scored.flatMap(h => h.criteria.filter(x => x.key === c.key && x.credit != null).map(x => x.credit));
    return { label: c.label, value: credits.length ? Math.round((credits.reduce((s, v) => s + v, 0) / credits.length) * 100) : null };
  }).filter(i => i.value != null).sort((p, q) => p.value - q.value);
  if (weak.length) barChart($('#exWeak'), weak.map(i => ({ label: i.label, value: i.value })),
    i => (i.value >= 80 ? 'var(--ok)' : i.value >= 50 ? 'var(--medium)' : 'var(--critical)'));
  else $('#exWeak').innerHTML = '<p class="muted">No scored exercises yet.</p>';
}
$('#exHistory tbody').addEventListener('click', async e => {
  const tr = e.target.closest('tr[data-ex]');
  if (!tr) return;
  exShown = Number(tr.dataset.ex);
  try { renderScorecard(await api(`/api/exercises/${exShown}`)); } catch (err) { toast(err.message, true); }
});

function scoreChart(el, list) {
  if (!list.length) { el.innerHTML = '<p class="muted">Finish an exercise to see your progress.</p>'; return; }
  const W = 600, H = 150, P = 28;
  const x = i => P + (i * (W - 2 * P)) / Math.max(1, list.length - 1);
  const y = v => H - P - (v / 100) * (H - 2 * P);
  const path = list.map((h, i) => `${i ? 'L' : 'M'}${x(i)},${y(h.score)}`).join(' ');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" style="height:${H}px">
    ${[0, 50, 100].map(v => `<line x1="${P}" y1="${y(v)}" x2="${W - P}" y2="${y(v)}" stroke="var(--line)"/><text x="2" y="${y(v) + 4}">${v}</text>`).join('')}
    <path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2"/>
    ${list.map((h, i) => `<circle cx="${x(i)}" cy="${y(h.score)}" r="4" fill="var(--accent)"><title>#${h.id} ${esc(h.name)}: ${h.score}/100 (${esc(h.headline)})</title></circle>`).join('')}
  </svg>`;
}

// ---------- shift handover ----------
let HREPORT = null;
const toLocalInput = ts => { const d = new Date(ts); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };

function handoverQuery() {
  const v = $('#hWindow').value;
  if (v !== 'custom') return `hours=${v}`;
  const from = new Date($('#hFrom').value).getTime();
  const to = new Date($('#hTo').value).getTime();
  if (!from || !to) throw new Error('Pick both a start and an end for the custom window');
  return `from=${from}&to=${to}`;
}

async function loadHandover() {
  let q;
  try { q = handoverQuery(); } catch (e) { toast(e.message, true); return; }
  let r, list;
  try { [r, list] = await Promise.all([api(`/api/handover?${q}`), api('/api/handovers')]); }
  catch (e) { toast(e.message, true); return; }
  HREPORT = r;
  $('#hNotesPanel').hidden = false;
  if (document.activeElement !== $('#hNotes')) $('#hNotes').value = r.draft;
  mirrorNotes();
  const p = r.previous;
  $('#hPrev').innerHTML = p ? `<div class="panel h-prev"><h3>Previous handover #${p.id} &middot; ${esc(p.analyst || 'unknown analyst')} &middot; ${fmtTs(p.createdTs)}</h3>
    <div class="muted">Window ${fmtTs(p.fromTs)} &ndash; ${fmtTs(p.toTs)} &middot; <a href="#handover" data-h-open="${p.id}">open its full report</a></div>
    <div class="h-notes-text">${esc(p.notes) || '<span class="muted">(no notes)</span>'}</div></div>` : '';
  renderHandover(r, null);
  $('#hList tbody').innerHTML = list.map(h => `<tr data-h-open="${h.id}"><td class="mono">${h.id}</td><td class="mono">${fmtTs(h.createdTs)}</td>
    <td>${esc(h.analyst) || '<span class="muted">-</span>'}</td><td class="mono">${fmtTs(h.fromTs)} &ndash; ${fmtTs(h.toTs)}</td>
    <td>${esc(h.notes.slice(0, 120))}${h.notes.length > 120 ? '&hellip;' : ''}</td></tr>`).join('') ||
    '<tr><td colspan="5" class="muted">None saved yet.</td></tr>';
}

const mirrorNotes = () => { $('#hNotesPrint').textContent = $('#hNotes').value || '(no notes)'; };

// Renders a live report (saved = null) or a saved handover's frozen snapshot
function renderHandover(r, saved) {
  const A = r.alerts;
  const sevRows = ['critical', 'high', 'medium', 'low'].map(s => `<tr><td><span class="sev ${s}">${s}</span></td>
    <td class="mono">${A.new[s]}</td><td class="mono">${A.open[s]}</td><td class="mono">${A.closed[s]}</td></tr>`).join('');
  $('#hReport').innerHTML = `
    <div class="h-title"><h2>Shift handover</h2>
      <div class="muted">${fmtTs(r.fromTs)} &ndash; ${fmtTs(r.toTs)} &middot; generated ${fmtTs(r.generatedTs)}${saved ? ` &middot; saved handover #${saved.id}${saved.analyst ? ` by ${esc(saved.analyst)}` : ''}` : ''}</div>
      <div class="print-only">SIMULATED TRAINING DATA: every event, user, host and IP address in this report is made up by the SOC Training Simulator.</div></div>
    ${saved ? `<div class="verdict no-print">Viewing saved handover #${saved.id} (frozen at ${fmtTs(saved.createdTs)}). <a href="#handover" id="hBackLive">Back to the live report</a></div>` : ''}
    <div class="kpis">
      <div class="kpi"><div class="kpi-label">New alerts</div><div class="kpi-val">${A.totals.new}</div></div>
      <div class="kpi"><div class="kpi-label">Open alerts</div><div class="kpi-val">${A.totals.open}</div></div>
      <div class="kpi"><div class="kpi-label">Closed alerts</div><div class="kpi-val">${A.totals.closed}</div></div>
      <div class="kpi"><div class="kpi-label">Open cases</div><div class="kpi-val">${r.cases.open.length}</div></div>
      <div class="kpi" title="Mean time to acknowledge, for alerts acknowledged in this window"><div class="kpi-label">Shift MTTA (${r.ackCount})</div><div class="kpi-val">${fmtDur(r.mttaSeconds)}</div></div>
      <div class="kpi" title="Mean time to resolve, for alerts closed in this window"><div class="kpi-label">Shift MTTR (${r.closeCount})</div><div class="kpi-val">${fmtDur(r.mttrSeconds)}</div></div>
    </div>
    <div class="grid">
      <div class="panel"><h3>Alerts by severity</h3>
        <table class="h-sev"><thead><tr><th>Severity</th><th>New</th><th>Open</th><th>Closed</th></tr></thead><tbody>${sevRows}
          <tr><td><b>Total</b></td><td class="mono">${A.totals.new}</td><td class="mono">${A.totals.open}</td><td class="mono">${A.totals.closed}</td></tr></tbody></table>
        <p class="muted">New = appeared in the window. Open = still open at the end of it. Closed: ${A.closedByVerdict.true_positive} true positive,
          ${A.closedByVerdict.false_positive} false positive, ${A.closedByVerdict.benign} benign. Cases opened ${r.cases.opened}, closed ${r.cases.closed}.</p></div>
      <div class="panel"><h3>Watch list (${r.watch.length})</h3>
        ${r.watch.map((w, i) => `<div class="watch ${w.level}"><span class="wl">${w.level}</span><a href="#handover" data-watch="${i}">${esc(w.text)}</a></div>`).join('') ||
          '<p class="muted">Nothing flagged for the next shift.</p>'}</div>
      <div class="panel wide"><h3>Open cases (${r.cases.open.length})</h3>
        <table><thead><tr><th>#</th><th>Sev</th><th>Title</th><th>NIST phase</th><th>Owner</th><th>Alerts</th><th>Playbook</th><th>IOCs</th><th>Opened</th><th>Last update</th></tr></thead>
        <tbody>${r.cases.open.map(c => `<tr data-h-case="${c.id}"><td class="mono">${c.id}</td><td><span class="sev ${c.severity}">${c.severity}</span></td><td>${esc(c.title)}</td>
          <td><span class="phase ${c.status}">${esc(c.status)}</span></td><td>${esc(c.owner) || '<b>unowned</b>'}</td><td class="mono">${c.alertCount}</td>
          <td class="mono">${c.stepsTotal ? `${c.stepsDone}/${c.stepsTotal}` : '-'}</td><td class="mono">${c.iocCount}</td>
          <td class="mono">${fmtTs(c.createdTs)}</td><td class="mono">${fmtTs(c.lastUpdateTs)}</td></tr>`).join('') ||
          '<tr><td colspan="10" class="muted">No open cases.</td></tr>'}</tbody></table></div>
      <div class="panel wide"><h3>Key IOCs (${r.iocs.length})</h3>
        <table><thead><tr><th>Type</th><th>Indicator</th><th>Threat intel</th><th>Sightings in window</th><th>Recorded on case</th><th>Alerts</th></tr></thead>
        <tbody>${r.iocs.map(x => `<tr><td>${IOC_TYPE[x.type]}</td><td class="mono"><a href="#ioc?v=${encodeURIComponent(x.value)}" title="${esc(x.value)}">${esc(shortIoc(x.value))}</a></td>
          <td>${x.intel ? `<span class="sev critical">listed</span> ${esc(x.intel)}` : '<span class="muted">not listed</span>'}</td><td class="mono">${x.sightings}</td>
          <td class="mono">${x.cases.map(id => `#${id}`).join(', ') || '-'}</td><td class="mono">${x.alertIds.map(id => `#${id}`).join(', ') || '-'}</td></tr>`).join('') ||
          '<tr><td colspan="6" class="muted">No key indicators in this window.</td></tr>'}</tbody></table></div>
    </div>
    ${saved ? `<div class="panel"><h3>Handover notes</h3><div class="h-notes-text">${esc(saved.notes) || '<span class="muted">(no notes)</span>'}</div></div>` : ''}`;

  const box = $('#hReport');
  box.querySelectorAll('[data-watch]').forEach(el => {
    el.onclick = ev => { ev.preventDefault(); followWatch(r.watch[el.dataset.watch].link); };
  });
  box.querySelectorAll('[data-h-case]').forEach(tr => { tr.onclick = () => { selectedCase = Number(tr.dataset.hCase); location.hash = '#cases'; }; });
  if (saved) $('#hBackLive').onclick = ev => { ev.preventDefault(); loadHandover(); };
}

function followWatch(link) {
  if (!link) return;
  if (link.type === 'alert') { location.hash = '#alerts'; openAlert(link.id).catch(e => toast(e.message, true)); }
  else if (link.type === 'alerts') { $('#fStatus').value = link.status; location.hash = '#alerts'; }
  else if (link.type === 'case') { selectedCase = link.id; location.hash = '#cases'; }
  else if (link.type === 'search') searchFor({ host: link.host || '', user: link.user || '' });
  else if (link.type === 'ioc') location.hash = `#ioc?v=${encodeURIComponent(link.value)}`;
  else if (link.type === 'rule') location.hash = '#rules';
}

async function openSavedHandover(id) {
  try {
    const h = await api(`/api/handovers/${id}`);
    $('#hNotesPanel').hidden = true;
    renderHandover(h.snapshot, h);
    window.scrollTo(0, 0);
  } catch (e) { toast(e.message, true); }
}
$('#view-handover').addEventListener('click', e => {
  const el = e.target.closest('[data-h-open]');
  if (!el) return;
  e.preventDefault();
  openSavedHandover(Number(el.dataset.hOpen));
});
$('#hWindow').addEventListener('change', () => {
  const custom = $('#hWindow').value === 'custom';
  $('#hCustom').hidden = !custom;
  if (custom && !$('#hFrom').value) { $('#hTo').value = toLocalInput(Date.now()); $('#hFrom').value = toLocalInput(Date.now() - 8 * 3600e3); }
  if (!custom) loadHandover();
});
$('#hRefresh').onclick = loadHandover;
$('#hPrint').onclick = () => window.print();
$('#hNotes').addEventListener('input', mirrorNotes);
$('#hNotes').addEventListener('change', async () => {
  try { await api('/api/handover/draft', { method: 'PUT', body: { notes: $('#hNotes').value } }); $('#hDraftMsg').textContent = `Draft saved ${fmtTs(Date.now())}`; }
  catch (e) { toast(e.message, true); }
});
$('#hSave').onclick = async () => {
  if (!HREPORT) return;
  try {
    const h = await api('/api/handovers', { method: 'POST', body: { fromTs: HREPORT.fromTs, toTs: HREPORT.toTs, analyst: $('#hAnalyst').value, notes: $('#hNotes').value } });
    $('#hNotes').value = '';
    toast(`Handover #${h.id} saved`);
    loadHandover();
  } catch (e) { toast(e.message, true); }
};

// ---------- rules ----------
async function loadRules() {
  $('#rulesText').value = JSON.stringify(await api('/api/rules'), null, 2);
  $('#rulesMsg').textContent = '';
}
$('#rulesReload').onclick = loadRules;
$('#rulesSave').onclick = async () => {
  try {
    const parsed = JSON.parse($('#rulesText').value);
    await api('/api/rules', { method: 'PUT', body: parsed });
    $('#rulesMsg').textContent = 'Saved. New rules apply to incoming events.';
    toast('Rules saved');
  } catch (e) { $('#rulesMsg').textContent = ''; toast(e.message, true); }
};

// ---------- generator ----------
async function loadGenerator() {
  const g = await api('/api/generator');
  $('#gRunning').checked = g.running;
  $('#gRate').value = g.rate;
  $('#gAuto').checked = g.autoScenarios;
  $('#dataFile').textContent = META.dataFile;
  await refreshExercise();
  document.querySelectorAll('#scenarioButtons button').forEach(b => { b.disabled = EX.running; });
  $('#gAuto').disabled = EX.running;
  $('#gExNote').textContent = EX.running ? 'An exercise is running: injection and auto-scenarios are off until it is submitted.' : '';
  const intel = await api('/api/intel');
  $('#intelList').innerHTML = [...intel.badIps, ...intel.badDomains, ...intel.badHashes]
    .map(i => `<div><span class="mono" title="${esc(i.value)}">${esc(shortIoc(i.value))}</span> <span class="muted">${esc(i.note)}</span></div>`).join('');
}
$('#gApply').onclick = async () => {
  try {
    await api('/api/generator', { method: 'POST', body: { running: $('#gRunning').checked, rate: Number($('#gRate').value), autoScenarios: $('#gAuto').checked } });
    toast('Generator updated'); refreshBadge();
  } catch (e) { toast(e.message, true); }
};
$('#resetBtn').onclick = async () => {
  if (!confirm('Delete all events, alerts and notes and generate a fresh 24h history?')) return;
  await api('/api/reset', { method: 'POST', body: {} });
  toast('State reset'); selectedAlert = null; selectedCase = null;
  $('#alertDetail').innerHTML = '<p class="muted">Select an alert to triage it.</p>';
  $('#caseDetail').innerHTML = '<p class="muted">Select a case, or use "Escalate to case" on an alert.</p>';
};

// ---------- header ----------
async function refreshBadge() {
  const [s, g] = await Promise.all([api('/api/stats'), api('/api/generator')]);
  $('#openBadge').textContent = s.open;
  $('#caseBadge').textContent = s.openCases;
  $('#genDot').classList.toggle('on', g.running);
}
setInterval(() => { $('#clock').textContent = new Date().toLocaleString(); renderBanner(); }, 1000);

// ---------- init ----------
(async function init() {
  [META, PLAYBOOKS] = await Promise.all([api('/api/meta'), api('/api/playbooks')]);
  $('#cStatusF').innerHTML += META.caseStatuses.map(s => `<option>${esc(s)}</option>`).join('');
  $('#fStatus').innerHTML += META.statuses.map(s => `<option>${s}</option>`).join('');
  $('#fSeverity').innerHTML += META.severities.map(s => `<option>${s}</option>`).join('');
  $('#fAssignee').innerHTML += META.analysts.map(s => `<option>${s}</option>`).join('');
  $('#sHost').innerHTML += META.hosts.map(h => `<option>${esc(h)}</option>`).join('');
  $('#sUser').innerHTML += META.users.map(u => `<option>${esc(u)}</option>`).join('');
  $('#scenarioButtons').innerHTML = META.scenarios.map(s => `<button class="ghost" data-key="${s.key}">${esc(s.name)}</button>`).join('');
  $('#scenarioButtons').onclick = async e => {
    const key = e.target.dataset.key;
    if (!key) return;
    try { const r = await api('/api/generator/inject', { method: 'POST', body: { scenario: key } }); toast(`Injected: ${r.injected}`); }
    catch (err) { toast(err.message, true); }
  };
  $('#fMitre').innerHTML += META.mitre.map(t => `<option value="${esc(t.id)}">${esc(t.id)} ${esc(t.name)}</option>`).join('');
  $('#hAnalyst').innerHTML = `<option value="">-</option>${META.analysts.map(a => `<option>${esc(a)}</option>`).join('')}`;
  await refreshExercise().catch(() => {});
  show(currentView());
  refreshBadge();
  setInterval(() => {
    refreshBadge();
    refreshExercise().catch(() => {});
    const v = currentView();
    if (v === 'dashboard') loadDashboard();
    if (v === 'alerts') loadAlerts();
    if (v === 'mitre') loadMitre();
  }, 5000);
})();
