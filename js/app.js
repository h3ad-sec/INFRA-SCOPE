
/* ── View switching ───────────────────────────────────────────────────────── */
function switchView(view) {
  document.getElementById('view-overview').style.display = view === 'overview' ? '' : 'none';
  document.getElementById('view-workspace').style.display = view === 'overview' ? 'none' : '';
  document.querySelectorAll('.view-tab').forEach(t => t.classList.toggle('active', t.dataset.view === view));
  document.body.classList.toggle('view-is-overview', view === 'overview');
  localStorage.setItem('is_view', view);
  if (view === 'overview') window.scrollTo({ top: 0 });
}

/* ── Toast helper ─────────────────────────────────────────────────────────── */
function showToast(msg, type) {
  const wrap = document.getElementById('toastWrap');
  if (!wrap) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type || 'success'}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

/* ── BYOK key services & management ──────────────────────────────────────── */
const KEY_SERVICES = ['vt', 'shodan', 'otx', 'threatfox', 'urlscan', 'ipinfo'];

function getKey(service) {
  if (service === 'censys') {
    const id = localStorage.getItem('is_censys_id');
    const secret = localStorage.getItem('is_censys_secret');
    if (id && secret) return { id, secret };
    return null;
  }
  return localStorage.getItem(`is_${service}`) || null;
}

function getAllConfiguredCount() {
  let n = KEY_SERVICES.filter(s => getKey(s)).length;
  if (getKey('censys')) n++;
  return n;
}

function saveKeys() {
  KEY_SERVICES.forEach(s => {
    const el = document.getElementById(`${s}-key`);
    if (!el) return;
    const val = el.value.trim();
    if (val) localStorage.setItem(`is_${s}`, val);
    else localStorage.removeItem(`is_${s}`);
  });

  const idEl = document.getElementById('censys-id-key');
  const idVal = idEl ? idEl.value.trim() : '';
  if (idVal) localStorage.setItem('is_censys_id', idVal);
  else localStorage.removeItem('is_censys_id');

  const secretEl = document.getElementById('censys-secret-key');
  const secretVal = secretEl ? secretEl.value.trim() : '';
  if (secretVal) localStorage.setItem('is_censys_secret', secretVal);
  else localStorage.removeItem('is_censys_secret');

  const msg = document.getElementById('key-saved-msg');
  if (msg) {
    msg.classList.add('show');
    setTimeout(() => msg.classList.remove('show'), 2000);
  }

  updateKeysNavBadge();
}

function clearKeys() {
  ['is_vt', 'is_shodan', 'is_otx', 'is_threatfox', 'is_urlscan', 'is_ipinfo', 'is_censys_id', 'is_censys_secret']
    .forEach(k => localStorage.removeItem(k));

  KEY_SERVICES.forEach(s => {
    const el = document.getElementById(`${s}-key`);
    if (el) el.value = '';
  });
  const idEl = document.getElementById('censys-id-key');
  if (idEl) idEl.value = '';
  const secretEl = document.getElementById('censys-secret-key');
  if (secretEl) secretEl.value = '';

  updateKeysNavBadge();
  showToast('All keys cleared', 'success');
}

function loadSavedKeys() {
  KEY_SERVICES.forEach(s => {
    const el = document.getElementById(`${s}-key`);
    const val = localStorage.getItem(`is_${s}`);
    if (el && val) el.value = val;
  });
  const idEl = document.getElementById('censys-id-key');
  const idVal = localStorage.getItem('is_censys_id');
  if (idEl && idVal) idEl.value = idVal;
  const secretEl = document.getElementById('censys-secret-key');
  const secretVal = localStorage.getItem('is_censys_secret');
  if (secretEl && secretVal) secretEl.value = secretVal;
}

function toggleKey(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  const btn = input.nextElementSibling;
  if (btn) btn.textContent = isPassword ? 'HIDE' : 'SHOW';
}

function updateKeysNavBadge() {
  const n = getAllConfiguredCount();
  const text = n > 0 ? ` (${n}/7)` : '';
  const el = document.getElementById('nav-keys-count');
  if (el) el.textContent = text;
  const drawerEl = document.getElementById('nav-keys-count-drawer');
  if (drawerEl) drawerEl.textContent = text;
}

/* ── Key import (txt/csv/md/json/xlsx → key input fields) ────────────────── */
const KEY_ALIASES = {
  vt:             ['vt', 'virustotal', 'virus total'],
  shodan:         ['shodan'],
  censys_id:      ['censysid', 'censys id', 'censys api id', 'censysapiid'],
  censys_secret:  ['censyssecret', 'censys secret', 'censys api secret', 'censysapisecret'],
  otx:            ['otx', 'alienvault', 'alienvault otx', 'alien vault'],
  threatfox:      ['tf', 'threatfox', 'threat fox'],
  urlscan:        ['us', 'urlscan', 'url scan'],
  ipinfo:         ['ipinfo', 'ip info', 'ipinfo.io'],
};

function normalizeKeyName(raw) {
  const clean = String(raw || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!clean) return null;
  for (const [service, aliases] of Object.entries(KEY_ALIASES)) {
    if (aliases.some(a => a.replace(/[^a-z0-9]/g, '') === clean)) return service;
  }
  return null;
}

/* txt/csv/md all share one parser: markdown table rows ("| Source | Key |"),
   and source:key / source=key / source,key lines all reduce to the same
   [name, value] pairs. */
function parseKeyPairsFromText(text) {
  const pairs = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('|')) {
      const cells = line.split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length >= 2 && !/^-+$/.test(cells[0])) pairs.push([cells[0], cells[1]]);
      continue;
    }
    const m = line.match(/^([^=:,\t/]+)[=:,\t/]\s*(.+)$/);
    if (m) pairs.push([m[1].trim(), m[2].trim().replace(/^["']|["']$/g, '')]);
  }
  return pairs;
}

function applyImportedKeys(pairs) {
  let matched = 0, skipped = 0;
  for (const [rawName, rawValue] of pairs) {
    const service = normalizeKeyName(rawName);
    const value = String(rawValue ?? '').trim();
    const el = service && document.getElementById(`${service.replace('_', '-')}-key`);
    if (el && value) { el.value = value; matched++; } else skipped++;
  }
  if (matched) showToast(`Imported ${matched} key${matched !== 1 ? 's' : ''}${skipped ? ` · ${skipped} unrecognized` : ''}, review then SAVE KEYS`, 'success');
  else showToast('No recognizable source keys found in that file', 'error');
}

function handleKeyImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  const ext = file.name.split('.').pop().toLowerCase();

  if (ext === 'xlsx' || ext === 'xls') {
    if (typeof XLSX === 'undefined') { showToast('Excel library not ready, try again', 'error'); return; }
    const r = new FileReader();
    r.onload = ev => {
      try {
        const wb = XLSX.read(new Uint8Array(ev.target.result), { type: 'array' });
        const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1 });
        applyImportedKeys(rows.filter(row => row.length >= 2).map(row => [row[0], row[1]]));
      } catch(_) { showToast('Failed to parse Excel file', 'error'); }
    };
    r.readAsArrayBuffer(file);
  } else if (ext === 'json') {
    const r = new FileReader();
    r.onload = ev => {
      try {
        const obj = JSON.parse(ev.target.result);
        const pairs = Array.isArray(obj)
          ? obj.map(o => [o.source ?? o.name ?? o.service, o.key ?? o.value ?? o.apikey ?? o.apiKey]).filter(p => p[0] != null)
          : (obj && typeof obj === 'object') ? Object.entries(obj) : [];
        applyImportedKeys(pairs);
      } catch(_) { showToast('Failed to parse JSON file', 'error'); }
    };
    r.readAsText(file);
  } else {
    const r = new FileReader();
    r.onload = ev => applyImportedKeys(parseKeyPairsFromText(ev.target.result));
    r.readAsText(file);
  }
  e.target.value = '';
}

function expDateTag() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadKeyTemplate() {
  const fmt = document.getElementById('key-template-format')?.value || 'json';
  const services = ['vt', 'shodan', 'censys_id', 'censys_secret', 'otx', 'threatfox', 'urlscan', 'ipinfo'];
  const dateTag = expDateTag();
  const base = `infra-scope-keys-template-${dateTag}`;

  if (fmt === 'json') {
    const obj = {};
    services.forEach(s => { obj[s] = ''; });
    downloadFile(JSON.stringify(obj, null, 2), `${base}.json`, 'application/json');
  } else if (fmt === 'txt') {
    downloadFile(services.map(s => `${s}=`).join('\n') + '\n', `${base}.txt`, 'text/plain;charset=utf-8;');
  } else if (fmt === 'csv') {
    const lines = ['source,key', ...services.map(s => `${s},`)];
    downloadFile('﻿' + lines.join('\r\n'), `${base}.csv`, 'text/csv;charset=utf-8;');
  } else if (fmt === 'md') {
    const rows = ['| Source | Key |', '|---|---|', ...services.map(s => `| ${s} |  |`)];
    downloadFile(rows.join('\n') + '\n', `${base}.md`, 'text/markdown;charset=utf-8;');
  } else if (fmt === 'xlsx') {
    if (typeof XLSX === 'undefined') { showToast('Excel library not ready, try again', 'error'); return; }
    const wb = XLSX.utils.book_new();
    const sheet = XLSX.utils.aoa_to_sheet([['source', 'key'], ...services.map(s => [s, ''])]);
    XLSX.utils.book_append_sheet(wb, sheet, 'Keys');
    XLSX.writeFile(wb, `${base}.xlsx`);
  }
  showToast('Template downloaded', 'success');
}

/* ── Target input ─────────────────────────────────────────────────────────── */
let currentTarget = '';

function detectTargetType(v) {
  v = v.trim();
  if (!v) return null;
  const ip4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ip6 = /^[0-9a-f:]+:[0-9a-f:]+$/i;
  if (ip4.test(v) || ip6.test(v)) return 'IP';
  const domain = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  if (domain.test(v)) return 'DOMAIN';
  return 'UNKNOWN';
}

function onTargetInput() {
  const input = document.getElementById('targetInput');
  const badge = document.getElementById('inputTypeBadge');
  const btn = document.getElementById('scanBtn');
  const type = detectTargetType(input.value);
  if (badge) badge.textContent = type && type !== 'UNKNOWN' ? type : '';
  if (btn) btn.disabled = !type || type === 'UNKNOWN';
}

async function startScan() {
  const input = document.getElementById('targetInput');
  const type = detectTargetType(input.value);
  if (!type || type === 'UNKNOWN') { showToast('Enter a valid domain or IP first', 'error'); return; }
  currentTarget = input.value.trim().toLowerCase();
  const scanBtn = document.getElementById('scanBtn');
  const stopBtn = document.getElementById('stopBtn');
  if (scanBtn) scanBtn.disabled = true;
  if (stopBtn) stopBtn.style.display = '';
  try {
    await runScan(currentTarget, type.toLowerCase());
  } finally {
    if (scanBtn) scanBtn.disabled = false;
    if (stopBtn) stopBtn.style.display = 'none';
  }
}

function stopScan() { stopScanEngine(); }

function clearAll() {
  const t = document.getElementById('targetInput'); if (t) t.value = '';
  onTargetInput();
  document.querySelectorAll('.panel[id$="-panel"]').forEach(p => { if (p.id !== 'input-panel') p.style.display = 'none'; });
}

/* ── Collapsible result panels ────────────────────────────────────────────── */
function togglePanel(id) {
  const panel = document.getElementById(id);
  if (!panel) return;
  const collapsed = panel.classList.toggle('panel-collapsed');
  const chevronId = id.replace('-panel', '-chevron');
  const chevron = document.getElementById(chevronId);
  if (chevron) chevron.classList.toggle('closed', collapsed);
}

/* ── Keys modal + key-prompt modal open/close ────────────────────────────── */
function openKeysModal() { document.getElementById('keys-modal')?.classList.add('open'); }
function closeKeysModal(e) { if (e && e.target !== document.getElementById('keys-modal')) return; document.getElementById('keys-modal')?.classList.remove('open'); }
function skipKeyPrompt(e) { if (e && e.target !== document.getElementById('keyprompt-modal')) return; document.getElementById('keyprompt-modal')?.classList.remove('open'); }
function goToKeySetup() { document.getElementById('keyprompt-modal')?.classList.remove('open'); openKeysModal(); }

/* ── DOMContentLoaded wiring ──────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  switchView(localStorage.getItem('is_view') === 'overview' ? 'overview' : 'workspace');

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeKeysModal();
      skipKeyPrompt();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('scanBtn');
      if (!btn?.disabled) startScan();
    }
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const tag = e.target?.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
      if (!typing) { e.preventDefault(); openKeysModal(); }
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      document.getElementById('targetInput')?.focus();
    }
  });

  loadSavedKeys();
  updateKeysNavBadge();

  const promptShown = sessionStorage.getItem('is_key_prompt_seen');
  if (getAllConfiguredCount() === 0 && !promptShown) {
    sessionStorage.setItem('is_key_prompt_seen', '1');
    document.getElementById('keyprompt-modal')?.classList.add('open');
  }
});
