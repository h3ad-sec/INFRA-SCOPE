/* ══ INFRA-SCOPE: ui.js, render functions, one per panel ════════════════════
   Each renderX(state) writes into the DOM ids already present in index.html.
   Reuses existing CSS classes only, nothing new is added to style.css. */

function escapeHtml(str) {
  return String(str == null ? '' : str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function dohAnswers(res, wantType) {
  if (!res || !Array.isArray(res.Answer)) return [];
  return wantType ? res.Answer.filter(a => a.type === wantType) : res.Answer;
}

function vcardFn(entity) {
  if (!entity || !Array.isArray(entity.vcardArray) || !Array.isArray(entity.vcardArray[1])) return null;
  const fnEntry = entity.vcardArray[1].find(e => Array.isArray(e) && e[0] === 'fn');
  return fnEntry && fnEntry[3] ? fnEntry[3] : null;
}

function findEntityRecursive(entities, role) {
  if (!Array.isArray(entities)) return null;
  for (const e of entities) {
    if (Array.isArray(e.roles) && e.roles.includes(role)) return e;
    if (e.entities) {
      const found = findEntityRecursive(e.entities, role);
      if (found) return found;
    }
  }
  return null;
}

function kv(label, value) {
  return `<div class="modal-k">${escapeHtml(label)}</div><div class="modal-v">${escapeHtml(value)}</div>`;
}

function tagList(label, values) {
  if (!values || !values.length) return '';
  return `<div class="intel-sub-label">${escapeHtml(label)}</div><div class="modal-tags">${values.map(v => `<span class="modal-tag">${escapeHtml(v)}</span>`).join('')}</div>`;
}

/* ── WHOIS · RDAP ─────────────────────────────────────────────────────────── */
function renderWhois(state) {
  const body = document.getElementById('whois-body');
  const meta = document.getElementById('whois-meta');
  if (!body) return;
  const rdap = state.rdap;

  if (!rdap) {
    body.innerHTML = `<div class="intel-na">RDAP lookup failed or returned no data.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  if (state.type === 'domain') {
    const registrarEntity = findEntityRecursive(rdap.entities, 'registrar');
    const abuseEntity = findEntityRecursive(rdap.entities, 'abuse');
    const registrarName = vcardFn(registrarEntity) || 'N/A';
    const abuseName = vcardFn(abuseEntity) || 'N/A';
    const events = Array.isArray(rdap.events) ? rdap.events : [];
    const getEvent = action => {
      const e = events.find(x => x.eventAction === action);
      if (!e || !e.eventDate) return 'N/A';
      const d = new Date(e.eventDate);
      return isNaN(d.getTime()) ? e.eventDate : d.toISOString().slice(0, 10);
    };
    const created = getEvent('registration');
    const expires = getEvent('expiration');
    const lastChanged = getEvent('last changed');
    const dnssec = rdap.secureDNS && rdap.secureDNS.delegationSigned ? 'Signed' : 'Not signed';
    const ns = Array.isArray(rdap.nameservers) ? rdap.nameservers.map(n => n.ldhName).filter(Boolean) : [];
    const statuses = Array.isArray(rdap.status) ? rdap.status : [];

    body.innerHTML = `
      <div class="modal-kv-grid">
        ${kv('Domain', rdap.ldhName || state.target)}
        ${kv('Registrar', registrarName)}
        ${kv('Abuse Contact', abuseName)}
        ${kv('Created', created)}
        ${kv('Expires', expires)}
        ${kv('Last Changed', lastChanged)}
        ${kv('DNSSEC', dnssec)}
      </div>
      ${tagList('STATUS', statuses)}
      ${tagList('NAMESERVERS', ns)}
    `;
    if (meta) meta.textContent = registrarName;
    state.registrarName = registrarName;
    state.rdapCreated = created;
    state.rdapDnssec = dnssec;
    state.rdapNsCount = ns.length;
  } else {
    const cidrs = Array.isArray(rdap.cidr0_cidrs)
      ? rdap.cidr0_cidrs.map(c => `${c.v4prefix || c.v6prefix || ''}/${c.length}`)
      : [];
    const registrantEntity = findEntityRecursive(rdap.entities, 'registrant');
    const orgName = rdap.name || vcardFn(registrantEntity) || 'N/A';

    body.innerHTML = `
      <div class="modal-kv-grid">
        ${kv('Network Name', orgName)}
        ${kv('Handle', rdap.handle || 'N/A')}
        ${kv('Range', `${rdap.startAddress || 'N/A'} – ${rdap.endAddress || 'N/A'}`)}
        ${kv('Country', rdap.country || 'N/A')}
      </div>
      ${tagList('CIDR BLOCKS', cidrs)}
    `;
    if (meta) meta.textContent = orgName;
    state.registrarName = orgName;
  }
}

/* ── Live DNS Records ─────────────────────────────────────────────────────── */
function renderLiveDNS(state) {
  const body = document.getElementById('livedns-body');
  const meta = document.getElementById('livedns-meta');
  if (!body) return;

  if (state.type === 'ip') {
    if (state.ptrUnsupported) {
      body.innerHTML = `<div class="intel-na">IPv6 PTR not implemented yet.</div>`;
      if (meta) meta.textContent = 'N/A';
      return;
    }
    const ptrRecords = dohAnswers(state.ptr).map(a => a.data);
    body.innerHTML = ptrRecords.length
      ? tagList('PTR (REVERSE DNS)', ptrRecords)
      : `<div class="intel-na">No PTR record found.</div>`;
    if (meta) meta.textContent = `${ptrRecords.length} record${ptrRecords.length === 1 ? '' : 's'}`;
    return;
  }

  const sections = [];
  let total = 0;
  const add = (label, values) => { if (values.length) { sections.push(tagList(label, values)); total += values.length; } };

  add('A', state.a || []);
  add('AAAA', state.aaaa || []);
  add('MX', dohAnswers(state.mx, 15).map(a => a.data));
  add('NS', dohAnswers(state.ns, 2).map(a => a.data));
  add('TXT', dohAnswers(state.txt, 16).map(a => a.data));
  add('CAA', dohAnswers(state.caa, 257).map(a => a.data));
  add('SOA', dohAnswers(state.soa, 6).map(a => a.data));
  add('CNAME', dohAnswers(state.cname, 5).map(a => a.data));

  body.innerHTML = sections.length ? sections.join('') : `<div class="intel-na">No DNS records resolved.</div>`;
  if (meta) meta.textContent = `${total} record${total === 1 ? '' : 's'}`;
  state.liveDnsCount = total;
}

/* ── Email Infrastructure ─────────────────────────────────────────────────── */
function renderEmail(state) {
  const body = document.getElementById('email-body');
  const meta = document.getElementById('email-meta');
  if (!body) return;

  if (state.type === 'ip') {
    body.innerHTML = `<div class="intel-na">Not applicable for a raw IP target.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const txtRecords = dohAnswers(state.txt, 16).map(a => a.data.replace(/^"|"$/g, ''));
  const spf = txtRecords.find(t => /^v=spf1/i.test(t));
  const dmarcRecords = dohAnswers(state.dmarc, 16).map(a => a.data.replace(/^"|"$/g, ''));
  const dmarc = dmarcRecords.find(t => /^v=dmarc1/i.test(t));
  const dkimFound = Array.isArray(state.dkim) ? state.dkim : [];
  const mxValues = dohAnswers(state.mx, 15).map(a => a.data);

  const parts = [];
  parts.push(`<div class="modal-kv-grid">
    ${kv('SPF', spf ? 'Found' : 'Missing')}
    ${kv('DMARC', dmarc ? 'Found' : 'Missing')}
    ${kv('DKIM', dkimFound.length ? `${dkimFound.length} selector${dkimFound.length === 1 ? '' : 's'} found` : 'None found (common selectors only)')}
  </div>`);
  if (spf) parts.push(tagList('SPF RECORD', [spf]));
  if (dmarc) parts.push(tagList('DMARC RECORD', [dmarc]));
  if (dkimFound.length) parts.push(tagList('DKIM SELECTORS FOUND', dkimFound.map(d => d.selector)));
  if (mxValues.length) parts.push(tagList('MX RECORDS', mxValues));

  body.innerHTML = parts.join('');
  const summary = `SPF ${spf ? '✓' : '✗'} · DMARC ${dmarc ? '✓' : '✗'} · DKIM ${dkimFound.length} found`;
  if (meta) meta.textContent = summary;
  state.emailSummary = summary;
}

/* ── ASN · Network ─────────────────────────────────────────────────────────── */
function renderASN(state) {
  const body = document.getElementById('asn-body');
  const meta = document.getElementById('asn-meta');
  if (!body) return;

  if (state.type === 'domain' && state.asnStatus === 'no-a-record') {
    body.innerHTML = `<div class="intel-na">No A record to resolve ASN from.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const net = state.networkInfo;
  if (!net || !net.data) {
    body.innerHTML = `<div class="intel-na">ASN lookup failed or returned no data.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const asns = Array.isArray(net.data.asns) ? net.data.asns : [];
  const prefix = net.data.prefix || 'N/A';
  const holder = state.asOverview && state.asOverview.data ? state.asOverview.data.holder : null;
  const announced = state.asOverview && state.asOverview.data && typeof state.asOverview.data.announced === 'boolean'
    ? state.asOverview.data.announced : null;
  const located = state.geoloc && state.geoloc.data && Array.isArray(state.geoloc.data.located_resources)
    ? state.geoloc.data.located_resources[0] : null;
  const loc = located && Array.isArray(located.locations) ? located.locations[0] : null;

  const rows = [
    kv('ASN', asns.length ? `AS${asns[0]}` : 'N/A'),
    kv('Holder', holder || 'N/A'),
    kv('Prefix', prefix),
    kv('Announced', announced === null ? 'N/A' : (announced ? 'Yes' : 'No')),
  ];
  if (loc) {
    const knownParts = [loc.city, loc.country].filter(v => v && v !== '?');
    rows.push(kv('Location', knownParts.length ? knownParts.join(', ') : 'N/A'));
  }

  body.innerHTML = `<div class="modal-kv-grid">${rows.join('')}</div>${asns.length > 1 ? tagList('ALL ANNOUNCING ASNS', asns.map(a => `AS${a}`)) : ''}`;

  const asnMeta = asns.length ? `AS${asns[0]}` : 'N/A';
  if (meta) meta.textContent = asnMeta;
  state.asnMeta = asnMeta;
  state.asnHolder = holder || 'N/A';
}

/* ── Certificates · CT Logs ───────────────────────────────────────────────── */
function renderCerts(state) {
  const body = document.getElementById('certs-body');
  const meta = document.getElementById('certs-meta');
  if (!body) return;

  if (state.type === 'ip') {
    body.innerHTML = `<div class="intel-na">Not applicable for a raw IP target.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  if (state.crt === undefined) {
    body.innerHTML = `<div class="intel-na">crt.sh unavailable right now, try rescanning in a moment.</div>`;
    if (meta) meta.textContent = 'Unavailable';
    return;
  }

  const certs = Array.isArray(state.crt) ? state.crt : [];
  if (!certs.length) {
    body.innerHTML = `<div class="intel-na">No certificates found in CT logs.</div>`;
    if (meta) meta.textContent = '0 certs';
    state.certCount = 0;
    return;
  }

  const sorted = certs.slice().sort((a, b) => new Date(b.entry_timestamp || b.not_before || 0) - new Date(a.entry_timestamp || a.not_before || 0));
  const shown = sorted.slice(0, 50);
  const rows = shown.map(c => `
    <div class="modal-kv-grid" style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)">
      ${kv('Common Name', c.common_name || 'N/A')}
      ${kv('Issuer', c.issuer_name || 'N/A')}
      ${kv('Not Before', c.not_before || 'N/A')}
      ${kv('Not After', c.not_after || 'N/A')}
    </div>`).join('');
  const note = certs.length > 50 ? `<div class="intel-na">Showing 50 most recent of ${certs.length} certificates.</div>` : '';

  body.innerHTML = note + rows;
  if (meta) meta.textContent = `${certs.length} cert${certs.length === 1 ? '' : 's'}`;
  state.certCount = certs.length;
}

/* ── Subdomains ───────────────────────────────────────────────────────────── */
function renderSubdomains(state) {
  const body = document.getElementById('subdomains-body');
  const meta = document.getElementById('subdomains-meta');
  if (!body) return;

  if (state.type === 'ip') {
    body.innerHTML = `<div class="intel-na">Not applicable for a raw IP target.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const subs = Array.isArray(state.subdomains) ? state.subdomains : [];
  if (!subs.length) {
    body.innerHTML = `<div class="intel-na">No subdomains found.</div>`;
    if (meta) meta.textContent = '0 found';
    return;
  }

  body.innerHTML = `<div class="modal-tags">${subs.map(s => `<span class="modal-tag">${escapeHtml(s)}</span>`).join('')}</div>`;
  if (meta) meta.textContent = `${subs.length} unique`;
}

/* ── Overview (summary of everything else, rendered last) ───────────────────── */
function renderOverview(state) {
  const grid = document.getElementById('overviewGrid');
  const scantime = document.getElementById('overview-scantime');
  if (!grid) return;

  const resolvedIps = state.type === 'ip' ? [state.target] : [...(state.a || []), ...(state.aaaa || [])];
  const registrarOrOrg = state.registrarName || 'N/A';
  const created = state.rdapCreated || 'N/A';
  const dnssec = state.rdapDnssec || 'N/A';
  const nsCount = typeof state.rdapNsCount === 'number' ? state.rdapNsCount : 'N/A';
  const asnMeta = state.asnMeta || 'N/A';
  const asnHolder = state.asnHolder || 'N/A';
  const subCount = state.type === 'ip' ? 'N/A' : (Array.isArray(state.subdomains) ? state.subdomains.length : 0);
  const certCount = state.type === 'ip'
    ? 'N/A'
    : (typeof state.certCount === 'number' ? state.certCount : (state.crt === undefined ? 'Unavailable' : 0));

  const block = (label, value) => `<div class="modal-kv-grid">${kv(label, value)}</div>`;

  grid.innerHTML = [
    block('Target', state.target),
    block('Type', state.type === 'ip' ? 'IP Address' : 'Domain'),
    block('Resolved IP(s)', resolvedIps.length ? resolvedIps.join(', ') : 'N/A'),
    block('Registrar / Org', registrarOrOrg),
    block('Created', created),
    block('DNSSEC', dnssec),
    block('Nameservers', nsCount),
    block('ASN', asnMeta),
    block('ASN Holder', asnHolder),
    block('Subdomains Found', subCount),
    block('Certificates Found', certCount),
  ].join('');

  if (scantime) scantime.textContent = `Scanned ${state.target} · ${new Date().toLocaleString()}`;
}
