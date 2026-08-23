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

/* ══ Phase 2: the 9 BYOK/relay panels ═══════════════════════════════════════
   Each source within a multi-source panel renders its own .intel-sub-label
   sub-section with an explicit "no key configured" state when the relevant
   getKey() lookup came back empty, same N/A philosophy as .intel-na above,
   never blocking the rest of the panel. */

function noKeyBlock(sourceLabel) {
  return `<div class="intel-na">No ${escapeHtml(sourceLabel)} key configured.</div>`;
}

/* ── Threat Intelligence ──────────────────────────────────────────────────── */
function vtStatsBlock(vt) {
  const attrs = vt && vt.data && vt.data.attributes;
  if (!attrs) return `<div class="intel-na">No VirusTotal data returned.</div>`;
  const stats = attrs.last_analysis_stats || {};
  const cats = attrs.categories ? Object.values(attrs.categories) : [];
  const rows = [
    kv('Malicious', stats.malicious ?? 'N/A'),
    kv('Suspicious', stats.suspicious ?? 'N/A'),
    kv('Harmless', stats.harmless ?? 'N/A'),
    kv('Undetected', stats.undetected ?? 'N/A'),
    kv('Reputation', attrs.reputation ?? 'N/A'),
  ];
  return `<div class="modal-kv-grid">${rows.join('')}</div>${tagList('CATEGORIES', cats)}`;
}

function renderThreatIntel(state) {
  const body = document.getElementById('ti-body');
  const meta = document.getElementById('ti-meta');
  if (!body) return;

  const parts = [];
  const metaBits = [];

  parts.push(`<div class="intel-sub-label">VIRUSTOTAL</div>`);
  if (!state.hasVT) {
    parts.push(noKeyBlock('VirusTotal'));
  } else {
    parts.push(vtStatsBlock(state.vtGeneral));
    const mal = state.vtGeneral && state.vtGeneral.data && state.vtGeneral.data.attributes && state.vtGeneral.data.attributes.last_analysis_stats
      ? state.vtGeneral.data.attributes.last_analysis_stats.malicious : undefined;
    if (typeof mal === 'number') metaBits.push(`VT mal:${mal}`);
  }

  parts.push(`<div class="intel-sub-label">ALIENVAULT OTX</div>`);
  if (!state.hasOTX) {
    parts.push(noKeyBlock('OTX'));
  } else if (!state.otxGeneral) {
    parts.push(`<div class="intel-na">No OTX data returned.</div>`);
  } else {
    const pulses = state.otxGeneral.pulse_info && Array.isArray(state.otxGeneral.pulse_info.pulses) ? state.otxGeneral.pulse_info.pulses : [];
    const count = state.otxGeneral.pulse_info ? (state.otxGeneral.pulse_info.count ?? pulses.length) : pulses.length;
    const tagSet = new Set();
    const malSet = new Set();
    pulses.forEach(p => {
      (p.tags || []).forEach(t => tagSet.add(t));
      (p.malware_families || []).forEach(m => malSet.add(m));
    });
    parts.push(`<div class="modal-kv-grid">${kv('Pulse Count', count)}</div>`);
    if (tagSet.size) parts.push(tagList('TAGS', Array.from(tagSet).slice(0, 15)));
    if (malSet.size) parts.push(tagList('MALWARE FAMILIES', Array.from(malSet).slice(0, 15)));
    metaBits.push(`OTX pulses:${count}`);
  }

  parts.push(`<div class="intel-sub-label">THREATFOX</div>`);
  if (!state.hasThreatFox) {
    parts.push(noKeyBlock('ThreatFox'));
  } else if (!state.threatfox || state.threatfox.query_status !== 'ok' || !Array.isArray(state.threatfox.data) || !state.threatfox.data.length) {
    parts.push(`<div class="intel-na">No ThreatFox matches.</div>`);
  } else {
    const rows = state.threatfox.data.slice(0, 20).map(d => `
      <div class="modal-kv-grid" style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)">
        ${kv('IOC', d.ioc || 'N/A')}
        ${kv('Threat Type', d.threat_type || 'N/A')}
        ${kv('Malware', d.malware_printable || d.malware || 'N/A')}
        ${kv('Confidence', d.confidence_level != null ? `${d.confidence_level}%` : 'N/A')}
        ${kv('First Seen', d.first_seen || 'N/A')}
      </div>`).join('');
    parts.push(rows);
    metaBits.push(`TF hits:${state.threatfox.data.length}`);
  }

  body.innerHTML = parts.join('');
  if (meta) meta.textContent = metaBits.length ? metaBits.join(' · ') : ((state.hasVT || state.hasOTX || state.hasThreatFox) ? 'No hits' : 'No keys configured');
}

/* ── Passive DNS ──────────────────────────────────────────────────────────── */
function renderPassiveDNS(state) {
  const body = document.getElementById('pdns-body');
  const meta = document.getElementById('pdns-meta');
  if (!body) return;

  const parts = [];
  let total = 0;

  parts.push(`<div class="intel-sub-label">VIRUSTOTAL RESOLUTIONS</div>`);
  if (!state.hasVT) {
    parts.push(noKeyBlock('VirusTotal'));
  } else {
    const items = state.vtResolutions && Array.isArray(state.vtResolutions.data) ? state.vtResolutions.data : [];
    if (!items.length) {
      parts.push(`<div class="intel-na">No VirusTotal resolution history.</div>`);
    } else {
      const chips = items.slice(0, 40).map(i => {
        const a = i.attributes || {};
        const val = a.ip_address || a.host_name || 'N/A';
        const dateStr = a.date ? ` (${new Date(a.date * 1000).toISOString().slice(0, 10)})` : '';
        return escapeHtml(val + dateStr);
      });
      parts.push(`<div class="modal-tags">${chips.map(c => `<span class="modal-tag">${c}</span>`).join('')}</div>`);
      total += items.length;
    }
  }

  parts.push(`<div class="intel-sub-label">OTX PASSIVE DNS</div>`);
  if (!state.hasOTX) {
    parts.push(noKeyBlock('OTX'));
  } else {
    const items = state.otxPdns && Array.isArray(state.otxPdns.passive_dns) ? state.otxPdns.passive_dns : [];
    if (!items.length) {
      parts.push(`<div class="intel-na">No OTX passive DNS records.</div>`);
    } else {
      const chips = items.slice(0, 40).map(i => {
        const val = i.hostname || i.address || 'N/A';
        const lastStr = i.last ? ` (last ${String(i.last).slice(0, 10)})` : '';
        return escapeHtml(val + lastStr);
      });
      parts.push(`<div class="modal-tags">${chips.map(c => `<span class="modal-tag">${c}</span>`).join('')}</div>`);
      total += items.length;
    }
  }

  parts.push(`<div class="intel-sub-label">ROBTEX</div>`);
  if (state.type !== 'domain') {
    parts.push(`<div class="intel-na">Not applicable for a raw IP target.</div>`);
  } else {
    const items = Array.isArray(state.robtexPdns) ? state.robtexPdns : [];
    if (!items.length) {
      parts.push(`<div class="intel-na">No Robtex forward DNS records.</div>`);
    } else {
      const chips = items.slice(0, 40).map(i => escapeHtml(`${i.rrdata || 'N/A'} (${i.rrtype || '?'})`));
      parts.push(`<div class="modal-tags">${chips.map(c => `<span class="modal-tag">${c}</span>`).join('')}</div>`);
      total += items.length;
    }
  }

  body.innerHTML = parts.join('');
  if (meta) meta.textContent = total ? `${total} record${total === 1 ? '' : 's'}` : 'No records';
}

/* ── Co-hosted Infra ──────────────────────────────────────────────────────── */
function renderCohosted(state, ip) {
  const body = document.getElementById('cohosted-body');
  const meta = document.getElementById('cohosted-meta');
  if (!body) return;

  if (!ip) {
    body.innerHTML = `<div class="intel-na">No IP resolved to check for co-hosted infrastructure.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const set = new Set();
  if (state.hasShodan && state.shodanHost) {
    (state.shodanHost.hostnames || []).forEach(h => set.add(String(h).toLowerCase()));
    (state.shodanHost.domains || []).forEach(d => set.add(String(d).toLowerCase()));
  }
  (state.hackertargetReverse || []).forEach(h => set.add(String(h).toLowerCase()));

  const parts = [];
  if (!state.hasShodan) parts.push(`<div class="intel-na">No Shodan key configured (Shodan-seen hostnames skipped, HackerTarget still included).</div>`);

  const list = Array.from(set).filter(h => h && h !== state.target).sort();
  if (!list.length) {
    parts.push(`<div class="intel-na">No co-hosted hostnames found.</div>`);
  } else {
    parts.push(`<div class="modal-tags">${list.map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}</div>`);
  }

  body.innerHTML = parts.join('');
  if (meta) meta.textContent = `${list.length} found`;
}

/* ── Ports · Services ─────────────────────────────────────────────────────── */
function renderPorts(state, ip) {
  const body = document.getElementById('ports-body');
  const meta = document.getElementById('ports-meta');
  if (!body) return;

  if (!ip) {
    body.innerHTML = `<div class="intel-na">No IP resolved to scan ports.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }
  if (!state.hasShodan) {
    body.innerHTML = noKeyBlock('Shodan');
    if (meta) meta.textContent = 'No key';
    return;
  }
  if (!state.shodanHost || !Array.isArray(state.shodanHost.data) || !state.shodanHost.data.length) {
    body.innerHTML = `<div class="intel-na">No Shodan port data returned for this IP.</div>`;
    if (meta) meta.textContent = '0 ports';
    return;
  }

  const items = state.shodanHost.data;
  const rows = items.map(d => {
    const raw = d.data || '';
    const banner = raw.length > 200 ? raw.slice(0, 200) + ' …(truncated)' : raw;
    return `<div class="modal-kv-grid" style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)">
      ${kv('Port', d.port ?? 'N/A')}
      ${kv('Transport', d.transport || 'N/A')}
      ${kv('Module', (d._shodan && d._shodan.module) || 'N/A')}
      ${kv('Banner', banner || 'N/A')}
    </div>`;
  }).join('');

  body.innerHTML = rows;
  if (meta) meta.textContent = `${items.length} port${items.length === 1 ? '' : 's'}`;
}

/* ── Fingerprints · JARM · Favicon ────────────────────────────────────────── */
function renderFingerprints(state, ip) {
  const body = document.getElementById('fp-body');
  const meta = document.getElementById('fp-meta');
  if (!body) return;

  if (!ip) {
    body.innerHTML = `<div class="intel-na">No IP resolved.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }
  if (!state.hasShodan) {
    body.innerHTML = noKeyBlock('Shodan');
    if (meta) meta.textContent = 'No key';
    return;
  }
  const items = (state.shodanHost && Array.isArray(state.shodanHost.data)) ? state.shodanHost.data : [];
  if (!items.length) {
    body.innerHTML = `<div class="intel-na">No fingerprint data returned.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const jarms = new Set();
  const favicons = new Set();
  const rows = [];
  items.forEach(d => {
    const jarm = d.ssl && d.ssl.jarm;
    const favHash = d.http && d.http.favicon ? d.http.favicon.hash : undefined;
    const title = d.http && d.http.title;
    const server = d.http && d.http.server;
    if (jarm) jarms.add(jarm);
    if (favHash != null) favicons.add(String(favHash));
    if (jarm || favHash != null || title || server) {
      rows.push(`<div class="modal-kv-grid" style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)">
        ${kv('Port', d.port ?? 'N/A')}
        ${jarm ? kv('JARM', jarm) : ''}
        ${favHash != null ? kv('Favicon Hash', favHash) : ''}
        ${title ? kv('HTTP Title', title) : ''}
        ${server ? kv('HTTP Server', server) : ''}
      </div>`);
    }
  });

  body.innerHTML = rows.length ? rows.join('') : `<div class="intel-na">No JARM/favicon/HTTP fingerprints found.</div>`;
  if (meta) meta.textContent = `JARM:${jarms.size} · Favicon:${favicons.size}`;
}

/* ── Cloud · Hosting Provider ─────────────────────────────────────────────── */
function wordOverlap(a, b) {
  if (!a || !b) return false;
  const wa = String(a).toLowerCase().replace(/[^a-z0-9 ]/g, '').split(/\s+/).filter(w => w.length > 2);
  const wb = String(b).toLowerCase();
  return wa.some(w => wb.includes(w));
}

function renderCloudHosting(state, ip) {
  const body = document.getElementById('cloud-body');
  const meta = document.getElementById('cloud-meta');
  if (!body) return;

  const holder = state.asnHolder && state.asnHolder !== 'N/A' ? state.asnHolder : null;
  const asnMeta = state.asnMeta || 'N/A';
  const shodanOrg = state.hasShodan && state.shodanHost ? (state.shodanHost.org || state.shodanHost.isp) : null;
  const ipinfoOrg = state.ipinfoData ? state.ipinfoData.org : null;

  const rows = [
    kv('ASN', asnMeta),
    kv('RIPE Holder', holder || 'N/A'),
    kv('Shodan Org/ISP', shodanOrg || (state.hasShodan ? 'N/A' : 'No key configured')),
    kv('ipinfo.io Org', ipinfoOrg || 'N/A'),
  ];

  let matchNote = 'N/A';
  if (holder && (shodanOrg || ipinfoOrg)) {
    const matches = wordOverlap(holder, shodanOrg || '') || wordOverlap(holder, ipinfoOrg || '');
    matchNote = matches ? 'Consistent across sources' : 'Sources disagree, verify manually';
  }
  rows.push(kv('Cross-check', matchNote));

  let html = `<div class="modal-kv-grid">${rows.join('')}</div>`;
  if (!ip) html += `<div class="intel-na" style="margin-top:10px">No IP resolved, Shodan/ipinfo lookups skipped.</div>`;
  body.innerHTML = html;
  if (meta) meta.textContent = holder || shodanOrg || asnMeta;
}

/* ── CDN · WAF Detection ──────────────────────────────────────────────────── */
function renderCdnWaf(state) {
  const body = document.getElementById('cdnwaf-body');
  const meta = document.getElementById('cdnwaf-meta');
  if (!body) return;

  const hp = state.headerProbe;
  if (!hp) {
    body.innerHTML = `<div class="intel-na">Header probe failed or returned no data.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const verdicts = [];
  if (hp.cfRay) verdicts.push('Cloudflare');
  if (hp.xAmzCfId) verdicts.push('Amazon CloudFront');
  if (hp.akamai) verdicts.push('Akamai');
  if (hp.xSucuriId) verdicts.push('Sucuri');
  if (hp.xCdn) verdicts.push(hp.xCdn);
  if (!verdicts.length && hp.via) verdicts.push(`Possible: ${hp.via}`);
  if (!verdicts.length && hp.xCache) verdicts.push('Cache header present (unidentified CDN)');
  const verdictLine = verdicts.length ? verdicts.join(', ') : 'No CDN/WAF signature detected';

  const rows = [
    kv('Verdict', verdictLine),
    kv('Server', hp.server || 'N/A'),
    kv('Via', hp.via || 'N/A'),
    kv('X-Cache', hp.xCache || 'N/A'),
    kv('CF-Ray', hp.cfRay || 'N/A'),
    kv('X-Amz-Cf-Id', hp.xAmzCfId || 'N/A'),
    kv('Akamai', hp.akamai ? 'Detected' : 'Not detected'),
    kv('X-Sucuri-Id', hp.xSucuriId || 'N/A'),
    kv('HTTP Status', hp.status ?? 'N/A'),
  ];

  body.innerHTML = `<div class="modal-kv-grid">${rows.join('')}</div>`;
  if (meta) meta.textContent = verdictLine;
}

/* ── URLScan · Screenshot ─────────────────────────────────────────────────── */
function renderUrlscan(state) {
  const body = document.getElementById('urlscan-body');
  const meta = document.getElementById('urlscan-meta');
  if (!body) return;

  if (state.urlscanPolling) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Scan submitted, polling for result…</div>`;
    if (meta) meta.textContent = 'Scanning…';
    return;
  }

  const r = state.urlscanResult;
  if (!r) {
    if (state.urlscanSubmitFailed) {
      body.innerHTML = `<div class="intel-na">URLScan submission failed (check your API key).</div>`;
      if (meta) meta.textContent = 'Submit failed';
      return;
    }
    if (state.urlscanTimedOut) {
      body.innerHTML = `<div class="intel-na">Scan submitted but the result did not complete in time. Check URLScan.io directly.</div>`;
      if (meta) meta.textContent = 'Timed out';
      return;
    }
    if (state.urlscanNoKey) {
      body.innerHTML = `<div class="intel-na">No existing scan found and no URLScan key configured to submit a fresh one.</div>`;
      if (meta) meta.textContent = 'No key';
      return;
    }
    body.innerHTML = `<div class="intel-na">No URLScan data available.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const task = r.task || {};
  const page = r.page || {};
  const stats = r.stats || {};
  const uuid = task.uuid || state.urlscanUuid;
  const screenshot = r.screenshot || (uuid ? `https://urlscan.io/screenshots/${uuid}.png` : null);
  const reportUrl = uuid ? `https://urlscan.io/result/${uuid}/` : (task.url || '#');

  const rows = [
    kv('Server', page.server || 'N/A'),
    kv('Page IP', page.ip || 'N/A'),
    kv('ASN', page.asnname || page.asn || 'N/A'),
    kv('TLS Issuer', page.tlsIssuer || 'N/A'),
    kv('Requests', stats.requests ?? 'N/A'),
    kv('Unique IPs', stats.uniqIPs ?? 'N/A'),
  ];

  body.innerHTML = `
    ${screenshot ? `<img src="${escapeHtml(screenshot)}" alt="URLScan screenshot" style="max-width:100%;border:1px solid var(--border);border-radius:6px;margin-bottom:12px;">` : ''}
    <div class="modal-kv-grid">${rows.join('')}</div>
    <div class="intel-sub-label">FULL REPORT</div>
    <div class="modal-tags"><a class="modal-tag" href="${escapeHtml(reportUrl)}" target="_blank" rel="noopener" style="text-decoration:none">${escapeHtml(reportUrl)}</a></div>
    ${state.urlscanFresh ? '' : '<div class="intel-na" style="margin-top:8px">Showing an existing recent scan from URLScan.io.</div>'}
  `;
  if (meta) meta.textContent = state.urlscanFresh ? 'Fresh scan' : 'Existing scan';
}

/* ── Lookalike · Permutations ─────────────────────────────────────────────── */
function renderLookalike(state) {
  const body = document.getElementById('lookalike-body');
  const meta = document.getElementById('lookalike-meta');
  if (!body) return;

  if (state.type !== 'domain') {
    body.innerHTML = `<div class="intel-na">Not applicable for a raw IP target.</div>`;
    if (meta) meta.textContent = 'N/A';
    return;
  }

  const results = Array.isArray(state.lookalikeResults) ? state.lookalikeResults : [];
  if (!results.length) {
    body.innerHTML = `<div class="intel-na">No live lookalike/permutation domains found.</div>`;
    if (meta) meta.textContent = '0 found';
    return;
  }

  const chips = results.map(r => `<span class="modal-tag">${escapeHtml(r.domain)} → ${escapeHtml(r.ip)}</span>`).join('');
  body.innerHTML = `<div class="modal-tags">${chips}</div><div class="intel-na" style="margin-top:10px">These are live-resolving lookalike domains, not proof of malicious intent.</div>`;
  if (meta) meta.textContent = `${results.length} live`;
}
