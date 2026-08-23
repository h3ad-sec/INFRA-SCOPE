/* ══ INFRA-SCOPE: scanner.js, orchestration for the 7 no-key panels ════════ */

let scanAborted = false;
let currentAbortController = null;

const SCAN_PANEL_IDS = [
  'overview-panel', 'whois-panel', 'livedns-panel', 'email-panel', 'asn-panel', 'certs-panel', 'subdomains-panel',
  'ti-panel', 'pdns-panel', 'cohosted-panel', 'ports-panel', 'fp-panel', 'cloud-panel', 'cdnwaf-panel', 'urlscan-panel', 'lookalike-panel',
];
const SCAN_LOADING_BODY_IDS = [
  'whois-body', 'livedns-body', 'email-body', 'asn-body', 'certs-body', 'subdomains-body',
  'ti-body', 'pdns-body', 'cohosted-body', 'ports-body', 'fp-body', 'cloud-body', 'cdnwaf-body', 'urlscan-body', 'lookalike-body',
];
const SCAN_TOTAL_STEPS = 16;
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'dkim', 'mail', 'smtp'];
const HOMOGLYPH_MAP = { o: '0', l: '1', i: '1', e: '3', s: '5', a: '4' };
const LOOKALIKE_TLD_SWAP_SET = ['com', 'net', 'org', 'co', 'io'];
const LOOKALIKE_CAP = 70;
const LOOKALIKE_BATCH = 8;

function ipv4ToPtrName(ip) {
  if (!ip || ip.indexOf(':') !== -1) return null; // IPv6, unsupported here
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return parts.slice().reverse().join('.') + '.in-addr.arpa';
}

function revealScanPanels() {
  SCAN_PANEL_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  });
  SCAN_LOADING_BODY_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<div class="loading-row"><div class="spinner"></div>Scanning…</div>`;
  });
}

function setScanProgress(done, total, label) {
  const stats = document.getElementById('progressStats');
  const fill = document.getElementById('progressFill');
  const sub = document.getElementById('progressSub');
  if (stats) stats.textContent = `${done}/${total}`;
  if (fill) fill.style.width = `${Math.min(100, (done / total) * 100)}%`;
  if (sub) sub.textContent = label || '';
}

function stopScanEngine() {
  scanAborted = true;
  if (currentAbortController) currentAbortController.abort();
}

async function runScan(target, type) {
  scanAborted = false;
  currentAbortController = new AbortController();
  const signal = currentAbortController.signal;

  const progressPanel = document.getElementById('progressPanel');
  const progressLabel = document.getElementById('progressLabel');
  if (progressPanel) progressPanel.style.display = '';
  if (progressLabel) progressLabel.textContent = 'MAPPING…';
  setScanProgress(0, SCAN_TOTAL_STEPS, 'Starting scan…');

  revealScanPanels();

  const state = {
    target, type,
    a: [], aaaa: [],
    rdap: null,
    networkInfo: null, asOverview: null, geoloc: null,
    mx: null, txt: null, ns: null, caa: null, soa: null, cname: null,
    dmarc: null, dkim: [],
    crt: undefined, hackertarget: [], subdomains: [],
    ptr: null, ptrUnsupported: false,
    // Phase 2 fields, populated by runNewPanels().
    hasVT: false, hasShodan: false, hasOTX: false, hasThreatFox: false, hasUrlscanKey: false, hasCensys: false,
    resolvedIp: null,
    vtGeneral: undefined, vtResolutions: undefined, otxGeneral: undefined, otxPdns: undefined, threatfox: undefined,
    shodanHost: undefined, censysHost: undefined, ipinfoData: undefined, robtexPdns: [], hackertargetReverse: [],
    headerProbe: null,
    urlscanResult: null, urlscanFresh: false, urlscanPolling: false, urlscanNoKey: false,
    urlscanSubmitFailed: false, urlscanTimedOut: false, urlscanUuid: null,
    lookalikeResults: [],
  };

  let stepsDone = 0;
  function stepDone(label) {
    stepsDone++;
    setScanProgress(stepsDone, SCAN_TOTAL_STEPS, label);
  }

  try {
    if (type === 'domain') {
      const [aRes, aaaaRes] = await Promise.all([
        fetchDoH(target, 'A', signal),
        fetchDoH(target, 'AAAA', signal),
      ]);
      state.a = dohList(aRes, 1);
      state.aaaa = dohList(aaaaRes, 28);
      const resolvedIp = state.a.length ? state.a[0] : null;

      const asnPromise = (async () => {
        if (!state.a.length) {
          state.asnStatus = 'no-a-record';
          if (!scanAborted) { renderASN(state); stepDone('ASN · Network'); }
          return;
        }
        const ip = state.a[0];
        const net = await fetchRIPENetworkInfo(ip, signal);
        if (scanAborted) return;
        state.networkInfo = net;
        const asns = net && net.data && Array.isArray(net.data.asns) ? net.data.asns : [];
        if (asns.length) {
          const [overview, geoloc] = await Promise.all([
            fetchRIPEASOverview(asns[0], signal),
            fetchRIPEGeoloc(ip, signal),
          ]);
          if (scanAborted) return;
          state.asOverview = overview;
          state.geoloc = geoloc;
        }
        if (scanAborted) return;
        renderASN(state);
        stepDone('ASN · Network');
      })();

      const rdapPromise = fetchRDAP(target, 'domain', signal).then(r => {
        if (scanAborted) return;
        state.rdap = r;
        renderWhois(state);
        stepDone('WHOIS · RDAP');
      });

      const dnsPromise = Promise.all([
        fetchDoH(target, 'MX', signal),
        fetchDoH(target, 'TXT', signal),
        fetchDoH(target, 'NS', signal),
        fetchDoH(target, 'CAA', signal),
        fetchDoH(target, 'SOA', signal),
        fetchDoH(target, 'CNAME', signal),
      ]).then(([mx, txt, ns, caa, soa, cname]) => {
        if (scanAborted) return;
        state.mx = mx; state.txt = txt; state.ns = ns; state.caa = caa; state.soa = soa; state.cname = cname;
        renderLiveDNS(state);
        stepDone('Live DNS Records');
      });

      const emailPromise = dnsPromise.then(async () => {
        if (scanAborted) return;
        const [dmarc, ...dkimResults] = await Promise.all([
          fetchDoH('_dmarc.' + target, 'TXT', signal),
          ...DKIM_SELECTORS.map(sel => fetchDoH(`${sel}._domainkey.${target}`, 'TXT', signal)),
        ]);
        if (scanAborted) return;
        state.dmarc = dmarc;
        state.dkim = DKIM_SELECTORS
          .map((sel, i) => ({ selector: sel, result: dkimResults[i] }))
          .filter(x => x.result && Array.isArray(x.result.Answer) && x.result.Answer.length);
        renderEmail(state);
        stepDone('Email Infrastructure');
      });

      const certsPromise = fetchCrtSh(target, signal).then(crt => {
        if (scanAborted) return;
        state.crt = crt;
        renderCerts(state);
        stepDone('Certificates · CT Logs');
      });

      const htPromise = fetchHackerTargetHostSearch(target, signal).then(ht => {
        if (scanAborted) return;
        state.hackertarget = ht;
      });

      const subdomainsPromise = Promise.all([certsPromise, htPromise]).then(() => {
        if (scanAborted) return;
        const set = new Set();
        if (Array.isArray(state.crt)) {
          state.crt.forEach(c => {
            if (c && c.name_value) {
              c.name_value.split('\n').forEach(n => {
                n = n.trim().replace(/^\*\./, '');
                if (n) set.add(n.toLowerCase());
              });
            }
          });
        }
        (state.hackertarget || []).forEach(h => { if (h.hostname) set.add(h.hostname.toLowerCase()); });
        state.subdomains = Array.from(set).sort();
        renderSubdomains(state);
        stepDone('Subdomains');
      });

      const newPanelsPromise = runNewPanels(state, resolvedIp, asnPromise, signal, stepDone);

      await Promise.all([asnPromise, rdapPromise, dnsPromise, emailPromise, certsPromise, subdomainsPromise, newPanelsPromise]);
    } else {
      // type === 'ip'
      const rdapPromise = fetchRDAP(target, 'ip', signal).then(r => {
        if (scanAborted) return;
        state.rdap = r;
        renderWhois(state);
        stepDone('WHOIS · RDAP');
      });

      const asnPromise = (async () => {
        const net = await fetchRIPENetworkInfo(target, signal);
        if (scanAborted) return;
        state.networkInfo = net;
        const asns = net && net.data && Array.isArray(net.data.asns) ? net.data.asns : [];
        if (asns.length) {
          const [overview, geoloc] = await Promise.all([
            fetchRIPEASOverview(asns[0], signal),
            fetchRIPEGeoloc(target, signal),
          ]);
          if (scanAborted) return;
          state.asOverview = overview;
          state.geoloc = geoloc;
        }
        if (scanAborted) return;
        renderASN(state);
        stepDone('ASN · Network');
      })();

      const dnsPromise = (async () => {
        const ptrName = ipv4ToPtrName(target);
        if (!ptrName) {
          state.ptrUnsupported = true;
        } else {
          state.ptr = await fetchDoH(ptrName, 'PTR', signal);
        }
        if (scanAborted) return;
        renderLiveDNS(state);
        stepDone('Live DNS Records');
      })();

      // Not meaningful for a raw IP target, render the not-applicable state now.
      renderEmail(state); stepDone('Email Infrastructure');
      renderCerts(state); stepDone('Certificates · CT Logs');
      renderSubdomains(state); stepDone('Subdomains');

      const newPanelsPromise = runNewPanels(state, target, asnPromise, signal, stepDone);

      await Promise.all([rdapPromise, asnPromise, dnsPromise, newPanelsPromise]);
    }

    if (!scanAborted) {
      renderOverview(state);
      stepDone('Overview');
    }
  } catch (_) {
    // swallow: aborts and unexpected errors both leave whatever already rendered
  }

  // Let the 100% state be visible briefly before collapsing the progress bar.
  await new Promise(resolve => setTimeout(resolve, 500));
  if (progressPanel) progressPanel.style.display = 'none';
  const scanBtn = document.getElementById('scanBtn');
  const stopBtn = document.getElementById('stopBtn');
  if (scanBtn) scanBtn.disabled = false;
  if (stopBtn) stopBtn.style.display = 'none';

  return state;
}

function dohList(res, wantType) {
  if (!res || !Array.isArray(res.Answer)) return [];
  return res.Answer.filter(a => a.type === wantType).map(a => a.data);
}

/* ══ Phase 2: the 9 BYOK/relay panels ═══════════════════════════════════════
   ip is the already-resolved IP to use for IP-keyed sources (Shodan, Censys,
   ipinfo, HackerTarget reverseiplookup): for a domain target this is the
   first A record from the free DNS step, for an IP target it's the target
   itself. asnPromise is awaited before rendering the Cloud panel so it can
   read the same RIPE holder data the free ASN panel already fetched, no
   second RIPE fetch. */
async function runNewPanels(state, ip, asnPromise, signal, stepDone) {
  const hasVT = !!getKey('vt');
  const hasShodan = !!getKey('shodan');
  const hasOTX = !!getKey('otx');
  const hasThreatFox = !!getKey('threatfox');
  const hasUrlscanKey = !!getKey('urlscan');
  const censysKey = getKey('censys');
  const hasCensys = !!censysKey;

  state.hasVT = hasVT;
  state.hasShodan = hasShodan;
  state.hasOTX = hasOTX;
  state.hasThreatFox = hasThreatFox;
  state.hasUrlscanKey = hasUrlscanKey;
  state.hasCensys = hasCensys;
  state.resolvedIp = ip;

  const otxType = state.type === 'ip' ? 'IPv4' : 'domain';
  const vtPathBase = state.type === 'ip' ? `ip_addresses/${state.target}` : `domains/${state.target}`;
  const vtResPath = state.type === 'ip' ? `ip_addresses/${state.target}/resolutions` : `domains/${state.target}/resolutions`;

  const tiPromise = (async () => {
    const [vt, otx, tf] = await Promise.all([
      hasVT ? fetchVT(vtPathBase, getKey('vt'), signal) : Promise.resolve(undefined),
      hasOTX ? fetchOTXGeneral(state.target, otxType, getKey('otx'), signal) : Promise.resolve(undefined),
      hasThreatFox ? fetchThreatFox(state.target, getKey('threatfox'), signal) : Promise.resolve(undefined),
    ]);
    if (scanAborted) return;
    state.vtGeneral = vt;
    state.otxGeneral = otx;
    state.threatfox = tf;
    renderThreatIntel(state);
    stepDone('Threat Intelligence');
  })();

  const pdnsPromise = (async () => {
    const [vtRes, otxPdns, robtex] = await Promise.all([
      hasVT ? fetchVT(vtResPath, getKey('vt'), signal) : Promise.resolve(undefined),
      hasOTX ? fetchOTXPassiveDNS(state.target, otxType, getKey('otx'), signal) : Promise.resolve(undefined),
      state.type === 'domain' ? fetchRobtexPDNS(state.target, signal) : Promise.resolve([]),
    ]);
    if (scanAborted) return;
    state.vtResolutions = vtRes;
    state.otxPdns = otxPdns;
    state.robtexPdns = robtex;
    renderPassiveDNS(state);
    stepDone('Passive DNS');
  })();

  // Shared Shodan host lookup, one fetch feeding Co-hosted/Ports/Fingerprints/Cloud.
  const shodanPromise = (async () => {
    if (!ip || !hasShodan) return;
    state.shodanHost = await fetchShodanHost(ip, getKey('shodan'), signal);
  })();

  const censysPromise = (async () => {
    if (!ip || !hasCensys) return;
    state.censysHost = await fetchCensysHost(ip, censysKey, signal);
  })();

  const ipinfoPromise = (async () => {
    if (!ip) return;
    state.ipinfoData = await fetchIpinfo(ip, getKey('ipinfo'), signal);
  })();

  const cohostedPromise = (async () => {
    const [ht] = await Promise.all([
      ip ? fetchHackerTargetReverseIP(ip, signal) : Promise.resolve([]),
      shodanPromise,
    ]);
    if (scanAborted) return;
    state.hackertargetReverse = ht;
    renderCohosted(state, ip);
    stepDone('Co-hosted Infra');
  })();

  const portsPromise = shodanPromise.then(() => {
    if (scanAborted) return;
    renderPorts(state, ip);
    stepDone('Ports · Services');
  });

  const fpPromise = shodanPromise.then(() => {
    if (scanAborted) return;
    renderFingerprints(state, ip);
    stepDone('Fingerprints · JARM · Favicon');
  });

  const cloudPromise = (async () => {
    await Promise.all([shodanPromise, censysPromise, ipinfoPromise, asnPromise]);
    if (scanAborted) return;
    renderCloudHosting(state, ip);
    stepDone('Cloud · Hosting Provider');
  })();

  const cdnwafPromise = (async () => {
    state.headerProbe = await fetchHeaderProbe(state.target, signal);
    if (scanAborted) return;
    renderCdnWaf(state);
    stepDone('CDN · WAF Detection');
  })();

  const urlscanPromise = (async () => {
    const search = await fetchUrlscanSearch(state.target, signal);
    if (scanAborted) return;
    const existing = search && Array.isArray(search.results) && search.results.length ? search.results[0] : null;

    if (existing) {
      state.urlscanResult = existing;
      state.urlscanFresh = false;
      renderUrlscan(state);
      stepDone('URLScan · Screenshot');
      return;
    }
    if (!hasUrlscanKey) {
      state.urlscanNoKey = true;
      renderUrlscan(state);
      stepDone('URLScan · Screenshot');
      return;
    }

    state.urlscanPolling = true;
    renderUrlscan(state);
    const submit = await submitUrlscan(state.target, getKey('urlscan'), signal);
    if (scanAborted) return;
    if (!submit || submit.error || !submit.uuid) {
      state.urlscanPolling = false;
      state.urlscanSubmitFailed = true;
      renderUrlscan(state);
      stepDone('URLScan · Screenshot');
      return;
    }
    state.urlscanUuid = submit.uuid;
    const result = await pollUrlscanResult(submit.uuid, signal);
    if (scanAborted) return;
    state.urlscanPolling = false;
    if (result) {
      state.urlscanResult = result;
      state.urlscanFresh = true;
    } else {
      state.urlscanTimedOut = true;
    }
    renderUrlscan(state);
    stepDone('URLScan · Screenshot');
  })();

  const lookalikePromise = (async () => {
    if (state.type !== 'domain') {
      renderLookalike(state);
      stepDone('Lookalike · Permutations');
      return;
    }
    const candidates = generateLookalikeCandidates(state.target);
    const resolved = await checkLookalikeCandidates(candidates, signal);
    if (scanAborted) return;
    state.lookalikeResults = resolved;
    renderLookalike(state);
    stepDone('Lookalike · Permutations');
  })();

  await Promise.all([
    tiPromise, pdnsPromise, cohostedPromise, portsPromise, fpPromise,
    cloudPromise, cdnwafPromise, urlscanPromise, lookalikePromise,
  ]);
}

/* ── Lookalike / permutation generation, pure client-side, no key/relay ─────
   Splits the target into label + rest (e.g. "cloudflare" + ".com") and
   generates candidates via a handful of cheap typosquat strategies, capped
   and sampled down to stay responsive since every candidate costs a DoH
   round-trip. */
function splitRegistrableDomain(target) {
  const idx = target.indexOf('.');
  if (idx === -1) return { label: target, rest: '' };
  return { label: target.slice(0, idx), rest: target.slice(idx) };
}

function generateLookalikeCandidates(target) {
  const { label, rest } = splitRegistrableDomain(target);
  if (!label || !rest) return [];
  const candidates = new Set();

  for (let i = 0; i < label.length; i++) {
    candidates.add(label.slice(0, i) + label.slice(i + 1) + rest);
  }
  for (let i = 0; i < label.length; i++) {
    candidates.add(label.slice(0, i + 1) + label[i] + label.slice(i + 1) + rest);
  }
  for (let i = 0; i < label.length - 1; i++) {
    const chars = label.split('');
    const tmp = chars[i]; chars[i] = chars[i + 1]; chars[i + 1] = tmp;
    candidates.add(chars.join('') + rest);
  }
  for (let i = 0; i < label.length; i++) {
    const sub = HOMOGLYPH_MAP[label[i]];
    if (sub) candidates.add(label.slice(0, i) + sub + label.slice(i + 1) + rest);
  }
  for (let i = 1; i < label.length; i++) {
    candidates.add(label.slice(0, i) + '-' + label.slice(i) + rest);
  }
  const restBare = rest.replace(/^\./, '');
  if (LOOKALIKE_TLD_SWAP_SET.includes(restBare)) {
    LOOKALIKE_TLD_SWAP_SET.forEach(tld => {
      if (tld !== restBare) candidates.add(label + '.' + tld);
    });
  }

  candidates.delete(target);
  let list = Array.from(candidates);
  if (list.length > LOOKALIKE_CAP) {
    for (let i = list.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      const tmp = list[i]; list[i] = list[j]; list[j] = tmp;
    }
    list = list.slice(0, LOOKALIKE_CAP);
  }
  return list;
}

async function checkLookalikeCandidates(candidates, signal) {
  const results = [];
  for (let i = 0; i < candidates.length; i += LOOKALIKE_BATCH) {
    if (scanAborted) break;
    const batch = candidates.slice(i, i + LOOKALIKE_BATCH);
    const batchResults = await Promise.all(batch.map(async name => {
      const res = await fetchDoH(name, 'A', signal);
      if (res && Array.isArray(res.Answer) && res.Answer.length) {
        const aRecord = res.Answer.find(a => a.type === 1) || res.Answer[0];
        return { domain: name, ip: aRecord.data };
      }
      return null;
    }));
    batchResults.forEach(r => { if (r) results.push(r); });
  }
  return results;
}
