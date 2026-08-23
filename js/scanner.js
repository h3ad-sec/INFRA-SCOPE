/* ══ INFRA-SCOPE: scanner.js, orchestration for the 7 no-key panels ════════ */

let scanAborted = false;
let currentAbortController = null;

const SCAN_PANEL_IDS = ['overview-panel', 'whois-panel', 'livedns-panel', 'email-panel', 'asn-panel', 'certs-panel', 'subdomains-panel'];
const SCAN_LOADING_BODY_IDS = ['whois-body', 'livedns-body', 'email-body', 'asn-body', 'certs-body', 'subdomains-body'];
const SCAN_TOTAL_STEPS = 7;
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'dkim', 'mail', 'smtp'];

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

      await Promise.all([asnPromise, rdapPromise, dnsPromise, emailPromise, certsPromise, subdomainsPromise]);
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

      await Promise.all([rdapPromise, asnPromise, dnsPromise]);
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
