/* ══ INFRA-SCOPE: api.js, thin fetch wrappers, no key, no relay ════════════
   Every function returns parsed data, or a documented "no data" marker
   (null / [] / undefined depending on the function) on any failure.
   None of these throw past their own boundary. */

async function fetchRDAP(target, type, signal) {
  try {
    const url = type === 'ip'
      ? `https://rdap.org/ip/${encodeURIComponent(target)}`
      : `https://rdap.org/domain/${encodeURIComponent(target)}`;
    const res = await fetch(url, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

async function fetchDoH(name, type, signal) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

async function fetchRIPENetworkInfo(ip, signal) {
  try {
    const res = await fetch(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

async function fetchRIPEASOverview(asn, signal) {
  try {
    const res = await fetch(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${encodeURIComponent(asn)}`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

async function fetchRIPEGeoloc(ip, signal) {
  try {
    const res = await fetch(`https://stat.ripe.net/data/geoloc/data.json?resource=${encodeURIComponent(ip)}`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* crt.sh is flaky (known to 502). Distinguish "down" (undefined) from
   "genuinely no certs" ([]) so the UI can show a different message. */
async function fetchCrtSh(domain, signal) {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { signal });
    if (!res.ok) return undefined;
    const text = await res.text();
    if (!text || !text.trim()) return [];
    try {
      return JSON.parse(text);
    } catch (_) {
      return undefined;
    }
  } catch (_) {
    return undefined;
  }
}

/* HackerTarget returns plain text: "hostname,ip" per line, or a one-line
   error string like "error check your search parameter". */
async function fetchHackerTargetHostSearch(domain, signal) {
  try {
    const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { signal });
    if (!res.ok) return [];
    const text = await res.text();
    if (!text || /error/i.test(text)) return [];
    return text
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean)
      .map(line => {
        const idx = line.indexOf(',');
        if (idx === -1) return { hostname: line, ip: '' };
        return { hostname: line.slice(0, idx).trim(), ip: line.slice(idx + 1).trim() };
      })
      .filter(x => x.hostname);
  } catch (_) {
    return [];
  }
}

/* ══ Phase 2: BYOK / relay-backed sources for the 9 previously-stubbed panels ══
   All functions below take the caller's key (already resolved via getKey())
   as an explicit argument rather than reading localStorage themselves, so
   the "no key configured" decision stays in scanner.js/ui.js where the
   per-source UI state is rendered. Same failure convention as above: never
   throw past the function boundary. */

/* VirusTotal via the same-origin relay (api/vt.js). path is e.g.
   "domains/example.com" or "ip_addresses/1.2.3.4/resolutions". */
async function fetchVT(path, key, signal) {
  try {
    const res = await fetch(`/api/vt?path=${encodeURIComponent(path)}`, {
      headers: { 'x-user-key': key },
      signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* ThreatFox via the same-origin relay (api/threatfox.js). */
async function fetchThreatFox(searchTerm, key, signal) {
  try {
    const res = await fetch('/api/threatfox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-user-key': key },
      body: JSON.stringify({ query: 'search_ioc', search_term: searchTerm }),
      signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* Header probe via the same-origin relay (api/headers.js), no key needed. */
async function fetchHeaderProbe(target, signal) {
  try {
    const res = await fetch(`/api/headers?target=${encodeURIComponent(target)}`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* Shodan host lookup, direct from the browser, IP only. */
async function fetchShodanHost(ip, key, signal) {
  try {
    const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* Censys v2 host lookup, direct from the browser, Basic auth of id:secret. */
async function fetchCensysHost(ip, censysKey, signal) {
  try {
    const res = await fetch(`https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`, {
      headers: { Authorization: 'Basic ' + btoa(`${censysKey.id}:${censysKey.secret}`) },
      signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* OTX general pulse info. type is 'domain' or 'IPv4'. */
async function fetchOTXGeneral(target, type, key, signal) {
  try {
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(target)}/general`, {
      headers: { 'X-OTX-API-KEY': key },
      signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* OTX passive DNS, same target/type convention as fetchOTXGeneral. */
async function fetchOTXPassiveDNS(target, type, key, signal) {
  try {
    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(target)}/passive_dns`, {
      headers: { 'X-OTX-API-KEY': key },
      signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* ipinfo.io, key optional (higher rate limit with one). */
async function fetchIpinfo(ip, key, signal) {
  try {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json${key ? '?token=' + encodeURIComponent(key) : ''}`;
    const res = await fetch(url, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* Robtex forward passive DNS for a domain. NDJSON body: one JSON object
   per line, not a single JSON array. */
async function fetchRobtexPDNS(domain, signal) {
  try {
    const res = await fetch(`https://freeapi.robtex.com/pdns/forward/${encodeURIComponent(domain)}`, { signal });
    if (!res.ok) return [];
    const text = await res.text();
    if (!text || !text.trim()) return [];
    return text
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean)
      .map(l => {
        try { return JSON.parse(l); } catch (_) { return null; }
      })
      .filter(Boolean);
  } catch (_) {
    return [];
  }
}

/* HackerTarget reverseiplookup, same plain-text convention as hostsearch. */
async function fetchHackerTargetReverseIP(ip, signal) {
  try {
    const res = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, { signal });
    if (!res.ok) return [];
    const text = await res.text();
    if (!text || /error/i.test(text)) return [];
    return text.split('\n').map(l => l.trim()).filter(Boolean);
  } catch (_) {
    return [];
  }
}

/* URLScan: check for an existing recent scan first, no key required. */
async function fetchUrlscanSearch(target, signal) {
  try {
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=page.domain:%22${encodeURIComponent(target)}%22&size=5`, { signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/* URLScan: submit a fresh scan, needs a key. Returns {error:true, body} on
   a non-OK response (e.g. 401 with no key) so the caller can distinguish
   "bad/missing key" from "network failure" (null). */
async function submitUrlscan(target, key, signal) {
  try {
    const res = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: { 'API-Key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://' + target, visibility: 'public' }),
      signal,
    });
    const body = await res.json().catch(() => null);
    if (!res.ok) return { error: true, body };
    return body;
  } catch (_) {
    return null;
  }
}

/* URLScan: poll the result endpoint every ~3s (a fresh scan takes 10-20s),
   up to 8 attempts, until it stops 404ing. Returns null on timeout/abort. */
async function pollUrlscanResult(uuid, signal) {
  const url = `https://urlscan.io/api/v1/result/${encodeURIComponent(uuid)}/`;
  for (let i = 0; i < 8; i++) {
    if (signal && signal.aborted) return null;
    try {
      const res = await fetch(url, { signal });
      if (res.ok) return await res.json();
    } catch (_) {
      // keep polling, a 404 while the scan is still processing is expected
    }
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  return null;
}
