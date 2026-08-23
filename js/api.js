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
