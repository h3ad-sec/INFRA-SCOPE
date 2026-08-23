export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { target } = req.query;
  if (!target) return res.status(400).json({ error: 'Missing target parameter' });

  /* Always route through the WHATWG URL parser before inspecting the host,
     even for a bare hostname input (wrapped as https://<target> first).
     Checking the raw query-param string directly is not safe: the URL host
     parser canonicalizes decimal/octal/hex IPv4 forms (e.g. the bare digit
     string "2130706433" parses to 127.0.0.1) and IPv6 shorthand, so a check
     against the un-parsed string can be bypassed by encoding a private IP
     in one of those alternate forms while still resolving to the real
     address once fetch() itself parses the URL. Parsing once up front and
     validating the canonical hostname closes that gap. */
  let parsedUrl;
  try {
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target) ? target : `https://${target}`;
    parsedUrl = new URL(candidate);
  } catch {
    return res.status(400).json({ error: 'Invalid target parameter' });
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return res.status(400).json({ error: 'Invalid target parameter' });
  }

  let hostname = parsedUrl.hostname.toLowerCase();

  /* Bare-hostname shape check: letters, digits, dots, hyphens only. Blocks
     anything that isn't a plain DNS name (IPv6 literals with brackets/
     colons included) now that the value has already been canonicalized
     above. */
  if (!/^[a-z0-9.-]+$/.test(hostname) || hostname.length > 253) {
    return res.status(400).json({ error: 'Invalid target parameter' });
  }

  /* SSRF guard: reject loopback / private / link-local / obviously-internal
     ranges before this server ever issues the outbound fetch, since this
     endpoint could otherwise be abused to probe Vercel's internal network
     from a public, unauthenticated relay. IPv6 literals (bracketed, e.g.
     "[::1]") are already rejected by the shape check above since they
     contain characters outside [a-z0-9.-], so no separate IPv6 pattern is
     needed here. */
  const privatePatterns = [
    /^localhost$/,
    /^127\./,
    /^0\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  ];
  if (privatePatterns.some(p => p.test(hostname))) {
    return res.status(400).json({ error: 'Target not allowed' });
  }

  const url = `https://${hostname}`;

  async function probe(method) {
    return fetch(url, { method, redirect: 'follow' });
  }

  try {
    let upstream;
    try {
      upstream = await probe('HEAD');
    } catch {
      upstream = await probe('GET');
    }

    const h = upstream.headers;
    const result = {
      status: upstream.status,
      finalUrl: upstream.url || url,
      server: h.get('server') || null,
      via: h.get('via') || null,
      'x-cache': h.get('x-cache') || null,
      'cf-ray': h.get('cf-ray') || null,
      'x-amz-cf-id': h.get('x-amz-cf-id') || null,
      'x-sucuri-id': h.get('x-sucuri-id') || null,
      'x-cdn': h.get('x-cdn') || null,
    };

    const akamaiHeaders = {};
    for (const [key, value] of h.entries()) {
      if (key.toLowerCase().startsWith('x-akamai-')) {
        akamaiHeaders[key.toLowerCase()] = value;
      }
    }
    result.akamaiHeaders = akamaiHeaders;

    return res.status(200).json(result);
  } catch (e) {
    return res.status(502).json({ error: 'Probe request failed', detail: e.message });
  }
}
