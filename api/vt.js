export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-user-key'];
  if (!apiKey) return res.status(400).json({ error: 'Missing API key. Add your own key in Settings.' });

  const { path } = req.query;
  if (!path) return res.status(400).json({ error: 'Missing path parameter' });

  const decodedPath = decodeURIComponent(path);
  /* Relative-path allowlist only: no scheme prefix (blocks redirecting the
     relay at an arbitrary host), no traversal, and must start with one of
     the VT sub-resources this tool actually queries (domain/IP lookups and
     their passive-DNS resolutions). Anything else is rejected so this can't
     become an open relay to arbitrary VT (or non-VT) URLs. */
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(decodedPath) || decodedPath.includes('..')) {
    return res.status(400).json({ error: 'Invalid path parameter' });
  }
  const allowed = ['domains/', 'ip_addresses/'];
  if (!allowed.some(p => decodedPath.startsWith(p))) {
    return res.status(400).json({ error: 'Endpoint not allowed' });
  }

  try {
    const upstream = await fetch(`https://www.virustotal.com/api/v3/${decodedPath}`, {
      headers: { 'x-apikey': apiKey },
    });
    const data = await upstream.json().catch(() => null);
    if (data === null) {
      return res.status(upstream.status >= 400 ? upstream.status : 502).json({ error: 'Upstream request failed' });
    }
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
