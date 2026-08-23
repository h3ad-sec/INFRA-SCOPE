export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-user-key'];
  if (!apiKey) return res.status(400).json({ error: 'Missing API key. Add your own key in Settings.' });

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Missing or invalid JSON body' });
  }

  try {
    const upstream = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Auth-Key': apiKey,
      },
      body: JSON.stringify(body),
    });
    const data = await upstream.json().catch(() => null);

    /* Auth failures come back as HTTP 401 (missing/bad key) or, on some
       query types, HTTP 403 with query_status:'unknown_auth_key' (invalid
       key). Both must be passed through with their real status code and
       body, not coerced into a fake 200 empty-result response, otherwise
       "your key is invalid" is indistinguishable from "genuinely no data
       found" on the frontend. */
    if (data === null) {
      return res.status(upstream.status >= 400 ? upstream.status : 502).json({ error: 'Upstream request failed' });
    }
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
