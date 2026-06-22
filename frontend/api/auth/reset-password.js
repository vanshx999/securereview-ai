const BACKEND = 'https://securereview-ai-backend.onrender.com';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let body = '';
  for await (const chunk of req) body += chunk;
  let token = '', password = '';
  try {
    const parsed = JSON.parse(body);
    token = parsed.token || '';
    password = parsed.password || '';
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  try {
    const backendRes = await fetch(`${BACKEND}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password }),
    });
    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Backend unreachable' });
  }
}
