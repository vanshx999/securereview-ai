const BACKEND = 'https://securereview-ai-backend.onrender.com';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }
  try {
    const backendRes = await fetch(`${BACKEND}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: req.body.email }),
    });
    const data = await backendRes.json();
    return res.status(backendRes.status).json(data);
  } catch (err) {
    return res.status(502).json({ detail: 'Backend unreachable' });
  }
}
