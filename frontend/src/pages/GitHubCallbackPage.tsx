import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, setAccessToken, setRefreshToken } from '../services/api';
import { Shield } from 'lucide-react';

export default function GitHubCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      setError('No authorization code received from GitHub.');
      return;
    }

    api.auth.githubLogin(code)
      .then((data) => {
        const remember = localStorage.getItem('remember_me') !== 'false';
        setAccessToken(data.access_token, remember);
        setRefreshToken(data.refresh_token, remember);
        navigate('/dashboard', { replace: true });
      })
      .catch((err) => {
        setError(err.detail || 'GitHub login failed. Please try again.');
      });
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-brand-600 rounded-2xl mb-4">
          <Shield className="w-10 h-10 text-white" />
        </div>
        <h1 className="text-3xl font-bold text-white mb-4">SecureReview AI</h1>
        {error ? (
          <div>
            <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">
              {error}
            </div>
            <button
              onClick={() => navigate('/login')}
              className="text-brand-400 hover:text-brand-300"
            >
              Back to login
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
            <p className="text-gray-500">Completing GitHub sign in...</p>
          </div>
        )}
      </div>
    </div>
  );
}
