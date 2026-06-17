import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { GitBranch, Trash2, RefreshCw, Github, Gitlab as GitlabIcon, Plus } from 'lucide-react';
import type { Repository } from '../types';

export default function RepositoriesPage() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRepos();
  }, []);

  async function loadRepos() {
    try {
      const data = await api.repositories.list();
      setRepos(data);
    } catch (err) {
      console.error('Failed to load repos:', err);
    } finally {
      setLoading(false);
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Deactivate this repository?')) return;
    try {
      await api.repositories.delete(id);
      setRepos(prev => prev.filter(r => r.id !== id));
    } catch (err) {
      console.error('Failed to delete repo:', err);
    }
  };

  const handleInstallGithub = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/repositories/install-url`);
      const data = await res.json();
      if (data.url) window.open(data.url, '_blank');
    } catch {
      window.open('https://github.com/apps/securereview-ai/installations/new', '_blank');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Repositories</h1>
          <p className="text-gray-500 mt-1">Connected repositories for automated PR reviews</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={handleInstallGithub} className="btn-primary flex items-center gap-2">
            <Github className="w-4 h-4" /> Install GitHub App
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card border-dashed border-gray-700 flex flex-col items-center justify-center py-8 text-center hover:border-brand-500/50 cursor-pointer transition-colors" onClick={handleInstallGithub}>
          <Github className="w-10 h-10 text-gray-600 mb-3" />
          <h3 className="font-medium text-gray-400">Add GitHub Repo</h3>
          <p className="text-xs text-gray-600 mt-1">Install the SecureReview GitHub App</p>
        </div>

        <div className="card border-dashed border-gray-700 flex flex-col items-center justify-center py-8 text-center opacity-50">
          <GitlabIcon className="w-10 h-10 text-gray-600 mb-3" />
          <h3 className="font-medium text-gray-400">GitLab (Coming Soon)</h3>
          <p className="text-xs text-gray-600 mt-1">Self-hosted GitLab support</p>
        </div>

        <div className="card border-dashed border-gray-700 flex flex-col items-center justify-center py-8 text-center opacity-50">
          <GitBranch className="w-10 h-10 text-gray-600 mb-3" />
          <h3 className="font-medium text-gray-400">Azure DevOps (Coming Soon)</h3>
          <p className="text-xs text-gray-600 mt-1">Enterprise repository support</p>
        </div>
      </div>

      {repos.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold text-white">Connected Repositories</h2>
          {repos.map((repo) => (
            <div key={repo.id} className="card">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gray-800 rounded-lg">
                    {repo.git_provider === 'github' ? <Github className="w-5 h-5 text-gray-400" /> : <GitlabIcon className="w-5 h-5 text-gray-400" />}
                  </div>
                  <div>
                    <h3 className="font-medium text-white">{repo.full_name}</h3>
                    <p className="text-xs text-gray-500">
                      {repo.git_provider} · {repo.default_branch} branch
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${repo.is_active ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                    {repo.is_active ? 'Active' : 'Inactive'}
                  </span>
                  <button onClick={() => handleDelete(repo.id)} className="text-gray-500 hover:text-red-400">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {repos.length === 0 && !loading && (
        <div className="card text-center py-12">
          <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400">No repositories connected</h3>
          <p className="text-gray-600 text-sm mt-1">Install the GitHub App to start analyzing PRs</p>
        </div>
      )}
    </div>
  );
}
