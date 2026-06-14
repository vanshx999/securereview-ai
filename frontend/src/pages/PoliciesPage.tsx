import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Plus, Edit, Trash2, ToggleLeft, ToggleRight, AlertTriangle } from 'lucide-react';
import type { Policy } from '../types';

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function load() {
      try {
        const data = await api.policies.list();
        setPolicies(data);
      } catch (err) {
        console.error('Failed to load policies:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleToggle = async (policy: Policy) => {
    try {
      await api.policies.update(policy.id, { is_active: !policy.is_active });
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, is_active: !p.is_active } : p));
    } catch (err) {
      console.error('Failed to toggle policy:', err);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return;
    try {
      await api.policies.delete(id);
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (err) {
      console.error('Failed to delete policy:', err);
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
          <h1 className="text-2xl font-bold text-white">Security Policies</h1>
          <p className="text-gray-500 mt-1">Write natural language rules to enforce security standards</p>
        </div>
        <button onClick={() => navigate('/policies/new')} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Policy
        </button>
      </div>

      {policies.length === 0 && (
        <div className="card text-center py-12">
          <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400">No policies yet</h3>
          <p className="text-gray-600 text-sm mt-1">Create your first security policy to start enforcing rules</p>
          <button onClick={() => navigate('/policies/new')} className="btn-primary mt-4">Create Policy</button>
        </div>
      )}

      <div className="space-y-3">
        {policies.map((policy) => (
          <div key={policy.id} className="card">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <h3 className="font-medium text-white">{policy.name}</h3>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    policy.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-400' :
                    policy.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-400' :
                    policy.severity === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-400' :
                    'bg-green-900/50 text-green-400'
                  }`}>{policy.severity}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${policy.is_active ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                    v{policy.version}
                  </span>
                </div>
                <p className="text-sm text-gray-500 mt-1 line-clamp-2">{policy.natural_language_rule}</p>
                {policy.target_file_patterns && policy.target_file_patterns.length > 0 && (
                  <div className="flex items-center gap-2 mt-2">
                    <span className="text-xs text-gray-600">Targets:</span>
                    {policy.target_file_patterns.map((pattern, i) => (
                      <span key={i} className="px-2 py-0.5 bg-gray-800 text-gray-400 rounded text-xs font-mono">{pattern}</span>
                    ))}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => handleToggle(policy)} className="text-gray-500 hover:text-gray-300">
                  {policy.is_active ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5" />}
                </button>
                <button onClick={() => navigate(`/policies/${policy.id}`)} className="text-gray-500 hover:text-brand-400">
                  <Edit className="w-4 h-4" />
                </button>
                <button onClick={() => handleDelete(policy.id)} className="text-gray-500 hover:text-red-400">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
