import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { ArrowLeft, Save, Code2, Loader2 } from 'lucide-react';
import type { Policy } from '../types';
import Editor from '@monaco-editor/react';

export default function PolicyEditorPage() {
  const { id } = useParams<{ id: string }>();
  const isEditing = !!id;
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [rule, setRule] = useState('');
  const [severity, setSeverity] = useState('HIGH');
  const [filePatterns, setFilePatterns] = useState('');
  const [compiledRule, setCompiledRule] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [compiling, setCompiling] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isEditing) {
      api.policies.get(id!).then(policy => {
        setName(policy.name);
        setDescription(policy.description || '');
        setRule(policy.natural_language_rule);
        setSeverity(policy.severity);
        setFilePatterns((policy.target_file_patterns || []).join(', '));
        setCompiledRule(policy.compiled_rule);
      }).catch(() => navigate('/policies'));
    }
  }, [id]);

  const handleCompile = async () => {
    if (!rule.trim()) return;
    setCompiling(true);
    try {
      const result = await api.policies.compile(id!);
      setCompiledRule(result.compiled_rule);
    } catch (err) {
      // If new policy, just show a mock compiled rule
      setCompiledRule({
        type: 'regex_pattern',
        pattern: '',
        file_patterns: filePatterns.split(',').map(f => f.trim()).filter(Boolean),
        severity: severity,
        description: `Rule: ${rule.substring(0, 100)}...`,
      });
    } finally {
      setCompiling(false);
    }
  };

  const handleSave = async () => {
    if (!name.trim() || !rule.trim()) {
      setError('Name and rule are required');
      return;
    }
    setSaving(true);
    setError('');

    const data = {
      name,
      description,
      natural_language_rule: rule,
      severity,
      target_file_patterns: filePatterns.split(',').map(f => f.trim()).filter(Boolean),
    };

    try {
      if (isEditing) {
        await api.policies.update(id!, data);
      } else {
        await api.policies.create(data);
      }
      navigate('/policies');
    } catch (err: any) {
      setError(err.detail || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <button onClick={() => navigate('/policies')} className="flex items-center gap-2 text-gray-500 hover:text-gray-300 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to Policies
      </button>

      <div className="card">
        <h1 className="text-2xl font-bold text-white mb-6">{isEditing ? 'Edit Policy' : 'Create Security Policy'}</h1>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">{error}</div>
        )}

        <div className="space-y-4">
          <div>
            <label className="label">Policy Name</label>
            <input type="text" className="input" placeholder="e.g., PII Data Protection" value={name} onChange={(e) => setName(e.target.value)} />
          </div>

          <div>
            <label className="label">Description</label>
            <textarea className="input" rows={2} placeholder="Brief description of what this policy enforces" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>

          <div>
            <label className="label">Natural Language Rule</label>
            <textarea
              className="input font-mono text-sm"
              rows={6}
              placeholder='Write your security policy in plain English...&#10;&#10;Example: "Flag any function handling PII that calls logger.info() or logger.error() without first calling approved_anonymize()"'
              value={rule}
              onChange={(e) => setRule(e.target.value)}
            />
            <p className="text-xs text-gray-600 mt-1">The AI will compile this into an enforceable check</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">Default Severity</label>
              <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
            <div>
              <label className="label">File Patterns (comma-separated)</label>
              <input type="text" className="input font-mono text-sm" placeholder="*.py, src/**/*.ts, *.java" value={filePatterns} onChange={(e) => setFilePatterns(e.target.value)} />
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button onClick={handleSave} className="btn-primary flex items-center gap-2" disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              {saving ? 'Saving...' : 'Save Policy'}
            </button>
            {isEditing && (
              <button onClick={handleCompile} className="btn-secondary flex items-center gap-2" disabled={compiling}>
                {compiling ? <Loader2 className="w-4 h-4 animate-spin" /> : <Code2 className="w-4 h-4" />}
                Re-compile Rule
              </button>
            )}
          </div>
        </div>
      </div>

      {compiledRule && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-3">Compiled Rule (Preview)</h3>
          <pre className="bg-gray-950 rounded-lg p-4 text-sm font-mono text-gray-300 overflow-x-auto border border-gray-800">
            <code>{JSON.stringify(compiledRule, null, 2)}</code>
          </pre>
        </div>
      )}
    </div>
  );
}
