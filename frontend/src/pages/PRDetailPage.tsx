import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../services/api';
import { ArrowLeft, ChevronDown, ChevronRight, X } from 'lucide-react';
import type { PullRequest, Finding } from '../types';
import { useNavigate } from 'react-router-dom';

const severityColors: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-900/30 border-red-800',
  HIGH: 'text-orange-400 bg-orange-900/30 border-orange-800',
  MEDIUM: 'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  LOW: 'text-green-400 bg-green-900/30 border-green-800',
};

function SeverityIcon({ severity }: { severity: string }) {
  const icons: Record<string, string> = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
  return <span>{icons[severity] || '⚪'}</span>;
}

export default function PRDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [pr, setPr] = useState<PullRequest | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [dismissReason, setDismissReason] = useState('');
  const [dismissModal, setDismissModal] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function load() {
      try {
        const [prData, findingsData] = await Promise.all([
          api.prs.get(id!),
          api.prs.findings(id!),
        ]);
        setPr(prData);
        setFindings(findingsData);
      } catch (err) {
        console.error('Failed to load PR:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  const handleDismiss = async (findingId: string) => {
    try {
      await api.prs.updateFinding(pr!.id, findingId, { status: 'dismissed', dismissed_reason: dismissReason });
      setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: 'dismissed', dismissed_reason: dismissReason } : f));
      setDismissModal(null);
      setDismissReason('');
    } catch (err) {
      console.error('Failed to dismiss finding:', err);
    }
  };

  const handleFix = async (findingId: string) => {
    try {
      await api.prs.updateFinding(pr!.id, findingId, { status: 'fixed' });
      setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: 'fixed' } : f));
    } catch (err) {
      console.error('Failed to fix finding:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
      </div>
    );
  }

  if (!pr) {
    return <div className="text-gray-500">PR not found</div>;
  }

  const severityCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => { if (f.severity in severityCount) severityCount[f.severity as keyof typeof severityCount]++; });

  return (
    <div className="space-y-6">
      <button onClick={() => navigate('/dashboard')} className="flex items-center gap-2 text-gray-500 hover:text-gray-300 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to Dashboard
      </button>

      <div className="card">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">
              PR #{pr.pr_number}: {pr.title || 'Untitled'}
            </h1>
            <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
              <span>Branch: <code className="text-gray-300">{pr.branch}</code></span>
              <span>Base: <code className="text-gray-300">{pr.base_branch}</code></span>
              <span>Author: {pr.author || 'Unknown'}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
              pr.health_score >= 80 ? 'bg-green-900/30 text-green-400' :
              pr.health_score >= 50 ? 'bg-yellow-900/30 text-yellow-400' :
              'bg-red-900/30 text-red-400'
            }`}>
              Score: {pr.health_score}/100
            </span>
            {pr.ai_code_percentage > 0 && (
              <span className="px-3 py-1 bg-blue-900/30 text-blue-400 rounded-full text-sm font-medium">
                {Math.round(pr.ai_code_percentage)}% AI Code
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4 mt-6">
          {Object.entries(severityCount).map(([sev, count]) => (
            <div key={sev} className={`p-3 rounded-lg border ${severityColors[sev]}`}>
              <p className="text-2xl font-bold">{count || 0}</p>
              <p className="text-sm">{sev}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Findings ({findings.length})</h2>
        {findings.length === 0 && (
          <div className="card text-center py-8">
            <p className="text-green-400 text-lg font-medium">✅ No security issues found</p>
            <p className="text-gray-500 text-sm mt-1">This PR looks clean!</p>
          </div>
        )}
        {findings.map((finding) => (
          <div key={finding.id} className={`card border-l-4 ${
            finding.severity === 'CRITICAL' ? 'border-l-red-500' :
            finding.severity === 'HIGH' ? 'border-l-orange-500' :
            finding.severity === 'MEDIUM' ? 'border-l-yellow-500' : 'border-l-green-500'
          } ${finding.status !== 'open' ? 'opacity-50' : ''}`}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <SeverityIcon severity={finding.severity} />
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    finding.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-400' :
                    finding.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-400' :
                    finding.severity === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-400' :
                    'bg-green-900/50 text-green-400'
                  }`}>{finding.severity}</span>
                  <h3 className="font-medium text-white">{finding.title}</h3>
                  {finding.is_ai_generated && (
                    <span className="px-2 py-0.5 bg-purple-900/50 text-purple-400 rounded text-xs font-medium">AI-Generated</span>
                  )}
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    finding.status === 'open' ? 'bg-gray-800 text-gray-400' :
                    finding.status === 'fixed' ? 'bg-green-900/30 text-green-400' :
                    'bg-gray-800 text-gray-500'
                  }`}>{finding.status}</span>
                </div>
                <p className="text-sm text-gray-400 mt-1">{finding.description}</p>
                <p className="text-xs text-gray-500 mt-1">
                  {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ''}
                  {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ''}
                </p>
              </div>
              <div className="flex items-center gap-2">
                {finding.status === 'open' && (
                  <>
                    <button onClick={() => handleFix(finding.id)} className="btn-secondary text-xs py-1.5">Mark Fixed</button>
                    <button onClick={() => setDismissModal(finding.id)} className="btn-secondary text-xs py-1.5 text-gray-500">Dismiss</button>
                  </>
                )}
                <button onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)} className="text-gray-500 hover:text-gray-300">
                  {expandedFinding === finding.id ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {expandedFinding === finding.id && (
              <div className="mt-4 space-y-3">
                {finding.code_snippet && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1 font-medium">Code Snippet</p>
                    <pre className="bg-gray-950 rounded-lg p-3 text-sm font-mono text-gray-300 overflow-x-auto border border-gray-800">
                      <code>{finding.code_snippet}</code>
                    </pre>
                  </div>
                )}
                {finding.suggested_fix && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1 font-medium">Suggested Fix</p>
                    <pre className="bg-green-950/30 rounded-lg p-3 text-sm font-mono text-green-300 overflow-x-auto border border-green-900/30">
                      <code>{finding.suggested_fix}</code>
                    </pre>
                  </div>
                )}
              </div>
            )}

            {dismissModal === finding.id && (
              <div className="mt-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium text-gray-200">Dismiss Finding</p>
                  <button onClick={() => setDismissModal(null)}><X className="w-4 h-4 text-gray-500" /></button>
                </div>
                <input type="text" className="input text-sm" placeholder="Reason for dismissal..." value={dismissReason} onChange={(e) => setDismissReason(e.target.value)} />
                <div className="flex gap-2 mt-2">
                  <button onClick={() => handleDismiss(finding.id)} className="btn-secondary text-xs py-1.5" disabled={!dismissReason}>Confirm Dismiss</button>
                  <button onClick={() => setDismissModal(null)} className="btn-secondary text-xs py-1.5">Cancel</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
