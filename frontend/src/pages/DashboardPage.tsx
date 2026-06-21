import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useAuthStore } from '../hooks/useAuth';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, AreaChart, Area, PieChart, Pie, Cell,
} from 'recharts';
import {
  Shield, AlertTriangle, GitPullRequest, TrendingUp, Activity,
  ArrowUpRight, ArrowDownRight, Code, Server, Users,
} from 'lucide-react';
import type { DashboardStats, PullRequest, Finding } from '../types';

const severityColors = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#16a34a' };

function StatCard({ title, value, icon: Icon, trend, subtitle }: any) {
  return (
    <div className="card">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-500">{title}</p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <div className="p-3 bg-brand-600/10 rounded-lg">
          <Icon className="w-6 h-6 text-brand-400" />
        </div>
      </div>
      {trend !== undefined && (
        <div className="flex items-center gap-1 mt-3">
          {trend >= 0 ? (
            <ArrowUpRight className="w-4 h-4 text-green-400" />
          ) : (
            <ArrowDownRight className="w-4 h-4 text-red-400" />
          )}
          <span className={`text-sm ${trend >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {Math.abs(trend)}% from last month
          </span>
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low',
  };
  return <span className={colors[severity] || 'badge-low'}>{severity}</span>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentPrs, setRecentPrs] = useState<PullRequest[]>([]);
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [trends, setTrends] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { user } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    async function load() {
      try {
        const [s, prs, findings, t] = await Promise.all([
          api.dashboard.stats(),
          api.dashboard.recentPrs(5),
          api.dashboard.recentFindings(10),
          api.dashboard.vulnerabilityTrends(14),
        ]);
        setStats(s);
        setRecentPrs(prs);
        setRecentFindings(findings);
        setTrends(t);
      } catch (err) {
        console.error('Failed to load dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
      </div>
    );
  }

  const severityData = [
    { name: 'Critical', value: stats?.critical_findings || 0, color: '#dc2626' },
    { name: 'High', value: (stats?.total_findings || 0) - (stats?.critical_findings || 0) > 0 ? Math.max(0, (stats?.total_findings || 0) - (stats?.critical_findings || 0)) : 0, color: '#ea580c' },
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-500 mt-1">Welcome back, {user?.name || 'User'}</p>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-6">
        <StatCard title="Total Findings" value={stats?.total_findings || 0} icon={AlertTriangle} />
        <StatCard title="Critical Issues" value={stats?.critical_findings || 0} icon={Shield} />
        <StatCard title="PRs Analyzed" value={stats?.total_prs_analyzed || 0} icon={GitPullRequest} />
        <StatCard title="Health Score" value={`${Math.round(stats?.avg_health_score || 100)}%`} icon={Activity} subtitle="Average across repos" />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Vulnerability Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trends.length > 0 ? trends : [{ date: 'Today', CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }]}>
              <defs>
                <linearGradient id="critical" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} /><stop offset="95%" stopColor="#dc2626" stopOpacity={0} /></linearGradient>
                <linearGradient id="high" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ea580c" stopOpacity={0.3} /><stop offset="95%" stopColor="#ea580c" stopOpacity={0} /></linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="date" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="CRITICAL" stroke="#dc2626" fill="url(#critical)" strokeWidth={2} />
              <Area type="monotone" dataKey="HIGH" stroke="#ea580c" fill="url(#high)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Top Vulnerability Types</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={(stats?.top_vulnerabilities?.length ? stats.top_vulnerabilities : [{ category: 'No data', count: 0 }]).map(v => ({ category: v.category, count: v.count || v.counts || 0 }))}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="category" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }} />
              <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Pull Requests</h3>
          <div className="space-y-3">
            {recentPrs.length === 0 && <p className="text-gray-500 text-sm">No PRs analyzed yet</p>}
            {recentPrs.map((pr) => (
              <div key={pr.id} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg hover:bg-gray-800 cursor-pointer"
                onClick={() => navigate(`/prs/${pr.id}`)}>
                <div>
                  <p className="text-sm font-medium text-gray-200">#{pr.pr_number} {pr.title}</p>
                  <p className="text-xs text-gray-500">{pr.author} · {pr.branch}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-sm font-medium ${pr.health_score >= 80 ? 'text-green-400' : pr.health_score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {pr.health_score}/100
                  </span>
                  {pr.critical_findings > 0 && (
                    <span className="badge-critical">{pr.critical_findings} critical</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Findings</h3>
          <div className="space-y-3">
            {recentFindings.length === 0 && <p className="text-gray-500 text-sm">No findings yet</p>}
            {recentFindings.map((finding) => (
              <div key={finding.id} className="flex items-start gap-3 p-3 bg-gray-800/50 rounded-lg">
                <SeverityBadge severity={finding.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-200 truncate">{finding.title}</p>
                  <p className="text-xs text-gray-500 truncate">{finding.file_path}:{finding.line_start}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">AI Code Analysis</h3>
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">AI-Generated Code</span>
                <span className="text-sm font-medium text-white">{Math.round(stats?.avg_ai_code_percentage || 0)}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="bg-brand-500 h-2 rounded-full" style={{ width: `${Math.min(100, stats?.avg_ai_code_percentage || 0)}%` }} />
              </div>
              <p className="text-xs text-gray-500 mt-2">Average across all analyzed PRs</p>
            </div>
            <div className="p-4 bg-brand-600/10 rounded-xl">
              <Code className="w-8 h-8 text-brand-400" />
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
          <div className="grid grid-cols-2 gap-3">
            <button onClick={() => navigate('/repositories')} className="p-4 bg-gray-800 rounded-xl text-left hover:bg-gray-700 transition-colors">
              <Server className="w-5 h-5 text-brand-400 mb-2" />
              <p className="text-sm font-medium text-gray-200">Add Repository</p>
              <p className="text-xs text-gray-500">Connect GitHub/GitLab</p>
            </button>
            <button onClick={() => navigate('/policies/new')} className="p-4 bg-gray-800 rounded-xl text-left hover:bg-gray-700 transition-colors">
              <Shield className="w-5 h-5 text-brand-400 mb-2" />
              <p className="text-sm font-medium text-gray-200">New Policy</p>
              <p className="text-xs text-gray-500">Create security rule</p>
            </button>
            <button onClick={() => navigate('/admin')} className="p-4 bg-gray-800 rounded-xl text-left hover:bg-gray-700 transition-colors">
              <Users className="w-5 h-5 text-brand-400 mb-2" />
              <p className="text-sm font-medium text-gray-200">Manage Users</p>
              <p className="text-xs text-gray-500">Configure access</p>
            </button>
            <button onClick={() => navigate('/notifications')} className="p-4 bg-gray-800 rounded-xl text-left hover:bg-gray-700 transition-colors">
              <TrendingUp className="w-5 h-5 text-brand-400 mb-2" />
              <p className="text-sm font-medium text-gray-200">Compliance</p>
              <p className="text-xs text-gray-500">Export reports</p>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
