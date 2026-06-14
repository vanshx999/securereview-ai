import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { FileText, Download, Users, History, CreditCard, ArrowDown } from 'lucide-react';

export default function AdminPage() {
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [orgUsers, setOrgUsers] = useState<any[]>([]);
  const [subscription, setSubscription] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'users' | 'audit' | 'compliance' | 'subscription'>('users');

  useEffect(() => {
    loadData();
  }, [activeTab]);

  async function loadData() {
    try {
      if (activeTab === 'users') {
        const users = await api.admin.users();
        setOrgUsers(users);
      } else if (activeTab === 'audit') {
        const logs = await api.admin.auditLogs(100);
        setAuditLogs(logs);
      } else if (activeTab === 'subscription') {
        const sub = await api.admin.subscription();
        setSubscription(sub);
      }
    } catch (err) {
      console.error('Failed to load admin data:', err);
    }
  }

  const handleExportPDF = async () => {
    try {
      const response = await api.admin.complianceReport('pdf');
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'securereview-compliance-report.pdf';
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export report:', err);
    }
  };

  const handleExportCSV = async () => {
    try {
      const response = await api.admin.complianceReport('csv');
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'securereview-compliance-report.csv';
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export CSV:', err);
    }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await api.admin.updateUserRole(userId, role);
      setOrgUsers(prev => prev.map(u => u.id === userId ? { ...u, role } : u));
    } catch (err) {
      console.error('Failed to update role:', err);
    }
  };

  const tabs = [
    { id: 'users', label: 'Users', icon: Users },
    { id: 'audit', label: 'Audit Log', icon: History },
    { id: 'compliance', label: 'Compliance', icon: FileText },
    { id: 'subscription', label: 'Subscription', icon: CreditCard },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Admin Panel</h1>
        <p className="text-gray-500 mt-1">Manage your organization and compliance</p>
      </div>

      <div className="flex gap-2 border-b border-gray-800 pb-2">
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id ? 'bg-brand-600/10 text-brand-400 border border-brand-600/20' : 'text-gray-500 hover:text-gray-300'
            }`}>
            <tab.icon className="w-4 h-4" /> {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'users' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Organization Users</h3>
          <div className="space-y-3">
            {orgUsers.length === 0 && <p className="text-gray-500 text-sm">No users found</p>}
            {orgUsers.map((user) => (
              <div key={user.id} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center text-sm font-medium text-gray-300">
                    {user.name?.[0] || user.email?.[0] || '?'}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-200">{user.name || 'Unnamed'}</p>
                    <p className="text-xs text-gray-500">{user.email}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <select className="input text-sm py-1 w-32" value={user.role} onChange={(e) => handleRoleChange(user.id, e.target.value)}>
                    <option value="admin">Admin</option>
                    <option value="security">Security</option>
                    <option value="dev">Developer</option>
                  </select>
                  <span className={`px-2 py-0.5 rounded text-xs ${user.is_active ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'audit' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Audit Trail</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 text-gray-500 font-medium">Action</th>
                  <th className="text-left py-2 text-gray-500 font-medium">Entity</th>
                  <th className="text-left py-2 text-gray-500 font-medium">User</th>
                  <th className="text-left py-2 text-gray-500 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id} className="border-b border-gray-800/50">
                    <td className="py-2 text-gray-300">{log.action}</td>
                    <td className="py-2 text-gray-400">{log.entity_type}:{log.entity_id?.substring(0, 8)}</td>
                    <td className="py-2 text-gray-400">{log.user_id?.substring(0, 8) || 'system'}</td>
                    <td className="py-2 text-gray-500">{new Date(log.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <div className="grid grid-cols-2 gap-6">
          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">Compliance Reports</h3>
            <p className="text-sm text-gray-500 mb-6">Export audit-ready compliance reports for SOC 2, ISO 27001, and other frameworks.</p>

            <div className="space-y-4">
              <div className="p-4 bg-gray-800 rounded-lg">
                <h4 className="font-medium text-gray-200 mb-2">SOC 2 Compliance Report</h4>
                <p className="text-sm text-gray-500 mb-3">Comprehensive security audit including all findings, policies, and remediation actions.</p>
                <div className="flex gap-2">
                  <button onClick={handleExportPDF} className="btn-secondary text-sm flex items-center gap-2">
                    <Download className="w-4 h-4" /> Export PDF
                  </button>
                  <button onClick={handleExportCSV} className="btn-secondary text-sm flex items-center gap-2">
                    <Download className="w-4 h-4" /> Export CSV
                  </button>
                </div>
              </div>

              <div className="p-4 bg-gray-800 rounded-lg">
                <h4 className="font-medium text-gray-200 mb-2">ISO 27001 Evidence Report</h4>
                <p className="text-sm text-gray-500 mb-3">Audit trail of all security events, policy changes, and user actions for ISO 27001:2022.</p>
                <button onClick={handleExportPDF} className="btn-secondary text-sm flex items-center gap-2">
                  <Download className="w-4 h-4" /> Export PDF
                </button>
              </div>
            </div>
          </div>

          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">Framework Coverage</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">SOC 2 (Security)</span>
                <span className="px-2 py-0.5 bg-green-900/30 text-green-400 rounded text-xs font-medium">Covered</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">ISO 27001:2022</span>
                <span className="px-2 py-0.5 bg-green-900/30 text-green-400 rounded text-xs font-medium">Covered</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">GDPR (Art. 32-33)</span>
                <span className="px-2 py-0.5 bg-yellow-900/30 text-yellow-400 rounded text-xs font-medium">Partial</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">PCI DSS v4.0</span>
                <span className="px-2 py-0.5 bg-gray-800 text-gray-500 rounded text-xs font-medium">Planned</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">HIPAA</span>
                <span className="px-2 py-0.5 bg-gray-800 text-gray-500 rounded text-xs font-medium">Planned</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'subscription' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Subscription Details</h3>
          {subscription ? (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-500">Plan</p>
                  <p className="text-lg font-bold text-white capitalize">{subscription.plan}</p>
                </div>
                <div className="p-4 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-500">Seats</p>
                  <p className="text-lg font-bold text-white">{subscription.seat_count}</p>
                </div>
                <div className="p-4 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-500">Billing</p>
                  <p className="text-lg font-bold text-white capitalize">{subscription.billing_cycle}</p>
                </div>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <div>
                  <p className="text-sm text-gray-500">Status</p>
                  <p className={`font-medium ${subscription.status === 'active' ? 'text-green-400' : 'text-yellow-400'}`}>
                    {subscription.status}
                  </p>
                </div>
                {subscription.current_period_end && (
                  <p className="text-sm text-gray-500">
                    Renews: {new Date(subscription.current_period_end).toLocaleDateString()}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-gray-500">No active subscription</p>
              <button className="btn-primary mt-4">Upgrade Plan</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
