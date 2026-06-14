import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Bell, Slack, MessageCircle, Mail, CheckCircle, Loader2 } from 'lucide-react';
import type { NotificationSetting } from '../types';

const channelIcons: Record<string, any> = {
  slack: Slack,
  discord: MessageCircle,
  email: Mail,
};

export default function NotificationsPage() {
  const [settings, setSettings] = useState<NotificationSetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      const data = await api.notifications.settings();
      // Ensure default channels exist
      const channels = ['slack', 'discord', 'email'];
      for (const channel of channels) {
        if (!data.find((s: any) => s.channel === channel)) {
          data.push({ id: '', channel, enabled: false, config: {} });
        }
      }
      setSettings(data);
    } catch (err) {
      console.error('Failed to load notification settings:', err);
    } finally {
      setLoading(false);
    }
  }

  const handleToggle = async (channel: string, enabled: boolean) => {
    const setting = settings.find(s => s.channel === channel);
    setSaving(channel);
    try {
      await api.notifications.update({ channel, enabled, config: setting?.config || {} });
      setSettings(prev => prev.map(s => s.channel === channel ? { ...s, enabled } : s));
    } catch (err) {
      console.error('Failed to update setting:', err);
    } finally {
      setSaving(null);
    }
  };

  const handleConfigUpdate = async (channel: string, key: string, value: string) => {
    const setting = settings.find(s => s.channel === channel);
    const newConfig = { ...(setting?.config || {}), [key]: value };
    setSettings(prev => prev.map(s => s.channel === channel ? { ...s, config: newConfig } : s));
  };

  const handleSaveConfig = async (channel: string) => {
    const setting = settings.find(s => s.channel === channel);
    setSaving(channel);
    try {
      await api.notifications.update({ channel, enabled: setting?.enabled || false, config: setting?.config || {} });
    } catch (err) {
      console.error('Failed to save:', err);
    } finally {
      setSaving(null);
    }
  };

  const handleTest = async (channel: string) => {
    setTesting(channel);
    setTestResult(null);
    try {
      const result = await api.notifications.test(channel);
      setTestResult(`✅ ${channel} notification sent successfully`);
    } catch (err: any) {
      setTestResult(`❌ Failed: ${err.detail || 'Unknown error'}`);
    } finally {
      setTesting(null);
      setTimeout(() => setTestResult(null), 5000);
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
      <div>
        <h1 className="text-2xl font-bold text-white">Notifications</h1>
        <p className="text-gray-500 mt-1">Configure alerts for security findings and PR reviews</p>
      </div>

      {testResult && (
        <div className={`px-4 py-3 rounded-lg text-sm ${testResult.startsWith('✅') ? 'bg-green-900/30 text-green-400 border border-green-800' : 'bg-red-900/30 text-red-400 border border-red-800'}`}>
          {testResult}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4">
        {settings.map((setting) => {
          const Icon = channelIcons[setting.channel] || Bell;
          const isEmail = setting.channel === 'email';
          const isSlack = setting.channel === 'slack';
          const isDiscord = setting.channel === 'discord';

          return (
            <div key={setting.channel} className="card">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gray-800 rounded-lg">
                    <Icon className="w-5 h-5 text-gray-400" />
                  </div>
                  <div>
                    <h3 className="font-medium text-white capitalize">{setting.channel}</h3>
                    <p className="text-sm text-gray-500">
                      {isSlack && 'Send alerts to Slack channels'}
                      {isDiscord && 'Send alerts to Discord channels'}
                      {isEmail && 'Send email notifications for critical findings'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {setting.enabled && (
                    <button onClick={() => handleTest(setting.channel)} className="btn-secondary text-xs py-1.5 flex items-center gap-1" disabled={testing === setting.channel}>
                      {testing === setting.channel ? <Loader2 className="w-3 h-3 animate-spin" /> : <Bell className="w-3 h-3" />}
                      Test
                    </button>
                  )}
                  <button
                    onClick={() => handleToggle(setting.channel, !setting.enabled)}
                    className={`relative w-11 h-6 rounded-full transition-colors ${setting.enabled ? 'bg-brand-600' : 'bg-gray-700'}`}
                    disabled={saving === setting.channel}
                  >
                    <div className={`absolute w-5 h-5 bg-white rounded-full top-0.5 transition-transform ${setting.enabled ? 'translate-x-[22px]' : 'translate-x-0.5'}`} />
                  </button>
                </div>
              </div>

              <div className="space-y-3 pl-11">
                {isSlack && (
                  <>
                    <div>
                      <label className="label">Webhook URL</label>
                      <input type="url" className="input" placeholder="https://hooks.slack.com/services/..." value={setting.config?.webhook_url || ''} onChange={(e) => handleConfigUpdate('slack', 'webhook_url', e.target.value)} />
                    </div>
                    <button onClick={() => handleSaveConfig('slack')} className="btn-secondary text-xs" disabled={saving === 'slack'}>
                      {saving === 'slack' ? 'Saving...' : 'Save'}
                    </button>
                  </>
                )}
                {isDiscord && (
                  <>
                    <div>
                      <label className="label">Webhook URL</label>
                      <input type="url" className="input" placeholder="https://discord.com/api/webhooks/..." value={setting.config?.webhook_url || ''} onChange={(e) => handleConfigUpdate('discord', 'webhook_url', e.target.value)} />
                    </div>
                    <button onClick={() => handleSaveConfig('discord')} className="btn-secondary text-xs" disabled={saving === 'discord'}>
                      {saving === 'discord' ? 'Saving...' : 'Save'}
                    </button>
                  </>
                )}
                {isEmail && (
                  <>
                    <div>
                      <label className="label">Email Address</label>
                      <input type="email" className="input" placeholder="security@company.com" value={setting.config?.email || ''} onChange={(e) => handleConfigUpdate('email', 'email', e.target.value)} />
                    </div>
                    <button onClick={() => handleSaveConfig('email')} className="btn-secondary text-xs" disabled={saving === 'email'}>
                      {saving === 'email' ? 'Saving...' : 'Save'}
                    </button>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Notification Triggers</h3>
        <div className="space-y-3">
          {[
            { event: 'Critical/Highest finding detected', severity: 'CRITICAL' },
            { event: 'PR analysis complete', severity: 'INFO' },
            { event: 'Policy violation detected', severity: 'HIGH' },
            { event: 'Unresolved findings escalation (24h)', severity: 'URGENT' },
            { event: 'Daily digest of PR reviews', severity: 'DIGEST' },
          ].map((trigger, i) => (
            <div key={i} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
              <div className="flex items-center gap-3">
                <CheckCircle className="w-4 h-4 text-brand-400" />
                <span className="text-sm text-gray-300">{trigger.event}</span>
              </div>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                trigger.severity === 'CRITICAL' ? 'badge-critical' :
                trigger.severity === 'HIGH' ? 'badge-high' : 'badge-medium'
              }`}>{trigger.severity}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
