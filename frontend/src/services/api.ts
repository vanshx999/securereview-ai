import type { AuthTokens, User } from '../types';

const _raw = import.meta.env.VITE_API_URL || '';
const API_BASE = _raw
  ? `${_raw.replace(/\/+$/, '')}/api`
  : 'https://securereview-ai-backend.onrender.com/api';

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem('access_token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    const refresh = localStorage.getItem('refresh_token');
    if (refresh && !endpoint.includes('/auth/')) {
      const refreshed = await refreshTokens(refresh);
      if (refreshed) {
        headers['Authorization'] = `Bearer ${localStorage.getItem('access_token')}`;
        const retry = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
        if (!retry.ok) throw new ApiError(await retry.json(), retry.status);
        return retry.json();
      }
    }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new ApiError(error, response.status);
  }

  if (response.status === 204) return {} as T;
  return response.json();
}

async function refreshTokens(refreshToken: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data: AuthTokens = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

class ApiError extends Error {
  status: number;
  detail: string;
  constructor(body: any, status: number) {
    super(body.detail || 'API Error');
    this.status = status;
    this.detail = body.detail || 'API Error';
  }
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<AuthTokens>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }),
    register: (email: string, password: string, name: string, role: string) =>
      request<AuthTokens>('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password, name, role }),
      }),
    me: () => request<User>('/auth/me'),
    githubLogin: (code: string) =>
      request<AuthTokens>(`/auth/github/callback?code=${code}`, { method: 'POST' }),
  },
  dashboard: {
    stats: () => request<any>('/dashboard/stats'),
    recentPrs: (limit = 10) => request<any[]>(`/dashboard/recent-prs?limit=${limit}`),
    recentFindings: (limit = 20) => request<any[]>(`/dashboard/recent-findings?limit=${limit}`),
    vulnerabilityTrends: (days = 30) => request<any[]>(`/dashboard/vulnerability-trends?days=${days}`),
    topVulnerabilities: (limit = 10) => request<any[]>(`/dashboard/top-vulnerabilities?limit=${limit}`),
  },
  prs: {
    list: (params?: { repo_id?: string; status?: string }) => {
      const q = new URLSearchParams();
      if (params?.repo_id) q.set('repo_id', params.repo_id);
      if (params?.status) q.set('status', params.status);
      return request<any[]>(`/prs/?${q}`);
    },
    get: (id: string) => request<any>(`/prs/${id}`),
    findings: (prId: string) => request<any[]>(`/prs/${prId}/findings`),
    updateFinding: (prId: string, findingId: string, data: any) =>
      request<any>(`/prs/${prId}/findings/${findingId}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    reanalyze: (prId: string) =>
      request<any>(`/prs/${prId}/reanalyze`, { method: 'POST' }),
  },
  policies: {
    list: () => request<any[]>('/policies/'),
    create: (data: any) =>
      request<any>('/policies/', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    get: (id: string) => request<any>(`/policies/${id}`),
    update: (id: string, data: any) =>
      request<any>(`/policies/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      request<any>(`/policies/${id}`, { method: 'DELETE' }),
    compile: (id: string) =>
      request<any>(`/policies/${id}/compile`, { method: 'POST' }),
    violations: (id: string) => request<any[]>(`/policies/${id}/violations`),
  },
  repositories: {
    list: () => request<any[]>('/repositories/'),
    get: (id: string) => request<any>(`/repositories/${id}`),
    installGithub: (code: string) =>
      request<any>(`/repositories/install-github?code=${code}`, { method: 'POST' }),
    delete: (id: string) =>
      request<any>(`/repositories/${id}`, { method: 'DELETE' }),
  },
  admin: {
    auditLogs: (limit = 50) => request<any[]>(`/admin/audit-logs?limit=${limit}`),
    subscription: () => request<any>('/admin/subscription'),
    complianceReport: (format: string, dateFrom?: string, dateTo?: string) => {
      const q = new URLSearchParams({ format });
      if (dateFrom) q.set('date_from', dateFrom);
      if (dateTo) q.set('date_to', dateTo);
      return fetch(`${API_BASE}/admin/compliance-report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('access_token')}`,
        },
        body: JSON.stringify({ format, date_from: dateFrom, date_to: dateTo }),
      });
    },
    users: () => request<any[]>('/admin/users'),
    updateUserRole: (userId: string, role: string) =>
      request<any>(`/admin/users/${userId}/role?role=${role}`, { method: 'PATCH' }),
  },
  notifications: {
    settings: () => request<any[]>('/notifications/settings'),
    update: (data: any) =>
      request<any>('/notifications/settings', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    test: (channel: string) =>
      request<any>(`/notifications/test/${channel}`, { method: 'POST' }),
  },
};
