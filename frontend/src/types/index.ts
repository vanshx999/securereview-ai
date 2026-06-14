export interface User {
  id: string;
  email: string;
  name: string | null;
  role: 'admin' | 'security' | 'dev';
  org_id: string;
  avatar_url: string | null;
  is_active: boolean;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: 'free' | 'starter' | 'pro' | 'enterprise';
  created_at: string;
}

export interface Repository {
  id: string;
  org_id: string;
  name: string;
  full_name: string;
  git_provider: string;
  is_active: boolean;
  default_branch: string;
  created_at: string;
}

export interface PullRequest {
  id: string;
  repo_id: string;
  pr_number: number;
  title: string | null;
  branch: string;
  base_branch: string;
  commit_sha: string;
  author: string | null;
  status: 'open' | 'closed' | 'merged';
  ai_code_percentage: number;
  health_score: number;
  total_findings: number;
  critical_findings: number;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  pr_id: string;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  title: string;
  description: string | null;
  code_snippet: string | null;
  suggested_fix: string | null;
  is_ai_generated: boolean;
  status: 'open' | 'fixed' | 'dismissed';
  dismissed_by: string | null;
  dismissed_reason: string | null;
  created_at: string;
}

export interface Policy {
  id: string;
  org_id: string;
  name: string;
  description: string | null;
  natural_language_rule: string;
  compiled_rule: any;
  target_file_patterns: string[];
  is_active: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_repos: number;
  total_prs_analyzed: number;
  total_findings: number;
  open_findings: number;
  critical_findings: number;
  avg_health_score: number;
  avg_ai_code_percentage: number;
  mean_time_to_resolution_hours: number;
  vulnerability_trends: any[];
  top_vulnerabilities: { category: string; count: number }[];
  ai_code_trends: any[];
}

export interface AuditLog {
  id: string;
  org_id: string;
  user_id: string | null;
  action: string;
  entity_type: string;
  entity_id: string | null;
  metadata: any;
  ip_address: string | null;
  created_at: string;
}

export interface Subscription {
  id: string;
  org_id: string;
  plan: string;
  seat_count: number;
  billing_cycle: string;
  status: string;
  current_period_end: string | null;
}

export interface NotificationSetting {
  id: string;
  channel: string;
  enabled: boolean;
  config: Record<string, any>;
}
