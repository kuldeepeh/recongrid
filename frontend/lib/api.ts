// Thin API client. All calls include credentials so the session cookie rides along.
const BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  // auth
  login: (password: string) =>
    req<{ ok: boolean }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ password }),
    }),
  logout: () => req("/auth/logout", { method: "POST" }),
  me: () => req<{ authenticated: boolean }>("/auth/me"),

  // targets
  listTargets: () => req<Target[]>("/targets"),
  getTarget: (id: number) => req<TargetDetail>(`/targets/${id}`),
  createTarget: (body: TargetCreateBody) =>
    req<TargetDetail>("/targets", { method: "POST", body: JSON.stringify(body) }),
  confirmAuthorization: (id: number, note: string) =>
    req<TargetDetail>(`/targets/${id}/confirm-authorization`, {
      method: "POST",
      body: JSON.stringify({ authorization_note: note }),
    }),
  updateScope: (id: number, body: ScopeConfigBody) =>
    req<TargetDetail>(`/targets/${id}/scope`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteTarget: (id: number) => req(`/targets/${id}`, { method: "DELETE" }),

  // assets
  subdomains: (id: number) => req<Subdomain[]>(`/targets/${id}/subdomains`),
  dnsRecords: (id: number) => req<DnsRecord[]>(`/targets/${id}/dns-records`),
  ports: (id: number) => req<Port[]>(`/targets/${id}/ports`),
  httpServices: (id: number) => req<HttpService[]>(`/targets/${id}/http-services`),
  endpoints: (id: number) => req<Endpoint[]>(`/targets/${id}/endpoints`),
  findings: (id: number) => req<Finding[]>(`/targets/${id}/findings`),
  diffs: (id: number) => req<DiffEvent[]>(`/targets/${id}/diffs`),

  // scans
  listScans: (id: number) => req<ScanRun[]>(`/targets/${id}/scans`),
  triggerScan: (id: number, profileId?: number) =>
    req<ScanRun>(`/targets/${id}/scans`, {
      method: "POST",
      body: JSON.stringify({ scan_profile_id: profileId ?? null }),
    }),
  triggerTool: (id: number, tool: string, body: SingleToolBody) =>
    req<ScanRun>(`/targets/${id}/scans/${tool}`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getScan: (runId: number) => req<ScanRunDetail>(`/scans/${runId}`),

  // profiles
  toolSchema: () => req<ToolSchema>("/scan-profiles/tool-schema"),
  listProfiles: () => req<ScanProfile[]>("/scan-profiles"),

  // maintenance
  toolVersions: () => req<ToolVersions>("/maintenance/tools"),
  updateTemplates: () =>
    req<{ queued: boolean; task_id: string }>("/maintenance/update-templates", {
      method: "POST",
    }),
};

// ─── Types ───────────────────────────────────────────────────────────
export interface Target {
  id: number;
  name: string;
  root_domain: string;
  is_authorized: boolean;
  project_type: string;
  expires_at: string | null;
  last_activity_at: string | null;
  created_at: string;
}
export interface TargetDetail extends Target {
  scope_config: Record<string, unknown>;
  authorization_note: string | null;
  subdomain_count: number;
  open_finding_count: number;
  unacked_diff_count: number;
}
export interface TargetCreateBody {
  name: string;
  root_domain: string;
  project_type: "temporary" | "permanent";
  scope_config?: Record<string, unknown>;
}
export interface ScopeConfigBody {
  extra_in_scope: string[];
  cidrs: string[];
  excluded_hosts: string[];
}
export interface Subdomain {
  id: number;
  hostname: string;
  source_tool: string | null;
  is_active: boolean;
}
export interface DnsRecord {
  id: number;
  hostname: string;
  record_type: string;
  value: string;
}
export interface Port {
  id: number;
  ip: string;
  port: number;
  protocol: string;
  service_guess: string | null;
  service_product: string | null;
  service_version: string | null;
  os_guess: string | null;
}
export interface HttpService {
  id: number;
  url: string;
  normalized_url: string;
  status_code: number | null;
  title: string | null;
  tech_stack: string[];
  server_header: string | null;
  occurrence_count: number;
}
export interface Endpoint {
  id: number;
  url: string;
  normalized_url: string;
  method: string;
  status_code: number | null;
  occurrence_count: number;
}
export interface Finding {
  id: number;
  template_id: string;
  severity: string;
  matched_at: string;
  name: string | null;
  description: string | null;
}
export interface DiffEvent {
  id: number;
  change_type: string;
  entity_ref: Record<string, unknown>;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  severity: string;
  acknowledged: boolean;
  created_at: string;
}
export interface StageExecution {
  id: number;
  tool: string;
  command: string;
  started_at: string | null;
  completed_at: string | null;
  exit_code: number | null;
  result_count: number;
}
export interface ScanRun {
  id: number;
  target_id: number;
  triggered_by: string;
  tool: string | null;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  stage_status: Record<string, { status: string; duration: number | null }>;
  error: string | null;
  created_at: string;
}
export interface ScanRunDetail extends ScanRun {
  stage_executions: StageExecution[];
}
export interface SingleToolBody {
  scan_profile_id?: number | null;
  target_source?: "all_crawled" | "selected";
  endpoint_ids?: number[];
}
export interface ScanProfile {
  id: number;
  name: string;
  is_default: boolean;
  tool_config: Record<string, any>;
}
export interface ToolSchema {
  stages: string[];
  tools: Record<
    string,
    { base_flags: string[]; advanced_keys: string[]; defaults: Record<string, any> }
  >;
}
export interface ToolVersions {
  tools: { name: string; version: string }[];
}
