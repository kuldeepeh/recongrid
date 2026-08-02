"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  api,
  ApiError,
  DiffEvent,
  Finding,
  ScanRun,
  TargetDetail,
  ToolSchema,
} from "@/lib/api";
import { ToolTab } from "@/components/ToolTab";
import { CommandViewer, SeverityChip, Spinner, StatusDot } from "@/components/ui";

const TOOLS = ["subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei"] as const;
const TABS = ["overview", "timeline", ...TOOLS, "findings", "scans"] as const;
type Tab = (typeof TABS)[number];

export default function TargetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = Number(params.id);

  const [target, setTarget] = useState<TargetDetail | null>(null);
  const [schema, setSchema] = useState<ToolSchema | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [scanning, setScanning] = useState(false);
  const [deleting, setDeleting] = useState(false);

  async function loadTarget() {
    try {
      setTarget(await api.getTarget(id));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) router.push("/login");
    }
  }

  useEffect(() => {
    loadTarget();
    api.toolSchema().then(setSchema).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function deleteTarget() {
    if (
      !confirm(
        `Delete "${target?.name}" and all its scans, assets, and findings? This cannot be undone.`
      )
    )
      return;
    setDeleting(true);
    try {
      await api.deleteTarget(id);
      router.push("/");
    } catch {
      setDeleting(false);
    }
  }

  async function runFullScan() {
    setScanning(true);
    try {
      const run = await api.triggerScan(id);
      // poll
      for (let i = 0; i < 200; i++) {
        const d = await api.getScan(run.id);
        if (d.status === "completed" || d.status === "failed") break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      await loadTarget();
    } finally {
      setScanning(false);
    }
  }

  if (!target) return <Spinner label="loading target..." />;

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-mono text-xl font-bold text-neutral-100">
              {target.name}
            </h1>
            <span className={`chip ${target.is_authorized ? "sevlow" : "sevhigh"}`}>
              {target.is_authorized ? "authorized" : "unconfirmed"}
            </span>
            <span className="chip sevinfo">{target.project_type}</span>
          </div>
          <div className="font-mono text-xs text-neutral-500">{target.root_domain}</div>
        </div>
        <div className="flex gap-2">
          <button
            className="btn-primary"
            disabled={scanning || !target.is_authorized}
            onClick={runFullScan}
            title={target.is_authorized ? "" : "authorize target first"}
          >
            {scanning ? "scan running..." : "▶ run full scan"}
          </button>
          <button
            className="btn-ghost hover:!border-blood-600 hover:!text-blood-500"
            disabled={deleting}
            onClick={deleteTarget}
            title="delete this target and all its data"
          >
            {deleting ? "deleting..." : "🗑 delete"}
          </button>
        </div>
      </div>

      {/* Stat strip */}
      <div className="mb-6 grid grid-cols-3 gap-3 sm:grid-cols-3">
        <Stat label="subdomains" value={target.subdomain_count} />
        <Stat label="findings" value={target.open_finding_count} accent />
        <Stat label="new activity" value={target.unacked_diff_count} />
      </div>

      {/* Tabs */}
      <div className="mb-4 flex flex-wrap gap-1 border-b border-ink-600">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-2 font-mono text-xs uppercase tracking-wider transition ${
              tab === t
                ? "border-b-2 border-blood-500 text-blood-500"
                : "text-neutral-500 hover:text-neutral-300"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Panels */}
      {tab === "overview" && <Overview target={target} onSaved={loadTarget} />}
      {tab === "timeline" && <Timeline id={id} />}
      {TOOLS.includes(tab as any) && (
        <ToolTab targetId={id} tool={tab as any} schema={schema} />
      )}
      {tab === "findings" && <Findings id={id} />}
      {tab === "scans" && <Scans id={id} />}
    </div>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: boolean;
}) {
  return (
    <div className="card p-4">
      <div className="label">{label}</div>
      <div
        className={`font-mono text-2xl font-bold ${
          accent ? "text-blood-500" : "text-neutral-100"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function toLines(v: unknown): string {
  return Array.isArray(v) ? (v as string[]).join("\n") : "";
}
function fromLines(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function Overview({
  target,
  onSaved,
}: {
  target: TargetDetail;
  onSaved: () => void;
}) {
  const sc = (target.scope_config || {}) as Record<string, unknown>;
  const [extra, setExtra] = useState(toLines(sc.extra_in_scope));
  const [cidrs, setCidrs] = useState(toLines(sc.cidrs));
  const [excluded, setExcluded] = useState(toLines(sc.excluded_hosts));
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setMsg(null);
    try {
      await api.updateScope(target.id, {
        extra_in_scope: fromLines(extra),
        cidrs: fromLines(cidrs),
        excluded_hosts: fromLines(excluded),
      });
      setMsg("Scope saved. Out-of-scope assets are pruned on the next scan.");
      onSaved();
    } catch (e) {
      setMsg(e instanceof ApiError ? `! ${e.message}` : "! failed to save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="card p-5">
        <div className="label">authorization note</div>
        <p className="font-mono text-xs text-neutral-300">
          {target.authorization_note || "— not yet confirmed —"}
        </p>
      </div>

      <div className="card p-5">
        <div className="mb-1 font-mono text-sm font-semibold text-blood-500">
          scope
        </div>
        <p className="mb-4 font-mono text-[11px] leading-relaxed text-neutral-500">
          The root domain{" "}
          <span className="text-neutral-300">{target.root_domain}</span> and its
          subdomains are always in scope. Only in-scope hosts are tracked and scanned
          — third-party hosts a crawl references are ignored. Add extra scope below
          (one entry per line).
        </p>

        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <label className="label">extra in-scope domains</label>
            <textarea
              className="input h-28 resize-none"
              value={extra}
              onChange={(e) => setExtra(e.target.value)}
              placeholder={"other-domain.com\napp.partner.io"}
            />
          </div>
          <div>
            <label className="label">in-scope CIDRs</label>
            <textarea
              className="input h-28 resize-none"
              value={cidrs}
              onChange={(e) => setCidrs(e.target.value)}
              placeholder={"203.0.113.0/24\n10.0.0.0/8"}
            />
          </div>
          <div>
            <label className="label">excluded hosts</label>
            <textarea
              className="input h-28 resize-none"
              value={excluded}
              onChange={(e) => setExcluded(e.target.value)}
              placeholder={"staging.xyntara.in"}
            />
          </div>
        </div>

        {msg && (
          <p
            className={`mt-3 font-mono text-[11px] ${
              msg.startsWith("!") ? "text-blood-500" : "text-emerald-500"
            }`}
          >
            {msg}
          </p>
        )}
        <div className="mt-4">
          <button className="btn-primary" disabled={saving} onClick={save}>
            {saving ? "saving..." : "save scope"}
          </button>
        </div>
      </div>
    </div>
  );
}

function describeDiff(e: DiffEvent): string {
  const d = { ...(e.entity_ref || {}), ...(e.before || {}), ...(e.after || {}) } as any;
  switch (e.change_type) {
    case "new_subdomain":
      return `new subdomain discovered: ${d.hostname}`;
    case "removed_subdomain":
      return `subdomain no longer resolving: ${d.hostname}`;
    case "new_port": {
      const svc = d.service ? ` (${d.service})` : "";
      return `port ${d.port}${svc} opened on ${d.ip}`;
    }
    case "closed_port":
      return `port ${d.port} closed on ${d.ip}`;
    case "cert_change":
      return `TLS certificate rotated`;
    case "http_change":
      return `HTTP response changed`;
    case "new_finding":
      return `new finding: ${d.name || d.template_id}`;
    default:
      return JSON.stringify(d);
  }
}

function Timeline({ id }: { id: number }) {
  const [events, setEvents] = useState<DiffEvent[] | null>(null);
  useEffect(() => {
    api.diffs(id).then(setEvents).catch(() => setEvents([]));
  }, [id]);
  if (!events) return <Spinner />;
  if (events.length === 0)
    return (
      <div className="card p-8 text-center font-mono text-sm text-neutral-600">
        no changes recorded yet — the timeline fills in after two or more scans
      </div>
    );
  return (
    <div className="space-y-2">
      {events.map((e) => (
        <div key={e.id} className="card flex items-center gap-4 p-3">
          <SeverityChip severity={e.severity} />
          <span className="w-32 shrink-0 font-mono text-[11px] uppercase tracking-wider text-blood-500">
            {e.change_type.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-xs text-neutral-200">
            {describeDiff(e)}
          </span>
          <span className="ml-auto shrink-0 font-mono text-[11px] text-neutral-600">
            {new Date(e.created_at).toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

function Findings({ id }: { id: number }) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  useEffect(() => {
    api.findings(id).then(setFindings).catch(() => setFindings([]));
  }, [id]);
  if (!findings) return <Spinner />;
  if (findings.length === 0)
    return (
      <div className="card p-8 text-center font-mono text-sm text-neutral-600">
        no findings
      </div>
    );
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <div key={f.id} className="card p-3">
          <div className="flex items-center gap-3">
            <SeverityChip severity={f.severity} />
            <span className="font-mono text-xs text-neutral-100">
              {f.name || f.template_id}
            </span>
            <span className="ml-auto font-mono text-[11px] text-neutral-500">
              {f.matched_at}
            </span>
          </div>
          {f.description && (
            <p className="mt-2 font-mono text-[11px] text-neutral-500">
              {f.description}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function Scans({ id }: { id: number }) {
  const [scans, setScans] = useState<ScanRun[] | null>(null);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;

    async function tick() {
      try {
        const data = await api.listScans(id);
        if (!active) return;
        setScans(data);
        // Keep polling while anything is still queued/running.
        const busy = data.some(
          (s) => s.status === "running" || s.status === "queued"
        );
        timer = setTimeout(tick, busy ? 2000 : 8000);
      } catch {
        if (active) setScans([]);
      }
    }
    tick();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [id]);

  if (!scans) return <Spinner />;
  if (scans.length === 0)
    return (
      <div className="card p-8 text-center font-mono text-sm text-neutral-600">
        no scans yet
      </div>
    );
  return (
    <div className="space-y-2">
      {scans.map((s) => (
        <div key={s.id} className="card flex items-center gap-4 p-3">
          <StatusDot status={s.status} />
          <span className="font-mono text-xs text-neutral-100">run #{s.id}</span>
          <span className="font-mono text-[11px] text-neutral-500">
            {s.tool ? `single: ${s.tool}` : "full pipeline"} · {s.triggered_by}
          </span>
          <span className="ml-auto font-mono text-[11px] text-neutral-500">
            {s.status}
          </span>
        </div>
      ))}
    </div>
  );
}
