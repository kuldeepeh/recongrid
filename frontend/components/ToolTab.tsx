"use client";
import { useEffect, useState } from "react";
import {
  api,
  DnsRecord,
  Endpoint,
  HttpService,
  Port,
  ScanRunDetail,
  Subdomain,
  ToolSchema,
} from "@/lib/api";
import { CommandViewer, EmptyState, Spinner } from "@/components/ui";

type ToolName =
  | "subfinder"
  | "dnsx"
  | "httpx"
  | "naabu"
  | "katana"
  | "nuclei";

const TOOL_BLURB: Record<ToolName, string> = {
  subfinder: "passive subdomain enumeration",
  dnsx: "dns resolution & record lookup",
  httpx: "http probing & fingerprinting",
  naabu: "tcp connect port scan",
  katana: "web crawl & endpoint discovery",
  nuclei: "template-based vuln scan",
};

export function ToolTab({
  targetId,
  tool,
  schema,
}: {
  targetId: number;
  tool: ToolName;
  schema: ToolSchema | null;
}) {
  const [mode, setMode] = useState<"default" | "advanced">("default");
  const [advanced, setAdvanced] = useState<Record<string, any>>({});
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState<ScanRunDetail | null>(null);
  const [rows, setRows] = useState<any[] | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const spec = schema?.tools[tool];

  useEffect(() => {
    if (spec) setAdvanced({ ...spec.defaults });
  }, [spec]);

  async function loadResults() {
    if (tool === "subfinder") {
      setRows(await api.subdomains(targetId));
    } else if (tool === "dnsx") {
      setRows(await api.dnsRecords(targetId));
    } else if (tool === "httpx") {
      setRows(await api.httpServices(targetId));
    } else if (tool === "naabu") {
      setRows(await api.ports(targetId));
    } else if (tool === "katana") {
      setRows(await api.endpoints(targetId));
    } else if (tool === "nuclei") {
      setRows(await api.findings(targetId));
    }
  }

  useEffect(() => {
    loadResults();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tool, targetId]);

  async function run(nucleiSelected = false) {
    setRunning(true);
    try {
      const body: any = {
        scan_profile_id: null,
      };
      if (tool === "nuclei") {
        body.target_source = nucleiSelected ? "selected" : "all_crawled";
        body.endpoint_ids = nucleiSelected ? Array.from(selected) : [];
      }
      // Note: advanced config is applied via the active scan profile in this MVP;
      // the per-tab controls preview what Advanced mode would send.
      const run = await api.triggerTool(targetId, tool, body);
      await poll(run.id);
      await loadResults();
    } finally {
      setRunning(false);
    }
  }

  async function poll(runId: number) {
    for (let i = 0; i < 150; i++) {
      const detail = await api.getScan(runId);
      setLastRun(detail);
      if (detail.status === "completed" || detail.status === "failed") return;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  function toggle(id: number) {
    setSelected((s) => {
      const next = new Set(s);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  const stageExec = lastRun?.stage_executions.find((e) => e.tool === tool);

  return (
    <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
      {/* Config panel */}
      <div className="card h-fit p-4">
        <div className="mb-1 font-mono text-sm font-semibold text-blood-500">
          {tool}
        </div>
        <p className="mb-4 font-mono text-[11px] text-neutral-500">
          {TOOL_BLURB[tool]}
        </p>

        <div className="mb-4 grid grid-cols-2 gap-1 border border-ink-600 p-1">
          {(["default", "advanced"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition ${
                mode === m
                  ? "bg-blood-900/50 text-blood-500"
                  : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              {m}
            </button>
          ))}
        </div>

        {mode === "default" ? (
          <div className="mb-4">
            <div className="label">command preview</div>
            <div className="cmd">{spec?.base_flags.join(" ") || "..."}</div>
          </div>
        ) : (
          <div className="mb-4 space-y-3">
            {spec?.advanced_keys.map((key) => (
              <AdvancedControl
                key={key}
                name={key}
                value={advanced[key]}
                onChange={(v) => setAdvanced((a) => ({ ...a, [key]: v }))}
              />
            ))}
            {tool === "nuclei" && (
              <label className="flex items-center gap-2 font-mono text-[11px] text-amber-400">
                <input
                  type="checkbox"
                  checked={!!advanced.intrusive_confirmed}
                  onChange={(e) =>
                    setAdvanced((a) => ({
                      ...a,
                      intrusive_confirmed: e.target.checked,
                    }))
                  }
                />
                confirm intrusive/dos/fuzz templates
              </label>
            )}
          </div>
        )}

        <button
          className="btn-primary w-full"
          disabled={running}
          onClick={() => run(false)}
        >
          {running ? "running..." : "▶ run this tool"}
        </button>

        {stageExec && (
          <div className="mt-4">
            <div className="label">last command</div>
            <CommandViewer
              command={stageExec.command}
              exitCode={stageExec.exit_code}
              resultCount={stageExec.result_count}
            />
          </div>
        )}
      </div>

      {/* Results panel */}
      <div className="card p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="font-mono text-xs uppercase tracking-wider text-neutral-400">
            results {rows ? `(${rows.length})` : ""}
          </div>
          {tool === "katana" && selected.size > 0 && (
            <button
              className="btn-primary"
              disabled={running}
              onClick={() => run(true)}
            >
              run nuclei on {selected.size} selected
            </button>
          )}
        </div>

        {rows === null ? (
          <Spinner />
        ) : rows.length === 0 ? (
          <EmptyState>no results yet — run the tool</EmptyState>
        ) : (
          <ResultsTable tool={tool} rows={rows} selected={selected} onToggle={toggle} />
        )}
      </div>
    </div>
  );
}

function AdvancedControl({
  name,
  value,
  onChange,
}: {
  name: string;
  value: any;
  onChange: (v: any) => void;
}) {
  if (typeof value === "boolean") {
    return (
      <label className="flex items-center justify-between font-mono text-[11px] text-neutral-400">
        <span>{name}</span>
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
        />
      </label>
    );
  }
  if (Array.isArray(value)) {
    return (
      <div>
        <div className="label">{name}</div>
        <input
          className="input"
          value={value.join(",")}
          onChange={(e) =>
            onChange(e.target.value.split(",").map((s) => s.trim()).filter(Boolean))
          }
        />
      </div>
    );
  }
  return (
    <div>
      <div className="label">{name}</div>
      <input
        className="input"
        value={value ?? ""}
        onChange={(e) =>
          onChange(
            typeof value === "number" ? Number(e.target.value) : e.target.value
          )
        }
      />
    </div>
  );
}

function ResultsTable({
  tool,
  rows,
  selected,
  onToggle,
}: {
  tool: ToolName;
  rows: any[];
  selected: Set<number>;
  onToggle: (id: number) => void;
}) {
  const cellCls = "px-3 py-1.5 font-mono text-xs text-neutral-300";
  const headCls =
    "px-3 py-1.5 text-left font-mono text-[10px] uppercase tracking-wider text-neutral-600";

  if (tool === "subfinder") {
    return (
      <Table head={["hostname", "source", "active"]} headCls={headCls}>
        {(rows as Subdomain[]).map((r) => (
          <tr key={r.id} className="border-t border-ink-700">
            <td className={cellCls}>{r.hostname}</td>
            <td className={cellCls}>{r.source_tool}</td>
            <td className={cellCls}>{r.is_active ? "●" : "○"}</td>
          </tr>
        ))}
      </Table>
    );
  }
  if (tool === "dnsx") {
    return (
      <Table head={["hostname", "type", "value"]} headCls={headCls}>
        {(rows as DnsRecord[]).map((r) => (
          <tr key={r.id} className="border-t border-ink-700">
            <td className={cellCls}>{r.hostname}</td>
            <td className={cellCls}>
              <span className="chip sevinfo">{r.record_type}</span>
            </td>
            <td className={cellCls}>{r.value}</td>
          </tr>
        ))}
      </Table>
    );
  }
  if (tool === "httpx") {
    return (
      <Table head={["url", "status", "title", "tech"]} headCls={headCls}>
        {(rows as HttpService[]).map((r) => (
          <tr key={r.id} className="border-t border-ink-700">
            <td className={cellCls}>{r.url}</td>
            <td className={cellCls}>{r.status_code ?? "-"}</td>
            <td className={cellCls}>{r.title ?? "-"}</td>
            <td className={cellCls}>{r.tech_stack?.join(", ")}</td>
          </tr>
        ))}
      </Table>
    );
  }
  if (tool === "naabu") {
    return (
      <Table
        head={["ip", "port", "service", "version", "os (nmap)"]}
        headCls={headCls}
      >
        {(rows as Port[]).map((r) => {
          const version = [r.service_product, r.service_version]
            .filter(Boolean)
            .join(" ");
          return (
            <tr key={r.id} className="border-t border-ink-700">
              <td className={cellCls}>{r.ip}</td>
              <td className={cellCls}>{r.port}</td>
              <td className={cellCls}>{r.service_guess ?? "-"}</td>
              <td className={cellCls}>{version || "-"}</td>
              <td className={cellCls}>{r.os_guess ?? "-"}</td>
            </tr>
          );
        })}
      </Table>
    );
  }
  if (tool === "katana") {
    return (
      <Table head={["", "method", "url", "hits"]} headCls={headCls}>
        {(rows as Endpoint[]).map((r) => (
          <tr key={r.id} className="border-t border-ink-700">
            <td className={cellCls}>
              <input
                type="checkbox"
                checked={selected.has(r.id)}
                onChange={() => onToggle(r.id)}
              />
            </td>
            <td className={cellCls}>{r.method}</td>
            <td className={cellCls}>{r.url}</td>
            <td className={cellCls}>×{r.occurrence_count}</td>
          </tr>
        ))}
      </Table>
    );
  }
  // nuclei
  return (
    <Table head={["severity", "template", "matched"]} headCls={headCls}>
      {rows.map((r: any) => (
        <tr key={r.id} className="border-t border-ink-700">
          <td className={cellCls}>{r.severity}</td>
          <td className={cellCls}>{r.template_id}</td>
          <td className={cellCls}>{r.matched_at}</td>
        </tr>
      ))}
    </Table>
  );
}

function Table({
  head,
  headCls,
  children,
}: {
  head: string[];
  headCls: string;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} className={headCls}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
