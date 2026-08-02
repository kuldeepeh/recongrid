"use client";
import { ReactNode } from "react";

export function SeverityChip({ severity }: { severity: string }) {
  const cls =
    { critical: "sevcrit", high: "sevhigh", medium: "sevmed", low: "sevlow" }[
      severity
    ] || "sevinfo";
  return <span className={`chip ${cls}`}>{severity}</span>;
}

export function StatusDot({ status }: { status: string }) {
  const color =
    status === "completed"
      ? "bg-emerald-500"
      : status === "running"
      ? "bg-blood-500 animate-pulse-glow"
      : status === "failed"
      ? "bg-blood-700"
      : "bg-neutral-600";
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />;
}

export function CommandViewer({
  command,
  exitCode,
  resultCount,
  duration,
}: {
  command: string;
  exitCode?: number | null;
  resultCount?: number;
  duration?: number | null;
}) {
  return (
    <div className="space-y-1">
      <div className="cmd">
        <span className="text-blood-600">$ </span>
        {command}
      </div>
      <div className="flex gap-3 text-[11px] font-mono text-neutral-500">
        {exitCode != null && (
          <span className={exitCode === 0 ? "text-emerald-500" : "text-blood-500"}>
            exit {exitCode}
          </span>
        )}
        {resultCount != null && <span>{resultCount} results</span>}
        {duration != null && <span>{duration.toFixed(1)}s</span>}
      </div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="border border-dashed border-ink-600 p-8 text-center font-mono text-sm text-neutral-600">
      {children}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 font-mono text-sm text-blood-500">
      <span className="inline-block h-3 w-3 animate-spin border-2 border-blood-600 border-t-transparent" />
      {label || "loading..."}
    </div>
  );
}
