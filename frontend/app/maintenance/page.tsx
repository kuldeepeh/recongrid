"use client";
import { useEffect, useState } from "react";
import { api, ToolVersions } from "@/lib/api";
import { Spinner } from "@/components/ui";

export default function MaintenancePage() {
  const [versions, setVersions] = useState<ToolVersions | null>(null);
  const [updating, setUpdating] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function loadVersions() {
    setVersions(null);
    try {
      setVersions(await api.toolVersions());
    } catch {
      setVersions({ tools: [] });
    }
  }

  useEffect(() => {
    loadVersions();
  }, []);

  async function updateTemplates() {
    setUpdating(true);
    setMsg(null);
    try {
      await api.updateTemplates();
      setMsg(
        "Nuclei template update started in the worker. It runs in the background — new templates apply to your next scan."
      );
    } catch {
      setMsg("Failed to start template update.");
    } finally {
      setUpdating(false);
    }
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-mono text-xl font-bold text-neutral-100">
          <span className="text-blood-500">//</span> maintenance
        </h1>
        <p className="font-mono text-xs text-neutral-500">
          installed recon engines &amp; template updates
        </p>
      </div>

      {/* Nuclei templates */}
      <div className="card mb-6 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-mono text-sm font-semibold text-blood-500">
              nuclei templates
            </div>
            <p className="mt-1 font-mono text-[11px] text-neutral-500">
              Pull the latest vulnerability templates from ProjectDiscovery so new
              checks are available to scans.
            </p>
          </div>
          <button
            className="btn-primary"
            disabled={updating}
            onClick={updateTemplates}
          >
            {updating ? "starting..." : "⟳ update templates"}
          </button>
        </div>
        {msg && (
          <p className="mt-3 border-l-2 border-blood-600 pl-3 font-mono text-[11px] text-neutral-300">
            {msg}
          </p>
        )}
      </div>

      {/* Tool versions */}
      <div className="card p-5">
        <div className="mb-3 flex items-center justify-between">
          <div className="font-mono text-xs uppercase tracking-wider text-neutral-400">
            installed engines
          </div>
          <button className="btn-ghost" onClick={loadVersions}>
            refresh
          </button>
        </div>
        {versions === null ? (
          <Spinner label="querying tool versions..." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="px-3 py-1.5 text-left font-mono text-[10px] uppercase tracking-wider text-neutral-600">
                    engine
                  </th>
                  <th className="px-3 py-1.5 text-left font-mono text-[10px] uppercase tracking-wider text-neutral-600">
                    version
                  </th>
                </tr>
              </thead>
              <tbody>
                {versions.tools.map((t) => (
                  <tr key={t.name} className="border-t border-ink-700">
                    <td className="px-3 py-1.5 font-mono text-xs text-blood-500">
                      {t.name}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs text-neutral-300">
                      {t.version}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-4 font-mono text-[11px] leading-relaxed text-neutral-600">
          Engines are third-party OSS by ProjectDiscovery (MIT), pinned at image build
          time. To upgrade the binaries themselves, rebuild the worker image
          (<span className="text-neutral-400">docker compose build worker</span>).
        </p>
      </div>
    </div>
  );
}
