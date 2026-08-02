"use client";
import { useEffect, useState } from "react";
import { api, ScanProfile, ToolSchema } from "@/lib/api";
import { Spinner } from "@/components/ui";

export default function ProfilesPage() {
  const [profiles, setProfiles] = useState<ScanProfile[] | null>(null);
  const [schema, setSchema] = useState<ToolSchema | null>(null);

  useEffect(() => {
    api.listProfiles().then(setProfiles).catch(() => setProfiles([]));
    api.toolSchema().then(setSchema).catch(() => {});
  }, []);

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-mono text-xl font-bold text-neutral-100">
          <span className="text-blood-500">//</span> scan profiles
        </h1>
        <p className="font-mono text-xs text-neutral-500">
          named tool-option bundles · one default applied to new scans
        </p>
      </div>

      {profiles === null ? (
        <Spinner />
      ) : (
        <div className="mb-8 grid gap-3 sm:grid-cols-2">
          {profiles.map((p) => (
            <div key={p.id} className="card p-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm text-neutral-100">{p.name}</span>
                {p.is_default && <span className="chip sevlow">default</span>}
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {(p.tool_config.enabled_stages || []).map((s: string) => (
                  <span key={s} className="chip sevinfo">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {schema && (
        <div className="card p-5">
          <div className="label">per-tool allowlist (advanced mode)</div>
          <p className="mb-4 font-mono text-[11px] text-neutral-600">
            Default mode runs the base command only. Advanced mode exposes these
            curated flags — never the tool&apos;s full --help. Anything not listed
            here cannot reach the command line.
          </p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(schema.tools).map(([tool, t]) => (
              <div key={tool} className="border border-ink-600 p-3">
                <div className="font-mono text-xs font-semibold text-blood-500">
                  {tool}
                </div>
                <div className="mt-1 font-mono text-[10px] text-neutral-500">
                  base: {t.base_flags.join(" ")}
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {t.advanced_keys.map((k) => (
                    <span key={k} className="chip sevinfo">
                      {k}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
