"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, Target } from "@/lib/api";
import { AddTargetModal } from "@/components/AddTargetModal";
import { EmptyState, Spinner } from "@/components/ui";

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  async function load() {
    try {
      setTargets(await api.listTargets());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) router.push("/login");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-neutral-100">
            <span className="text-blood-500">//</span> targets
          </h1>
          <p className="font-mono text-xs text-neutral-500">
            attack surfaces under continuous watch
          </p>
        </div>
        <button className="btn-primary" onClick={() => setShowAdd(true)}>
          + add target
        </button>
      </div>

      {targets === null ? (
        <Spinner label="loading targets..." />
      ) : targets.length === 0 ? (
        <EmptyState>
          no targets yet — add your authorized lab to begin
        </EmptyState>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {targets.map((t) => (
            <Link
              key={t.id}
              href={`/targets/${t.id}`}
              className="card card-hover group p-5"
            >
              <div className="mb-2 flex items-start justify-between">
                <div>
                  <div className="font-mono text-sm font-semibold text-neutral-100 group-hover:text-blood-500">
                    {t.name}
                  </div>
                  <div className="font-mono text-xs text-neutral-500">
                    {t.root_domain}
                  </div>
                </div>
                <span
                  className={`chip ${
                    t.is_authorized ? "sevlow" : "sevhigh"
                  }`}
                >
                  {t.is_authorized ? "authorized" : "unconfirmed"}
                </span>
              </div>
              <div className="mt-4 flex items-center gap-2 font-mono text-[11px] text-neutral-500">
                <span className="chip sevinfo">{t.project_type}</span>
                {t.project_type === "temporary" && t.expires_at && (
                  <span className="text-amber-500/80">
                    expires {new Date(t.expires_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}

      {showAdd && (
        <AddTargetModal onClose={() => setShowAdd(false)} onCreated={load} />
      )}
    </div>
  );
}
