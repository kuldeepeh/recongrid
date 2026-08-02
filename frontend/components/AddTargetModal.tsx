"use client";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";

export function AddTargetModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [step, setStep] = useState<1 | 2>(1);
  const [name, setName] = useState("");
  const [rootDomain, setRootDomain] = useState("");
  const [projectType, setProjectType] = useState<"temporary" | "permanent">(
    "permanent"
  );
  const [note, setNote] = useState("");
  const [targetId, setTargetId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function createTarget(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const t = await api.createTarget({
        name,
        root_domain: rootDomain,
        project_type: projectType,
      });
      setTargetId(t.id);
      setStep(2);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  async function confirmAuth(e: React.FormEvent) {
    e.preventDefault();
    if (!targetId) return;
    setBusy(true);
    setError(null);
    try {
      await api.confirmAuthorization(targetId, note);
      onCreated();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="card w-full max-w-lg p-6 shadow-glow">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-mono text-sm uppercase tracking-wider text-blood-500">
            {step === 1 ? "// new target" : "// authorization gate"}
          </h2>
          <button onClick={onClose} className="text-neutral-500 hover:text-blood-500">
            ✕
          </button>
        </div>

        {step === 1 ? (
          <form onSubmit={createTarget} className="space-y-4">
            <div>
              <label className="label">name</label>
              <input
                className="input"
                value={name}
                autoFocus
                onChange={(e) => setName(e.target.value)}
                placeholder="Local Lab"
                required
              />
            </div>
            <div>
              <label className="label">root domain / host</label>
              <input
                className="input"
                value={rootDomain}
                onChange={(e) => setRootDomain(e.target.value)}
                placeholder="localhost"
                required
              />
            </div>
            <div>
              <label className="label">project type</label>
              <div className="grid grid-cols-2 gap-2">
                {(["permanent", "temporary"] as const).map((pt) => (
                  <button
                    key={pt}
                    type="button"
                    onClick={() => setProjectType(pt)}
                    className={`btn ${
                      projectType === pt
                        ? "border-blood-600 text-blood-500 bg-blood-900/40"
                        : "border-ink-600 text-neutral-400"
                    }`}
                  >
                    {pt}
                  </button>
                ))}
              </div>
              <p className="mt-2 font-mono text-[11px] text-neutral-600">
                {projectType === "temporary"
                  ? "auto-deleted after 7 days of inactivity"
                  : "kept until you delete it"}
              </p>
            </div>
            {error && <p className="font-mono text-xs text-blood-500">! {error}</p>}
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={onClose} className="btn-ghost">
                cancel
              </button>
              <button className="btn-primary" disabled={busy}>
                {busy ? "..." : "next"}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={confirmAuth} className="space-y-4">
            <div className="border border-blood-700 bg-blood-900/20 p-3">
              <p className="font-mono text-xs leading-relaxed text-neutral-300">
                Active reconnaissance is only lawful against systems you own or have
                written authorization to test. Confirm you are authorized to scan{" "}
                <span className="text-blood-500">{rootDomain}</span>.
              </p>
            </div>
            <div>
              <label className="label">authorization attestation (min 10 chars)</label>
              <textarea
                className="input h-24 resize-none"
                value={note}
                autoFocus
                onChange={(e) => setNote(e.target.value)}
                placeholder="I own this host / I have written authorization ref #..."
                required
                minLength={10}
              />
            </div>
            {error && <p className="font-mono text-xs text-blood-500">! {error}</p>}
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={onClose} className="btn-ghost">
                skip for now
              </button>
              <button className="btn-primary" disabled={busy || note.length < 10}>
                {busy ? "..." : "authorize + save"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
