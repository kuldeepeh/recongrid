"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(password);
      router.push("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center">
      <form onSubmit={submit} className="card w-full max-w-sm p-8 shadow-glow">
        <div className="mb-6 text-center">
          <div className="font-mono text-2xl font-bold text-blood-500">
            ▚ RECON<span className="text-neutral-100">GRID</span>
          </div>
          <p className="mt-1 font-mono text-[11px] uppercase tracking-widest text-neutral-600">
            attack surface management
          </p>
        </div>
        <label className="label">admin password</label>
        <input
          type="password"
          className="input"
          value={password}
          autoFocus
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••••••"
        />
        {error && (
          <p className="mt-3 font-mono text-xs text-blood-500">! {error}</p>
        )}
        <button className="btn-primary mt-6 w-full" disabled={busy}>
          {busy ? "authenticating..." : "access"}
        </button>
      </form>
    </div>
  );
}
