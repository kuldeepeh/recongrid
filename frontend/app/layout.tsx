import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "ReconGrid — Attack Surface Management",
  description: "Self-hosted ASM. Orchestration over ProjectDiscovery recon tools.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-blood-gradient font-sans">
        <div className="relative z-10">
          <header className="border-b border-ink-600 bg-ink-950/60 backdrop-blur">
            <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
              <Link href="/" className="group flex items-center gap-2">
                <span className="text-blood-500 text-lg font-mono font-bold tracking-tight group-hover:animate-pulse-glow">
                  ▚ RECON<span className="text-neutral-200">GRID</span>
                </span>
              </Link>
              <nav className="flex items-center gap-4 font-mono text-xs uppercase tracking-wider text-neutral-400">
                <Link href="/" className="hover:text-blood-500">
                  targets
                </Link>
                <Link href="/profiles" className="hover:text-blood-500">
                  profiles
                </Link>
                <Link href="/maintenance" className="hover:text-blood-500">
                  maintenance
                </Link>
                <form action="/login" method="get">
                  <button className="hover:text-blood-500" type="submit">
                    logout
                  </button>
                </form>
              </nav>
            </div>
            <div className="h-px w-full bg-blood-line opacity-40" />
          </header>
          <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
          <footer className="mx-auto max-w-7xl px-6 pb-10 pt-4">
            <p className="border-t border-ink-700 pt-3 font-mono text-[11px] leading-relaxed text-neutral-600">
              Recon engines (Subfinder · DNSX · HTTPX · Naabu · Katana · Nuclei) are
              third-party OSS by{" "}
              <span className="text-neutral-400">ProjectDiscovery</span> (MIT). ReconGrid
              provides orchestration, scheduling, historical diffing and the dashboard —
              not the scanning logic. Authorized targets only.
            </p>
          </footer>
        </div>
      </body>
    </html>
  );
}
