"use client";

import { FormEvent, useState } from "react";

type AnalysisResult = {
  normalizedUrl: string;
  domain: string;
  score: number;
  level: "Low Risk" | "Suspicious" | "High Risk";
  findings: string[];
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");

  function analyzeUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);

    try {
      const normalizedInput = url.startsWith("http://") ||
        url.startsWith("https://")
        ? url
        : `https://${url}`;

      const parsedUrl = new URL(normalizedInput);
      const domain = parsedUrl.hostname.toLowerCase();
      const findings: string[] = [];
      let score = 0;

      if (parsedUrl.protocol !== "https:") {
        score += 20;
        findings.push("Connection does not use HTTPS");
      }

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        score += 30;
        findings.push("Uses an IP address instead of a domain name");
      }

      if (normalizedInput.includes("@")) {
        score += 25;
        findings.push("Contains an @ symbol that may hide the destination");
      }

      if (domain.includes("xn--")) {
        score += 25;
        findings.push("Contains an internationalized domain encoding");
      }

      if (normalizedInput.length > 100) {
        score += 15;
        findings.push("URL is unusually long");
      }

      const suspiciousWords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "banking",
        "confirm",
        "wallet",
        "invoice",
      ];

      const detectedWords = suspiciousWords.filter((word) =>
        normalizedInput.toLowerCase().includes(word)
      );

      if (detectedWords.length > 0) {
        score += Math.min(detectedWords.length * 8, 24);
        findings.push(
          `Suspicious keywords detected: ${detectedWords.join(", ")}`
        );
      }

      const domainParts = domain.split(".");

      if (domainParts.length > 4) {
        score += 15;
        findings.push("Contains an unusually high number of subdomains");
      }

      const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
      ];

      if (shorteners.includes(domain)) {
        score += 20;
        findings.push("Uses a URL-shortening service");
      }

      score = Math.min(score, 100);

      let level: AnalysisResult["level"] = "Low Risk";

      if (score >= 60) {
        level = "High Risk";
      } else if (score >= 25) {
        level = "Suspicious";
      }

      if (findings.length === 0) {
        findings.push("No obvious structural phishing indicators detected");
      }

      setResult({
        normalizedUrl: normalizedInput,
        domain,
        score,
        level,
        findings,
      });
    } catch {
      setError("Enter a valid URL or domain, such as example.com");
    }
  }

  const riskColor =
    result?.level === "High Risk"
      ? "text-red-400"
      : result?.level === "Suspicious"
        ? "text-amber-400"
        : "text-emerald-400";

  const riskBar =
    result?.level === "High Risk"
      ? "bg-red-500"
      : result?.level === "Suspicious"
        ? "bg-amber-500"
        : "bg-emerald-500";

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-12 text-slate-100">
      <div className="mx-auto max-w-5xl">
        <header className="mb-12 text-center">
          <div className="mb-4 inline-flex rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-300">
            Cybersecurity Intelligence Tool
          </div>

          <h1 className="text-4xl font-bold tracking-tight md:text-6xl">
            Phishing URL
            <span className="text-cyan-400"> Analyzer</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-slate-400">
            Inspect suspicious links and identify common phishing indicators
            without opening the destination.
          </p>
        </header>

        <section className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-2xl shadow-cyan-950/30 md:p-10">
          <form onSubmit={analyzeUrl}>
            <label
              htmlFor="url"
              className="mb-3 block text-sm font-medium text-slate-300"
            >
              Suspicious URL
            </label>

            <div className="flex flex-col gap-3 md:flex-row">
              <input
                id="url"
                type="text"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/login"
                className="flex-1 rounded-xl border border-slate-700 bg-slate-950 px-5 py-4 text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
              />

              <button
                type="submit"
                className="rounded-xl bg-cyan-500 px-7 py-4 font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Analyze URL
              </button>
            </div>

            {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
          </form>

          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {[
              ["Static Inspection", "Does not open the submitted link"],
              ["Risk Scoring", "Evaluates structural URL indicators"],
              ["Threat Intelligence", "VirusTotal integration coming next"],
            ].map(([title, description]) => (
              <div
                key={title}
                className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5"
              >
                <h2 className="font-semibold text-cyan-300">{title}</h2>
                <p className="mt-2 text-sm text-slate-500">{description}</p>
              </div>
            ))}
          </div>
        </section>

        {result && (
          <section className="mt-8 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 md:p-10">
            <div className="flex flex-col justify-between gap-5 md:flex-row">
              <div>
                <p className="text-sm text-slate-500">Analysis result</p>
                <h2 className={`mt-1 text-3xl font-bold ${riskColor}`}>
                  {result.level}
                </h2>
              </div>

              <div className="md:text-right">
                <p className="text-sm text-slate-500">Risk score</p>
                <p className="mt-1 text-3xl font-bold">{result.score}/100</p>
              </div>
            </div>

            <div className="mt-6 h-3 overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full rounded-full transition-all duration-700 ${riskBar}`}
                style={{ width: `${Math.max(result.score, 3)}%` }}
              />
            </div>

            <div className="mt-8 grid gap-6 md:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
                <p className="text-sm text-slate-500">Resolved domain</p>
                <p className="mt-2 break-all font-mono text-cyan-300">
                  {result.domain}
                </p>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
                <p className="text-sm text-slate-500">Normalized URL</p>
                <p className="mt-2 break-all font-mono text-slate-300">
                  {result.normalizedUrl}
                </p>
              </div>
            </div>

            <div className="mt-6">
              <h3 className="font-semibold">Detected indicators</h3>

              <div className="mt-3 space-y-3">
                {result.findings.map((finding) => (
                  <div
                    key={finding}
                    className="flex gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-300"
                  >
                    <span className="text-cyan-400">●</span>
                    <span>{finding}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        <footer className="mt-10 text-center text-sm text-slate-600">
          Built by Fayyad Dahweesh · Defensive Security Project
        </footer>
      </div>
    </main>
  );
}