"use client";

import { FormEvent, useState } from "react";

type VirusTotalStats = {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
};

type VirusTotalResult = {
  found: boolean;
  message?: string;
  stats?: VirusTotalStats;
  reputation?: number;
  categories?: Record<string, string>;
  title?: string | null;
  lastAnalysisDate?: string | null;
  error?: string;
};

type AnalysisResult = {
  normalizedUrl: string;
  domain: string;
  score: number;
  level: "Low Risk" | "Suspicious" | "High Risk";
  findings: string[];
  virusTotal: VirusTotalResult | null;
  virusTotalError: string;
};

function getRiskLevel(
  score: number
): "Low Risk" | "Suspicious" | "High Risk" {
  if (score >= 60) return "High Risk";
  if (score >= 25) return "Suspicious";
  return "Low Risk";
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyzeUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);

    try {
      const normalizedInput =
        url.startsWith("http://") || url.startsWith("https://")
          ? url.trim()
          : `https://${url.trim()}`;

      const parsedUrl = new URL(normalizedInput);

      if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        throw new Error("Unsupported protocol");
      }

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
        findings.push("Contains internationalized domain encoding");
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

      if (domain.split(".").length > 4) {
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

      let virusTotal: VirusTotalResult | null = null;
      let virusTotalError = "";

      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url: normalizedInput }),
        });

        const data = (await response.json()) as VirusTotalResult;

        if (!response.ok) {
          throw new Error(data.error || "Threat-intelligence lookup failed");
        }

        virusTotal = data;

        if (data.found && data.stats) {
          const { malicious, suspicious } = data.stats;
          let intelligenceScore = 0;

          if (malicious >= 5) {
            intelligenceScore = 100;
          } else if (malicious >= 2) {
            intelligenceScore = 85;
          } else if (malicious === 1) {
            intelligenceScore = 65;
          } else if (suspicious > 0) {
            intelligenceScore = 45;
          }

          score = Math.max(score, intelligenceScore);

          if (malicious > 0) {
            findings.push(
              `VirusTotal: ${malicious} security engines marked this URL malicious`
            );
          }

          if (suspicious > 0) {
            findings.push(
              `VirusTotal: ${suspicious} security engines marked this URL suspicious`
            );
          }
        }
      } catch (threatError) {
        virusTotalError =
          threatError instanceof Error
            ? threatError.message
            : "Threat-intelligence lookup failed";
      }

      if (findings.length === 0) {
        findings.push("No obvious structural phishing indicators detected");
      }

      setResult({
        normalizedUrl: normalizedInput,
        domain,
        score,
        level: getRiskLevel(score),
        findings,
        virusTotal,
        virusTotalError,
      });
    } catch {
      setError("Enter a valid HTTP or HTTPS URL, such as example.com");
    } finally {
      setLoading(false);
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

  const categories = result?.virusTotal?.categories
    ? [...new Set(Object.values(result.virusTotal.categories))].slice(0, 4)
    : [];

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
            Inspect suspicious links using structural analysis and live
            VirusTotal threat intelligence without opening the destination.
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
                disabled={loading}
                className="rounded-xl bg-cyan-500 px-7 py-4 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading ? "Analyzing..." : "Analyze URL"}
              </button>
            </div>

            {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
          </form>

          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {[
              ["Static Inspection", "Does not open the submitted link"],
              ["Risk Scoring", "Evaluates structural URL indicators"],
              ["Threat Intelligence", "Checks existing VirusTotal reports"],
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
          <>
            <section className="mt-8 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 md:p-10">
              <div className="flex flex-col justify-between gap-5 md:flex-row">
                <div>
                  <p className="text-sm text-slate-500">Combined assessment</p>
                  <h2 className={`mt-1 text-3xl font-bold ${riskColor}`}>
                    {result.level}
                  </h2>
                </div>

                <div className="md:text-right">
                  <p className="text-sm text-slate-500">Risk score</p>
                  <p className="mt-1 text-3xl font-bold">
                    {result.score}/100
                  </p>
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

            <section className="mt-8 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 md:p-10">
              <div className="flex flex-col justify-between gap-2 md:flex-row">
                <div>
                  <p className="text-sm text-cyan-400">
                    Live threat intelligence
                  </p>
                  <h2 className="mt-1 text-2xl font-bold">
                    VirusTotal Reputation
                  </h2>
                </div>

                {result.virusTotal?.title && (
                  <p className="text-sm text-slate-400">
                    {result.virusTotal.title}
                  </p>
                )}
              </div>

              {result.virusTotalError && (
                <div className="mt-6 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-300">
                  {result.virusTotalError}
                </div>
              )}

              {result.virusTotal &&
                !result.virusTotal.found &&
                !result.virusTotalError && (
                  <div className="mt-6 rounded-xl border border-slate-700 bg-slate-950/60 p-4 text-sm text-slate-400">
                    {result.virusTotal.message}
                  </div>
                )}

              {result.virusTotal?.found && result.virusTotal.stats && (
                <>
                  <div className="mt-7 grid grid-cols-2 gap-4 md:grid-cols-4">
                    {[
                      [
                        "Harmless",
                        result.virusTotal.stats.harmless,
                        "text-emerald-400",
                      ],
                      [
                        "Malicious",
                        result.virusTotal.stats.malicious,
                        "text-red-400",
                      ],
                      [
                        "Suspicious",
                        result.virusTotal.stats.suspicious,
                        "text-amber-400",
                      ],
                      [
                        "Undetected",
                        result.virusTotal.stats.undetected,
                        "text-slate-300",
                      ],
                    ].map(([label, value, color]) => (
                      <div
                        key={String(label)}
                        className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 text-center"
                      >
                        <p className={`text-3xl font-bold ${color}`}>
                          {value}
                        </p>
                        <p className="mt-2 text-sm text-slate-500">{label}</p>
                      </div>
                    ))}
                  </div>

                  <div className="mt-6 grid gap-4 md:grid-cols-2">
                    <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
                      <p className="text-sm text-slate-500">
                        Community reputation
                      </p>
                      <p className="mt-2 text-xl font-semibold text-cyan-300">
                        {result.virusTotal.reputation ?? 0}
                      </p>
                    </div>

                    <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5">
                      <p className="text-sm text-slate-500">Last analysis</p>
                      <p className="mt-2 text-sm text-slate-300">
                        {result.virusTotal.lastAnalysisDate
                          ? new Date(
                              result.virusTotal.lastAnalysisDate
                            ).toLocaleString()
                          : "Not available"}
                      </p>
                    </div>
                  </div>

                  {categories.length > 0 && (
                    <div className="mt-6">
                      <p className="text-sm text-slate-500">Categories</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {categories.map((category) => (
                          <span
                            key={category}
                            className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-300"
                          >
                            {category}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </section>
          </>
        )}

        <footer className="mt-10 text-center text-sm text-slate-600">
          Built by Fayyad Dahweesh · Defensive Security Project
          <p className="mt-2">
            Results support investigation and do not guarantee that a URL is
            safe.
          </p>
        </footer>
      </div>
    </main>
  );
}