export const runtime = "nodejs";

const CACHE_DURATION = 15 * 60 * 1000;
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 4;

type VirusTotalResponse = {
  data?: {
    attributes?: {
      last_analysis_stats?: {
        harmless?: number;
        malicious?: number;
        suspicious?: number;
        undetected?: number;
        timeout?: number;
      };
      last_analysis_date?: number;
      reputation?: number;
      categories?: Record<string, string>;
      title?: string;
    };
  };
};

type PublicResult = {
  found: boolean;
  message?: string;
  stats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
    timeout: number;
  };
  reputation?: number;
  categories?: Record<string, string>;
  title?: string | null;
  lastAnalysisDate?: string | null;
};

type CacheEntry = {
  expiresAt: number;
  result: PublicResult;
};

const reportCache = new Map<string, CacheEntry>();

let rateLimitWindowStarted = Date.now();
let requestsInCurrentWindow = 0;

function getCachedResult(identifier: string) {
  const cached = reportCache.get(identifier);

  if (!cached) return null;

  if (cached.expiresAt <= Date.now()) {
    reportCache.delete(identifier);
    return null;
  }

  return cached.result;
}

function cacheResult(identifier: string, result: PublicResult) {
  reportCache.set(identifier, {
    expiresAt: Date.now() + CACHE_DURATION,
    result,
  });
}

function canRequestVirusTotal() {
  const now = Date.now();

  if (now - rateLimitWindowStarted >= RATE_LIMIT_WINDOW) {
    rateLimitWindowStarted = now;
    requestsInCurrentWindow = 0;
  }

  if (requestsInCurrentWindow >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }

  requestsInCurrentWindow += 1;
  return true;
}

export async function POST(request: Request) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return Response.json(
      { error: "VirusTotal API key is not configured." },
      { status: 500 }
    );
  }

  try {
    const body = await request.json();
    const submittedUrl =
      typeof body?.url === "string" ? body.url.trim() : "";

    if (!submittedUrl) {
      return Response.json(
        { error: "A URL is required." },
        { status: 400 }
      );
    }

    if (submittedUrl.length > 2048) {
      return Response.json(
        { error: "The submitted URL is too long." },
        { status: 400 }
      );
    }

    const normalizedUrl =
      submittedUrl.startsWith("http://") ||
      submittedUrl.startsWith("https://")
        ? submittedUrl
        : `https://${submittedUrl}`;

    const parsedUrl = new URL(normalizedUrl);

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return Response.json(
        { error: "Only HTTP and HTTPS URLs are supported." },
        { status: 400 }
      );
    }

    if (parsedUrl.username || parsedUrl.password) {
      return Response.json(
        { error: "URLs containing credentials are not supported." },
        { status: 400 }
      );
    }

    const urlIdentifier = Buffer.from(normalizedUrl)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    const cachedResult = getCachedResult(urlIdentifier);

    if (cachedResult) {
      return Response.json({
        ...cachedResult,
        cached: true,
      });
    }

    if (!canRequestVirusTotal()) {
      return Response.json(
        {
          error:
            "The threat-intelligence request limit was reached. Please wait one minute.",
        },
        { status: 429 }
      );
    }

    const virusTotalResponse = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlIdentifier}`,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          "x-apikey": apiKey,
        },
        cache: "no-store",
      }
    );

    if (virusTotalResponse.status === 404) {
      const result: PublicResult = {
        found: false,
        message: "VirusTotal has no existing report for this URL.",
      };

      cacheResult(urlIdentifier, result);

      return Response.json(result);
    }

    if (virusTotalResponse.status === 429) {
      return Response.json(
        {
          error:
            "VirusTotal request limit reached. Please wait before trying again.",
        },
        { status: 429 }
      );
    }

    if (virusTotalResponse.status === 401) {
      return Response.json(
        { error: "VirusTotal rejected the configured API key." },
        { status: 401 }
      );
    }

    if (!virusTotalResponse.ok) {
      return Response.json(
        { error: "VirusTotal could not complete the reputation lookup." },
        { status: 502 }
      );
    }

    const responseData =
      (await virusTotalResponse.json()) as VirusTotalResponse;

    const attributes = responseData.data?.attributes;
    const stats = attributes?.last_analysis_stats;

    const result: PublicResult = {
      found: true,
      stats: {
        harmless: stats?.harmless ?? 0,
        malicious: stats?.malicious ?? 0,
        suspicious: stats?.suspicious ?? 0,
        undetected: stats?.undetected ?? 0,
        timeout: stats?.timeout ?? 0,
      },
      reputation: attributes?.reputation ?? 0,
      categories: attributes?.categories ?? {},
      title: attributes?.title ?? null,
      lastAnalysisDate: attributes?.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : null,
    };

    cacheResult(urlIdentifier, result);

    return Response.json(result);
  } catch {
    return Response.json(
      { error: "The URL could not be analyzed." },
      { status: 400 }
    );
  }
}