export const runtime = "nodejs";

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
      return Response.json({
        found: false,
        message: "VirusTotal has no existing report for this URL.",
      });
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

    return Response.json({
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
    });
  } catch {
    return Response.json(
      { error: "The URL could not be analyzed." },
      { status: 400 }
    );
  }
}