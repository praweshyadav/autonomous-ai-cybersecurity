import { NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL;

export const maxDuration = 120;

export async function GET() {
  const apiKey = process.env.API_KEY;

  if (!API_BASE) {
    return NextResponse.json(
      { detail: "Dashboard API base URL is not configured." },
      { status: 500 }
    );
  }

  if (!apiKey) {
    return NextResponse.json(
      { detail: "Dashboard API key is not configured." },
      { status: 500 }
    );
  }

  const headers = {
    Authorization: `Bearer ${apiKey}`,
  };

  for (let attempt = 1; attempt <= 2; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 90000);

    try {
      const response = await fetch(`${API_BASE}/api/v1/incidents`, {
        cache: "no-store",
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const data = await response.json();

      return NextResponse.json(data, {
        status: response.status,
      });
    } catch (error) {
      clearTimeout(timeout);

      if (attempt === 2) {
        console.error("Cybersecurity API request failed:", error);

        return NextResponse.json(
          {
            detail:
              "Unable to connect to the cybersecurity API. The backend may still be waking up.",
          },
          { status: 502 }
        );
      }

      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }

  return NextResponse.json(
    { detail: "Unable to connect to the cybersecurity API." },
    { status: 502 }
  );
}
