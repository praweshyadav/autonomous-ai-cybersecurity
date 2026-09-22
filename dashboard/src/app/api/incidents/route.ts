import { NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL;

export async function GET() {
  const apiKey = process.env.API_KEY;

  if (!apiKey) {
    return NextResponse.json(
      { detail: "Dashboard API key is not configured." },
      { status: 500 }
    );
  }

  try {
    const response = await fetch(`${API_BASE}/api/v1/incidents`, {
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    });

    const data = await response.json();

    return NextResponse.json(data, {
      status: response.status,
    });
  } catch {
    return NextResponse.json(
      { detail: "Unable to connect to the cybersecurity API." },
      { status: 502 }
    );
  }
}
