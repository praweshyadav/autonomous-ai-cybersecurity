"use client";

import { useEffect, useState } from "react";

type Incident = {
  incident_id: string;
  start_time: string;
  end_time: string;
  severity: string;
  primary_attack_family: string;
  confidence: number;
  event_count: number;
  source_ips: string[];
  destination_ips: string[];
  destination_ports: number[];
  protocols: number[];
  family_distribution: Record<string, number>;
};

const API_BASE = "";

export default function Home() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadIncidents() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_BASE}/api/incidents`, {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const data: Incident[] = await response.json();
      setIncidents(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to the cybersecurity API."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(loadIncidents, 10000);

    return () => clearInterval(interval);
  }, []);

  const totalIncidents = incidents.length;
  const criticalIncidents = incidents.filter(
    (incident) => incident.severity.toLowerCase() === "critical"
  ).length;
  const highIncidents = incidents.filter(
    (incident) => incident.severity.toLowerCase() === "high"
  ).length;
  const totalEvents = incidents.reduce(
    (total, incident) => total + incident.event_count,
    0
  );

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.25em] text-cyan-400">
              Autonomous AI Cybersecurity
            </p>
            <h1 className="mt-1 text-2xl font-bold">
              Security Operations Dashboard
            </h1>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            API Connected
          </div>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-6 py-8">
        {error && (
          <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">
            <p className="font-semibold">Backend connection error</p>
            <p className="mt-1 text-sm">{error}</p>
            <button
              onClick={loadIncidents}
              className="mt-3 rounded-lg bg-red-500/20 px-3 py-2 text-sm font-medium hover:bg-red-500/30"
            >
              Retry
            </button>
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="Total Incidents"
            value={totalIncidents}
            description="Persisted security incidents"
          />

          <MetricCard
            title="Critical"
            value={criticalIncidents}
            description="Critical-severity incidents"
          />

          <MetricCard
            title="High Severity"
            value={highIncidents}
            description="High-severity incidents"
          />

          <MetricCard
            title="Security Events"
            value={totalEvents}
            description="Events across incidents"
          />
        </div>

        <section className="mt-8 overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">
          <div className="flex items-center justify-between border-b border-slate-800 px-6 py-5">
            <div>
              <h2 className="text-lg font-semibold">Recent Incidents</h2>
              <p className="mt-1 text-sm text-slate-400">
                Data retrieved from PostgreSQL through the FastAPI backend.
              </p>
            </div>

            <button
              onClick={loadIncidents}
              className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
            >
              Refresh
            </button>
          </div>

          {loading ? (
            <div className="px-6 py-12 text-center text-slate-400">
              Loading incidents...
            </div>
          ) : incidents.length === 0 ? (
            <div className="px-6 py-12 text-center">
              <p className="text-lg font-medium text-slate-300">
                No incidents found
              </p>
              <p className="mt-2 text-sm text-slate-500">
                The detection pipeline has not currently persisted any
                incidents.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-950/50 text-xs uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-6 py-4">Incident</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">Attack Family</th>
                    <th className="px-6 py-4">Confidence</th>
                    <th className="px-6 py-4">Events</th>
                    <th className="px-6 py-4">Start Time</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800">
                  {incidents.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      className="hover:bg-slate-800/50"
                    >
                      <td className="px-6 py-4 font-mono text-cyan-400">
                        {incident.incident_id}
                      </td>

                      <td className="px-6 py-4">
                        <SeverityBadge severity={incident.severity} />
                      </td>

                      <td className="px-6 py-4 text-slate-300">
                        {incident.primary_attack_family}
                      </td>

                      <td className="px-6 py-4 text-slate-300">
                        {(incident.confidence * 100).toFixed(1)}%
                      </td>

                      <td className="px-6 py-4 text-slate-300">
                        {incident.event_count}
                      </td>

                      <td className="px-6 py-4 text-slate-400">
                        {new Date(incident.start_time).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <p className="mt-6 text-center text-xs text-slate-600">
          Incident data refreshes automatically every 10 seconds.
        </p>
      </section>
    </main>
  );
}

function MetricCard({
  title,
  value,
  description,
}: {
  title: string;
  value: number;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="mt-3 text-3xl font-bold">{value}</p>
      <p className="mt-2 text-xs text-slate-500">{description}</p>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();

  const className =
    normalized === "critical"
      ? "border-red-500/30 bg-red-500/10 text-red-400"
      : normalized === "high"
        ? "border-orange-500/30 bg-orange-500/10 text-orange-400"
        : normalized === "medium"
          ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
          : "border-slate-600 bg-slate-800 text-slate-300";

  return (
    <span
      className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase ${className}`}
    >
      {severity}
    </span>
  );
}


