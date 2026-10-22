// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  events: number;
  eventsLastDay: number;
  rules: { total: number; enabled: number; failing: number };
  /** Open signals (new or being investigated) by severity. */
  signals: Record<string, number>;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="siem",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_siem_events Events kept.",
    "# TYPE openasy_siem_events gauge",
    `openasy_siem_events ${g.events}`,
    "# HELP openasy_siem_events_last_day Events received in the last 24 hours.",
    "# TYPE openasy_siem_events_last_day gauge",
    `openasy_siem_events_last_day ${g.eventsLastDay}`,
    "# HELP openasy_siem_rules Detection rules by state.",
    "# TYPE openasy_siem_rules gauge",
    `openasy_siem_rules{state="enabled"} ${g.rules.enabled}`,
    `openasy_siem_rules{state="disabled"} ${g.rules.total - g.rules.enabled}`,
    `openasy_siem_rules{state="failing"} ${g.rules.failing}`,
    "# HELP openasy_siem_open_signals Open signals by severity.",
    "# TYPE openasy_siem_open_signals gauge",
    ...Object.entries(g.signals).map(([s, n]) => `openasy_siem_open_signals{severity="${s}"} ${n}`),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
