// What the search window (Cmd+K) finds in SIEM: events with the text, rules by title or tag, and open signals by rule
// or host.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Bell, ListFilter, ShieldCheck } from "lucide-react";
import type { Rule, Signal } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [rules, signals] = await Promise.all([
      call<{ rules: Rule[] }>("/api/v1/rules?limit=500", { signal }),
      call<{ signals: Signal[] }>("/api/v1/signals?limit=500", { signal }),
    ]);
    const has = (...texts: string[]) => texts.some((x) => x.toLowerCase().includes(q));
    return [
      {
        id: "events",
        label: t("search.eventsWith", { text: q }),
        kind: t("search.events"),
        icon: ListFilter,
        href: `/events?${new URLSearchParams({ q })}`,
      },
      ...signals.signals
        .filter((s) => has(s.rule.title, s.host))
        .slice(0, 6)
        .map((s): SearchResult => ({
          id: `signal:${s.id}`,
          label: s.rule.title,
          detail: t("search.signalDetail", { host: s.host, count: s.count }),
          kind: t("search.signal"),
          icon: Bell,
          severity: s.severity,
          href: `/?${new URLSearchParams({ host: s.host })}`,
        })),
      ...rules.rules
        .filter((r) => has(r.title, ...r.tags))
        .slice(0, 6)
        .map((r): SearchResult => ({
          id: `rule:${r.id}`,
          label: r.title,
          detail: r.enabled ? t("search.ruleDetail", { matches: r.matches }) : t("search.disabled"),
          kind: t("search.rule"),
          icon: ShieldCheck,
          severity: r.level,
          href: "/rules",
        })),
    ];
  };
}
