import type { Severity } from "./types";

export const remediationTickets: Array<{ id: string; title: string; system: "ServiceNow" | "Jira"; owner: string; status: "Open" | "In Change" | "Blocked" | "Ready to Close"; priority: Severity; due: string }> = [
  { id: "CHG0042191", title: "Promote WAF virtual patch waf-rules#419 to production", system: "ServiceNow", owner: "AppSec Engineering", status: "In Change", priority: "Critical", due: "2026-04-30 18:00 IST" },
  { id: "JIRA-CRVM-883", title: "Close reopened AWS Security Group egress path", system: "Jira", owner: "Cloud Platform", status: "Open", priority: "High", due: "2026-05-01 12:00 IST" },
  { id: "CHG0042230", title: "Patch API gateway golden image after virtual patch validation", system: "ServiceNow", owner: "Platform Engineering", status: "Blocked", priority: "Critical", due: "2026-05-02 20:00 IST" }
];

export const ingestionRuns = [
  { id: "ingest-001", source: "EY CRVM", records: 1247, normalized: 1238, rejected: 9, status: "Healthy" },
  { id: "ingest-002", source: "Wiz", records: 214, normalized: 214, rejected: 0, status: "Healthy" },
  { id: "ingest-003", source: "Tenable", records: 642, normalized: 617, rejected: 25, status: "Warning" },
  { id: "ingest-004", source: "Qualys", records: 488, normalized: 481, rejected: 7, status: "Healthy" }
] as const;

export const executiveReports = [
  { id: "report-board", title: "Board risk reduction pack", audience: "Board", sections: ["Top attack paths", "Residual severity movement", "Patch-mandatory exceptions", "SLA heat"], status: "Ready" },
  { id: "report-audit", title: "Audit evidence pack", audience: "Audit", sections: ["Approvals", "Virtual patch validation", "IaC pull requests", "Drift history"], status: "Needs Evidence" },
  { id: "report-ops", title: "Daily operations brief", audience: "Operations", sections: ["Owner queues", "Blocked changes", "Connector health", "Open drift"], status: "Ready" }
] as const;
