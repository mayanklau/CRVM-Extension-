# CRVM Attack Path Control Center

Production-grade product for extending EY CRVM from vulnerability counting into attack-path risk reduction, connector validation, approval workflow, and executive reporting.

## What It Does

- Groups high-volume vulnerability findings into attack paths.
- Recommends firewall, SIEM, IAM, EDR, patching, and governance actions.
- Simulates residual severity after compensating controls.
- Creates management-ready risk reduction views without hiding original severity.
- Connects the operating model for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, Tenable, and Qualys.
- Tracks automated infrastructure-as-code pull request references for firewall, cloud firewall, and IAM changes.
- Includes approval workflow, RBAC roles, owner notifications, LLM-assisted executive briefs, drift monitoring, and real-time validation states.
- Adds virtual patching for WAF, IPS, API gateway, RASP, and EDR shielding when patch windows cannot move fast enough.
- Produces evidence packs and SLA heat insights so leaders can see which mitigations are proven, expiring, or overdue.
- Adds a multi-view product shell with Command, Workbench, Governance, Integrations, and Reports views.
- Includes ingestion pipeline status, remediation ticket queues, report packs, role context, search, and operating actions.

## Product Modules

- Attack path dashboard
- Residual risk and severity degradation engine
- Connector health control plane
- Virtual patching command center
- IaC pull request orchestration
- Approval workflow and RBAC lane
- Asset owner notification queue
- Evidence pack builder
- SLA heat and escalation view
- Ingestion pipeline monitor
- Remediation work queue
- Board, audit, CISO, and operations report packs
- Executive brief generator
- Continuous drift and validation monitor

## Run Locally

```bash
npm install
npm run dev
```

## Test

```bash
npm test
```

## Product Requirements

See [docs/PRD.md](docs/PRD.md).
