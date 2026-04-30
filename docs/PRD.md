# CRVM Attack Path Control Center PRD

## Product Name

CRVM Attack Path Control Center

## Problem Statement

The client already has Wiz, which reports fewer vulnerabilities and is easier to explain to management. EY CRVM discovers broader exposure and can surface thousands of vulnerabilities, but a large raw count is hard to operationalize. The required product is not another vulnerability counter. It must reduce real exploitable risk by breaking attack paths, validating compensating controls, and proving residual severity reduction with governance.

## Product Positioning

CRVM Attack Path Control Center turns CRVM into a control orchestration layer. It correlates Wiz, CRVM, SIEM, firewall, cloud firewall, ticketing, and vulnerability scanner signals, then recommends and tracks the fastest defensible action: patch, virtual patch, firewall change, SIEM detection, IAM restriction, EDR hardening, configuration change, or governed exception.

## Built Capabilities

### Attack Path Risk Reduction

- Groups vulnerability findings by exploitable attack path and critical business service.
- Preserves original vulnerability severity and calculates residual severity separately.
- Prevents permanent closure for internet-exposed critical exploited findings unless patched.
- Shows compensating-control candidates when exploitability or blast radius can be materially reduced.

### Product Workbench

- Provides Command, Workbench, Governance, Integrations, and Reports views.
- Supports role context for CISO, vulnerability manager, SOC engineer, network engineer, and application owner.
- Includes search across attack paths, assets, and services.
- Provides operating actions for executive brief export and change creation.

### Connector Control Plane

Built connector coverage for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, Tenable, and Qualys. Each connector tracks status, last sync, coverage, and capability so the platform can show whether a risk decision is backed by current evidence.

### Automated IaC Pull Request Orchestration

- Firewall, IAM, AWS Security Group, Azure NSG, and WAF controls can carry an infrastructure-as-code pull request reference.
- The product models the PR as part of the control evidence package.
- A control is not treated as validated until the PR, approval, and reachability evidence are present.

### Virtual Patching

- Provides a dedicated virtual patching module for WAF, IPS, API gateway, RASP, and EDR enforcement points.
- Tracks CVE, protected asset, rule name, enforcement mode, confidence, false-positive risk, rollback plan, and expiry.
- Allows immediate residual severity reduction for validated virtual patches while keeping the permanent patch obligation visible.
- Supports emergency shielding when patch windows are delayed but exploit traffic is active.

### Approval Workflow and RBAC

- Built role-aware approval lanes for CISO, vulnerability manager, SOC engineer, network engineer, and application owner.
- Each risk decision has requester, approver, approval status, policy, and SLA metadata.
- Risk acceptance requires CISO approval, expiry, and validated compensating controls.

### Asset Owner Notification

- Built owner notification queue across ServiceNow, Jira, Email, and Teams-style channels.
- Notifications are tied to owners and operational messages such as firewall validation, detection evidence, and exception readiness.

### Evidence Packs

- Builds audit-ready evidence packs for each major risk reduction decision.
- Tracks artifact completeness across WAF logs, exploit replay results, firewall reachability tests, SIEM validation, ServiceNow approvals, IAM diffs, and owner sign-off.
- Gives management a clear answer to whether risk reduction is proven or only planned.

### SLA Heat and Escalation

- Highlights at-risk and breached queues such as internet-exposed criticals, pending evidence, and drift remediation.
- Recommends next action for each queue so operating teams know where to focus.
- Helps management distinguish blocked patch work from fast compensating-control progress.

### Ingestion Pipeline Monitor

- Shows ingestion health for EY CRVM, Wiz, Tenable, and Qualys.
- Tracks received, normalized, and rejected records so data quality issues are visible.
- Separates connector health from data normalization health.

### Remediation Work Queue

- Shows ServiceNow and Jira remediation tickets with owner, priority, status, and due date.
- Tracks blocked changes and ready-to-close items so operational teams can work directly from the product.

### Report Packs

- Produces board, audit, CISO, and operations report packs.
- Each report pack shows audience, readiness, and included sections.
- Keeps evidence completeness visible before an audit or board pack is treated as ready.

### LLM-Assisted Executive Brief

- Generates a management-ready narrative explaining what risk was reduced, what remains patch-mandatory, and why CRVM volume is being converted into attack-path actions.
- Keeps executive messaging grounded in the same control and validation data shown to operators.

### Continuous Attack Path Drift Monitoring

- Tracks drift signals by attack path and source system.
- Reopens risk when firewall, SIEM, IAM, virtual patch, or cloud firewall controls no longer match the approved state.
- Shows validated, drift detected, and pending evidence states.

### Real-Time Validation

- Models real-time validation from SIEM and firewall APIs through connector status, last sync, control evidence, and drift events.
- Separates selected controls from validated controls so management cannot confuse intent with implemented risk reduction.

## Core Workflows

1. Ingest CRVM, Wiz, Tenable, and Qualys findings.
2. Group findings into attack paths and business services.
3. Recommend breakpoints across firewall, SIEM, IAM, EDR, patching, and configuration.
4. Deploy virtual patches for exposed services when permanent patching requires a maintenance window.
5. Generate IaC pull request references for network and cloud-firewall changes.
6. Route approvals using RBAC policy.
7. Notify asset owners through ticketing or collaboration channels.
8. Build evidence packs and SLA escalation views.
9. Triage remediation tickets in the Workbench view.
10. Monitor ingestion quality in the Integrations view.
11. Generate board, audit, and operations report packs.
12. Validate controls through SIEM/firewall/cloud connector evidence.
13. Recalculate residual severity and executive impact.
14. Monitor for drift and reopen risk if controls degrade.

## Acceptance Criteria

- The product displays CRVM findings grouped by attack path.
- The product compares CRVM-only signals against Wiz-visible signals.
- The product includes connector state for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, Tenable, and Qualys.
- The product shows IaC pull request references for applicable controls.
- The product includes virtual patch plans with enforcement point, confidence, rollback plan, and expiry.
- The product shows approval status, RBAC requester/approver roles, and SLA.
- The product shows owner notifications and delivery status.
- The product shows evidence-pack completeness and SLA heat.
- The product includes ingestion pipeline monitoring.
- The product includes ServiceNow/Jira remediation work queues.
- The product includes board, audit, CISO, and operations report packs.
- The product supports multi-view navigation and role context.
- The product generates an executive brief from current risk and control context.
- The product shows drift and validation state by source system.
- Tests cover downgrade guardrails, virtual patching behavior, product operations modules, and enterprise workflow data.
