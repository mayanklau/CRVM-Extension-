# CRVM Attack Path Control Center PRD

## Product Name

CRVM Attack Path Control Center

## Problem Statement

The client already has Wiz, which reports fewer vulnerabilities and is easier to explain to management. EY CRVM discovers broader exposure and can surface thousands of vulnerabilities, but a large raw count is hard to operationalize. The required product is not another vulnerability counter. It must reduce real exploitable risk by breaking attack paths, validating compensating controls, and proving residual severity reduction with governance.

## Product Positioning

CRVM Attack Path Control Center turns CRVM into a control orchestration layer. It correlates Wiz, CRVM, SIEM, firewall, cloud firewall, ticketing, and vulnerability scanner signals, then recommends and tracks the fastest defensible action: patch, firewall change, SIEM detection, IAM restriction, EDR hardening, configuration change, or governed exception.

## Built Capabilities

### Attack Path Risk Reduction

- Groups vulnerability findings by exploitable attack path and critical business service.
- Preserves original vulnerability severity and calculates residual severity separately.
- Prevents soft downgrades for internet-exposed critical exploited findings unless patched.
- Shows compensating-control candidates when exploitability or blast radius can be materially reduced.

### Connector Control Plane

Built connector coverage for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, Tenable, and Qualys. Each connector tracks status, last sync, coverage, and capability so the platform can show whether a risk decision is backed by current evidence.

### Automated IaC Pull Request Orchestration

- Firewall, IAM, AWS Security Group, and Azure NSG controls can carry an infrastructure-as-code pull request reference.
- The product models the PR as part of the control evidence package.
- A control is not treated as validated until the PR, approval, and reachability evidence are present.

### Approval Workflow and RBAC

- Built role-aware approval lanes for CISO, vulnerability manager, SOC engineer, network engineer, and application owner.
- Each risk decision has requester, approver, approval status, policy, and SLA metadata.
- Risk acceptance requires CISO approval, expiry, and validated compensating controls.

### Asset Owner Notification

- Built owner notification queue across ServiceNow, Jira, Email, and Teams-style channels.
- Notifications are tied to owners and operational messages such as firewall validation, detection evidence, and exception readiness.

### LLM-Assisted Executive Brief

- Generates a management-ready narrative explaining what risk was reduced, what remains patch-mandatory, and why CRVM volume is being converted into attack-path actions.
- Keeps executive messaging grounded in the same control and validation data shown to operators.

### Continuous Attack Path Drift Monitoring

- Tracks drift signals by attack path and source system.
- Reopens risk when firewall, SIEM, IAM, or cloud firewall controls no longer match the approved state.
- Shows validated, drift detected, and pending evidence states.

### Real-Time Validation

- Models real-time validation from SIEM and firewall APIs through connector status, last sync, control evidence, and drift events.
- Separates selected controls from validated controls so management cannot confuse intent with implemented risk reduction.

## Target Users

- CISO: needs an executive view of risk reduction and governance.
- Vulnerability manager: needs path-based prioritization and defensible residual severity.
- SOC engineer: needs detection-rule changes and validation evidence.
- Network security engineer: needs firewall and segmentation breakpoints.
- Cloud platform engineer: needs AWS Security Group, Azure NSG, and IAM change tracking.
- Application owner: needs approval tasks, patch obligations, and exception context.
- Auditor / risk committee: needs evidence, owner, expiry, approval, and validation trail.

## Core Workflows

1. Ingest CRVM, Wiz, Tenable, and Qualys findings.
2. Group findings into attack paths and business services.
3. Recommend breakpoints across firewall, SIEM, IAM, EDR, patching, and configuration.
4. Generate IaC pull request references for network and cloud-firewall changes.
5. Route approvals using RBAC policy.
6. Notify asset owners through ticketing or collaboration channels.
7. Validate controls through SIEM/firewall/cloud connector evidence.
8. Recalculate residual severity and executive impact.
9. Monitor for drift and reopen risk if controls degrade.

## Acceptance Criteria

- The product displays CRVM findings grouped by attack path.
- The product compares CRVM-only signals against Wiz-visible signals.
- The product includes connector state for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, Tenable, and Qualys.
- The product shows IaC pull request references for applicable controls.
- The product shows approval status, RBAC requester/approver roles, and SLA.
- The product shows owner notifications and delivery status.
- The product generates an executive brief from current risk and control context.
- The product shows drift and validation state by source system.
- Tests cover downgrade guardrails and enterprise workflow data.
