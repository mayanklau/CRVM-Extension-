# CRVM Extension Product Requirements Document

## Product Name

CRVM Attack Path Control Center

## Problem Statement

Enterprise clients already use vulnerability platforms such as Wiz that report a smaller, prioritized vulnerability set. EY CRVM can discover a broader inventory, sometimes surfacing thousands of vulnerabilities. Security and management teams struggle to operationalize that volume, especially when patching everything is unrealistic.

The client does not want another dashboard that only counts vulnerabilities. They need a capability that reduces exploitable risk by breaking attack paths through firewall changes, SIEM detection rules, compensating controls, exception governance, and risk scoring degradation when exposure is materially reduced. They are also concerned about MITRE ATT&CK / Mythos-style discovery and lateral movement paths that may not be obvious from raw CVE lists.

## Product Vision

Turn CRVM from a vulnerability reporting agent into a risk reduction planner that recommends the fastest defensible way to break attack paths, reduce severity, and create management-ready remediation plans.

## Goals

- Reduce vulnerability overload by grouping findings into exploitable attack paths and business services.
- Recommend compensating controls when patching is not immediately feasible.
- Simulate how firewall changes, SIEM detections, EDR hardening, IAM restrictions, and segmentation reduce residual risk.
- Provide management-friendly evidence showing why a vulnerability can be downgraded, accepted temporarily, or prioritized for patching.
- Keep auditability: every downgrade must have a reason, control mapping, owner, expiry, and evidence requirement.
- Complement Wiz rather than compete with it by enriching Wiz/CRVM findings with attack path and control recommendations.

## Non-Goals

- Replace Wiz, SIEM, firewall managers, ticketing systems, or patch management tools.
- Automatically push firewall or SIEM changes without approval workflows.
- Hide vulnerabilities without compensating controls and governance.
- Claim a vulnerability is fixed when only exploitability has been reduced.

## Target Users

- CISO / security leadership: wants a reduced, defensible risk posture.
- Vulnerability manager: needs prioritization and remediation planning.
- SOC engineer: needs detection logic and SIEM rule updates.
- Network security engineer: needs firewall / segmentation changes.
- Application owner: needs clear remediation recommendations and deadlines.
- Auditor / risk committee: needs evidence for downgraded severity and exceptions.

## Core Use Cases

1. As a vulnerability manager, I can ingest or view CRVM findings and see the attack paths they participate in.
2. As a SOC engineer, I can see recommended SIEM rules mapped to MITRE ATT&CK techniques.
3. As a network security engineer, I can see firewall rule recommendations that break internet exposure or lateral movement.
4. As a CISO, I can compare raw severity against residual severity after controls.
5. As an application owner, I can see whether the required action is patching, configuration hardening, segmentation, detection, or exception approval.
6. As an auditor, I can see why severity was downgraded, what evidence supports it, and when the exception expires.

## MVP Scope

### 1. Attack Path Graph

- Display assets, entry points, identities, and critical business services.
- Show vulnerability count by attack path rather than flat CVE count.
- Highlight paths with internet exposure, privilege escalation, lateral movement, or critical data access.

### 2. Risk Degradation Simulator

- Calculate inherent score from severity, exploitability, exposure, asset criticality, and lateral movement potential.
- Calculate residual score after selected compensating controls.
- Show severity downgrade only when controls materially reduce exploitability or blast radius.
- Preserve original severity and distinguish it from residual severity.

### 3. Control Recommendation Engine

Recommend actions across patching, firewall, SIEM, EDR, IAM, configuration hardening, and temporary risk acceptance. Each recommendation includes expected risk reduction, owner, effort, evidence, and approval requirement.

### 4. Management Summary

- Show total raw vulnerabilities.
- Show prioritized attack paths.
- Show risk reduced without immediate patching.
- Show mandatory patch items that cannot be safely downgraded.
- Show control backlog by owner.

### 5. Governance

- Every downgrade requires a selected control, evidence, owner, and expiry.
- Controls expire automatically and return findings to prior residual state if not revalidated.
- Audit log records the rationale for score change.

## Future Scope

- Connectors for Wiz, ServiceNow, Splunk, Microsoft Sentinel, Palo Alto, Check Point, AWS Security Groups, Azure NSGs, Jira, and Tenable / Qualys.
- Automated pull requests for infrastructure-as-code firewall changes.
- Approval workflow and RBAC.
- Asset owner notification.
- LLM-assisted natural language executive briefings.
- Continuous attack path drift monitoring.
- Real-time validation from SIEM/firewall APIs.

## Product Principles

- Risk reduction over vulnerability counting.
- Transparent degradation, never silent suppression.
- Compensating controls must be evidence-backed.
- Business context matters as much as CVSS.
- Patch when required, compensate when justified, accept only with governance.

## Success Metrics

- 60% reduction in management-facing vulnerability volume through grouping and path-based prioritization.
- 30% reduction in critical exploitable attack paths within 90 days.
- 90% of downgraded findings have complete evidence, owner, and expiry metadata.
- Mean time to risk reduction decreases by 40% compared with patch-only remediation.
- 100% of critical internet-exposed exploitable vulnerabilities remain patch-mandatory unless a strong compensating control is approved.

## Data Model

### Finding

ID, CVE or weakness, asset, business service, raw severity, CVSS, exploitability, exposure, privilege context, lateral movement potential, existing controls, and source system.

### Attack Path

ID, entry asset, intermediate assets or identities, target service, techniques, findings, blast radius, and recommended breakpoints.

### Control

Type, description, owner, effort, expected reduction, evidence requirement, expiry, and approval status.

### Risk Decision

Inherent score, residual score, original severity, residual severity, degradation rationale, linked controls, approver, and review date.

## MVP Acceptance Criteria

- A user can see raw vulnerabilities grouped into attack paths.
- A user can choose recommended controls and see residual severity change.
- The product clearly distinguishes patch-required items from compensating-control candidates.
- The management view explains reduced risk without hiding original vulnerability volume.
- The codebase includes reusable risk scoring logic with tests.
- The product can run locally with a single install and start command.
