import type { ApprovalDecision, AttackPath, Connector, DriftSignal, EvidencePack, ExecutiveBrief, OwnerNotification, SlaInsight, VirtualPatchPlan } from "./types";

export const attackPaths: AttackPath[] = [
  {
    id: "path-internet-to-crown-jewel",
    name: "Internet edge to payments database",
    entry: "api-gateway-prod",
    target: "payments-db-primary",
    blastRadius: 10,
    findings: [
      { id: "finding-001", cve: "CVE-2024-3094", title: "Compromised compression package on public API host", asset: "api-gateway-prod", service: "Digital Payments", source: "Both", rawSeverity: "Critical", cvss: 9.8, exploitAvailable: true, internetExposed: true, privilegedAsset: false, lateralMovement: true, businessCriticality: 5, techniques: ["T1190", "T1059", "T1021"], controls: ["WAF", "EDR"] },
      { id: "finding-002", cve: "CVE-2023-3519", title: "Gateway appliance remote code execution", asset: "edge-vpn-02", service: "Corporate Access", source: "Wiz", rawSeverity: "Critical", cvss: 9.6, exploitAvailable: true, internetExposed: true, privilegedAsset: true, lateralMovement: true, businessCriticality: 5, techniques: ["T1190", "T1133", "T1021"], controls: ["MFA"] }
    ],
    recommendations: [
      { id: "ctrl-vpatch-CVE-2024-3094", type: "Virtual Patch", title: "Deploy WAF virtual patch for CVE-2024-3094 exploit chain", description: "Block known exploit payload patterns, suspicious compression library probes, and API gateway command injection indicators at the edge.", owner: "AppSec Engineering", effort: "Low", reduction: 2.6, evidence: "WAF rule in block mode, benign traffic replay, exploit simulation blocked, and rollback rule prepared.", approvalStatus: "Approved", validationStatus: "Validated", lastValidated: "2026-04-30 00:31 IST", iacPullRequest: "waf-rules#419", notificationTarget: "AppSec Engineering" },
      { id: "ctrl-fw-payments-edge", type: "Firewall", title: "Restrict payment API management plane", description: "Allowlist management access and block direct east-west access from api-gateway-prod to payments-db-primary.", owner: "Network Security", effort: "Medium", reduction: 2.1, evidence: "Approved firewall change, before/after reachability test, and rule expiry review.", approvalStatus: "Approved", validationStatus: "Validated", lastValidated: "2026-04-30 00:14 IST", iacPullRequest: "infra-firewall#1842", notificationTarget: "Network Security" },
      { id: "ctrl-siem-t1190", type: "SIEM", title: "Detect public exploit chain activity", description: "Add detections for T1190, T1059, and suspicious API gateway child processes.", owner: "SOC Engineering", effort: "Low", reduction: 1.1, evidence: "SIEM rule ID, test event, alert routing, and tuning owner.", approvalStatus: "Approved", validationStatus: "Validated", lastValidated: "2026-04-30 00:18 IST", notificationTarget: "SOC Engineering" },
      { id: "ctrl-patch-CVE-2024-3094", type: "Patch", title: "Patch CVE-2024-3094 on api-gateway-prod", description: "Upgrade affected package and rebuild the public API gateway image.", owner: "Platform Engineering", effort: "High", reduction: 8.5, evidence: "Golden image build, vulnerability rescan, and deployment record.", mandatory: true, approvalStatus: "Pending Approval", validationStatus: "Pending Evidence", notificationTarget: "Platform Engineering" }
    ]
  },
  {
    id: "path-workload-identity",
    name: "Container workload to privileged cloud role",
    entry: "claims-worker",
    target: "prod-admin-role",
    blastRadius: 8,
    findings: [
      { id: "finding-003", cve: "CVE-2024-21626", title: "Container escape risk on claims worker node", asset: "eks-nodepool-claims", service: "Insurance Claims", source: "EY CRVM", rawSeverity: "High", cvss: 8.6, exploitAvailable: true, internetExposed: false, privilegedAsset: true, lateralMovement: true, businessCriticality: 4, techniques: ["T1611", "T1068", "T1552"], controls: ["Runtime EDR"] },
      { id: "finding-004", cve: "CWE-250", title: "Over-privileged service account can assume admin role", asset: "claims-worker-sa", service: "Insurance Claims", source: "EY CRVM", rawSeverity: "High", cvss: 7.4, exploitAvailable: false, internetExposed: false, privilegedAsset: true, lateralMovement: true, businessCriticality: 4, techniques: ["T1552", "T1078", "T1098"], controls: ["CloudTrail"] }
    ],
    recommendations: [
      { id: "ctrl-iam-claims-admin", type: "IAM", title: "Remove admin role assumption from claims worker", description: "Replace broad role assumption with least-privilege task role and deny privileged session chaining.", owner: "Cloud Platform", effort: "Medium", reduction: 2.4, evidence: "IAM policy diff, access analyzer result, and successful application regression test.", approvalStatus: "Approved", validationStatus: "Validated", lastValidated: "2026-04-30 00:22 IST", iacPullRequest: "cloud-iam#772", notificationTarget: "Cloud Platform" },
      { id: "ctrl-edr-container-escape", type: "EDR", title: "Enforce container escape runtime guardrail", description: "Block privileged container launches and alert on namespace escape indicators.", owner: "Endpoint Security", effort: "Low", reduction: 1.4, evidence: "Policy ID, enforcement mode, and simulated escape test result.", approvalStatus: "Pending Approval", validationStatus: "Pending Evidence", notificationTarget: "Endpoint Security" },
      { id: "ctrl-siem-t1611", type: "SIEM", title: "Detect container escape and credential access", description: "Add detections for T1611, T1552, unexpected role assumption, and kubelet anomaly patterns.", owner: "SOC Engineering", effort: "Low", reduction: 1, evidence: "Detection rule, sample event, alert destination, and response playbook.", approvalStatus: "Approved", validationStatus: "Validated", lastValidated: "2026-04-30 00:25 IST", notificationTarget: "SOC Engineering" }
    ]
  },
  {
    id: "path-office-to-erp",
    name: "Office subnet to ERP administrator workstation",
    entry: "office-wifi-segment",
    target: "erp-admin-ws-07",
    blastRadius: 6,
    findings: [
      { id: "finding-005", cve: "CVE-2023-21716", title: "Office parser remote code execution exposure", asset: "erp-admin-ws-07", service: "Finance ERP", source: "EY CRVM", rawSeverity: "High", cvss: 7.8, exploitAvailable: true, internetExposed: false, privilegedAsset: true, lateralMovement: false, businessCriticality: 5, techniques: ["T1204", "T1059", "T1003"], controls: ["Email Gateway", "EDR"] }
    ],
    recommendations: [
      { id: "ctrl-config-office-macros", type: "Configuration", title: "Harden Office file execution policy", description: "Disable untrusted macros and enforce protected view for ERP admin workstation group.", owner: "Desktop Engineering", effort: "Low", reduction: 1.8, evidence: "GPO or MDM profile, target group, and endpoint validation screenshot.", approvalStatus: "Pending Approval", validationStatus: "Pending Evidence", notificationTarget: "Desktop Engineering" },
      { id: "ctrl-risk-accept-erp", type: "Risk Acceptance", title: "Temporary exception with 30 day expiry", description: "Permit temporary downgrade only after compensating controls are validated and ERP patch window is scheduled.", owner: "Application Risk Owner", effort: "Low", reduction: 0.4, evidence: "Risk approval, business justification, expiry date, and planned patch ticket.", expiryDays: 30, approvalStatus: "Draft", validationStatus: "Pending Evidence", notificationTarget: "Application Risk Owner" },
      { id: "ctrl-patch-CVE-2023-21716", type: "Patch", title: "Patch CVE-2023-21716 on erp-admin-ws-07", description: "Deploy the Office security update during the next ERP admin maintenance window.", owner: "Desktop Engineering", effort: "Medium", reduction: 6.8, evidence: "Patch deployment ring, reboot confirmation, and rescan result.", approvalStatus: "Pending Approval", validationStatus: "Pending Evidence", notificationTarget: "Desktop Engineering" }
    ]
  }
];

export const connectors: Connector[] = [
  { id: "wiz", name: "Wiz", category: "Cloud Risk", status: "Connected", lastSync: "2026-04-30 00:26 IST", coverage: 92, capability: "Cloud exposure, toxic combinations, and asset context" },
  { id: "servicenow", name: "ServiceNow", category: "Ticketing", status: "Connected", lastSync: "2026-04-30 00:19 IST", coverage: 86, capability: "Change approvals, CMDB ownership, and remediation tasks" },
  { id: "splunk", name: "Splunk", category: "SIEM", status: "Connected", lastSync: "2026-04-30 00:18 IST", coverage: 78, capability: "Detection rule validation and alert telemetry" },
  { id: "sentinel", name: "Microsoft Sentinel", category: "SIEM", status: "Connected", lastSync: "2026-04-30 00:17 IST", coverage: 73, capability: "KQL analytics, incident evidence, and response status" },
  { id: "paloalto", name: "Palo Alto", category: "Firewall", status: "Connected", lastSync: "2026-04-30 00:14 IST", coverage: 81, capability: "Rule simulation, policy push readiness, and hit counts" },
  { id: "checkpoint", name: "Check Point", category: "Firewall", status: "Needs Attention", lastSync: "2026-04-29 21:40 IST", coverage: 54, capability: "Perimeter policy validation and stale rule discovery" },
  { id: "aws-sg", name: "AWS Security Groups", category: "Cloud Firewall", status: "Connected", lastSync: "2026-04-30 00:21 IST", coverage: 89, capability: "Security group reachability and IaC pull requests" },
  { id: "azure-nsg", name: "Azure NSGs", category: "Cloud Firewall", status: "Connected", lastSync: "2026-04-30 00:20 IST", coverage: 84, capability: "NSG rule validation and segmentation drift" },
  { id: "jira", name: "Jira", category: "Ticketing", status: "Connected", lastSync: "2026-04-30 00:16 IST", coverage: 75, capability: "Engineering backlog, owner notifications, and SLA tracking" },
  { id: "tenable", name: "Tenable", category: "Vulnerability", status: "Connected", lastSync: "2026-04-30 00:15 IST", coverage: 82, capability: "Scanner findings, rescans, and patch verification" },
  { id: "qualys", name: "Qualys", category: "Vulnerability", status: "Connected", lastSync: "2026-04-30 00:13 IST", coverage: 79, capability: "External exposure and vulnerability evidence" }
];

export const approvalDecisions: ApprovalDecision[] = [
  { id: "appr-001", controlId: "ctrl-fw-payments-edge", requester: "Vulnerability Manager", approver: "Network Engineer", status: "Approved", policy: "Firewall change requires network approval and test evidence", dueInHours: 0 },
  { id: "appr-002", controlId: "ctrl-patch-CVE-2024-3094", requester: "Vulnerability Manager", approver: "Application Owner", status: "Pending Approval", policy: "Critical internet-exposed patch requires app owner maintenance approval", dueInHours: 12 },
  { id: "appr-003", controlId: "ctrl-risk-accept-erp", requester: "Application Owner", approver: "CISO", status: "Draft", policy: "Risk acceptance requires CISO approval, expiry, and compensating controls", dueInHours: 24 }
];

export const ownerNotifications: OwnerNotification[] = [
  { id: "notify-001", owner: "Network Security", channel: "ServiceNow", message: "Firewall PR infra-firewall#1842 is ready for validation against payment API path.", status: "Acknowledged" },
  { id: "notify-002", owner: "SOC Engineering", channel: "Jira", message: "Detection changes for T1190 and T1611 require test event evidence.", status: "Sent" },
  { id: "notify-003", owner: "Application Risk Owner", channel: "Email", message: "ERP temporary exception cannot be approved until compensating controls are validated.", status: "Queued" }
];

export const driftSignals: DriftSignal[] = [
  { id: "drift-001", pathId: "path-internet-to-crown-jewel", source: "Palo Alto", signal: "No drift: segmentation rule still blocks direct API to payments database traffic.", status: "Validated", detectedAt: "2026-04-30 00:26 IST" },
  { id: "drift-002", pathId: "path-workload-identity", source: "AWS Security Groups", signal: "Drift detected: temporary nodepool egress rule reopened admin API path.", status: "Drift Detected", detectedAt: "2026-04-30 00:28 IST" },
  { id: "drift-003", pathId: "path-office-to-erp", source: "Microsoft Sentinel", signal: "Pending evidence: ERP workstation detection has not produced a test alert.", status: "Pending Evidence", detectedAt: "2026-04-30 00:24 IST" }
];

export const executiveBrief: ExecutiveBrief = {
  headline: "CRVM risk is reduced by breaking exploitable paths, virtual patching exposed services, and validating controls.",
  narrative: "The platform preserves the full CRVM finding count, compares it with Wiz visibility, and shows which attack paths are actually exploitable. Controls are converted into approved virtual patch, firewall, SIEM, IAM, EDR, and patch actions with validation evidence. Critical internet-exposed findings can be immediately shielded by validated virtual patches while the permanent patch obligation remains tracked.",
  talkingPoints: [
    "Management sees path-level risk reduction instead of thousands of ungrouped vulnerabilities.",
    "Security teams get owner-specific actions, approval status, WAF/IPS virtual patch state, and real-time evidence.",
    "Drift monitoring reopens risk when firewall, SIEM, or cloud controls stop matching the approved state."
  ]
};

export const virtualPatchPlans: VirtualPatchPlan[] = [
  { id: "vp-001", cve: "CVE-2024-3094", asset: "api-gateway-prod", enforcementPoint: "WAF", ruleName: "block-xz-backdoor-probe-and-shell-spawn", mode: "Block", confidence: 92, falsePositiveRisk: "Low", rollbackPlan: "Disable rule group waf-rules#419 and retain SIEM alert-only detection for 24 hours.", expiry: "2026-05-07" },
  { id: "vp-002", cve: "CVE-2023-3519", asset: "edge-vpn-02", enforcementPoint: "IPS", ruleName: "citrix-gateway-rce-payload-deny", mode: "Block", confidence: 88, falsePositiveRisk: "Medium", rollbackPlan: "Revert IPS signature override after emergency VPN patch window completes.", expiry: "2026-05-03" },
  { id: "vp-003", cve: "CVE-2023-21716", asset: "erp-admin-ws-07", enforcementPoint: "EDR", ruleName: "office-parser-child-process-containment", mode: "Monitor", confidence: 74, falsePositiveRisk: "Low", rollbackPlan: "Keep EDR rule in monitor mode until finance confirms macro workflow impact.", expiry: "2026-05-10" }
];

export const evidencePacks: EvidencePack[] = [
  { id: "evidence-001", title: "Payment API emergency shield", owner: "AppSec Engineering", completeness: 91, artifacts: ["WAF block logs", "Exploit replay result", "Firewall reachability test", "ServiceNow approval"] },
  { id: "evidence-002", title: "Claims workload privilege reduction", owner: "Cloud Platform", completeness: 83, artifacts: ["IAM diff", "Access Analyzer output", "Kubernetes regression test", "CloudTrail validation"] },
  { id: "evidence-003", title: "ERP workstation exception pack", owner: "Application Risk Owner", completeness: 57, artifacts: ["Patch ticket", "EDR monitor rule", "Owner approval pending"] }
];

export const slaInsights: SlaInsight[] = [
  { id: "sla-001", queue: "Internet-exposed criticals", atRisk: 2, breached: 0, nextAction: "Keep virtual patch in block mode until permanent patch is deployed." },
  { id: "sla-002", queue: "Pending evidence", atRisk: 4, breached: 1, nextAction: "Escalate missing ERP detection evidence to application owner." },
  { id: "sla-003", queue: "Drift remediation", atRisk: 1, breached: 0, nextAction: "Close reopened AWS Security Group egress path." }
];
