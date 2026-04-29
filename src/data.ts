import type { AttackPath } from "./types";

export const attackPaths: AttackPath[] = [
  {
    id: "path-internet-to-crown-jewel",
    name: "Internet edge to payments database",
    entry: "api-gateway-prod",
    target: "payments-db-primary",
    blastRadius: 10,
    findings: [
      {
        id: "finding-001",
        cve: "CVE-2024-3094",
        title: "Compromised compression package on public API host",
        asset: "api-gateway-prod",
        service: "Digital Payments",
        source: "Both",
        rawSeverity: "Critical",
        cvss: 9.8,
        exploitAvailable: true,
        internetExposed: true,
        privilegedAsset: false,
        lateralMovement: true,
        businessCriticality: 5,
        techniques: ["T1190", "T1059", "T1021"],
        controls: ["WAF", "EDR"]
      },
      {
        id: "finding-002",
        cve: "CVE-2023-3519",
        title: "Gateway appliance remote code execution",
        asset: "edge-vpn-02",
        service: "Corporate Access",
        source: "Wiz",
        rawSeverity: "Critical",
        cvss: 9.6,
        exploitAvailable: true,
        internetExposed: true,
        privilegedAsset: true,
        lateralMovement: true,
        businessCriticality: 5,
        techniques: ["T1190", "T1133", "T1021"],
        controls: ["MFA"]
      }
    ],
    recommendations: [
      {
        id: "ctrl-fw-payments-edge",
        type: "Firewall",
        title: "Restrict payment API management plane",
        description: "Allowlist management access and block direct east-west access from api-gateway-prod to payments-db-primary.",
        owner: "Network Security",
        effort: "Medium",
        reduction: 2.1,
        evidence: "Approved firewall change, before/after reachability test, and rule expiry review."
      },
      {
        id: "ctrl-siem-t1190",
        type: "SIEM",
        title: "Detect public exploit chain activity",
        description: "Add detections for T1190, T1059, and suspicious API gateway child processes.",
        owner: "SOC Engineering",
        effort: "Low",
        reduction: 1.1,
        evidence: "SIEM rule ID, test event, alert routing, and tuning owner."
      },
      {
        id: "ctrl-patch-CVE-2024-3094",
        type: "Patch",
        title: "Patch CVE-2024-3094 on api-gateway-prod",
        description: "Upgrade affected package and rebuild the public API gateway image.",
        owner: "Platform Engineering",
        effort: "High",
        reduction: 8.5,
        evidence: "Golden image build, vulnerability rescan, and deployment record.",
        mandatory: true
      }
    ]
  },
  {
    id: "path-workload-identity",
    name: "Container workload to privileged cloud role",
    entry: "claims-worker",
    target: "prod-admin-role",
    blastRadius: 8,
    findings: [
      {
        id: "finding-003",
        cve: "CVE-2024-21626",
        title: "Container escape risk on claims worker node",
        asset: "eks-nodepool-claims",
        service: "Insurance Claims",
        source: "EY CRVM",
        rawSeverity: "High",
        cvss: 8.6,
        exploitAvailable: true,
        internetExposed: false,
        privilegedAsset: true,
        lateralMovement: true,
        businessCriticality: 4,
        techniques: ["T1611", "T1068", "T1552"],
        controls: ["Runtime EDR"]
      },
      {
        id: "finding-004",
        cve: "CWE-250",
        title: "Over-privileged service account can assume admin role",
        asset: "claims-worker-sa",
        service: "Insurance Claims",
        source: "EY CRVM",
        rawSeverity: "High",
        cvss: 7.4,
        exploitAvailable: false,
        internetExposed: false,
        privilegedAsset: true,
        lateralMovement: true,
        businessCriticality: 4,
        techniques: ["T1552", "T1078", "T1098"],
        controls: ["CloudTrail"]
      }
    ],
    recommendations: [
      {
        id: "ctrl-iam-claims-admin",
        type: "IAM",
        title: "Remove admin role assumption from claims worker",
        description: "Replace broad role assumption with least-privilege task role and deny privileged session chaining.",
        owner: "Cloud Platform",
        effort: "Medium",
        reduction: 2.4,
        evidence: "IAM policy diff, access analyzer result, and successful application regression test."
      },
      {
        id: "ctrl-edr-container-escape",
        type: "EDR",
        title: "Enforce container escape runtime guardrail",
        description: "Block privileged container launches and alert on namespace escape indicators.",
        owner: "Endpoint Security",
        effort: "Low",
        reduction: 1.4,
        evidence: "Policy ID, enforcement mode, and simulated escape test result."
      },
      {
        id: "ctrl-siem-t1611",
        type: "SIEM",
        title: "Detect container escape and credential access",
        description: "Add detections for T1611, T1552, unexpected role assumption, and kubelet anomaly patterns.",
        owner: "SOC Engineering",
        effort: "Low",
        reduction: 1,
        evidence: "Detection rule, sample event, alert destination, and response playbook."
      }
    ]
  },
  {
    id: "path-office-to-erp",
    name: "Office subnet to ERP administrator workstation",
    entry: "office-wifi-segment",
    target: "erp-admin-ws-07",
    blastRadius: 6,
    findings: [
      {
        id: "finding-005",
        cve: "CVE-2023-21716",
        title: "Office parser remote code execution exposure",
        asset: "erp-admin-ws-07",
        service: "Finance ERP",
        source: "EY CRVM",
        rawSeverity: "High",
        cvss: 7.8,
        exploitAvailable: true,
        internetExposed: false,
        privilegedAsset: true,
        lateralMovement: false,
        businessCriticality: 5,
        techniques: ["T1204", "T1059", "T1003"],
        controls: ["Email Gateway", "EDR"]
      }
    ],
    recommendations: [
      {
        id: "ctrl-config-office-macros",
        type: "Configuration",
        title: "Harden Office file execution policy",
        description: "Disable untrusted macros and enforce protected view for ERP admin workstation group.",
        owner: "Desktop Engineering",
        effort: "Low",
        reduction: 1.8,
        evidence: "GPO or MDM profile, target group, and endpoint validation screenshot."
      },
      {
        id: "ctrl-risk-accept-erp",
        type: "Risk Acceptance",
        title: "Temporary exception with 30 day expiry",
        description: "Permit temporary downgrade only after compensating controls are validated and ERP patch window is scheduled.",
        owner: "Application Risk Owner",
        effort: "Low",
        reduction: 0.4,
        evidence: "Risk approval, business justification, expiry date, and planned patch ticket.",
        expiryDays: 30
      },
      {
        id: "ctrl-patch-CVE-2023-21716",
        type: "Patch",
        title: "Patch CVE-2023-21716 on erp-admin-ws-07",
        description: "Deploy the Office security update during the next ERP admin maintenance window.",
        owner: "Desktop Engineering",
        effort: "Medium",
        reduction: 6.8,
        evidence: "Patch deployment ring, reboot confirmation, and rescan result."
      }
    ]
  }
];
