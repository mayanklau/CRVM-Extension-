export type Severity = "Critical" | "High" | "Medium" | "Low";

export type ControlType =
  | "Patch"
  | "Firewall"
  | "SIEM"
  | "EDR"
  | "IAM"
  | "Configuration"
  | "Risk Acceptance";

export type Effort = "Low" | "Medium" | "High";
export type ConnectorStatus = "Connected" | "Needs Attention" | "Not Configured";
export type ConnectorCategory = "Cloud Risk" | "Vulnerability" | "Ticketing" | "SIEM" | "Firewall" | "Cloud Firewall";
export type ApprovalStatus = "Draft" | "Pending Approval" | "Approved" | "Rejected";
export type ValidationStatus = "Validated" | "Drift Detected" | "Pending Evidence";
export type Role = "CISO" | "Vulnerability Manager" | "SOC Engineer" | "Network Engineer" | "Application Owner";

export interface ControlRecommendation {
  id: string;
  type: ControlType;
  title: string;
  description: string;
  owner: string;
  effort: Effort;
  reduction: number;
  evidence: string;
  expiryDays?: number;
  mandatory?: boolean;
  approvalStatus?: ApprovalStatus;
  validationStatus?: ValidationStatus;
  lastValidated?: string;
  iacPullRequest?: string;
  notificationTarget?: string;
}

export interface Finding {
  id: string;
  cve: string;
  title: string;
  asset: string;
  service: string;
  source: "EY CRVM" | "Wiz" | "Both";
  rawSeverity: Severity;
  cvss: number;
  exploitAvailable: boolean;
  internetExposed: boolean;
  privilegedAsset: boolean;
  lateralMovement: boolean;
  businessCriticality: number;
  techniques: string[];
  controls: string[];
}

export interface AttackPath {
  id: string;
  name: string;
  entry: string;
  target: string;
  blastRadius: number;
  findings: Finding[];
  recommendations: ControlRecommendation[];
}

export interface RiskResult {
  inherentScore: number;
  residualScore: number;
  rawSeverity: Severity;
  residualSeverity: Severity;
  downgradeAllowed: boolean;
  patchMandatory: boolean;
  rationale: string[];
}

export interface PortfolioSummary {
  totalFindings: number;
  wizVisibleFindings: number;
  crvmOnlyFindings: number;
  criticalPaths: number;
  mandatoryPatchFindings: number;
  compensatingControlCandidates: number;
  averageResidualReduction: number;
}

export interface Connector {
  id: string;
  name: string;
  category: ConnectorCategory;
  status: ConnectorStatus;
  lastSync: string;
  coverage: number;
  capability: string;
}

export interface ApprovalDecision {
  id: string;
  controlId: string;
  requester: Role;
  approver: Role;
  status: ApprovalStatus;
  policy: string;
  dueInHours: number;
}

export interface OwnerNotification {
  id: string;
  owner: string;
  channel: "Email" | "ServiceNow" | "Jira" | "Teams";
  message: string;
  status: "Queued" | "Sent" | "Acknowledged";
}

export interface DriftSignal {
  id: string;
  pathId: string;
  source: string;
  signal: string;
  status: ValidationStatus;
  detectedAt: string;
}

export interface ExecutiveBrief {
  headline: string;
  narrative: string;
  talkingPoints: string[];
}
