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
