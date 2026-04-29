import type { AttackPath, ControlRecommendation, Finding, PortfolioSummary, RiskResult, Severity } from "./types";

const severityFloor: Record<Severity, number> = {
  Critical: 9,
  High: 7,
  Medium: 4,
  Low: 1
};

export function scoreToSeverity(score: number): Severity {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export function calculateInherentScore(finding: Finding): number {
  const exploitBonus = finding.exploitAvailable ? 1.2 : 0;
  const exposureBonus = finding.internetExposed ? 1.1 : 0;
  const privilegeBonus = finding.privilegedAsset ? 0.8 : 0;
  const lateralBonus = finding.lateralMovement ? 0.7 : 0;
  const businessBonus = finding.businessCriticality * 0.25;
  return clampScore(Math.max(finding.cvss, severityFloor[finding.rawSeverity]) + exploitBonus + exposureBonus + privilegeBonus + lateralBonus + businessBonus);
}

export function calculateResidualRisk(finding: Finding, selectedControls: ControlRecommendation[]): RiskResult {
  const inherentScore = calculateInherentScore(finding);
  const totalReduction = selectedControls.reduce((sum, control) => sum + control.reduction, 0);
  const hasNetworkBreak = selectedControls.some((control) => control.type === "Firewall" || control.type === "IAM");
  const hasDetection = selectedControls.some((control) => control.type === "SIEM");
  const hasPatch = selectedControls.some((control) => control.type === "Patch");
  const hasGovernance = selectedControls.some((control) => control.type === "Risk Acceptance");
  const patchMandatory = finding.internetExposed && finding.exploitAvailable && finding.rawSeverity === "Critical";
  let residualScore = inherentScore - totalReduction;

  if (hasPatch) residualScore = Math.min(residualScore, 2.5);
  if (finding.lateralMovement && !hasNetworkBreak) residualScore += 0.6;
  if (finding.exploitAvailable && !hasDetection && !hasPatch) residualScore += 0.4;

  residualScore = clampScore(residualScore);
  const residualSeverity = scoreToSeverity(residualScore);
  const downgradeAllowed = !patchMandatory && residualSeverity !== finding.rawSeverity && selectedControls.length > 0 && (hasPatch || hasNetworkBreak || (hasDetection && hasGovernance));

  return {
    inherentScore,
    residualScore,
    rawSeverity: finding.rawSeverity,
    residualSeverity: downgradeAllowed || hasPatch ? residualSeverity : finding.rawSeverity,
    downgradeAllowed,
    patchMandatory,
    rationale: buildRationale(finding, selectedControls, patchMandatory, downgradeAllowed)
  };
}

export function summarizePortfolio(paths: AttackPath[], selectedControlIds: Set<string>): PortfolioSummary {
  const findings = paths.flatMap((path) => path.findings);
  const selectedControls = paths.flatMap((path) => path.recommendations).filter((control) => selectedControlIds.has(control.id));
  const results = findings.map((finding) => calculateResidualRisk(finding, selectedControlsForFinding(finding, selectedControls)));
  const totalReduction = results.reduce((sum, result) => sum + (result.inherentScore - result.residualScore), 0);

  return {
    totalFindings: findings.length,
    wizVisibleFindings: findings.filter((finding) => finding.source === "Wiz" || finding.source === "Both").length,
    crvmOnlyFindings: findings.filter((finding) => finding.source === "EY CRVM").length,
    criticalPaths: paths.filter((path) => path.blastRadius >= 8).length,
    mandatoryPatchFindings: results.filter((result) => result.patchMandatory).length,
    compensatingControlCandidates: results.filter((result) => !result.patchMandatory && result.inherentScore >= 7).length,
    averageResidualReduction: results.length === 0 ? 0 : Number((totalReduction / results.length).toFixed(1))
  };
}

export function selectedControlsForFinding(finding: Finding, selectedControls: ControlRecommendation[]): ControlRecommendation[] {
  return selectedControls.filter((control) => {
    if (control.type === "Patch") return control.title.includes(finding.cve);
    if (control.type === "SIEM") return finding.techniques.some((technique) => control.description.includes(technique));
    return true;
  });
}

function buildRationale(finding: Finding, selectedControls: ControlRecommendation[], patchMandatory: boolean, downgradeAllowed: boolean): string[] {
  const messages: string[] = [];
  if (patchMandatory) messages.push("Internet-exposed critical finding with known exploit remains patch-mandatory.");
  if (selectedControls.some((control) => control.type === "Firewall")) messages.push("Firewall or segmentation control breaks the reachable attack path.");
  if (selectedControls.some((control) => control.type === "SIEM")) messages.push("SIEM coverage improves detection for mapped ATT&CK techniques.");
  if (selectedControls.some((control) => control.type === "IAM")) messages.push("IAM restriction reduces privilege escalation and lateral movement.");
  if (selectedControls.some((control) => control.type === "Patch")) messages.push("Patch removes the vulnerable condition and clears residual exposure.");
  if (downgradeAllowed) messages.push("Residual downgrade is allowed with owner, expiry, and evidence.");
  if (!downgradeAllowed && !patchMandatory && selectedControls.length > 0) messages.push("Selected controls reduce risk but do not yet meet downgrade governance.");
  if (messages.length === 0) messages.push(`${finding.rawSeverity} severity is retained until a strong control or patch is selected.`);
  return messages;
}

function clampScore(score: number): number {
  return Number(Math.min(10, Math.max(0, score)).toFixed(1));
}
