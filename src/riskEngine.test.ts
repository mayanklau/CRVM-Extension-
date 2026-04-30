import { describe, expect, it } from "vitest";
import { approvalDecisions, attackPaths, connectors, driftSignals, evidencePacks, executiveBrief, ownerNotifications, slaInsights, virtualPatchPlans } from "./data";
import { executiveReports, ingestionRuns, remediationTickets } from "./productModules";
import { calculateInherentScore, calculateResidualRisk, scoreToSeverity, selectedControlsForFinding, summarizePortfolio } from "./riskEngine";

describe("risk engine", () => {
  it("keeps internet-exposed critical exploited findings patch mandatory", () => {
    const path = attackPaths[0];
    const finding = path.findings[0];
    const firewall = path.recommendations.find((control) => control.type === "Firewall");
    const siem = path.recommendations.find((control) => control.type === "SIEM");
    expect(firewall).toBeDefined();
    expect(siem).toBeDefined();
    const result = calculateResidualRisk(finding, [firewall!, siem!]);
    expect(result.patchMandatory).toBe(true);
    expect(result.downgradeAllowed).toBe(false);
    expect(result.residualSeverity).toBe("Critical");
  });

  it("allows governed downgrade when strong compensating controls break the path", () => {
    const path = attackPaths[1];
    const finding = path.findings[0];
    const selected = path.recommendations.filter((control) => ["IAM", "EDR", "SIEM"].includes(control.type));
    const result = calculateResidualRisk(finding, selected);
    expect(result.downgradeAllowed).toBe(true);
    expect(result.residualSeverity).toBe("Medium");
  });

  it("maps scores to severity bands", () => {
    expect(scoreToSeverity(9)).toBe("Critical");
    expect(scoreToSeverity(7)).toBe("High");
    expect(scoreToSeverity(4)).toBe("Medium");
    expect(scoreToSeverity(3.9)).toBe("Low");
  });

  it("scopes patch controls to their target CVE", () => {
    const path = attackPaths[2];
    const finding = path.findings[0];
    const selected = selectedControlsForFinding(finding, path.recommendations);
    expect(selected.some((control) => control.title.includes(finding.cve))).toBe(true);
  });

  it("summarizes CRVM-only and Wiz-visible findings separately", () => {
    const allControlIds = new Set(attackPaths.flatMap((path) => path.recommendations.map((control) => control.id)));
    const summary = summarizePortfolio(attackPaths, allControlIds);
    expect(summary.totalFindings).toBe(5);
    expect(summary.wizVisibleFindings).toBe(2);
    expect(summary.crvmOnlyFindings).toBe(3);
    expect(summary.averageResidualReduction).toBeGreaterThan(0);
  });

  it("never scores below zero or above ten", () => {
    const path = attackPaths[0];
    const finding = path.findings[0];
    const inherent = calculateInherentScore(finding);
    const residual = calculateResidualRisk(finding, path.recommendations);
    expect(inherent).toBeLessThanOrEqual(10);
    expect(residual.residualScore).toBeGreaterThanOrEqual(0);
  });

  it("includes the required enterprise connectors", () => {
    const connectorNames = new Set(connectors.map((connector) => connector.name));
    ["Wiz", "ServiceNow", "Splunk", "Microsoft Sentinel", "Palo Alto", "Check Point", "AWS Security Groups", "Azure NSGs", "Jira", "Tenable", "Qualys"].forEach((name) => expect(connectorNames.has(name)).toBe(true));
  });

  it("models approval, notification, executive brief, and drift workflows", () => {
    expect(approvalDecisions.some((decision) => decision.approver === "CISO")).toBe(true);
    expect(ownerNotifications.length).toBeGreaterThan(0);
    expect(executiveBrief.talkingPoints).toHaveLength(3);
    expect(driftSignals.some((signal) => signal.status === "Drift Detected")).toBe(true);
  });

  it("models virtual patching as immediate mitigation while permanent patch remains mandatory", () => {
    const path = attackPaths[0];
    const finding = path.findings[0];
    const virtualPatch = path.recommendations.find((control) => control.type === "Virtual Patch");
    const siem = path.recommendations.find((control) => control.type === "SIEM");
    expect(virtualPatch).toBeDefined();
    expect(siem).toBeDefined();
    const result = calculateResidualRisk(finding, [virtualPatch!, siem!]);
    expect(result.patchMandatory).toBe(true);
    expect(result.downgradeAllowed).toBe(true);
    expect(result.residualSeverity).not.toBe("Critical");
  });

  it("includes evidence packs and SLA heat insights as value-add modules", () => {
    expect(virtualPatchPlans.some((plan) => plan.mode === "Block")).toBe(true);
    expect(evidencePacks.some((pack) => pack.completeness >= 80)).toBe(true);
    expect(slaInsights.some((insight) => insight.breached > 0)).toBe(true);
  });

  it("includes full product operations modules", () => {
    expect(remediationTickets.some((ticket) => ticket.system === "ServiceNow")).toBe(true);
    expect(ingestionRuns.every((run) => run.normalized <= run.records)).toBe(true);
    expect(executiveReports.some((report) => report.audience === "Board")).toBe(true);
  });
});
