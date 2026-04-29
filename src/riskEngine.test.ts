import { describe, expect, it } from "vitest";
import { attackPaths } from "./data";
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
});
