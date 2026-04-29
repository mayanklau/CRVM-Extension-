import { useMemo, useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, ChevronRight, FileCheck2, Filter, Flame, GitBranch, LockKeyhole, Network, Radar, ShieldCheck, Siren, SlidersHorizontal, Wrench } from "lucide-react";
import { attackPaths } from "./data";
import { calculateResidualRisk, selectedControlsForFinding, summarizePortfolio } from "./riskEngine";
import type { AttackPath, ControlRecommendation, ControlType, Severity } from "./types";

const severityClass: Record<Severity, string> = {
  Critical: "severityCritical",
  High: "severityHigh",
  Medium: "severityMedium",
  Low: "severityLow"
};

const controlIcons: Record<ControlType, typeof ShieldCheck> = {
  Patch: Wrench,
  Firewall: Network,
  SIEM: Siren,
  EDR: ShieldCheck,
  IAM: LockKeyhole,
  Configuration: SlidersHorizontal,
  "Risk Acceptance": FileCheck2
};

export function App() {
  const [activePathId, setActivePathId] = useState(attackPaths[0].id);
  const [selectedControlIds, setSelectedControlIds] = useState<Set<string>>(new Set(["ctrl-fw-payments-edge", "ctrl-siem-t1190", "ctrl-iam-claims-admin"]));
  const activePath = attackPaths.find((path) => path.id === activePathId) ?? attackPaths[0];
  const allSelectedControls = useMemo(() => attackPaths.flatMap((path) => path.recommendations).filter((control) => selectedControlIds.has(control.id)), [selectedControlIds]);
  const summary = summarizePortfolio(attackPaths, selectedControlIds);

  function toggleControl(controlId: string) {
    setSelectedControlIds((current) => {
      const next = new Set(current);
      if (next.has(controlId)) next.delete(controlId);
      else next.add(controlId);
      return next;
    });
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <div className="eyMark">EY CRVM Extension</div>
          <h1>Attack Path Control Center</h1>
        </div>
        <div className="statusPill"><Activity size={16} /> Residual risk simulation active</div>
      </header>

      <section className="summaryGrid" aria-label="Portfolio summary">
        <MetricCard label="Raw CRVM findings" value={summary.totalFindings} detail="Original count retained" />
        <MetricCard label="Also visible in Wiz" value={summary.wizVisibleFindings} detail="Client's smaller view" />
        <MetricCard label="CRVM-only signals" value={summary.crvmOnlyFindings} detail="Needs path context" />
        <MetricCard label="Patch mandatory" value={summary.mandatoryPatchFindings} detail="No soft downgrade" tone="danger" />
        <MetricCard label="Compensate candidates" value={summary.compensatingControlCandidates} detail="Governed downgrade possible" tone="good" />
        <MetricCard label="Avg score reduction" value={summary.averageResidualReduction.toFixed(1)} detail="Selected controls" tone="good" />
      </section>

      <section className="workspace">
        <aside className="pathRail" aria-label="Attack paths">
          <div className="railTitle"><GitBranch size={18} /> Attack paths</div>
          {attackPaths.map((path) => (
            <button className={`pathButton ${path.id === activePathId ? "active" : ""}`} key={path.id} onClick={() => setActivePathId(path.id)} type="button">
              <span><strong>{path.name}</strong><small>{path.entry} <ChevronRight size={12} /> {path.target}</small></span>
              <b>{path.blastRadius}</b>
            </button>
          ))}
        </aside>

        <section className="pathPanel">
          <PathHeader path={activePath} />
          <div className="panelGrid">
            <section className="findingsPanel" aria-label="Findings">
              <div className="sectionTitle"><Radar size={18} /> Findings with residual risk</div>
              {activePath.findings.map((finding) => {
                const controlsForFinding = selectedControlsForFinding(finding, allSelectedControls);
                const risk = calculateResidualRisk(finding, controlsForFinding);
                return (
                  <article className="findingCard" key={finding.id}>
                    <div className="findingHeader">
                      <div><div className="findingMeta"><span>{finding.cve}</span><span>{finding.source}</span></div><h3>{finding.title}</h3></div>
                      <span className={`severity ${severityClass[finding.rawSeverity]}`}>{finding.rawSeverity}</span>
                    </div>
                    <div className="scoreRow">
                      <ScoreBlock label="Inherent" score={risk.inherentScore} severity={risk.rawSeverity} />
                      <ScoreBlock label="Residual" score={risk.residualScore} severity={risk.residualSeverity} />
                    </div>
                    <div className="signalGrid">
                      <Signal active={finding.internetExposed} label="Internet exposed" />
                      <Signal active={finding.exploitAvailable} label="Exploit known" />
                      <Signal active={finding.lateralMovement} label="Lateral path" />
                      <Signal active={finding.privilegedAsset} label="Privileged" />
                    </div>
                    <div className="rationale">{risk.patchMandatory ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}<span>{risk.rationale[0]}</span></div>
                  </article>
                );
              })}
            </section>

            <section className="controlsPanel" aria-label="Recommended controls">
              <div className="sectionTitle"><Filter size={18} /> Breakpoints and controls</div>
              {activePath.recommendations.map((control) => <ControlCard control={control} key={control.id} selected={selectedControlIds.has(control.id)} onToggle={() => toggleControl(control.id)} />)}
            </section>
          </div>
        </section>
      </section>
    </main>
  );
}

function MetricCard({ label, value, detail, tone }: { label: string; value: string | number; detail: string; tone?: "danger" | "good" }) {
  return <article className={`metricCard ${tone ?? ""}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function PathHeader({ path }: { path: AttackPath }) {
  return <header className="pathHeader"><div><p>Selected attack path</p><h2>{path.name}</h2><span>{path.entry} <ChevronRight size={14} /> {path.target}</span></div><div className="blastScore"><Flame size={18} /><span>Blast radius</span><strong>{path.blastRadius}/10</strong></div></header>;
}

function ScoreBlock({ label, score, severity }: { label: string; score: number; severity: Severity }) {
  return <div className="scoreBlock"><span>{label}</span><strong>{score.toFixed(1)}</strong><small className={severityClass[severity]}>{severity}</small></div>;
}

function Signal({ active, label }: { active: boolean; label: string }) {
  return <span className={`signal ${active ? "active" : ""}`}>{label}</span>;
}

function ControlCard({ control, selected, onToggle }: { control: ControlRecommendation; selected: boolean; onToggle: () => void }) {
  const Icon = controlIcons[control.type];
  return (
    <article className={`controlCard ${selected ? "selected" : ""}`}>
      <div className="controlHeader">
        <div className="controlIcon"><Icon size={18} /></div>
        <div><span>{control.type}</span><h3>{control.title}</h3></div>
        <button aria-pressed={selected} className="toggleButton" onClick={onToggle} title={selected ? "Remove control from simulation" : "Add control to simulation"} type="button">
          {selected ? <CheckCircle2 size={18} /> : <ShieldCheck size={18} />}
        </button>
      </div>
      <p>{control.description}</p>
      <dl className="controlFacts"><div><dt>Owner</dt><dd>{control.owner}</dd></div><div><dt>Effort</dt><dd>{control.effort}</dd></div><div><dt>Reduction</dt><dd>{control.reduction.toFixed(1)}</dd></div></dl>
      <footer>{control.evidence}</footer>
    </article>
  );
}
