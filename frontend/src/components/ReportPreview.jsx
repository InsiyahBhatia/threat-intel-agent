import React, { useState } from "react";
import { ShieldAlert, ExternalLink, RotateCcw, Flag, CheckCircle, ThumbsDown } from "lucide-react";
import { useTheme } from "./ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../lib/utils";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function WhyThisSeverity({ report, mlFeatures }) {
  const reasons = [];
  const flags = [];

  if (mlFeatures?.vt_malicious_ratio > 0.1)
    reasons.push(`VirusTotal: ${Math.round(mlFeatures.vt_malicious_ratio * 90)}/90 engines flagged`);

  if (mlFeatures?.abuse_confidence > 50)
    reasons.push(`AbuseIPDB confidence: ${mlFeatures.abuse_confidence}%`);

  if (mlFeatures?.is_tor)
    reasons.push("Tor exit node detected");

  if (mlFeatures?.shodan_cve_count > 0)
    reasons.push(`${mlFeatures.shodan_cve_count} CVEs on open ports`);

  if (mlFeatures?.otx_pulse_count > 0)
    reasons.push(`Appears in ${mlFeatures.otx_pulse_count} OTX threat pulses`);

  if (report.confidence_score < 60)
    flags.push("Low model confidence — verify before blocking");

  if (mlFeatures?.has_vt_data === 0 && mlFeatures?.has_abuse_data === 0 && mlFeatures?.has_shodan_data === 0)
    flags.push("No enrichment data returned — severity based on text analysis only");
  else if (mlFeatures?.vt_malicious_ratio === 0 && mlFeatures?.abuse_confidence < 20)
    flags.push("No VT/AbuseIPDB hits — consider false positive");

  if (reasons.length === 0 && flags.length === 0) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4 mt-4">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">
        Why {report.severity}
      </p>
      {reasons.length > 0 && (
        <ul className="space-y-1">
          {reasons.map((r, i) => (
            <li key={i} className="text-sm text-slate-200 flex gap-2">
              <span className="text-amber-400 mt-0.5">›</span> {r}
            </li>
          ))}
        </ul>
      )}
      {flags.map((f, i) => (
        <p key={i} className="text-xs text-amber-400 mt-3 flex gap-2">
          <span>⚠</span> {f}
        </p>
      ))}
    </div>
  );
}

const severityStyles = {
  CRITICAL: { text: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/30" },
  HIGH: { text: "text-amber-500", bg: "bg-amber-500/10", border: "border-amber-500/30" },
  LOW: { text: "text-teal-500", bg: "bg-teal-500/10", border: "border-teal-500/30" },
  CLEAN: { text: "text-green-500", bg: "bg-green-500/10", border: "border-green-500/30" },
  UNKNOWN: { text: "text-muted", bg: "bg-surface", border: "border-border/50" },
};

const severityBarColors = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-amber-500",
  LOW: "bg-teal-500",
  CLEAN: "bg-green-500",
  UNKNOWN: "bg-muted",
};

export default function ReportPreview({ report, onReRun, onIgnore, ignoredIocs }) {
  const r = report?.report || {};
  const isIgnored = ignoredIocs?.some((x) => x.ioc === report?.ioc);
  const sev = report?.severity || "UNKNOWN";
  const sevStyle = severityStyles[sev] || severityStyles.UNKNOWN;
  const barColor = severityBarColors[sev] || severityBarColors.UNKNOWN;
  const conf = Math.min(100, Math.max(0, r.confidence_score ?? r.ml_confidence ?? 0));
  const riskPct = r.risk_score != null ? Math.round(r.risk_score * 100) : null;
  const [showCorrection, setShowCorrection] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);

  async function handleFeedback(userLabel) {
    try {
      await fetch(`${API_URL}/api/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ioc: report.ioc,
          predicted_severity: sev,
          user_label: userLabel,
          source: "ui",
        }),
      });
      setFeedbackSent(true);
      setShowCorrection(false);
    } catch {}
  }

  if (!report) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className="bg-surface-light border border-border rounded-xl overflow-hidden mt-4"
    >
      {/* Header */}
      <div className="flex items-start gap-5 p-4 border-b border-border">
        <div className="flex flex-col items-start gap-1.5 min-w-[140px]">
          <span className={`font-bold text-lg px-3 py-1.5 rounded-md leading-tight ${sevStyle.text} ${sevStyle.bg}`}>
            {sev}
          </span>
          <div className="w-full h-[3px] bg-border rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${conf}%` }}
              transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
              className={`h-full rounded-full ${barColor}`}
            />
          </div>
          <span className="text-[10px] text-muted font-mono tracking-wide">{conf}% confidence</span>
        </div>

        <div className="flex-1 flex flex-col gap-1 justify-center min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-bold text-base break-all text-text">
              {report.ioc}
            </span>
            {report.ioc_type && (
              <span className="text-[10px] text-muted font-mono uppercase tracking-wider bg-surface px-2 py-0.5 rounded border border-border/50">
                {report.ioc_type}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-muted font-mono mt-0.5">
            {riskPct != null && <span>Risk: {riskPct}%</span>}
            {r.ml_verdict && <span>ML verdict: <span className="font-semibold text-text">{r.ml_verdict}</span> (conf: {r.ml_confidence || "?"}%)</span>}
            <span>Model: {r.model_name || "Ensemble"}</span>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="p-4 text-sm leading-relaxed max-h-[400px] overflow-y-auto space-y-3">
        {r.summary && <p className="text-text-secondary">{r.summary}</p>}

        {r.mitre_techniques?.length > 0 && (
          <div>
            <div className="text-[10px] font-bold text-muted uppercase tracking-wider mb-1.5 font-mono">
              MITRE ATT&CK
            </div>
            <div className="flex flex-wrap gap-1.5">
              {r.mitre_techniques.slice(0, 6).map((t, i) => (
                <a
                  key={i}
                  href={`https://attack.mitre.org/techniques/${(t.technique_id || "").replace(".", "/")}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[11px] font-mono bg-purple-500/10 text-purple-400 px-2 py-0.5 rounded no-underline hover:underline hover:bg-purple-500/20 transition-colors"
                >
                  {t.technique_id} {t.name}
                  <ExternalLink size={10} />
                </a>
              ))}
            </div>
          </div>
        )}

        <WhyThisSeverity report={r} mlFeatures={report.ml_features} />

        {r.recommended_actions?.length > 0 && (
          <div>
            <div className="text-[10px] font-bold text-muted uppercase tracking-wider mb-1.5 font-mono">
              Recommended Actions
            </div>
            <ul className="m-0 pl-4 text-sm leading-relaxed text-text-secondary space-y-1">
              {r.recommended_actions.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <div className="text-[10px] font-bold text-muted uppercase tracking-wider mb-1.5 font-mono">
            Raw Evidence
          </div>
          <pre className="bg-ink text-text-secondary p-3 rounded-lg text-[11px] font-mono leading-relaxed border border-border/50 max-h-[400px] overflow-y-auto whitespace-pre-wrap">
            {r.agent_output || JSON.stringify(r, null, 2).slice(0, 2000)}
          </pre>
        </div>
      </div>

      {/* Footer */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-t border-border bg-surface/50">
        {onReRun && (
          <button
            onClick={() => onReRun(report.ioc)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-border text-muted hover:text-text hover:border-text/30 transition-colors"
          >
            <RotateCcw size={12} />
            Re-run
          </button>
        )}
        {!feedbackSent ? (
          <>
            <button
              onClick={() => setShowCorrection(!showCorrection)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-border text-muted hover:text-text transition-colors"
            >
              <ThumbsDown size={12} />
              Wrong?
            </button>
            {showCorrection && (
              <div className="flex gap-1.5">
                {["CRITICAL", "HIGH", "LOW", "CLEAN"].map(sev => (
                  <button
                    key={sev}
                    onClick={() => handleFeedback(sev)}
                    className={cn(
                      "px-2 py-1 rounded text-[10px] font-bold uppercase",
                      severityStyles[sev].bg, severityStyles[sev].text
                    )}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            )}
          </>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-green-500">
            <CheckCircle size={12} /> Feedback submitted
          </span>
        )}
        {onIgnore && !isIgnored && (
          <button
            onClick={() => onIgnore(report.ioc, "User marked as false positive")}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-yellow-500/50 text-yellow-500 bg-yellow-500/10 hover:bg-yellow-500/20 transition-colors"
          >
            <Flag size={12} />
            Mark as FP / Ignore
          </button>
        )}
        {isIgnored && (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-green-500 bg-green-500/10 px-2 py-1 rounded-md">
            <CheckCircle size={12} />
            Ignored
          </span>
        )}
      </div>
    </motion.div>
  );
}
