import React from "react";
import SeverityTag from "../SeverityTag";
import TimelineView from "../TimelineView";
import ReportPreview from "../ReportPreview";
import { motion } from "framer-motion";
import { useTheme } from "../ThemeContext";
import { cn } from "../../lib/utils";

function fmtTime(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return "-";
  }
}

export default function HistoryTab({
  history,
  historyView,
  selReport,
  onViewChange,
  onReRun,
  onSelectReport,
  onExportCSV,
  onExportSTIX,
  onExportPDF,
  onClearHistory,
  onIgnore,
  ignoredIocs,
  palette,
}) {
  const { palette: themePalette } = useTheme();
  const p = palette || themePalette;
  const isIgnored = (ioc) => ignoredIocs?.some((x) => (typeof x === "string" ? x : x.ioc) === ioc);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-3"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-text">Investigation History</h2>
          {history.length > 0 && (
            <span className="text-[10px] text-muted font-mono">Max 200</span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <div className="flex items-center bg-surface-light rounded-md p-0.5 gap-0.5">
            <button
              onClick={() => onViewChange("table")}
              className={cn(
                "px-2.5 py-1.5 rounded text-[10px] font-semibold font-mono transition-colors",
                  historyView === "table"
                    ? "bg-primary/10 text-primary"
                    : "text-muted hover:text-text"
                )}
              >
                Table
            </button>
            <button
              onClick={() => onViewChange("timeline")}
              className={cn(
                "px-2.5 py-1.5 rounded text-[10px] font-semibold font-mono transition-colors",
                  historyView === "timeline"
                    ? "bg-primary/10 text-primary"
                    : "text-muted hover:text-text"
                )}
              >
                Timeline
            </button>
          </div>

          <button
            onClick={onExportCSV}
            className="px-2 py-1.5 rounded-md text-[10px] font-semibold font-mono text-muted hover:text-text bg-surface-light hover:bg-surface-hover transition-colors"
          >
            CSV
          </button>
          <button
            onClick={onExportSTIX}
            className="px-2 py-1.5 rounded-md text-[10px] font-semibold font-mono text-muted hover:text-text bg-surface-light hover:bg-surface-hover transition-colors"
          >
            STIX
          </button>
          <button
            onClick={onExportPDF}
            className="px-2 py-1.5 rounded-md text-[10px] font-semibold font-mono text-muted hover:text-text bg-surface-light hover:bg-surface-hover transition-colors"
          >
            Report
          </button>
          <button
            onClick={onClearHistory}
            className="px-2 py-1.5 rounded-md text-[10px] font-semibold font-mono text-danger hover:text-danger bg-danger/10 hover:bg-danger/20 transition-colors"
          >
            Clear All
          </button>
        </div>
      </div>

      {history.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted border border-dashed border-border rounded-lg">
          <p className="text-sm font-semibold text-text">No investigations yet</p>
          <p className="text-xs text-muted/70 mt-1">Run an IOC search to see history here.</p>
        </div>
      ) : historyView === "table" ? (
        <div className="w-full overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface-light">
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  IOC
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Type
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Severity
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Category
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Risk
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Time
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-right whitespace-nowrap border-b border-border">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => {
                const ignored = isIgnored(h.ioc);
                return (
                  <tr
                    key={h.ioc + i}
                    onClick={() => onSelectReport?.(h)}
                    className={cn(
                      "border-b border-border last:border-b-0 transition-colors cursor-pointer",
                      ignored
                        ? "opacity-50 hover:opacity-70"
                        : "hover:bg-surface-light/50"
                    )}
                  >
                    <td className="px-3 py-2.5">
                      <span className="font-mono font-semibold text-text text-xs max-w-[200px] truncate block">
                        {h.ioc}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted font-mono">
                      {h.ioc_type?.toUpperCase() || "-"}
                    </td>
                    <td className="px-3 py-2.5">
                      <SeverityTag severity={h.severity} small />
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted">
                      {h.report?.threat_category || "-"}
                    </td>
                    <td className="px-3 py-2.5 text-xs font-mono">
                      {h.report?.risk_score !== undefined
                        ? `${Math.round(h.report.risk_score * 100)}%`
                        : "-"}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted font-mono whitespace-nowrap">
                      {fmtTime(h.timestamp)}
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onReRun?.(h.ioc);
                        }}
                        className="px-2 py-1 rounded text-[10px] font-semibold font-mono text-primary hover:bg-primary/10 transition-colors"
                        title="Re-run investigation"
                      >
                        Re-run
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <TimelineView history={history} />
      )}

      {selReport?.report && (
        <ReportPreview
          report={selReport}
          onReRun={onReRun}
          onIgnore={onIgnore}
          ignoredIocs={ignoredIocs}
        />
      )}
    </motion.div>
  );
}
