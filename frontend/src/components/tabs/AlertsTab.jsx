import React from "react";
import SeverityTag from "../SeverityTag";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const statusStyles = {
  pending: "bg-amber-500/10 text-amber-400",
  delivered: "bg-green-500/10 text-green-400",
  failed: "bg-red-500/10 text-red-400",
};

export default function AlertsTab({
  alerts = [],
  alertStats = null,
  initialLoading = false,
  onFormatTime,
}) {
  const stats = alertStats || { total: 0, by_severity: {} };
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Alert History</h3>
        <p className="text-xs text-muted mt-0.5">
          Track alerts sent to notification channels
        </p>
      </div>

      {!initialLoading && stats.total > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
          {severityOrder.map((sev) => {
            const count = stats.by_severity?.[sev] || 0;
            if (count === 0) return null;
            return (
              <div
                key={sev}
                className="bg-surface border border-border rounded-lg px-3 py-2 text-center"
              >
                <div className="text-xs font-bold font-mono text-text">{count}</div>
                <div className="text-[10px] text-muted uppercase tracking-wider font-semibold mt-0.5">
                  {sev}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {initialLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-10 bg-surface rounded-lg animate-pulse" />
          ))}
        </div>
      ) : alerts.length > 0 ? (
        <div className="w-full overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface-light">
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  IOC
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Severity
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Channel
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Status
                </th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                  Time
                </th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, i) => (
                <tr
                  key={i}
                  className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors"
                >
                  <td className="px-3 py-2.5">
                    <span className="font-mono font-semibold text-text text-xs max-w-[200px] truncate block">
                      {alert.ioc}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    <SeverityTag severity={alert.severity} small />
                  </td>
                  <td className="px-3 py-2.5 text-xs text-muted font-mono">
                    {alert.channel || "-"}
                  </td>
                  <td className="px-3 py-2.5">
                    <span
                      className={cn(
                        "text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded",
                        statusStyles[alert.status] || "text-muted bg-surface"
                      )}
                    >
                      {alert.status || "unknown"}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-muted font-mono whitespace-nowrap">
                    {onFormatTime ? onFormatTime(alert.created_at) : alert.created_at || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border rounded-lg"
        >
          <p className="text-sm font-semibold text-text mb-1">No alerts yet</p>
          <p className="text-xs text-muted">Alerts will appear here when threats are detected</p>
        </motion.div>
      )}
    </motion.div>
  );
}
