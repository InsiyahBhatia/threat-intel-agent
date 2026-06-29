import React from "react";
import SeverityTag from "../SeverityTag";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function BulkImportTab({
  bulkInput = "",
  bulkLoading = false,
  onBulkInputChange,
  onDoBulkImport,
  bulkResults = null,
}) {
  const iocCount = bulkInput.trim()
    ? bulkInput.trim().split("\n").filter((l) => l.trim()).length
    : 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Bulk IOC Import</h3>
        <p className="text-xs text-muted mt-0.5">
          Import multiple IOCs at once — one per line
        </p>
      </div>

      <textarea
        value={bulkInput}
        onChange={(e) => onBulkInputChange(e.target.value)}
        placeholder={`192.168.1.1\nmalicious.example.com\nd41d8cd98f00b204e9800998ecf8427e`}
        rows={8}
        className="w-full bg-surface border border-border rounded-lg px-3 py-2.5 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all resize-y"
      />

      <div className="flex items-center justify-between mt-3">
        <span className="text-xs text-muted font-mono">
          {iocCount} IOC{iocCount !== 1 ? "s" : ""} detected
        </span>
        <button
          onClick={onDoBulkImport}
          disabled={bulkLoading || iocCount === 0}
          className={cn(
            "bg-primary hover:bg-primary-hover text-white px-5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all",
            (bulkLoading || iocCount === 0) && "opacity-50 cursor-not-allowed"
          )}
        >
          {bulkLoading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Importing...
            </>
          ) : (
            <>
              Investigate
            </>
          )}
        </button>
      </div>

      {bulkResults && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
          className="mt-4 space-y-3"
        >
          <div className="flex gap-3">
            <div className="flex items-center gap-2 bg-green-500/10 text-green-400 rounded-lg px-3 py-2">
              <span className="text-xs font-semibold font-mono">{bulkResults.succeeded ?? 0} succeeded</span>
            </div>
            <div className="flex items-center gap-2 bg-red-500/10 text-red-400 rounded-lg px-3 py-2">
              <span className="text-xs font-semibold font-mono">{bulkResults.failed ?? 0} failed</span>
            </div>
          </div>

          {bulkResults.errors && bulkResults.errors.length > 0 && (
            <div className="bg-surface border border-border rounded-lg p-3 max-h-[120px] overflow-y-auto">
              {bulkResults.errors.map((err, i) => (
                <div key={i} className="text-[10px] font-mono text-danger leading-relaxed">
                  {err}
                </div>
              ))}
            </div>
          )}

          {bulkResults.results && bulkResults.results.length > 0 && (
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
                      Category
                    </th>
                    <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                      Risk
                    </th>
                    <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {bulkResults.results.map((row, i) => (
                    <tr
                      key={i}
                      className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors"
                    >
                      <td className="px-3 py-2.5">
                        <span className="font-mono font-semibold text-text text-xs max-w-[180px] truncate block">
                          {row.ioc}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityTag severity={row.severity} small />
                      </td>
                      <td className="px-3 py-2.5 text-xs text-muted">
                        {row.category || "-"}
                      </td>
                      <td className="px-3 py-2.5 text-xs font-mono">
                        {row.risk !== undefined && row.risk !== null
                          ? typeof row.risk === "number"
                            ? `${Math.round(row.risk * 100)}%`
                            : row.risk
                          : "-"}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={cn(
                          "text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded",
                          row.status === "success"
                            ? "bg-green-500/10 text-green-400"
                            : "bg-red-500/10 text-red-400"
                        )}>
                          {row.status || "unknown"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      )}
    </motion.div>
  );
}
