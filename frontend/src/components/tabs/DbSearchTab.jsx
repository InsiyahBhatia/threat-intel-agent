import React from "react";
import SeverityTag from "../SeverityTag";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function DbSearchTab({
  dbSearch = "",
  dbLoading = false,
  onDbSearchChange,
  onDoDbSearch,
  dbResults = null,
  onInvestigate,
}) {
  const results = dbResults?.results || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Investigation Database</h3>
        <p className="text-xs text-muted mt-0.5">
          Search past investigation results across all IOCs
        </p>
      </div>

      <div className="flex gap-2 mb-4">
        <input
          type="text"
          value={dbSearch}
          onChange={(e) => onDbSearchChange(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !dbLoading && onDoDbSearch()}
          placeholder="Search IOCs, categories, risk scores..."
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <button
          onClick={onDoDbSearch}
          disabled={dbLoading || !dbSearch.trim()}
          className={cn(
            "bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-lg text-xs font-semibold transition-all",
            (dbLoading || !dbSearch.trim()) && "opacity-50 cursor-not-allowed"
          )}
        >
          {dbLoading ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Searching
            </span>
          ) : (
            "Search"
          )}
        </button>
      </div>

      {dbResults !== null && (
        <div className="mb-3">
          <span className="text-xs text-muted font-mono">
            {results.length} result{results.length !== 1 ? "s" : ""}
          </span>
        </div>
      )}

      {results.length > 0 ? (
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
                  Time
                </th>
              </tr>
            </thead>
            <tbody>
              {results.map((row, i) => (
                <tr
                  key={i}
                  onClick={() => onInvestigate?.(row.ioc)}
                  className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors cursor-pointer"
                >
                  <td className="px-3 py-2.5">
                    <span className="font-mono font-semibold text-text text-xs max-w-[200px] truncate block">
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
                  <td className="px-3 py-2.5 text-xs text-muted font-mono whitespace-nowrap">
                    {row.created_at || row.timestamp
                      ? new Date(row.created_at || row.timestamp).toLocaleDateString("en-US", {
                          month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
                        })
                      : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : dbResults !== null ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border rounded-lg"
        >
          <p className="text-sm font-semibold text-text mb-1">No results found</p>
          <p className="text-xs text-muted">Try a different search term</p>
        </motion.div>
      ) : (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border rounded-lg"
        >
          <p className="text-sm font-semibold text-text mb-1">Search the database</p>
          <p className="text-xs text-muted">Enter an IOC or keyword to find past investigations</p>
        </motion.div>
      )}
    </motion.div>
  );
}
