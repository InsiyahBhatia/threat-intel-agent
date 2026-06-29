import React from "react";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function HuntTab({
  huntInput,
  huntRunning,
  huntResult,
  huntLogs,
  visRef,
  onHuntInputChange,
  onHunt,
  palette,
}) {
  const stats = huntResult?.graph
    ? {
        nodes: huntResult.graph.nodes?.length ?? 0,
        critical:
          huntResult.graph.nodes?.filter(
            (n) =>
              (n.severity && n.severity.toLowerCase() === "critical") ||
              (n.riskScore != null && n.riskScore >= 9) ||
              (n.type && n.type.toLowerCase() === "c2") ||
              (n.label && n.label.toLowerCase().includes("critical"))
          ).length ?? 0,
        edges: huntResult.graph.edges?.length ?? 0,
        ips:
          huntResult.graph.nodes?.filter(
            (n) =>
              /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(n.id ?? "") ||
              /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(n.label ?? "")
          ).length ?? 0,
      }
    : null;

  const hasLogs = huntLogs && huntLogs.length > 0;
  const isIdle = !huntResult?.graph && !hasLogs;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Autonomous Hunt</h3>
        <p className="text-xs text-muted mt-1 leading-relaxed">
          Trace related infrastructure from a seed IOC
        </p>
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={huntInput}
          onChange={(e) => onHuntInputChange(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !huntRunning && onHunt()}
          placeholder="Enter IOC (IP, domain, hash)..."
          disabled={huntRunning}
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-sm font-mono text-text placeholder:text-muted-faint focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all disabled:opacity-50"
        />
        <button
          onClick={onHunt}
          disabled={huntRunning || !huntInput.trim()}
          className={cn(
            "bg-primary hover:bg-primary-hover text-white px-5 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 transition-all",
            (huntRunning || !huntInput.trim()) && "opacity-50 cursor-not-allowed"
          )}
        >
          {huntRunning ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Hunting
            </>
          ) : (
            <>
              Hunt
            </>
          )}
        </button>
      </div>

      {huntResult?.graph && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <div className="text-2xl font-bold font-mono text-text">
                {stats?.nodes ?? 0}
              </div>
              <div className="text-[10px] text-muted uppercase tracking-wider font-semibold mt-1">
                Nodes
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <div className="text-2xl font-bold font-mono text-red-400">
                {stats?.critical ?? 0}
              </div>
              <div className="text-[10px] text-muted uppercase tracking-wider font-semibold mt-1">
                Critical
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <div className="text-2xl font-bold font-mono text-text">
                {stats?.edges ?? 0}
              </div>
              <div className="text-[10px] text-muted uppercase tracking-wider font-semibold mt-1">
                Edges
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <div className="text-2xl font-bold font-mono text-text">
                {stats?.ips ?? 0}
              </div>
              <div className="text-[10px] text-muted uppercase tracking-wider font-semibold mt-1">
                IPs
              </div>
            </div>
          </div>

          <div
            ref={visRef}
            className="w-full h-[320px] rounded-lg border border-border mt-3 bg-[#0a0a0c]"
          />

          {hasLogs && (
            <div className="bg-[#0a0a0c] text-[#a8b8ca] rounded-lg p-3 text-xs font-mono max-h-[200px] overflow-y-auto mt-3 border border-border">
              {huntLogs.map((log, i) => {
                const lc = log.toLowerCase();
                const isCritical =
                  lc.includes("critical") || lc.includes("c2") || lc.includes("malicious");
                const isHigh =
                  lc.includes("high") || lc.includes("suspicious");
                return (
                  <div
                    key={i}
                    className={cn(
                      "leading-relaxed",
                      isCritical && "text-red-400",
                      isHigh && "text-orange-400",
                      !isCritical && !isHigh && "text-[#a8b8ca]"
                    )}
                  >
                    {log}
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>
      )}

      {!huntResult?.graph && hasLogs && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.2 }}
          className="bg-[#0a0a0c] text-[#a8b8ca] rounded-lg p-3 text-xs font-mono max-h-[200px] overflow-y-auto mt-4 border border-border"
        >
          {huntLogs.map((log, i) => (
            <div key={i} className="leading-relaxed">{log}</div>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
}
