import React, { useState } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";
import { useTheme } from "../ThemeContext";
import MetricCard from "../MetricCard";
import DashboardCard from "../DashboardCard";
import SeverityTag from "../SeverityTag";
import ReportPreview from "../ReportPreview";

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.35 } },
};

function fmtTime(ts) {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

const severityBars = [
  { key: "CRITICAL", label: "CRITICAL", barClass: "bg-red-500" },
  { key: "HIGH", label: "HIGH", barClass: "bg-amber-500" },
  { key: "LOW", label: "LOW", barClass: "bg-blue-500" },
  { key: "CLEAN", label: "CLEAN", barClass: "bg-green-500" },
];

export default function DashboardTab({
  stats,
  history,
  feed,
  metrics,
  selReport,
  blocklist,
  localTrend,
  categoryBreakdown,
  chartMax,
  initialLoading,
  onInvestigate,
  onReRun,
  onIgnore,
  ignoredIocs,
  onTabChange,
  onSetIoc,
  onSetActiveTab,
  palette,
}) {
  const catMap = {};
  if (categoryBreakdown) {
    categoryBreakdown.forEach(([cat, count]) => {
      catMap[cat] = count;
    });
  }
  const maxCount = chartMax || Math.max(1, ...Object.values(catMap));

  const trendMax = chartMax || Math.max(1, ...(localTrend || []).map((d) => d.count));

  const topFeed = feed ? feed.slice(0, 20) : [];

  const [localIoc, setLocalIoc] = useState("");

  const handleInvestigate = () => {
    if (localIoc.trim() && onSetIoc) {
      onSetIoc(localIoc.trim());
    }
    if (typeof onInvestigate === "function") {
      onInvestigate(localIoc.trim());
    }
    setLocalIoc("");
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-5"
    >
      {/* Investigation Search */}
      <motion.div variants={itemVariants}>
        <div className="bg-surface border border-border rounded-xl p-4">
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input
                type="text"
                value={localIoc}
                onChange={(e) => setLocalIoc(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleInvestigate()}
                placeholder="Search IOC (IP, domain, hash)..."
                className="w-full bg-surface-light border border-border rounded-lg px-3 py-2.5 text-sm font-mono text-text placeholder:text-muted-faint focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all"
              />
            </div>
            <button
              onClick={handleInvestigate}
              disabled={!localIoc.trim()}
              className="bg-primary hover:bg-primary-hover text-white px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Investigate
            </button>
          </div>
        </div>
      </motion.div>

      {/* KPI Row */}
      <motion.div variants={itemVariants} className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard value={stats.total} label="Total Investigations" />
        <MetricCard value={stats.critical} label="Critical IOCs" />
        <MetricCard value={stats.high} label="High Severity" />
        <MetricCard value={stats.priority} label="Priority C+H" />
      </motion.div>

      {/* Severity Distribution + Activity Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 auto-rows-1fr gap-4">
        {/* Severity Distribution */}
        <motion.div variants={itemVariants}>
          <DashboardCard title="Severity Distribution">
            {severityBars.some(s => (catMap[s.key] || 0) > 0) ? (
              <div className="flex flex-col gap-2.5 mt-1 w-full">
                {severityBars.map((s) => {
                  const count = catMap[s.key] || 0;
                  const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  return (
                    <div key={s.key} className="flex items-center gap-3">
                      <span className="text-[10px] font-bold text-muted w-16 shrink-0 font-mono tracking-wide">
                        {s.label}
                      </span>
                      <div className="flex-1 h-5 bg-black/10 dark:bg-white/10 rounded overflow-hidden">
                        <div
                          className={cn("h-full rounded transition-all duration-500", s.barClass)}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-xs font-bold text-text font-mono w-8 text-right">
                        {count}
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-muted text-center py-6">No data yet</div>
            )}
          </DashboardCard>
        </motion.div>

        {/* Activity Feed */}
        <motion.div variants={itemVariants}>
          <DashboardCard title="Activity Feed">
            {topFeed.length > 0 ? (
              <div className="mt-2 divide-y divide-border">
                  {topFeed.map((item, i) => (
                  <div key={i} className="flex items-center gap-3 py-2.5 text-sm">
                    <span className={cn(
                      "w-2 h-2 rounded-full shrink-0",
                      item.severity === "CRITICAL" ? "bg-red-500" :
                      item.severity === "HIGH" ? "bg-amber-500" :
                      item.severity === "LOW" ? "bg-teal-500" :
                      item.severity === "CLEAN" ? "bg-green-500" : "bg-blue-500"
                    )} />
                    <span className="text-xs text-text font-mono font-semibold truncate flex-1">
                      {item.ioc || item.indicator || "-"}
                    </span>
                    <span className="text-[10px] text-muted font-mono shrink-0">
                      {fmtTime(item.ts || item.time || item.timestamp)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <p className="text-sm font-medium text-text">No recent activity</p>
              </div>
            )}
          </DashboardCard>
        </motion.div>

      </div>

      {/* Trend Chart */}
      <motion.div variants={itemVariants}>
        <DashboardCard title="14-Day Investigation Trend">
          {localTrend && localTrend.length > 0 ? (
            <div className="flex items-end gap-1.5 h-28 mt-3 px-1">
              {localTrend.map((d, i) => {
                const h = trendMax > 0 ? (d.count / trendMax) * 100 : 0;
                return (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1 h-full justify-end">
                    <span className="text-[9px] font-bold text-text font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                      {d.count}
                    </span>
                    <div
                      className="w-full rounded-t-md transition-all duration-500 bg-blue-500 hover:opacity-80 cursor-pointer"
                      style={{ height: `${Math.max(h, 2)}%` }}
                    />
                    <span className="text-[8px] text-muted font-mono text-center leading-tight">
                      {d.date ? d.date.slice(5) : ""}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <p className="text-sm font-medium text-text">No trend data available</p>
              <p className="text-xs text-muted mt-1">Investigations will appear here over time</p>
            </div>
          )}
        </DashboardCard>
      </motion.div>

      {/* Report Preview */}
      {selReport && selReport.ioc && (
        <motion.div variants={itemVariants}>
          <ReportPreview report={selReport} />
        </motion.div>
      )}
    </motion.div>
  );
}
