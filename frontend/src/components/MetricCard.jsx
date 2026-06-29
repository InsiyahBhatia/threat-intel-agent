import React from "react";
import { motion } from "framer-motion";
import { cn } from "../lib/utils";
import { TrendingUp, TrendingDown } from "lucide-react";

export default function MetricCard({
  icon,
  iconBg,
  iconColor,
  value,
  label,
  trend,
  sub,
  className,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "bg-surface-light border border-border rounded-xl p-5",
        "transition-all duration-200 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20",
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <div className={cn("text-3xl font-bold font-mono text-text")}>
            {value}
          </div>
          <div className="text-xs font-medium text-muted mt-1">{label}</div>
        </div>
        {icon && (
          <div
            className={cn(
              "w-10 h-10 rounded-lg flex items-center justify-center shrink-0",
              iconBg,
              iconColor
            )}
          >
            {icon}
          </div>
        )}
      </div>
      {trend && (
        <div className="flex items-center gap-1 mt-3">
          {trend.direction === "up" ? (
            <TrendingUp className="w-3.5 h-3.5 text-green-400" />
          ) : (
            <TrendingDown className="w-3.5 h-3.5 text-red-400" />
          )}
          <span
            className={cn(
              "text-xs font-medium",
              trend.direction === "up" ? "text-green-400" : "text-red-400"
            )}
          >
            {trend.value}
          </span>
        </div>
      )}
      {sub && <div className="text-xs text-muted-faint mt-2">{sub}</div>}
    </motion.div>
  );
}
