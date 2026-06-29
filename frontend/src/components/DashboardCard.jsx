import React from "react";
import { motion } from "framer-motion";
import { cn } from "../lib/utils";

export default function DashboardCard({
  icon,
  title,
  description,
  children,
  badge,
  className,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "bg-surface-light border border-border rounded-xl p-5",
        "h-full flex flex-col",
        "transition-all duration-200 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20",
        className
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 min-w-0">
          {icon && (
            <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0">
              {icon}
            </div>
          )}
          <h3 className="text-sm font-semibold text-text truncate">{title}</h3>
        </div>
        {badge && (
          <span
            className="text-[10px] font-bold px-1.5 py-0.5 rounded"
            style={{ color: badge.color, backgroundColor: `${badge.color}1A` }}
          >
            {badge.count}
          </span>
        )}
      </div>

      {description && (
        <p className="text-xs text-muted mt-2 leading-relaxed">{description}</p>
      )}

      {children && (
        <div className="pt-4 flex-1">
          {children}
        </div>
      )}
    </motion.div>
  );
}
