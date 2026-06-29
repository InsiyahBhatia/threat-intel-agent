import React from "react";
import SeverityTag from "../SeverityTag";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

function renderExplanation(text) {
  if (!text) return null;
  const parts = text.split(/(\*\*.*?\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    return part;
  });
}

export default function ExplainTab({
  explainInput,
  explainLoading,
  explainResult,
  onExplainInputChange,
  onExplain,
  palette,
}) {
  const maxImpact = explainResult?.feature_contributions?.length
    ? Math.max(...explainResult.feature_contributions.map((f) => Math.abs(f.impact)))
    : 1;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">ML Explainability</h3>
        <p className="text-xs text-muted mt-0.5">
          Get SHAP-style feature contributions for any IOC prediction
        </p>
      </div>

      <div className="flex gap-2 mb-4">
        <input
          type="text"
          value={explainInput}
          onChange={(e) => onExplainInputChange(e.target.value)}
          placeholder="Enter IOC to explain..."
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-sm font-mono text-text placeholder-muted focus:ring-2 focus:ring-primary/40 focus:border-primary transition-all"
          onKeyDown={(e) => e.key === "Enter" && !explainLoading && onExplain()}
        />
        <button
          onClick={onExplain}
          disabled={explainLoading || !explainInput.trim()}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            "bg-primary hover:bg-primary-hover text-white",
            "disabled:opacity-40 disabled:cursor-not-allowed",
            "flex items-center gap-2 shrink-0"
          )}
        >
          {explainLoading ? (
            <>
              <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Analyzing...
            </>
          ) : (
            "Explain"
          )}
        </button>
      </div>

      {explainResult && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
          className="space-y-4"
        >
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm font-semibold text-text">
              {explainResult.ioc}
            </span>
            <SeverityTag severity={explainResult.severity} small />
            <span className="text-xs text-muted font-medium">
              Confidence: {explainResult.confidence}%
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted bg-surface rounded-lg px-3 py-2">
            <span className="font-medium text-text">{explainResult.ml_verdict}</span>
            <span>by</span>
            <span className="font-mono text-text">{explainResult.model_name}</span>
            <span className="mx-1">·</span>
            <span>ML confidence: {explainResult.ml_confidence}%</span>
          </div>

          {explainResult.explanation && (
            <div className="text-xs text-text/80 whitespace-pre-wrap leading-relaxed bg-surface rounded-lg px-3 py-2.5">
              {renderExplanation(explainResult.explanation)}
            </div>
          )}

          {explainResult.feature_contributions?.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-text mb-2">
                Feature Contributions
              </h4>
              <div className="space-y-2">
                  {explainResult.feature_contributions.map((feature, i) => {
                  const isIncrease = feature.direction === "increases";
                  const pct = (Math.abs(feature.impact) / maxImpact) * 100;
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-text w-44 truncate shrink-0" title={feature.feature}>
                        {feature.name || feature.feature}
                      </span>
                      <span className="font-mono text-xs text-muted w-10 shrink-0">
                        {feature.value}
                      </span>
                      <div className="flex-1 bg-border rounded h-2 overflow-hidden">
                        <div
                          className={cn("h-full rounded", isIncrease ? "bg-danger" : "bg-green-500")}
                          style={{ width: `${Math.max(pct, 2)}%` }}
                        />
                      </div>
                      <span
                        className={cn(
                          "text-xs font-medium w-22 shrink-0",
                          isIncrease ? "text-danger" : "text-green-500"
                        )}
                      >
                        {isIncrease ? "raises risk" : "lowers risk"}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </motion.div>
      )}
    </motion.div>
  );
}
