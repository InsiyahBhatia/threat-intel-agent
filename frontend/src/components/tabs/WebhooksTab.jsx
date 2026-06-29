import React from "react";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function WebhooksTab({
  webhooks = [],
  whUrl = "",
  whEvents = "",
  onWhUrlChange,
  onWhEventsChange,
  onAddWebhook,
  onRemoveWebhook,
  initialLoading = false,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Webhook Notifications</h3>
        <p className="text-xs text-muted mt-0.5">
          Forward threat alerts to external services via webhooks
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-2 mb-4">
        <div className="flex-1">
          <input
            type="text"
            value={whUrl}
            onChange={(e) => onWhUrlChange(e.target.value)}
            placeholder="https://hooks.example.com/..."
            className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
          />
        </div>
        <input
          type="text"
          value={whEvents}
          onChange={(e) => onWhEventsChange(e.target.value)}
          placeholder="Events (e.g. critical,high)"
          className="w-full sm:w-44 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <button
          onClick={onAddWebhook}
          disabled={!whUrl.trim() || initialLoading}
          className={cn(
            "bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0",
            (!whUrl.trim() || initialLoading) && "opacity-50 cursor-not-allowed"
          )}
        >
          Add
        </button>
      </div>

      {initialLoading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-16 bg-surface rounded-lg animate-pulse" />
          ))}
        </div>
      ) : webhooks.length > 0 ? (
        <div className="space-y-2">
          {webhooks.map((wh) => (
            <motion.div
              key={wh.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="bg-surface border border-border rounded-lg p-3 flex items-start gap-3"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-text truncate">{wh.name || wh.url}</span>
                  <span className="text-[10px] text-muted font-mono truncate">{wh.url}</span>
                </div>
                {wh.events && wh.events.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {wh.events.map((ev) => (
                      <span
                        key={ev}
                        className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-primary/10 text-primary"
                      >
                        {ev}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <button
                onClick={() => onRemoveWebhook(wh.id)}
                className="p-1.5 rounded-md text-muted hover:text-danger hover:bg-danger/10 transition-colors shrink-0 text-[10px] font-semibold"
              >
                Remove
              </button>
            </motion.div>
          ))}
        </div>
      ) : (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border rounded-lg"
        >
          <p className="text-sm font-semibold text-text mb-1">No webhooks configured</p>
          <p className="text-xs text-muted">Add a webhook URL to receive threat alerts</p>
        </motion.div>
      )}
    </motion.div>
  );
}
