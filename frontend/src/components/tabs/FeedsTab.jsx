import React from "react";
import SeverityTag from "../SeverityTag";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function FeedsTab({
  feeds = [],
  feedEntries = [],
  newFeedName = "",
  newFeedUrl = "",
  feedPolling = false,
  onNewFeedNameChange,
  onNewFeedUrlChange,
  onAddFeed,
  onDeleteFeed,
  onPollFeeds,
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
        <h3 className="text-sm font-semibold text-text">Threat Feeds</h3>
        <p className="text-xs text-muted mt-0.5">
          Subscribe to external threat intelligence feeds
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Feed Management */}
        <div>
          <div className="flex flex-col sm:flex-row gap-2 mb-3">
            <input
              type="text"
              value={newFeedName}
              onChange={(e) => onNewFeedNameChange(e.target.value)}
              placeholder="Feed name..."
              className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
            />
            <input
              type="text"
              value={newFeedUrl}
              onChange={(e) => onNewFeedUrlChange(e.target.value)}
              placeholder="Feed URL..."
              className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
            />
            <button
              onClick={onAddFeed}
              disabled={!newFeedName.trim() || !newFeedUrl.trim() || initialLoading}
              className={cn(
                "bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0",
                (!newFeedName.trim() || !newFeedUrl.trim() || initialLoading) && "opacity-50 cursor-not-allowed"
              )}
            >
              Add
            </button>
          </div>

          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-muted font-mono">{feeds.length} feed{feeds.length !== 1 ? "s" : ""}</span>
            <button
              onClick={onPollFeeds}
              disabled={feedPolling || feeds.length === 0}
              className={cn(
                "border border-border text-muted hover:text-text hover:bg-surface-hover px-3 py-1.5 rounded-lg text-xs transition-colors",
                (feedPolling || feeds.length === 0) && "opacity-40 cursor-not-allowed"
              )}
            >
              Poll All
            </button>
          </div>

          {initialLoading ? (
            <div className="space-y-2">
              {[1, 2].map((i) => (
                <div key={i} className="h-14 bg-surface rounded-lg animate-pulse" />
              ))}
            </div>
          ) : feeds.length > 0 ? (
            <div className="space-y-2">
              {feeds.map((feed) => (
                <motion.div
                  key={feed.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-text truncate">{feed.name}</span>
                      <span className={cn(
                        "text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded",
                        feed.enabled
                          ? "bg-green-500/10 text-green-400"
                          : "bg-muted/10 text-muted"
                      )}>
                        {feed.enabled ? "Active" : "Paused"}
                      </span>
                    </div>
                    <p className="text-[10px] text-muted font-mono truncate mt-0.5">{feed.url}</p>
                  </div>
                  <button
                    onClick={() => onDeleteFeed(feed.id)}
                    className="p-1.5 rounded-md text-muted hover:text-danger hover:bg-danger/10 transition-colors shrink-0 text-[10px] font-semibold"
                  >
                    Remove
                  </button>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-center bg-surface rounded-lg border border-dashed border-border">
              <p className="text-xs font-semibold text-text">No feeds configured</p>
              <p className="text-[10px] text-muted mt-1">Add a feed to start receiving IOC data</p>
            </div>
          )}
        </div>

        {/* Right: Feed Entries */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-xs font-semibold text-text">Feed Entries</span>
            <span className="text-[10px] text-muted font-mono">{feedEntries.length}</span>
          </div>

          {feedEntries.length > 0 ? (
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
                      Feed
                    </th>
                    <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono px-3 py-2.5 text-left whitespace-nowrap border-b border-border">
                      Date
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {feedEntries.map((entry, i) => (
                    <tr
                      key={i}
                      className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors"
                    >
                      <td className="px-3 py-2.5">
                        <span className="font-mono font-semibold text-text text-xs max-w-[160px] truncate block">
                          {entry.ioc}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityTag severity={entry.severity} small />
                      </td>
                      <td className="px-3 py-2.5 text-xs text-muted font-mono">
                        {entry.feed_name || "-"}
                      </td>
                      <td className="px-3 py-2.5 text-xs text-muted font-mono whitespace-nowrap">
                        {entry.created_at
                          ? new Date(entry.created_at).toLocaleDateString("en-US", {
                              month: "short", day: "numeric",
                            })
                          : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-center bg-surface rounded-lg border border-dashed border-border">
              <p className="text-xs font-semibold text-text">No entries yet</p>
              <p className="text-[10px] text-muted mt-1">Poll feeds to fetch IOC entries</p>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
