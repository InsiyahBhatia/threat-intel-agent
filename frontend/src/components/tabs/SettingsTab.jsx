import React from "react";
import {} from "lucide-react";
import SeverityTag from "../SeverityTag";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "../../lib/utils";

function classifyIOC(ioc) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(ioc)) return "IP";
  if (/^[0-9a-f]{32}$/i.test(ioc) || /^[0-9a-f]{40}$/i.test(ioc) || /^[0-9a-f]{64}$/i.test(ioc)) return "HASH";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(ioc)) return "DOMAIN";
  return "OTHER";
}

function AccordionSection({ id, icon, title, description, color, count, badgeLabel, isOpen, onToggle, children }) {
  const chevronClass = isOpen ? "rotate-180" : "rotate-0";
  return (
    <div className="bg-surface-light border border-border rounded-xl overflow-hidden mb-4">
      <div
        onClick={() => onToggle(id)}
        className="flex items-center gap-3 px-5 py-3.5 cursor-pointer select-none hover:bg-surface-hover transition-colors"
      >
        {icon && (
          <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0", color.bg)}>
            {React.cloneElement(icon, { className: cn("w-4 h-4", color.text) })}
          </div>
        )}
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold text-text">{title}</div>
          {description && <div className="text-xs text-muted mt-0.5">{description}</div>}
        </div>
        {count != null && (
          <span className={cn("text-[10px] font-bold font-mono px-2 py-0.5 rounded-full shrink-0", color.bg, color.text)}>
            {count}
          </span>
        )}
        {badgeLabel && (
          <span className="text-[10px] font-semibold text-muted shrink-0">{badgeLabel}</span>
        )}
        <svg
          className={cn("w-4 h-4 text-muted transition-transform duration-200 shrink-0", chevronClass)}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="overflow-hidden border-t border-border"
          >
            <div className="px-5 py-4 space-y-4">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function WebhookRow({ webhooks, whUrl, whEvents, onWhUrlChange, onWhEventsChange, onAddWebhook, onRemoveWebhook }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Webhooks</div>
          <div className="text-[10px] text-muted mt-0.5">Fire notifications to URLs on CRITICAL/HIGH detection</div>
        </div>
        <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 shrink-0">
          {webhooks.length}
        </span>
      </div>
      <div className="flex items-center gap-2 mb-3">
        <input
          type="text"
          value={whUrl}
          onChange={(e) => onWhUrlChange(e.target.value)}
          placeholder="Webhook URL"
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <input
          type="text"
          value={whEvents}
          onChange={(e) => onWhEventsChange(e.target.value)}
          placeholder="Events (CRITICAL,HIGH)"
          className="w-36 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
          <button
            onClick={onAddWebhook}
            disabled={!whUrl.trim()}
            className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
          >
            Add
          </button>
        </div>
        {webhooks.length > 0 && (
          <div className="space-y-1.5">
            {webhooks.map((wh) => (
              <div key={wh.id} className="flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-2">
                <span className="flex-1 text-xs font-mono text-text truncate">{wh.name || wh.url}</span>
              <span className="text-[10px] text-muted font-mono truncate max-w-[120px]">{wh.events}</span>
              <button
                onClick={() => onRemoveWebhook(wh.id)}
                className="text-muted hover:text-danger transition-colors shrink-0 text-[10px] font-semibold"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AlertHistoryRow({ alerts, alertStats, formatTime }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Alert History</div>
          <div className="text-[10px] text-muted mt-0.5">Recent notifications dispatched via webhooks</div>
        </div>
        <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 shrink-0">
          {alertStats?.total || alerts.length}
        </span>
      </div>
      {alerts.length > 0 ? (
        <>
          {alertStats && (
            <div className="flex gap-2 mb-3">
              {Object.entries(alertStats.by_severity || {}).map(([sev, count]) => (
                <span key={sev} className="text-[10px] font-mono px-2 py-1 rounded bg-surface border border-border text-text">
                  {sev}: {count}
                </span>
              ))}
            </div>
          )}
          <div className="w-full overflow-x-auto rounded-lg border border-border">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-surface">
                  <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">IOC</th>
                  <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Severity</th>
                  <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Channel</th>
                  <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Status</th>
                  <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={i} className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors">
                    <td className="text-xs p-3 border-b border-border font-mono font-semibold text-text">{a.ioc}</td>
                    <td className="text-xs p-3 border-b border-border"><SeverityTag severity={a.severity} small /></td>
                    <td className="text-xs p-3 border-b border-border text-muted">{a.channel}</td>
                    <td className="text-xs p-3 border-b border-border">
                      <span className={cn(
                        "text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded",
                        a.status === "sent" && "bg-green-500/10 text-green-400",
                        a.status === "failed" && "bg-red-500/10 text-red-400",
                        a.status !== "sent" && a.status !== "failed" && "bg-surface-hover text-muted"
                      )}>
                        {a.status}
                      </span>
                    </td>
                    <td className="text-xs p-3 border-b border-border text-muted font-mono whitespace-nowrap">{formatTime ? formatTime(a.created_at) : a.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="flex flex-col items-center justify-center py-6 text-center">
          <p className="text-xs text-muted">No alerts dispatched yet</p>
        </div>
      )}
    </div>
  );
}

function ThreatFeedsRow({ feeds, newFeedName, newFeedUrl, feedPolling, onNewFeedNameChange, onNewFeedUrlChange, onAddFeed, onDeleteFeed, onPollFeeds }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Threat Feeds</div>
          <div className="text-[10px] text-muted mt-0.5">RSS/Atom feeds for IOC ingestion</div>
        </div>
        <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full bg-teal-500/10 text-teal-400 shrink-0">
          {feeds.length}
        </span>
      </div>
      <div className="flex items-center gap-2 mb-3">
        <input
          type="text"
          value={newFeedName}
          onChange={(e) => onNewFeedNameChange(e.target.value)}
          placeholder="Feed name"
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <input
          type="text"
          value={newFeedUrl}
          onChange={(e) => onNewFeedUrlChange(e.target.value)}
          placeholder="Feed URL"
          className="flex-[2] bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <button
          onClick={onAddFeed}
          disabled={!newFeedName.trim() || !newFeedUrl.trim()}
          className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
        >
          Add
        </button>
      </div>
      {feeds.length > 0 && (
        <div className="space-y-1.5 mb-3">
          {feeds.map((feed) => (
            <div key={feed.id} className="flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-2">
              <span className="flex-1 text-xs font-mono text-text truncate">{feed.name}</span>
              <span className="text-[10px] text-muted font-mono truncate max-w-[150px]">{feed.url}</span>
              <span className={cn(
                "text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded",
                feed.enabled ? "bg-green-500/10 text-green-400" : "bg-amber-500/10 text-amber-400"
              )}>
                {feed.enabled ? "Active" : "Paused"}
              </span>
              <button
                onClick={() => onDeleteFeed(feed.id)}
                className="text-muted hover:text-danger transition-colors shrink-0 text-[10px] font-semibold"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
      <button
        onClick={onPollFeeds}
        disabled={feedPolling || feeds.length === 0}
        className="border border-border text-muted hover:text-text hover:bg-surface-hover disabled:opacity-40 disabled:cursor-not-allowed px-3 py-1.5 rounded-lg text-xs transition-colors"
      >
        Poll Now
      </button>
    </div>
  );
}

function BulkImportRow({ bulkInput, bulkLoading, onBulkInputChange, onDoBulkImport, bulkResults }) {
  const detected = bulkInput.trim() ? bulkInput.trim().split("\n").filter((l) => l.trim()).length : 0;
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Bulk Import</div>
          <div className="text-[10px] text-muted mt-0.5">Investigate multiple IOCs at once</div>
        </div>
      </div>
      <textarea
        value={bulkInput}
        onChange={(e) => onBulkInputChange(e.target.value)}
        placeholder="Enter IOCs, one per line..."
        rows={4}
        className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all resize-none"
      />
      <div className="flex items-center justify-between mt-2">
        <span className="text-[10px] text-muted font-mono">{detected} IOC{detected !== 1 ? "s" : ""} detected</span>
        <button
          onClick={onDoBulkImport}
          disabled={bulkLoading || !bulkInput.trim()}
          className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
        >
          {bulkLoading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Investigating...
            </>
          ) : (
            <>
              Investigate
            </>
          )}
        </button>
      </div>
      {bulkResults && (
        <div className="mt-3 w-full overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface">
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">IOC</th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Severity</th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Status</th>
              </tr>
            </thead>
            <tbody>
              {(bulkResults.results || []).map((r, i) => (
                <tr key={i} className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors">
                  <td className="text-xs p-3 border-b border-border font-mono font-semibold text-text">{r.ioc}</td>
                  <td className="text-xs p-3 border-b border-border"><SeverityTag severity={r.severity} small /></td>
                  <td className="text-xs p-3 border-b border-border">
                    <span className={cn(
                      "text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded",
                      r.status === "success" && "bg-green-500/10 text-green-400",
                      r.status === "error" && "bg-red-500/10 text-red-400",
                      r.status !== "success" && r.status !== "error" && "bg-surface-hover text-muted"
                    )}>
                      {r.status}
                    </span>
                  </td>
                </tr>
              ))}
              {bulkResults.succeeded > 0 && (
                <tr className="bg-green-500/5">
                  <td colSpan={3} className="text-xs p-3 text-green-400 font-mono font-semibold">
                    {bulkResults.succeeded} succeeded
                  </td>
                </tr>
              )}
              {bulkResults.failed > 0 && (
                <tr className="bg-red-500/5">
                  <td colSpan={3} className="text-xs p-3 text-red-400 font-mono font-semibold">
                    {bulkResults.failed} failed
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DatabaseSearchRow({ dbSearch, dbLoading, onDbSearchChange, onDoDbSearch, dbResults }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Database Search</div>
          <div className="text-[10px] text-muted mt-0.5">Search past investigations by IOC or category</div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            type="text"
            value={dbSearch}
            onChange={(e) => onDbSearchChange(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !dbLoading && dbSearch.trim() && onDoDbSearch()}
            placeholder="Search by IOC or category..."
            className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
          />
        </div>
        <button
          onClick={onDoDbSearch}
          disabled={dbLoading || !dbSearch.trim()}
          className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
        >
          Search
        </button>
      </div>
      {dbResults && (
        <div className="mt-3 w-full overflow-x-auto rounded-lg border border-border">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface">
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">IOC</th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Severity</th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Category</th>
                <th className="text-[10px] uppercase tracking-wider text-muted font-semibold font-mono p-3 text-left border-b border-border">Time</th>
              </tr>
            </thead>
            <tbody>
              {(dbResults.results || []).map((r, i) => (
                <tr key={i} className="border-b border-border last:border-b-0 hover:bg-surface-light/50 transition-colors">
                  <td className="text-xs p-3 border-b border-border font-mono font-semibold text-text">{r.ioc}</td>
                  <td className="text-xs p-3 border-b border-border"><SeverityTag severity={r.severity} small /></td>
                  <td className="text-xs p-3 border-b border-border text-muted">{r.category || "-"}</td>
                  <td className="text-xs p-3 border-b border-border text-muted font-mono whitespace-nowrap">{r.time || "-"}</td>
                </tr>
              ))}
              {dbResults.results && dbResults.results.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-xs p-6 text-center text-muted">No results found</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SampleIocsRow({ sampleIocs, onInvestigate, onTabChange, onSetIoc, onSetActiveTab }) {
  const groups = { IP: [], DOMAIN: [], HASH: [], OTHER: [] };
  (sampleIocs || []).forEach((ioc) => {
    const type = classifyIOC(ioc);
    groups[type].push(ioc);
  });
  const groupColors = {
    IP: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/20" },
    DOMAIN: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/20" },
    HASH: { bg: "bg-purple-500/10", text: "text-purple-400", border: "border-purple-500/20" },
  };
  const groupLabels = { IP: "IP Addresses", DOMAIN: "Domains", HASH: "Hashes" };

  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Sample IOCs</div>
          <div className="text-[10px] text-muted mt-0.5">Quick-start investigations with sample indicators</div>
        </div>
      </div>
      <div className="space-y-3">
        {["IP", "DOMAIN", "HASH"].map((type) => {
          const items = groups[type];
          if (items.length === 0) return null;
          const c = groupColors[type];
          return (
            <div key={type}>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[10px] font-bold text-muted uppercase tracking-wider font-mono">
                  {groupLabels[type]}
                </span>
                <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded", c.bg, c.text)}>
                  {items.length}
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {items.map((ioc) => (
                  <button
                    key={ioc}
                    onClick={() => {
                      onTabChange && onTabChange("dashboard");
                      onSetIoc && onSetIoc(ioc);
                      onSetActiveTab && onSetActiveTab("dashboard");
                      onInvestigate && onInvestigate(ioc);
                    }}
                    className={cn(
                      "inline-flex items-center gap-1.5 bg-surface border rounded-lg px-2.5 py-1.5 text-xs font-mono text-text hover:border-blue-500/50 hover:text-blue-400 transition-colors group"
                    )}
                  >
                    <span className="max-w-[160px] truncate">{ioc}</span>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function BlocklistRow({ blocklist, onTabChange }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Blocklist</div>
          <div className="text-[10px] text-muted mt-0.5">Monitored indicators excluded from alerts</div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full bg-red-500/10 text-red-400">
            {blocklist?.length || 0}
          </span>
          <button
            onClick={() => onTabChange && onTabChange("blocklist")}
            className="border border-border text-muted hover:text-text hover:bg-surface-hover px-3 py-1.5 rounded-lg text-xs transition-colors"
          >
            Manage
          </button>
        </div>
      </div>
    </div>
  );
}

function WorkspaceSection({ workspaces, activeWorkspace, newWsName, initialLoading, onNewWsNameChange, onCreateWorkspace, onDeleteWorkspace, onSwitchWorkspace }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Create Workspace</div>
          <div className="text-[10px] text-muted mt-0.5">Manage isolated investigation environments</div>
        </div>
      </div>
      <div className="flex items-center gap-2 mb-3">
        <input
          type="text"
          value={newWsName}
          onChange={(e) => onNewWsNameChange(e.target.value)}
          placeholder="Workspace name"
          className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
        />
        <button
          onClick={onCreateWorkspace}
          disabled={initialLoading || !newWsName.trim()}
          className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
        >
          Create
        </button>
      </div>
      {workspaces && workspaces.length > 0 && (
        <div className="space-y-1.5">
          {workspaces.map((ws) => (
            <div key={ws.name} className="flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-2">
              <span className="flex-1 text-xs font-mono text-text truncate">{ws.name}</span>
              {ws.name === activeWorkspace ? (
                <span className="text-[10px] font-semibold font-mono text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded">Active</span>
              ) : (
                <button
                  onClick={() => onSwitchWorkspace(ws.name)}
                  className="text-[10px] font-semibold font-mono text-primary hover:text-primary-hover px-1.5 py-0.5 rounded hover:bg-primary/10 transition-colors"
                >
                  Switch
                </button>
              )}
              {ws.name !== activeWorkspace && (
                <button
                onClick={() => onDeleteWorkspace(ws.name)}
                className="text-muted hover:text-danger transition-colors shrink-0 text-[10px] font-semibold"
              >
                Delete
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function IgnoredIocsRow({ ignoredIocs, onUnmarkIgnored }) {
  return (
    <div>
      <div className="flex items-center justify-between py-3">
        <div>
          <div className="text-xs font-medium text-text">Ignored IOCs</div>
          <div className="text-[10px] text-muted mt-0.5">Indicators excluded from future alerts</div>
        </div>
        <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400">
          {ignoredIocs?.length || 0}
        </span>
      </div>
      {ignoredIocs && ignoredIocs.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {ignoredIocs.map((item) => {
            const ioc = typeof item === "string" ? item : item.ioc;
            return (
              <span
                key={ioc}
                className="inline-flex items-center gap-1.5 bg-surface border border-border rounded-lg px-2.5 py-1.5 text-xs font-mono text-text group hover:border-danger/50 transition-colors"
              >
                <span className="max-w-[160px] truncate">{ioc}</span>
                <button
                  onClick={() => onUnmarkIgnored(ioc)}
                  className="text-muted hover:text-danger transition-colors shrink-0 text-[10px] font-semibold"
                >
                  Unignore
                </button>
              </span>
            );
          })}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-6 text-center">
          <p className="text-xs text-muted">No ignored IOCs</p>
        </div>
      )}
    </div>
  );
}

export default function SettingsTab({
  health,
  healthStatus,
  settingsOpen,
  onToggleSection,
  webhooks = [],
  whUrl,
  whEvents,
  onWhUrlChange,
  onWhEventsChange,
  onAddWebhook,
  onRemoveWebhook,
  alerts = [],
  alertStats,
  feeds = [],
  newFeedName,
  newFeedUrl,
  feedPolling,
  onNewFeedNameChange,
  onNewFeedUrlChange,
  onAddFeed,
  onDeleteFeed,
  onPollFeeds,
  bulkInput,
  bulkLoading,
  onBulkInputChange,
  onDoBulkImport,
  bulkResults,
  dbSearch,
  dbLoading,
  onDbSearchChange,
  onDoDbSearch,
  dbResults,
  sampleIocs = [],
  blocklist = [],
  onInvestigate,
  workspaces = [],
  activeWorkspace,
  newWsName,
  initialLoading,
  onNewWsNameChange,
  onCreateWorkspace,
  onDeleteWorkspace,
  onSwitchWorkspace,
  ignoredIocs = [],
  onUnmarkIgnored,
  onTabChange,
  onSetIoc,
  onSetActiveTab,
  formatTime,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Notifications */}
      <AccordionSection
        id="notifications"
        icon={null}
        title="Notifications"
        description="Configure webhook alerts and view dispatch history"
        color={{ bg: "bg-blue-500/10", text: "text-blue-400" }}
        isOpen={settingsOpen === "notifications"}
        onToggle={onToggleSection}
      >
        <WebhookRow
          webhooks={webhooks}
          whUrl={whUrl}
          whEvents={whEvents}
          onWhUrlChange={onWhUrlChange}
          onWhEventsChange={onWhEventsChange}
          onAddWebhook={onAddWebhook}
          onRemoveWebhook={onRemoveWebhook}
        />
        <AlertHistoryRow alerts={alerts} alertStats={alertStats} formatTime={formatTime} />
      </AccordionSection>

      {/* Threat Intelligence */}
      <AccordionSection
        id="intel"
        icon={null}
        title="Threat Intelligence"
        description="Manage feeds, bulk imports, and database lookups"
        color={{ bg: "bg-teal-500/10", text: "text-teal-400" }}
        isOpen={settingsOpen === "intel"}
        onToggle={onToggleSection}
      >
        <ThreatFeedsRow
          feeds={feeds}
          newFeedName={newFeedName}
          newFeedUrl={newFeedUrl}
          feedPolling={feedPolling}
          onNewFeedNameChange={onNewFeedNameChange}
          onNewFeedUrlChange={onNewFeedUrlChange}
          onAddFeed={onAddFeed}
          onDeleteFeed={onDeleteFeed}
          onPollFeeds={onPollFeeds}
        />
        <BulkImportRow
          bulkInput={bulkInput}
          bulkLoading={bulkLoading}
          onBulkInputChange={onBulkInputChange}
          onDoBulkImport={onDoBulkImport}
          bulkResults={bulkResults}
        />
        <DatabaseSearchRow
          dbSearch={dbSearch}
          dbLoading={dbLoading}
          onDbSearchChange={onDbSearchChange}
          onDoDbSearch={onDoDbSearch}
          dbResults={dbResults}
        />
      </AccordionSection>

      {/* Samples & Blocklist */}
      <AccordionSection
        id="samples"
        icon={null}
        title="Samples & Blocklist"
        description="Quick-start indicators and managed blocklist"
        color={{ bg: "bg-red-500/10", text: "text-red-400" }}
        isOpen={settingsOpen === "samples"}
        onToggle={onToggleSection}
      >
        <SampleIocsRow sampleIocs={sampleIocs} onInvestigate={onInvestigate} onTabChange={onTabChange} onSetIoc={onSetIoc} onSetActiveTab={onSetActiveTab} />
        <BlocklistRow blocklist={blocklist} onTabChange={onTabChange} />
      </AccordionSection>

      {/* Workspace */}
      <AccordionSection
        id="workspace"
        icon={null}
        title="Workspace"
        description="Manage environments and ignored indicators"
        color={{ bg: "bg-purple-500/10", text: "text-purple-400" }}
        isOpen={settingsOpen === "workspace"}
        onToggle={onToggleSection}
      >
        <WorkspaceSection
          workspaces={workspaces}
          activeWorkspace={activeWorkspace}
          newWsName={newWsName}
          initialLoading={initialLoading}
          onNewWsNameChange={onNewWsNameChange}
          onCreateWorkspace={onCreateWorkspace}
          onDeleteWorkspace={onDeleteWorkspace}
          onSwitchWorkspace={onSwitchWorkspace}
        />
        <IgnoredIocsRow ignoredIocs={ignoredIocs} onUnmarkIgnored={onUnmarkIgnored} />
      </AccordionSection>
    </motion.div>
  );
}
