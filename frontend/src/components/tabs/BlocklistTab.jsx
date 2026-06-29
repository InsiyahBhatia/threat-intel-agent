import React from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

function classifyIOC(ioc) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(ioc)) return "IP";
  if (/^[0-9a-f]{32}$/i.test(ioc) || /^[0-9a-f]{40}$/i.test(ioc) || /^[0-9a-f]{64}$/i.test(ioc)) return "HASH";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(ioc)) return "DOMAIN";
  return "OTHER";
}

export default function BlocklistTab({
  blocklist = [],
  blInput = "",
  blSearch = "",
  blLoading = false,
  onBlInputChange,
  onBlSearchChange,
  onAddToBlocklist,
  onRemoveFromBlocklist,
  onClearBlocklist,
}) {
  const filtered = blocklist.filter((ioc) =>
    ioc.toLowerCase().includes(blSearch.toLowerCase())
  );

  const groups = { IP: [], DOMAIN: [], HASH: [], OTHER: [] };
  filtered.forEach((ioc) => {
    const type = classifyIOC(ioc);
    groups[type].push(ioc);
  });

  const groupOrder = ["IP", "DOMAIN", "HASH", "OTHER"];
  const groupColors = {
    IP: { bg: "bg-sky-500/10", text: "text-sky-400" },
    DOMAIN: { bg: "bg-amber-500/10", text: "text-amber-400" },
    HASH: { bg: "bg-purple-500/10", text: "text-purple-400" },
    OTHER: { bg: "bg-surface-hover", text: "text-muted" },
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      const lines = text.split("\n").map((s) => s.trim()).filter(Boolean);
      onAddToBlocklist(lines.length > 1 ? lines : text);
    } catch {}
  };

  return (
    <div className="bg-surface border border-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-surface-light">
        <h3 className="text-xs font-bold text-text uppercase tracking-wider">
          IOC Blocklist Manager
        </h3>
      </div>

      <div className="p-4 space-y-4">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={blInput}
            onChange={(e) => onBlInputChange(e.target.value)}
            placeholder="Enter IOC (IP, domain, hash...)"
            className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
          />
          <button
            onClick={() => onAddToBlocklist(blInput)}
            disabled={!blInput.trim() || blLoading}
            className="bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors"
          >
            Add
          </button>
          <button
            onClick={handlePaste}
            className="border border-border text-muted hover:text-text hover:bg-surface-hover px-4 py-2 rounded-lg text-xs transition-colors"
          >
            Paste
          </button>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-muted font-mono">
            {blocklist.length} IOC{blocklist.length !== 1 ? "s" : ""}
          </span>
          {blocklist.length > 0 && (
            <button
              onClick={onClearBlocklist}
              className="border border-danger/30 text-danger hover:bg-danger-light px-3 py-1.5 rounded-lg text-xs transition-colors"
            >
              Clear All
            </button>
          )}
        </div>

        <div>
          <input
            type="text"
            value={blSearch}
            onChange={(e) => onBlSearchChange(e.target.value)}
            placeholder="Search blocklist..."
            className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
          />
        </div>

        {blocklist.length > 0 ? (
          <div className="space-y-3">
            {groupOrder.map((type) => {
              const items = groups[type];
              if (items.length === 0) return null;
              const c = groupColors[type];
              return (
                <motion.div
                  key={type}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] font-bold text-muted uppercase tracking-wider font-mono">
                      {type}
                    </span>
                    <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded", c.bg, c.text)}>
                      {items.length}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {items.map((ioc) => (
                      <span
                        key={ioc}
                        className="inline-flex items-center gap-1.5 bg-surface border border-border rounded-lg px-2.5 py-1.5 text-xs font-mono text-text group hover:border-danger/50 transition-colors"
                      >
                        <span className="max-w-[180px] truncate">{ioc}</span>
                        <button
                          onClick={() => onRemoveFromBlocklist(ioc)}
                          className="text-muted hover:text-danger transition-colors flex-shrink-0 text-[10px] font-semibold"
                        >
                          Remove
                        </button>
                      </span>
                    ))}
                  </div>
                </motion.div>
              );
            })}
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border rounded-lg"
          >
            <p className="text-sm font-semibold text-text mb-1">Blocklist empty</p>
            <p className="text-xs text-muted">
              Add IPs, domains, hashes to monitor for threats
            </p>
          </motion.div>
        )}
      </div>
    </div>
  );
}
