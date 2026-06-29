import React from "react";
import { useTheme } from "../ThemeContext";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export default function WorkspaceTab({
  workspaces = [],
  activeWorkspace = "",
  newWsName = "",
  initialLoading = false,
  ignoredIocs = [],
  onNewWsNameChange,
  onCreateWorkspace,
  onDeleteWorkspace,
  onSwitchWorkspace,
  onUnmarkIgnored,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Workspaces</h3>
        <p className="text-xs text-muted mt-0.5">
          Manage workspaces and ignored IOCs
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Workspaces */}
        <div>
          <div className="flex gap-2 mb-3">
            <input
              type="text"
              value={newWsName}
              onChange={(e) => onNewWsNameChange(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !initialLoading && onCreateWorkspace()}
              placeholder="New workspace name..."
              className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted-faint focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none transition-all"
            />
            <button
              onClick={onCreateWorkspace}
              disabled={!newWsName.trim() || initialLoading}
              className={cn(
                "bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0",
                (!newWsName.trim() || initialLoading) && "opacity-50 cursor-not-allowed"
              )}
            >
              Create
            </button>
          </div>

          {initialLoading ? (
            <div className="space-y-2">
              {[1, 2].map((i) => (
                <div key={i} className="h-12 bg-surface rounded-lg animate-pulse" />
              ))}
            </div>
          ) : workspaces.length > 0 ? (
            <div className="space-y-1.5">
              {workspaces.map((ws) => {
                const isActive = ws.name === activeWorkspace;
                return (
                  <motion.div
                    key={ws.name}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={cn(
                      "flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-2.5 transition-colors",
                      isActive && "border-primary/40 bg-primary/5"
                    )}
                  >
                    <span className="flex-1 text-xs font-semibold text-text truncate">
                      {ws.name}
                    </span>
                    {isActive && (
                      <span className="text-[10px] font-mono font-semibold text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                        Active
                      </span>
                    )}
                    {!isActive && (
                      <button
                        onClick={() => onSwitchWorkspace(ws.name)}
                        className="p-1 rounded text-muted hover:text-text hover:bg-surface-hover transition-colors text-[10px] font-semibold"
                        title="Switch to this workspace"
                      >
                        Switch
                      </button>
                    )}
                    <button
                      onClick={() => onDeleteWorkspace(ws.name)}
                      className="p-1 rounded text-muted hover:text-danger hover:bg-danger/10 transition-colors text-[10px] font-semibold"
                      title="Delete workspace"
                    >
                      Delete
                    </button>
                  </motion.div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-center bg-surface rounded-lg border border-dashed border-border">
              <p className="text-xs font-semibold text-text">No workspaces</p>
              <p className="text-[10px] text-muted mt-1">Create a workspace to organize your work</p>
            </div>
          )}
        </div>

        {/* Right: Ignored IOCs */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-xs font-semibold text-text">Ignored IOCs</span>
            <span className="text-[10px] text-muted font-mono">{ignoredIocs.length}</span>
          </div>

          {ignoredIocs.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {ignoredIocs.map((item) => {
                const iocStr = typeof item === "string" ? item : item.ioc;
                return (
                  <span
                    key={iocStr}
                    className="inline-flex items-center gap-1.5 bg-surface border border-border rounded-lg px-2.5 py-1.5 text-xs font-mono text-text group hover:border-danger/50 transition-colors"
                  >
                    <span className="max-w-[160px] truncate">{iocStr}</span>
                    <button
                      onClick={() => onUnmarkIgnored(iocStr)}
                      className="text-muted hover:text-danger transition-colors shrink-0 text-[10px] font-semibold px-1.5 py-1"
                    >
                      Unignore
                    </button>
                  </span>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 text-center bg-surface rounded-lg border border-dashed border-border">
              <p className="text-xs font-semibold text-text">No ignored IOCs</p>
              <p className="text-[10px] text-muted mt-1">Ignored IOCs will appear here</p>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
