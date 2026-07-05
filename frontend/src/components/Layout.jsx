import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity, History, Crosshair, ShieldAlert, Ban, Webhook, Rss, Bell,
  Upload, FolderKanban, Database, Settings, AlertTriangle, FileText,
  ChevronDown, ChevronLeft, Cpu, MessageSquare, Send, Radio,
} from "lucide-react";
import { cn } from "../lib/utils";
import brandIcon from "../assest/brand-icon.png";

const navGroups = [
  {
    label: "Core",
    items: [
      { id: "dashboard", label: "Dashboard", icon: Activity },
      { id: "history", label: "History", icon: History },
      { id: "hunt", label: "Hunt", icon: Crosshair },
      { id: "explain", label: "Explain", icon: ShieldAlert },
    ],
  },
  {
    label: "Intel",
    items: [
      { id: "blocklist", label: "Blocklist", icon: Ban },
      { id: "yara", label: "YARA", icon: FileText },
      { id: "webhooks", label: "Webhooks", icon: Webhook },
      { id: "feeds", label: "Feeds", icon: Rss },
      { id: "alerts", label: "Alerts", icon: Bell },
      { id: "syslog", label: "Syslog", icon: Radio },
    ],
  },
  {
    label: "Manage",
    items: [
      { id: "bulk", label: "Bulk Import", icon: Upload },
      { id: "integrations", label: "Integrations", icon: Cpu },
      { id: "notifications", label: "Notifications", icon: Send },
      { id: "workspace", label: "Workspaces", icon: FolderKanban },
      { id: "dbsearch", label: "DB Search", icon: Database },
      { id: "feedback", label: "Feedback", icon: MessageSquare },
      { id: "health", label: "Settings", icon: Settings },
    ],
  },
];

function NavItem({ item, isActive, count, collapsed, onTabChange }) {
  const Icon = item.icon;
  return (
    <button
      onClick={() => onTabChange(item.id)}
      className={cn(
        "group relative flex items-center w-full rounded-lg text-xs font-medium transition-all duration-150",
        "hover:bg-surface-hover hover:text-text active:scale-[0.98]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-1 focus-visible:ring-offset-surface",
        collapsed ? "justify-center px-0 py-2.5" : "gap-2.5 px-3 py-2",
        isActive
          ? "bg-primary-light text-primary"
          : "text-muted"
      )}
      title={collapsed ? item.label : undefined}
      aria-current={isActive ? "page" : undefined}
    >
      {isActive && !collapsed && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-primary rounded-r-full shadow-[0_0_8px_theme(colors.primary.DEFAULT/0.5)]" />
      )}
      {isActive && collapsed && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-primary rounded-r-full shadow-[0_0_8px_theme(colors.primary.DEFAULT/0.5)]" />
      )}
      <Icon className={cn("w-4 h-4 shrink-0", isActive && "text-primary")} />
      {!collapsed && (
        <>
          <span className="flex-1 text-left">{item.label}</span>
          {count !== null && count > 0 && (
            <span className={cn(
              "text-[10px] font-bold font-mono px-1.5 py-0.5 rounded",
              isActive ? "bg-primary/20 text-primary" : "bg-surface-hover text-muted-faint"
            )}>
              {count}
            </span>
          )}
        </>
      )}
    </button>
  );
}

export default function Layout({
  children, activeTab, onTabChange, counts,
  healthStatus, workspaces, activeWorkspace,
  onWorkspaceChange, dark, onToggleTheme,
  backendOnline, sidebarCollapsed, onToggleSidebar,
}) {
  const getCount = (id) => {
    if (id === "blocklist") return counts.blocklist;
    if (id === "history") return counts.history;
    if (id === "webhooks") return counts.webhooks;
    if (id === "feeds") return counts.feeds;
    if (id === "alerts") return counts.alerts;
    return null;
  };

  const sidebarWidth = sidebarCollapsed ? "w-[60px]" : "w-[220px]";

  return (
    <div className="h-screen flex bg-ink text-text overflow-hidden">
      {/* ─── SIDEBAR ─── */}
      <aside className={cn(
        "flex-shrink-0 bg-surface border-r border-border flex flex-col h-screen transition-all duration-300 z-20",
        sidebarWidth
      )}>
        {/* Brand */}
        <div className="flex items-center gap-3 px-4 h-14 border-b border-border flex-shrink-0">
          <img src={brandIcon} className="w-7 h-7 rounded-lg flex-shrink-0" alt="Threat Intel" />
          {!sidebarCollapsed && (
            <motion.span
              initial={false} animate={{ opacity: 1 }}
              className="text-sm font-bold text-text tracking-tight"
            >
              Threat Intel
            </motion.span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto scrollbar-thin p-2 space-y-1">
          {navGroups.map((group) => (
            <div key={group.label}>
              {!sidebarCollapsed && (
                <div className="px-3 pt-3 pb-1">
                  <span className="text-[9px] font-bold font-mono text-muted-faint uppercase tracking-[0.12em]">
                    {group.label}
                  </span>
                </div>
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <NavItem
                    key={item.id}
                    item={item}
                    isActive={activeTab === item.id}
                    count={getCount(item.id)}
                    collapsed={sidebarCollapsed}
                    onTabChange={onTabChange}
                  />
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse toggle */}
        <div className="p-2 border-t border-border">
          <button
            onClick={onToggleSidebar}
            className="flex items-center justify-center w-full py-2 rounded-lg text-muted hover:text-text hover:bg-surface-hover transition-all active:scale-[0.96] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <ChevronLeft className={cn(
              "w-4 h-4 transition-transform duration-200",
              sidebarCollapsed && "rotate-180"
            )} />
          </button>
        </div>
      </aside>

      {/* ─── MAIN ─── */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <header className="bg-surface border-b border-border flex-shrink-0">
          <div className="h-14 px-5 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              {sidebarCollapsed && (
                <button
                  onClick={onToggleSidebar}
                  className="p-1.5 rounded-lg text-muted hover:text-text hover:bg-surface-hover transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                  aria-label="Expand sidebar"
                >
                  <ChevronLeft className="w-4 h-4 rotate-180" />
                </button>
              )}
              <select
                value={activeWorkspace}
                onChange={(e) => onWorkspaceChange(e.target.value)}
                className="bg-surface-light text-text border border-border rounded-lg px-3 py-1.5 text-xs font-medium cursor-pointer focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all"
              >
                {workspaces.length === 0 && <option value="default">default</option>}
                {workspaces.map((w) => (
                  <option key={w.name} value={w.name}>{w.name}</option>
                ))}
              </select>
            </div>

            <div /> {/* spacer */}
          </div>
        </header>

        {!backendOnline && (
          <div className="bg-danger text-white text-center py-2 px-4 text-xs font-semibold flex items-center justify-center gap-2 font-mono tracking-wide">
            <AlertTriangle className="w-3.5 h-3.5" />
            Backend unreachable — some features may not work
          </div>
        )}

        <main className="flex-1 overflow-y-auto scrollbar-thin">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="p-6"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
