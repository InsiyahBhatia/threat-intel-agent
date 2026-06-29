import React, { useMemo, useState, useEffect, useRef, useCallback } from "react";
import { ThemeProvider, useTheme } from "./components/ThemeContext";
import SeverityTag from "./components/SeverityTag";
import StatCard from "./components/StatCard";
import Toast from "./components/Toast";
import TimelineView from "./components/TimelineView";
import useKeyboardShortcuts from "./components/KeyboardShortcuts";
import Layout from "./components/Layout";
import ReportPreview from "./components/ReportPreview";
import DashboardTab from "./components/tabs/DashboardTab";
import HistoryTab from "./components/tabs/HistoryTab";
import HuntTab from "./components/tabs/HuntTab";
import ExplainTab from "./components/tabs/ExplainTab";
import BlocklistTab from "./components/tabs/BlocklistTab";
import BulkImportTab from "./components/tabs/BulkImportTab";
import WebhooksTab from "./components/tabs/WebhooksTab";
import AlertsTab from "./components/tabs/AlertsTab";
import FeedsTab from "./components/tabs/FeedsTab";
import DbSearchTab from "./components/tabs/DbSearchTab";
import WorkspaceTab from "./components/tabs/WorkspaceTab";
import SettingsTab from "./components/tabs/SettingsTab";
import { Network } from "vis-network";
import { DataSet } from "vis-data";
import "vis-network/styles/vis-network.min.css";
import brandIcon from "./assest/brand-icon.png";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const STORAGE_KEY = "tia-dashboard-history";
const BLOCKLIST_STORAGE_KEY = "tia-blocklist";
const WORKSPACE_KEY = "tia-active-workspace";

const severityConfig = {
  CRITICAL: { color: "#c32430", bg: "#fce9ea", label: "Critical" },
  HIGH: { color: "#c98600", bg: "#fef7e6", label: "High" },

  LOW: { color: "#00a5b8", bg: "#e6f6f8", label: "Low" },
  CLEAN: { color: "#1a854a", bg: "#eef6e5", label: "Clean" },
  UNKNOWN: { color: "#5c6370", bg: "#f0f2f5", label: "Unknown" },
};

const sampleIocs = ["185.220.101.1", "8.8.8.8", "malware-c2.ru", "d41d8cd98f00b204e9800998ecf8427e"];

const ICONS = {
  search: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
  shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  alert: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  graph: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><path d="M6 9v6"/><path d="M18 9v3"/><path d="M12 15v-3"/><path d="M9 6h6"/></svg>`,
  block: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`,
  history: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  activity: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  add: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  x: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  copy: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  play: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  webhook: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 1 0 12H8a6 6 0 0 1-6-6h4"/><path d="M14 12a4 4 0 0 1 0 8H6"/><path d="M10 8V4"/><path d="M6 8V2"/><path d="M10 16a2 2 0 1 1 0-4h4"/></svg>`,
  workspace: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>`,
  explain: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
  statTotal: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>`,
  statCritical: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>`,
  statHigh: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  statPriority: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
  import: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  bell: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  rss: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>`,
  db: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
  sun: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  emptyChart: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 17V13"/><path d="M11 17V9"/><path d="M15 17V5"/><path d="M19 17V11"/></svg>`,
  emptyShield: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="12" x2="15" y2="12"/></svg>`,
  emptyList: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>`,
};

function buildCss(p) {
  const isDark = p.ink === "#131315";
  return `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; }
  body { margin: 0; background: ${p.ink}; color: ${p.text}; font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 13px; -webkit-font-smoothing: antialiased; }
  button, input, textarea, select { font: inherit; outline: none; }
  button { border: 0; cursor: pointer; background: none; }
  #root { min-height: 100vh; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: ${isDark ? "#45464d" : "#c5c9d4"}; border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: ${isDark ? "#909097" : "#a8adb8"}; }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes spin { to { transform: rotate(360deg); } }
  .spinner-sm { width: 14px; height: 14px; border-radius: 50%; border: 2px solid ${p.line}; border-top-color: ${p.blue}; animation: spin 0.7s linear infinite; display: inline-block; }
  `;
}

function sevCfg(s) { return severityConfig[s] || severityConfig.UNKNOWN; }
function loadHistory() { try { const r = localStorage.getItem(STORAGE_KEY); return r ? JSON.parse(r) : []; } catch { return []; } }
function saveHistory(items) { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, 200))); } catch {} }
function loadBlocklist() { try { const r = localStorage.getItem(BLOCKLIST_STORAGE_KEY); return r ? JSON.parse(r) : []; } catch { return []; } }
function saveBlocklist(items) { try { localStorage.setItem(BLOCKLIST_STORAGE_KEY, JSON.stringify(items)); } catch {} }

function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts); const now = new Date(); const diff = (now - d) / 1000;
  if (isNaN(d.getTime())) return ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

function AppInner() {
  const { palette, dark, toggleTheme } = useTheme();
  const css = useMemo(() => buildCss(palette), [palette]);
  const [ioc, setIoc] = useState("");
  const [progress, setProgress] = useState([]);
  const progressRef = useRef([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState(null);
  const [history, setHistory] = useState(loadHistory);
  const [health, setHealth] = useState(null);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [selReport, setSelReport] = useState(null);
  const [settingsOpen, setSettingsOpen] = useState(null);
  const [feed, setFeed] = useState([]);
  const feedRef = useRef([]);
  const [ignoredIocs, setIgnoredIocs] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [huntInput, setHuntInput] = useState("");
  const [huntRunning, setHuntRunning] = useState(false);
  const [huntResult, setHuntResult] = useState(null);
  const [huntLogs, setHuntLogs] = useState([]);
  const visRef = useRef(null);
  const visNetworkRef = useRef(null);
  const [blocklist, setBlocklist] = useState(loadBlocklist);
  const [blInput, setBlInput] = useState("");
  const [blSearch, setBlSearch] = useState("");
  const [blLoading, setBlLoading] = useState(false);
  const [bulkInput, setBulkInput] = useState("");
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState(null);
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWorkspace, setActiveWorkspace] = useState("default");
  const [newWsName, setNewWsName] = useState("");
  const [webhooks, setWebhooks] = useState([]);
  const [whUrl, setWhUrl] = useState("");
  const [whEvents, setWhEvents] = useState("CRITICAL,HIGH");
  const [historyView, setHistoryView] = useState("table");
  const [alerts, setAlerts] = useState([]);
  const [alertStats, setAlertStats] = useState(null);
  const [feeds, setFeeds] = useState([]);
  const [feedEntries, setFeedEntries] = useState([]);
  const [newFeedName, setNewFeedName] = useState("");
  const [newFeedUrl, setNewFeedUrl] = useState("");
  const [feedPolling, setFeedPolling] = useState(false);
  const [dbSearch, setDbSearch] = useState("");
  const [dbResults, setDbResults] = useState(null);
  const [dbLoading, setDbLoading] = useState(false);
  const [explainInput, setExplainInput] = useState("");
  const [explainResult, setExplainResult] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [backendOnline, setBackendOnline] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const showToast = useCallback((msg, type = "info") => {
    const duration = type === "error" ? 6000 : 3500;
    setToast({ message: msg, type, key: Date.now() });
    setTimeout(() => setToast(null), duration);
  }, []);

  useKeyboardShortcuts({
    investigate: () => doInvestigate(),
    hunt: () => huntInput.trim() && doHunt(),
    blocklist: () => setActiveTab("blocklist"),
    dashboard: () => setActiveTab("dashboard"),
    toggleTheme,
    escape: () => { setSelReport(null); setError(""); },
  });

  useEffect(() => {
    const checkHealth = () => fetch(`${API_URL}/health`)
      .then(r => r.json()).then(d => { setHealth(d); setBackendOnline(true); })
      .catch(() => { setHealth({ status: "offline", api_keys_configured: {} }); setBackendOnline(false); });
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    Promise.allSettled([
      fetchWorkspaces(),
      fetchIgnored(),
      fetchWebhooks(),
      fetchMetrics(),
      fetchAlerts(),
      fetchFeeds(),
    ]).finally(() => setInitialLoading(false));
    return () => clearInterval(interval);
  }, []);

  useEffect(() => { saveHistory(history); }, [history]);
  useEffect(() => { saveBlocklist(blocklist); }, [blocklist]);

  useEffect(() => {
    if (!huntResult?.graph?.nodes) return;
    const timer = setTimeout(() => {
      if (visRef.current) {
        try {
          const nodes = new DataSet(huntResult.graph.nodes);
          const edges = new DataSet(huntResult.graph.edges);
          visNetworkRef.current = new Network(visRef.current, { nodes, edges }, {
            physics: { barnesHut: { gravitationalConstant: -3000, springLength: 100 } },
            nodes: { borderWidth: 2, font: { color: "#d8dce6", size: 10, face: "Inter" } },
            edges: { smooth: { type: "dynamic" }, arrows: { to: { scaleFactor: 0.5 } }, color: { color: "#3a4a5e" }, font: { color: "#8891a4", size: 8, face: "Inter" } },
            interaction: { hover: true, zoomView: true, dragView: true, tooltipDelay: 100 },
          });
        } catch (e) {
          setHuntLogs(prev => [...prev, `Graph render error: ${e.message}`]);
        }
      }
    }, 200);
    return () => { clearTimeout(timer); if (visNetworkRef.current) { visNetworkRef.current.destroy(); visNetworkRef.current = null; } };
  }, [huntResult]);

  useEffect(() => {
    fetch(`${API_URL}/api/blocklist`)
      .then(r => r.json()).then(d => {
        if (d.blocklist) setBlocklist(prev => [...new Set([...prev, ...d.blocklist])]);
      }).catch(() => showToast("Failed to load server blocklist", "error"));
  }, []);

  const stats = useMemo(() => {
    const t = history.length, c = history.filter(h => h.severity === "CRITICAL").length;
    const h = history.filter(x => x.severity === "HIGH").length;
    const m = history.filter(x => x.severity === "MEDIUM").length;
    return { total: t, critical: c, high: h, medium: m, priority: c + h };
  }, [history]);

  const categoryBreakdown = useMemo(() => {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"];
    const map = {};
    order.forEach(s => map[s] = 0);
    history.forEach(h => { const s = h.severity || "UNKNOWN"; if (s in map) map[s]++; });
    return Object.entries(map).filter(([, c]) => c > 0);
  }, [history]);

  const localTrend = useMemo(() => {
    const days = {};
    const now = new Date();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days[key] = 0;
    }
    history.forEach(h => {
      const d = new Date(h.timestamp).toISOString().slice(0, 10);
      if (d in days) days[d]++;
    });
    return Object.entries(days).map(([date, count]) => ({ date, count }));
  }, [history]);

  const chartMax = useMemo(() => Math.max(1, stats.critical, stats.high, stats.medium,
    history.filter(h => h.severity === "LOW").length, history.filter(h => h.severity === "CLEAN").length), [history, stats]);

  const healthStatus = health?.status === "healthy" ? "healthy" : health?.status === "demo_mode" ? "degraded" : "offline";

  async function fetchWorkspaces() {
    try {
      const r = await fetch(`${API_URL}/api/workspaces`);
      const d = await r.json();
      setWorkspaces(d.workspaces || []);
      const saved = localStorage.getItem(WORKSPACE_KEY);
      if (saved && d.workspaces?.some(w => w.name === saved)) setActiveWorkspace(saved);
      else setActiveWorkspace(d.active || "default");
    } catch { showToast("Failed to load workspaces", "error"); }
  }

  async function fetchIgnored() {
    try { const r = await fetch(`${API_URL}/api/ignore-mark`); const d = await r.json(); setIgnoredIocs(d.ignored || []); }
    catch { showToast("Failed to load ignored IOCs", "error"); }
  }

  async function fetchWebhooks() {
    try { const r = await fetch(`${API_URL}/api/webhooks`); const d = await r.json(); setWebhooks(d.webhooks || []); }
    catch { showToast("Failed to load webhooks", "error"); }
  }

  async function fetchMetrics() {
    try { const r = await fetch(`${API_URL}/api/metrics`); const d = await r.json(); setMetrics(d); }
    catch { showToast("Failed to load dashboard metrics", "error"); }
  }

  async function fetchAlerts() {
    try { const r = await fetch(`${API_URL}/api/alerts`); const d = await r.json(); setAlerts(d.alerts || []); setAlertStats(d.stats || null); }
    catch { showToast("Failed to load alerts", "error"); }
  }

  async function fetchFeeds() {
    try {
      const [fr, fe] = await Promise.all([
        fetch(`${API_URL}/api/feeds`).then(r => r.json()),
        fetch(`${API_URL}/api/feeds/entries?limit=50`).then(r => r.json()),
      ]);
      setFeeds(fr.feeds || []);
      setFeedEntries(fe.entries || []);
    } catch { showToast("Failed to load threat feeds", "error"); }
  }

  async function doDbSearch() {
    if (!dbSearch.trim()) return;
    setDbLoading(true);
    try {
      const r = await fetch(`${API_URL}/api/db/search`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ search: dbSearch.trim(), limit: 50 }),
      });
      setDbResults(await r.json());
    } catch { showToast("Database search failed", "error"); }
    setDbLoading(false);
  }

  function validateIoc(value) {
    const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const domain = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    const md5 = /^[a-fA-F0-9]{32}$/;
    const sha1 = /^[a-fA-F0-9]{40}$/;
    const sha256 = /^[a-fA-F0-9]{64}$/;
    const url = /^https?:\/\/.+/;
    return ipv4.test(value) || domain.test(value) || md5.test(value) || sha1.test(value) || sha256.test(value) || url.test(value);
  }

  function doInvestigate(target) {
    const value = (target || ioc).trim();
    if (!value || loading) return;
    if (!validateIoc(value)) {
      setError(`"${value}" does not look like a valid IOC (IP, domain, URL, or hash)`);
      return;
    }
    setLoading(true); setError("");
    const entry = { ioc: value, timestamp: Date.now(), severity: "UNKNOWN", report: null, progress: [] };
    let completed = false, retryCount = 0;
    const maxRetries = 5;

    function connectSSE() {
      const es = new EventSource(`${API_URL}/api/investigate/stream/${encodeURIComponent(value)}`);
      es.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.event === "start") {
            progressRef.current = [evt.ioc]; setProgress([...progressRef.current]);
          } else if (evt.event === "classified") {
            entry.ioc_type = evt.ioc_type; progressRef.current.push(`Type: ${evt.ioc_type}`); setProgress([...progressRef.current]);
          } else if (evt.event === "progress") {
            progressRef.current.push(evt.message); setProgress([...progressRef.current]);
          } else if (evt.event === "result") {
            entry.severity = evt.severity || entry.severity;
            entry.ioc_type = evt.ioc_type || entry.ioc_type;
            entry.ml_features = evt.ml_features || null;
            entry.report = {
              severity: evt.severity, confidence_score: evt.confidence, risk_score: evt.risk_score,
              ml_verdict: evt.ml_verdict, ml_confidence: evt.ml_confidence, summary: evt.summary,
              threat_category: evt.threat_category, mitre_techniques: evt.mitre_techniques,
              recommended_actions: evt.recommended_actions,
            };
            progressRef.current.push(`Result: ${evt.severity}`); setProgress([...progressRef.current]);
          } else if (evt.event === "complete") {
            completed = true; es.close();
            setProgress([]); progressRef.current = [];
            setHistory(prev => [entry, ...prev]);
            feedRef.current = [{ ioc: value, severity: entry.severity, ts: Date.now() }, ...feedRef.current].slice(0, 50);
            setFeed([...feedRef.current]);
            setSelReport(entry);
            fetchMetrics();
            showToast(`Complete: ${value} -- ${entry.severity}`, entry.severity === "CRITICAL" ? "error" : "success");
            setLoading(false); setIoc("");
          } else if (evt.event === "error") {
            completed = true; es.close();
            setProgress([]); progressRef.current = [];
            setError(evt.detail || "Investigation failed");
            entry.severity = "UNKNOWN"; entry.error = evt.detail;
            setHistory(prev => [entry, ...prev]);
            setLoading(false); setIoc("");
          }
        } catch {}
      };
      es.onerror = () => {
        es.close();
        if (completed) return;
        retryCount++;
        if (retryCount <= maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, retryCount), 10000);
          progressRef.current.push(`Connection lost — reconnecting in ${delay / 1000}s (attempt ${retryCount}/${maxRetries})`);
          setProgress([...progressRef.current]);
          setTimeout(connectSSE, delay);
        } else {
          setProgress([]); progressRef.current = [];
          setError("Connection lost — investigation failed after retries");
          entry.severity = "UNKNOWN";
          setHistory(prev => [entry, ...prev]);
          setLoading(false);
        }
      };
    }
    connectSSE();
  }

  function exportCSV() {
    const rows = [["IOC", "Type", "Severity", "Timestamp", "Category", "Risk", "Confidence"]];
    history.forEach(h => rows.push([h.ioc, h.ioc_type || "", h.severity || "", new Date(h.timestamp).toISOString(),
    h.report?.threat_category || "", h.report?.risk_score !== undefined ? Math.round(h.report.risk_score * 100) + "%" : "", h.report?.confidence_score || ""]));
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `tia-investigations-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
    showToast("CSV exported", "success");
  }

  async function exportSTIX() {
    try {
      const r = await fetch(`${API_URL}/api/export/stix`);
      const data = await r.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `tia-stix-${Date.now()}.json`;
      a.click(); URL.revokeObjectURL(url);
      showToast("STIX 2.1 bundle exported", "success");
    } catch { showToast("STIX export failed", "error"); }
  }

  async function exportPDF() {
    if (!selReport?.ioc) { showToast("Select an investigation first", "info"); return; }
    try {
      const r = await fetch(`${API_URL}/api/export/pdf`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: selReport.ioc }),
      });
      const html = await r.text();
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `tia-report-${selReport.ioc}-${Date.now()}.html`;
      a.click(); URL.revokeObjectURL(url);
      showToast("Report exported", "success");
    } catch { showToast("Report export failed", "error"); }
  }

  async function markIgnored(iocValue, note = "") {
    try {
      await fetch(`${API_URL}/api/ignore-mark`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ioc: iocValue, note }),
      });
      fetchIgnored();
      showToast(`Marked ${iocValue} as ignored`, "info");
    } catch { showToast("Failed to mark ignored", "error"); }
  }

  async function unmarkIgnored(iocValue) {
    try {
      await fetch(`${API_URL}/api/ignore-mark`, {
        method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ioc: iocValue }),
      });
      fetchIgnored();
    } catch { showToast("Failed to unmark IOC", "error"); }
  }

  async function doBulkImport() {
    const iocs = bulkInput.split(/[\n,; ]+/).map(s => s.trim()).filter(Boolean);
    if (!iocs.length) return;
    if (iocs.length > 100) showToast(`Only first 100 of ${iocs.length} IOCs will be processed`, "info");
    setBulkLoading(true); setBulkResults(null);
    try {
      const r = await fetch(`${API_URL}/api/bulk-investigate`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ iocs: iocs.slice(0, 100) }),
      });
      const data = await r.json();
      setBulkResults(data);
      if (data.results) {
        const entries = data.results.map(r => ({
          ioc: r.ioc, ioc_type: r.ioc_type || "", severity: r.severity || r.report?.severity || "UNKNOWN",
          report: r.report || {}, timestamp: Date.now(),
        }));
        setHistory(prev => [...entries, ...prev]);
        fetchMetrics();
      }
      showToast(`Bulk complete: ${data.succeeded} OK, ${data.failed} failed`, data.failed ? "error" : "success");
    } catch (err) { showToast(`Bulk import failed: ${err.message}`, "error"); }
    setBulkLoading(false);
  }

  async function switchWorkspace(name) {
    try {
      await fetch(`${API_URL}/api/workspaces/switch`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }),
      });
      setActiveWorkspace(name);
      localStorage.setItem(WORKSPACE_KEY, name);
      fetchIgnored(); fetchWebhooks(); fetchMetrics();
      showToast(`Switched to workspace: ${name}`, "success");
    } catch { showToast("Failed to switch workspace", "error"); }
  }

  async function createWorkspace() {
    if (!newWsName.trim()) return;
    try {
      await fetch(`${API_URL}/api/workspaces`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: newWsName.trim() }),
      });
      setNewWsName(""); fetchWorkspaces();
      showToast(`Workspace created: ${newWsName.trim()}`, "success");
    } catch (err) { showToast("Failed to create workspace", "error"); }
  }

  async function deleteWorkspace(name) {
    try {
      await fetch(`${API_URL}/api/workspaces/${name}`, { method: "DELETE" });
      fetchWorkspaces();
      if (activeWorkspace === name) switchWorkspace("default");
      showToast(`Deleted workspace: ${name}`, "info");
    } catch { showToast("Failed to delete workspace", "error"); }
  }

  async function addWebhook() {
    if (!whUrl.trim()) return;
    const events = whEvents.split(/[, ]+/).map(s => s.trim().toUpperCase()).filter(Boolean);
    try {
      await fetch(`${API_URL}/api/webhooks`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: whUrl.trim(), events }),
      });
      setWhUrl(""); fetchWebhooks(); showToast("Webhook added", "success");
    } catch { showToast("Failed to add webhook", "error"); }
  }

  async function removeWebhook(id) {
    try { await fetch(`${API_URL}/api/webhooks/${id}`, { method: "DELETE" }); fetchWebhooks(); }
    catch { showToast("Failed to remove webhook", "error"); }
  }

  async function doHunt() {
    const value = huntInput.trim();
    if (!value || huntRunning) return;
    setHuntRunning(true); setHuntLogs(["Starting hunt..."]);
    setHuntResult(null); visNetworkRef.current = null;
    const log = msgs => setHuntLogs(prev => [...prev, msgs]);
    try {
      const res = await fetch(`${API_URL}/api/chat`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: `hunt ${value}`, history: [] }),
      });
      const data = await res.json();
      log("Hunt complete.");
      if (data.graph && data.graph.nodes) {
        log(`Found ${data.graph.nodes.length} nodes, ${data.graph.edges.length} edges`);
        setHuntResult(data);
        const entries = data.graph.nodes.map(n => ({
          ioc: n.id || n.label,
          ioc_type: n.ioc_type || n.group || "",
          severity: (n.severity || "UNKNOWN").toUpperCase(),
          report: {},
          timestamp: Date.now(),
        }));
        setHistory(prev => [...entries, ...prev]);
        const feedEntries = entries.map(e => ({ ioc: e.ioc, severity: e.severity, ts: Date.now() }));
        feedRef.current = [...feedEntries, ...feedRef.current].slice(0, 50);
        setFeed([...feedRef.current]);
        fetchMetrics();
      }
    } catch (err) { log(`Error: ${err.message}`); showToast(`Hunt failed: ${err.message}`, "error"); }
    setHuntRunning(false);
  }

  async function doExplain() {
    const value = explainInput.trim();
    if (!value || explainLoading) return;
    setExplainLoading(true); setExplainResult(null);
    try {
      const r = await fetch(`${API_URL}/api/explain`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ioc: value }),
      });
      setExplainResult(await r.json());
    } catch (err) { showToast(`Explain failed: ${err.message}`, "error"); }
    setExplainLoading(false);
  }

  async function addToBlocklist(iocs) {
    const items = Array.isArray(iocs) ? iocs : [iocs];
    const trimmed = items.map(s => s.trim()).filter(Boolean);
    if (!trimmed.length) return;
    setBlLoading(true);
    const prevBlocklist = blocklist;
    setBlocklist(prev => [...new Set([...prev, ...trimmed])]);
    try {
      await fetch(`${API_URL}/api/blocklist`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ iocs: trimmed }),
      });
      showToast(`${trimmed.length} IOC(s) added to blocklist`, "success");
    } catch {
      setBlocklist(prevBlocklist);
      showToast("Failed to sync blocklist with server", "error");
    }
    setBlLoading(false); setBlInput("");
  }

  async function removeFromBlocklist(ioc) {
    setBlocklist(prev => prev.filter(x => x !== ioc));
    try {
      await fetch(`${API_URL}/api/blocklist`, {
        method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ iocs: [ioc] }),
      });
    } catch { showToast("Failed to sync blocklist with server", "error"); }
    showToast(`Removed ${ioc} from blocklist`, "info");
  }

  async function addFeed() {
    if (!newFeedName.trim() || !newFeedUrl.trim()) return;
    try {
      await fetch(`${API_URL}/api/feeds`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newFeedName.trim(), url: newFeedUrl.trim() }),
      });
      setNewFeedName(""); setNewFeedUrl(""); fetchFeeds(); showToast("Feed added", "success");
    } catch { showToast("Failed to add feed", "error"); }
  }

  async function deleteFeed(id) {
    try { await fetch(`${API_URL}/api/feeds/${id}`, { method: "DELETE" }); fetchFeeds(); showToast("Feed removed", "info"); }
    catch { showToast("Failed to remove feed", "error"); }
  }

  async function pollFeeds() {
    setFeedPolling(true);
    try { const r = await fetch(`${API_URL}/api/feeds/poll`, { method: "POST" }); const d = await r.json(); showToast(`Polled ${d.polled} feeds`, "success"); fetchFeeds(); }
    catch { showToast("Feed poll failed", "error"); }
    setFeedPolling(false);
  }

  return (
    <div>
      <style>{css}</style>
      {toast && <Toast key={toast.key} message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
      <Layout
        activeTab={activeTab}
        onTabChange={setActiveTab}
        counts={{ history: stats.total, blocklist: blocklist.length, webhooks: webhooks.length, feeds: feeds.length, alerts: alerts.length }}
        healthStatus={healthStatus}
        workspaces={workspaces}
        activeWorkspace={activeWorkspace}
        onWorkspaceChange={switchWorkspace}
        dark={dark}
        onToggleTheme={toggleTheme}
        backendOnline={backendOnline}
        sidebarCollapsed={sidebarCollapsed}
        onToggleSidebar={() => setSidebarCollapsed(p => !p)}
      >
        {activeTab === "dashboard" && (
          <DashboardTab
            stats={stats}
            history={history}
            feed={feed}
            metrics={metrics}
            selReport={selReport}
            blocklist={blocklist}
            localTrend={localTrend}
            categoryBreakdown={categoryBreakdown}
            chartMax={chartMax}
            initialLoading={initialLoading}
            onInvestigate={doInvestigate}
            onReRun={(ioc) => doInvestigate(ioc)}
            onIgnore={markIgnored}
            ignoredIocs={ignoredIocs}
            onTabChange={setActiveTab}
            onSetIoc={setIoc}
            onSetActiveTab={setActiveTab}
            palette={palette}
          />
        )}

        {activeTab === "history" && (
          <HistoryTab
            history={history}
            historyView={historyView}
            selReport={selReport}
            onViewChange={setHistoryView}
            onReRun={(ioc) => { setIoc(ioc); doInvestigate(ioc); }}
            onSelectReport={setSelReport}
            onExportCSV={exportCSV}
            onExportSTIX={exportSTIX}
            onExportPDF={exportPDF}
            onClearHistory={() => { setHistory([]); setFeed([]); feedRef.current = []; setSelReport(null); }}
            onIgnore={markIgnored}
            ignoredIocs={ignoredIocs}
            palette={palette}
          />
        )}

        {activeTab === "hunt" && (
          <HuntTab
            huntInput={huntInput}
            huntRunning={huntRunning}
            huntResult={huntResult}
            huntLogs={huntLogs}
            visRef={visRef}
            onHuntInputChange={setHuntInput}
            onHunt={doHunt}
            palette={palette}
          />
        )}

        {activeTab === "explain" && (
          <ExplainTab
            explainInput={explainInput}
            explainLoading={explainLoading}
            explainResult={explainResult}
            onExplainInputChange={setExplainInput}
            onExplain={doExplain}
            palette={palette}
          />
        )}

        {activeTab === "blocklist" && (
          <BlocklistTab
            blocklist={blocklist}
            blInput={blInput}
            blSearch={blSearch}
            blLoading={blLoading}
            onBlInputChange={setBlInput}
            onBlSearchChange={setBlSearch}
            onAddToBlocklist={addToBlocklist}
            onRemoveFromBlocklist={removeFromBlocklist}
            onClearBlocklist={() => { setBlocklist([]); showToast("Blocklist cleared", "info"); }}
          />
        )}

        {activeTab === "bulk" && (
          <BulkImportTab
            bulkInput={bulkInput}
            bulkLoading={bulkLoading}
            bulkResults={bulkResults}
            onBulkInputChange={setBulkInput}
            onDoBulkImport={doBulkImport}
          />
        )}

        {activeTab === "webhooks" && (
          <WebhooksTab
            webhooks={webhooks}
            whUrl={whUrl}
            whEvents={whEvents}
            onWhUrlChange={setWhUrl}
            onWhEventsChange={setWhEvents}
            onAddWebhook={addWebhook}
            onRemoveWebhook={removeWebhook}
            initialLoading={initialLoading}
          />
        )}

        {activeTab === "alerts" && (
          <AlertsTab
            alerts={alerts}
            alertStats={alertStats}
            initialLoading={initialLoading}
            onFormatTime={formatTime}
          />
        )}

        {activeTab === "feeds" && (
          <FeedsTab
            feeds={feeds}
            feedEntries={feedEntries}
            newFeedName={newFeedName}
            newFeedUrl={newFeedUrl}
            feedPolling={feedPolling}
            onNewFeedNameChange={setNewFeedName}
            onNewFeedUrlChange={setNewFeedUrl}
            onAddFeed={addFeed}
            onDeleteFeed={deleteFeed}
            onPollFeeds={pollFeeds}
            initialLoading={initialLoading}
          />
        )}

        {activeTab === "dbsearch" && (
          <DbSearchTab
            dbSearch={dbSearch}
            dbLoading={dbLoading}
            onDbSearchChange={setDbSearch}
            onDoDbSearch={doDbSearch}
            dbResults={dbResults}
            onInvestigate={(ioc) => { setActiveTab("dashboard"); setIoc(ioc); doInvestigate(ioc); }}
          />
        )}

        {activeTab === "workspace" && (
          <WorkspaceTab
            workspaces={workspaces}
            activeWorkspace={activeWorkspace}
            newWsName={newWsName}
            initialLoading={initialLoading}
            ignoredIocs={ignoredIocs}
            onNewWsNameChange={setNewWsName}
            onCreateWorkspace={createWorkspace}
            onDeleteWorkspace={deleteWorkspace}
            onSwitchWorkspace={switchWorkspace}
            onUnmarkIgnored={unmarkIgnored}
          />
        )}

        {activeTab === "health" && (
          <SettingsTab
            health={health}
            healthStatus={healthStatus}
            settingsOpen={settingsOpen}
            onToggleSection={setSettingsOpen}
            webhooks={webhooks}
            whUrl={whUrl}
            whEvents={whEvents}
            onWhUrlChange={setWhUrl}
            onWhEventsChange={setWhEvents}
            onAddWebhook={addWebhook}
            onRemoveWebhook={removeWebhook}
            alerts={alerts}
            alertStats={alertStats}
            feeds={feeds}
            newFeedName={newFeedName}
            newFeedUrl={newFeedUrl}
            feedPolling={feedPolling}
            onNewFeedNameChange={setNewFeedName}
            onNewFeedUrlChange={setNewFeedUrl}
            onAddFeed={addFeed}
            onDeleteFeed={deleteFeed}
            onPollFeeds={pollFeeds}
            bulkInput={bulkInput}
            bulkLoading={bulkLoading}
            onBulkInputChange={setBulkInput}
            onDoBulkImport={doBulkImport}
            bulkResults={bulkResults}
            dbSearch={dbSearch}
            dbLoading={dbLoading}
            onDbSearchChange={setDbSearch}
            onDoDbSearch={doDbSearch}
            dbResults={dbResults}
            sampleIocs={sampleIocs}
            blocklist={blocklist}
            onInvestigate={(ioc) => { setActiveTab("dashboard"); setIoc(ioc); doInvestigate(ioc); }}
            workspaces={workspaces}
            activeWorkspace={activeWorkspace}
            newWsName={newWsName}
            initialLoading={initialLoading}
            onNewWsNameChange={setNewWsName}
            onCreateWorkspace={createWorkspace}
            onDeleteWorkspace={deleteWorkspace}
            onSwitchWorkspace={switchWorkspace}
            ignoredIocs={ignoredIocs}
            onUnmarkIgnored={unmarkIgnored}
            onTabChange={setActiveTab}
            onSetIoc={setIoc}
            onSetActiveTab={setActiveTab}
            formatTime={formatTime}
          />
        )}

        {/* Investigation progress bar shown always when loading */}
        {progress.length > 0 && (
          <div className="fixed bottom-4 right-4 z-50">
            <div className="bg-[#0a0a0c] border border-border rounded-lg p-3 text-xs font-mono text-[#a8b8ca] max-h-[120px] overflow-y-auto shadow-xl">
              {progress.map((p, i) => <div key={i} className="opacity-80">{'>'} {p}</div>)}
            </div>
          </div>
        )}

        {/* Error toast */}
        {error && (
          <div className="fixed bottom-20 right-4 z-50 bg-danger-light border border-danger/30 text-danger rounded-lg px-4 py-3 text-xs font-medium flex items-center gap-2 shadow-xl animate-fade-in">
            <span dangerouslySetInnerHTML={{ __html: ICONS.alert }} />
            {error}
          </div>
        )}
      </Layout>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}
