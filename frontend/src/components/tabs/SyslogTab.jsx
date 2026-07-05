import React, { useState } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function SyslogTab({ palette }) {
  const [logs, setLogs] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function handleIngest() {
    const lines = logs.split("\n").map(s => s.trim()).filter(Boolean);
    if (!lines.length) return;
    setLoading(true); setResult(null);
    try {
      const r = await fetch(`${API_URL}/api/syslog`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: lines }),
      });
      const data = await r.json();
      if (!r.ok) setResult({ ok: false, msg: data.detail || "Ingest failed" });
      else setResult({ ok: true, ...data });
    } catch (e) { setResult({ ok: false, msg: e.message }); }
    finally { setLoading(false); }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Syslog Ingestion</h3>
        <p className="text-xs text-muted mt-0.5">
          Paste syslog lines to check against your blocklist in real time
        </p>
      </div>

      <textarea
        value={logs}
        onChange={e => setLogs(e.target.value)}
        placeholder="Paste syslog lines here...&#10;e.g.&#10;Jan 5 12:00:00 firewall src=192.168.1.100 dst=10.0.0.1&#10;Jan 5 12:00:01 proxy 203.0.113.5 - GET /malware.exe"
        rows={10}
        className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted focus:ring-2 focus:ring-primary/40 focus:border-primary transition-all mb-3"
      />

      <div className="flex gap-2 mb-4">
        <button
          onClick={handleIngest}
          disabled={loading || !logs.trim()}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            "bg-primary hover:bg-primary-hover text-white",
            "disabled:opacity-40 disabled:cursor-not-allowed",
            "flex items-center gap-2"
          )}
        >
          {loading ? (
            <><svg className="animate-spin w-4 h-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>Processing...</>
          ) : "Ingest"}
        </button>
      </div>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className={cn("rounded-lg px-3 py-2 text-xs", result.ok ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500")}
        >
          {result.ok ? (
            <>
              <p>Processed: <strong>{result.processed_logs}</strong> lines</p>
              {result.alerts?.length > 0 ? (
                <div className="mt-2 space-y-1">
                  <p className="font-semibold">Alerts ({result.alerts.length}):</p>
                  {result.alerts.map((a, i) => (
                    <div key={i} className="bg-red-500/10 rounded px-2 py-1 text-red-400 font-mono text-[10px]">
                      {a.ip}: {a.alert}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted mt-1">No blocklist hits</p>
              )}
            </>
          ) : (
            <p>{result.msg}</p>
          )}
        </motion.div>
      )}
    </motion.div>
  );
}
