import React, { useState } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function YaraTab({ palette }) {
  const [iocText, setIocText] = useState("");
  const [ruleName, setRuleName] = useState("auto_generated_rule");
  const [description, setDescription] = useState("Auto-generated YARA rule from Threat Intel Agent");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState(null);

  async function generate(iocs, name, desc) {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${API_URL}/api/yara/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iocs, rule_name: name, description: desc }),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.detail || "Generation failed"); setRules(null); }
      else { setRules(data.rules); }
    } catch (e) { setError(e.message); setRules(null); }
    finally { setLoading(false); }
  }

  function handleGenerate() {
    const iocs = iocText.split("\n").map(s => s.trim()).filter(Boolean);
    if (!iocs.length) return;
    generate(iocs, ruleName, description);
  }

  async function handleFromWorkspace() {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${API_URL}/api/yara/generate-from-workspace?rule_name=${encodeURIComponent(ruleName)}&max_iocs=100`);
      const data = await r.json();
      if (!r.ok) { setError(data.detail || "Workspace fetch failed"); setRules(null); }
      else { setRules(data.rules); }
    } catch (e) { setError(e.message); setRules(null); }
    finally { setLoading(false); }
  }

  function handleCopy() {
    if (!rules?.length) return;
    navigator.clipboard.writeText(rules.join("\n\n"));
  }

  function handleDownload() {
    if (!rules?.length) return;
    const blob = new Blob([rules.join("\n\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `${ruleName.replace(/[^a-zA-Z0-9_]/g, "_")}.yar`;
    a.click(); URL.revokeObjectURL(url);
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">YARA Rule Generator</h3>
        <p className="text-xs text-muted mt-0.5">
          Generate YARA rules from IOC patterns or your workspace blocklist
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-3">
        <div className="lg:col-span-2">
          <label className="block text-[11px] font-semibold text-muted uppercase mb-1">IOCs (one per line)</label>
          <textarea
            value={iocText}
            onChange={e => setIocText(e.target.value)}
            placeholder="8.8.8.8&#10;evil.com&#10;d41d8cd98f00b204e9800998ecf8427e"
            rows={6}
            className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text placeholder-muted focus:ring-2 focus:ring-primary/40 focus:border-primary transition-all"
          />
        </div>
        <div className="space-y-2">
          <div>
            <label className="block text-[11px] font-semibold text-muted uppercase mb-1">Rule Name</label>
            <input
              type="text"
              value={ruleName}
              onChange={e => setRuleName(e.target.value)}
              className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text focus:ring-2 focus:ring-primary/40 focus:border-primary transition-all"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-muted uppercase mb-1">Description</label>
            <input
              type="text"
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs font-mono text-text focus:ring-2 focus:ring-primary/40 focus:border-primary transition-all"
            />
          </div>
        </div>
      </div>

      <div className="flex gap-2 mb-4">
        <button
          onClick={handleGenerate}
          disabled={loading || !iocText.trim()}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            "bg-primary hover:bg-primary-hover text-white",
            "disabled:opacity-40 disabled:cursor-not-allowed",
            "flex items-center gap-2"
          )}
        >
          {loading ? (
            <><svg className="animate-spin w-4 h-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>Generating...</>
          ) : "Generate"}
        </button>
        <button
          onClick={handleFromWorkspace}
          disabled={loading}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            "bg-surface border border-border hover:bg-border text-text",
            "disabled:opacity-40 disabled:cursor-not-allowed",
            "flex items-center gap-2"
          )}
        >
          {loading ? "Loading..." : "From Workspace"}
        </button>
      </div>

      {error && (
        <div className="text-xs text-red-500 bg-red-500/10 rounded-lg px-3 py-2 mb-3">{error}</div>
      )}

      {rules && rules.map((rule, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: i * 0.1 }}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-semibold text-muted uppercase">Rule #{i + 1}</span>
            <div className="flex gap-1">
              <button onClick={handleCopy} className="text-[11px] text-primary hover:underline px-2 py-0.5">Copy</button>
              <button onClick={handleDownload} className="text-[11px] text-primary hover:underline px-2 py-0.5">Download</button>
            </div>
          </div>
          <pre className="bg-ink text-[11px] leading-relaxed text-green-400 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap max-h-[500px] overflow-y-auto scrollbar-thin font-mono">
            {rule}
          </pre>
        </motion.div>
      ))}
    </motion.div>
  );
}
