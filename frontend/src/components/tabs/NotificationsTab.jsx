import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function NotificationsTab({ palette }) {
  const [cfg, setCfg] = useState({
    email: { enabled: false, smtp_host: "", smtp_port: 587, smtp_user: "", smtp_pass: "", from_addr: "", to_addrs: [] },
    slack: { enabled: false, webhook_url: "" },
    teams: { enabled: false, webhook_url: "" },
  });
  const [saving, setSaving] = useState(false);
  const [emailTo, setEmailTo] = useState("");
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    fetch(`${API_URL}/api/integrations/notifications`)
      .then(r => r.json())
      .then(data => {
        setCfg(data);
        setEmailTo((data.email?.to_addrs || []).join(", "));
      })
      .catch(() => {});
  }, []);

  function update(section, key, value) {
    setCfg(c => ({ ...c, [section]: { ...c[section], [key]: value } }));
  }

  async function handleSave() {
    const payload = { ...cfg, email: { ...cfg.email, to_addrs: emailTo.split(",").map(s => s.trim()).filter(Boolean) } };
    setSaving(true);
    try {
      await fetch(`${API_URL}/api/integrations/notifications`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
    } catch {}
    setSaving(false);
  }

  async function handleTest(channel) {
    setTestResult(null);
    try {
      const r = await fetch(`${API_URL}/api/integrations/notifications/test?channel=${channel}`, { method: "POST" });
      const data = await r.json();
      setTestResult({ channel, ok: data.status === "ok", detail: data.detail });
    } catch (e) {
      setTestResult({ channel, ok: false, detail: e.message });
    }
  }

  function Section({ title, channel, fields }) {
    return (
      <div className="bg-surface border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-sm font-semibold text-text">{title}</h4>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={cfg[channel]?.enabled} onChange={e => update(channel, "enabled", e.target.checked)} className="rounded border-border" />
            <span className="text-xs text-muted">Enabled</span>
          </label>
        </div>
        <div className="space-y-2 mb-3">
          {fields.map(f => (
            <div key={f.key}>
              <label className="block text-[11px] font-semibold text-muted uppercase mb-0.5">{f.label}</label>
              {f.type === "number" ? (
                <input type="number" value={cfg[channel]?.[f.key] ?? ""} onChange={e => update(channel, f.key, parseInt(e.target.value) || 0)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
              ) : f.secret ? (
                <input type="password" value={cfg[channel]?.[f.key] ?? ""} onChange={e => update(channel, f.key, e.target.value)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
              ) : (
                <input type="text" value={cfg[channel]?.[f.key] ?? ""} onChange={e => update(channel, f.key, e.target.value)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
              )}
            </div>
          ))}
          {channel === "email" && (
            <div>
              <label className="block text-[11px] font-semibold text-muted uppercase mb-0.5">To Addresses (comma-separated)</label>
              <input type="text" value={emailTo} onChange={e => setEmailTo(e.target.value)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
            </div>
          )}
        </div>
        <button onClick={() => handleTest(channel)} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface border border-border hover:bg-border text-text">Send Test</button>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-surface-light border border-border rounded-xl p-5"
    >
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-text">Notification Channels</h3>
        <p className="text-xs text-muted mt-0.5">Configure Email, Slack, and Teams for automatic threat alerts</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <Section title="Email (SMTP)" channel="email" fields={[
          { key: "smtp_host", label: "SMTP Host" },
          { key: "smtp_port", label: "SMTP Port", type: "number" },
          { key: "smtp_user", label: "SMTP User" },
          { key: "smtp_pass", label: "SMTP Password", secret: true },
          { key: "from_addr", label: "From Address" },
        ]} />
        <Section title="Slack" channel="slack" fields={[
          { key: "webhook_url", label: "Webhook URL", secret: true },
        ]} />
        <Section title="Microsoft Teams" channel="teams" fields={[
          { key: "webhook_url", label: "Webhook URL", secret: true },
        ]} />
      </div>

      <div className="flex items-center gap-3">
        <button onClick={handleSave} disabled={saving} className="px-4 py-2 rounded-lg text-sm font-medium bg-primary hover:bg-primary-hover text-white disabled:opacity-40">
          {saving ? "Saving..." : "Save All"}
        </button>
        {testResult && (
          <span className={cn("text-xs", testResult.ok ? "text-green-500" : "text-red-500")}>
            {testResult.channel}: {testResult.ok ? "Test sent successfully" : (testResult.detail || "Failed")}
          </span>
        )}
      </div>
    </motion.div>
  );
}
