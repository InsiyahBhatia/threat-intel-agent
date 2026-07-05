import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function ConfigCard({ title, fields, config, onChange, onSave, onPush, pushLabel, saving }) {
  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <h4 className="text-sm font-semibold text-text mb-3">{title}</h4>
      <div className="space-y-2 mb-3">
        {fields.map(f => (
          <div key={f.key}>
            <label className="block text-[11px] font-semibold text-muted uppercase mb-0.5">{f.label}</label>
            {f.type === "toggle" ? (
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={config[f.key]} onChange={e => onChange(f.key, e.target.checked)} className="rounded border-border" />
                <span className="text-xs text-text">Enabled</span>
              </label>
            ) : f.type === "number" ? (
              <input type="number" value={config[f.key] ?? ""} onChange={e => onChange(f.key, parseInt(e.target.value) || 0)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
            ) : (
              <input type={f.secret ? "password" : "text"} value={config[f.key] ?? ""} onChange={e => onChange(f.key, e.target.value)} className="w-full bg-surface-light border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-text" />
            )}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <button onClick={onSave} disabled={saving} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-primary hover:bg-primary-hover text-white disabled:opacity-40">{saving ? "Saving..." : "Save"}</button>
        {onPush && <button onClick={onPush} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface border border-border hover:bg-border text-text">{pushLabel || "Push"}</button>}
      </div>
    </div>
  );
}

export default function IntegrationsTab({ palette }) {
  const [saving, setSaving] = useState({});
  const [pushResult, setPushResult] = useState(null);
  const [siem, setSiem] = useState({ enabled: false, format: "cef", target: "", port: 514, protocol: "udp" });
  const [misp, setMisp] = useState({ enabled: false, url: "", api_key: "", verify_ssl: true });
  const [opencti, setOpencti] = useState({ enabled: false, url: "", api_key: "" });
  const [thehive, setThehive] = useState({ enabled: false, url: "", api_key: "", organisation: "" });

  useEffect(() => {
    Promise.all([
      fetch(`${API_URL}/api/integrations/siem`).then(r => r.json()).then(setSiem).catch(() => {}),
      fetch(`${API_URL}/api/integrations/misp`).then(r => r.json()).then(setMisp).catch(() => {}),
      fetch(`${API_URL}/api/integrations/opencti`).then(r => r.json()).then(setOpencti).catch(() => {}),
      fetch(`${API_URL}/api/integrations/thehive`).then(r => r.json()).then(setThehive).catch(() => {}),
    ]);
  }, []);

  function save(endpoint, data, key) {
    setSaving(s => ({ ...s, [key]: true }));
    fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) })
      .then(r => { if (!r.ok) throw new Error("Save failed"); return r.json(); })
      .then(() => { setSaving(s => ({ ...s, [key]: false })); })
      .catch(() => { setSaving(s => ({ ...s, [key]: false })); });
  }

  function push(endpoint) {
    setPushResult(null);
    fetch(endpoint, { method: "POST" })
      .then(async r => {
        const text = await r.text();
        if (!text) throw new Error("Empty response from server");
        return JSON.parse(text);
      })
      .then(data => {
        setPushResult({ ok: true, msg: data.status || data.detail || data.message || "Push completed" });
      })
      .catch(e => {
        setPushResult({ ok: false, msg: e.message });
      });
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-4"
    >
      <div className="bg-surface-light border border-border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-text mb-1">SOAR & Platform Integrations</h3>
        <p className="text-xs text-muted mb-4">Configure connections to SIEM, MISP, OpenCTI, and TheHive</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ConfigCard title="SIEM Forwarding" fields={[
            { key: "enabled", label: "Enable", type: "toggle" },
            { key: "format", label: "Format" },
            { key: "target", label: "Target Host" },
            { key: "port", label: "Port", type: "number" },
            { key: "protocol", label: "Protocol" },
          ]} config={siem} onChange={(k, v) => setSiem(s => ({ ...s, [k]: v }))}
            onSave={() => save("/api/integrations/siem", siem, "siem")}
            onPush={() => push("/api/integrations/siem/forward")}
            pushLabel="Forward CRITICAL/HIGH" saving={saving.siem} />

          <ConfigCard title="MISP" fields={[
            { key: "enabled", label: "Enable", type: "toggle" },
            { key: "url", label: "URL" },
            { key: "api_key", label: "API Key", secret: true },
            { key: "verify_ssl", label: "Verify SSL", type: "toggle" },
          ]} config={misp} onChange={(k, v) => setMisp(s => ({ ...s, [k]: v }))}
            onSave={() => save("/api/integrations/misp", misp, "misp")}
            onPush={() => push("/api/integrations/misp/push")}
            pushLabel="Push IOCs" saving={saving.misp} />

          <ConfigCard title="OpenCTI" fields={[
            { key: "enabled", label: "Enable", type: "toggle" },
            { key: "url", label: "URL" },
            { key: "api_key", label: "API Key", secret: true },
          ]} config={opencti} onChange={(k, v) => setOpencti(s => ({ ...s, [k]: v }))}
            onSave={() => save("/api/integrations/opencti", opencti, "opencti")}
            onPush={() => push("/api/integrations/opencti/push")}
            pushLabel="Push IOCs" saving={saving.opencti} />

          <ConfigCard title="TheHive" fields={[
            { key: "enabled", label: "Enable", type: "toggle" },
            { key: "url", label: "URL" },
            { key: "api_key", label: "API Key", secret: true },
            { key: "organisation", label: "Organisation" },
          ]} config={thehive} onChange={(k, v) => setThehive(s => ({ ...s, [k]: v }))}
            onSave={() => save("/api/integrations/thehive", thehive, "thehive")}
            onPush={() => push("/api/integrations/thehive/create-case")}
            pushLabel="Create Case" saving={saving.thehive} />
        </div>
        {pushResult && (
          <div className={cn("text-xs mt-3 rounded-lg px-3 py-2", pushResult.ok ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500")}>
            {pushResult.msg}
          </div>
        )}
      </div>
    </motion.div>
  );
}
