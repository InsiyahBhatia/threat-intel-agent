import React from "react";

export default function StatCard({ icon, iconBg, iconColor, value, label, barColor, barWidth, sub }) {
  if (value === 0) {
    return (
      <div className="stat-card" style={{ borderLeftColor: "transparent", opacity: 0.5 }}>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {sub && <div style={{ fontSize: 10, color: "inherit", opacity: 0.45, marginTop: 2, fontWeight: 400 }}>{sub}</div>}
      </div>
    );
  }
  return (
    <div className="stat-card" style={{ borderLeftColor: barColor || "transparent" }}>
      <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", minHeight: 34 }}>
        {barWidth > 0 && (
          <span style={{
            fontSize: 9, fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace",
            color: barColor, background: barColor + "15", padding: "2px 6px",
            borderRadius: 3, letterSpacing: 0.3
          }}>
            {Math.round(barWidth)}%
          </span>
        )}
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontSize: 10, color: "inherit", opacity: 0.45, marginTop: 2, fontWeight: 400 }}>{sub}</div>}
      {barWidth !== undefined && (
        <div className="stat-bar" style={{ width: `${barWidth}%`, background: barColor }} />
      )}
    </div>
  );
}
