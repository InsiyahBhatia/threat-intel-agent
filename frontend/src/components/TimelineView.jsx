import React, { useMemo } from "react";
import SeverityTag from "./SeverityTag";
import { useTheme } from "./ThemeContext";

const ICONS = {
  emptyCalendar: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
};

export default function TimelineView({ history }) {
  const { palette } = useTheme();

  const timeline = useMemo(() => {
    const groups = {};
    history.forEach(h => {
      const d = new Date(h.timestamp);
      const day = d.toLocaleDateString();
      if (!groups[day]) groups[day] = [];
      groups[day].push(h);
    });
    return Object.entries(groups).sort((a, b) => new Date(b[0]) - new Date(a[0])).slice(0, 30);
  }, [history]);

  if (history.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-icon"><span dangerouslySetInnerHTML={{ __html: ICONS.emptyCalendar }} /></div>
        <div className="empty-title">No timeline data</div>
        <div className="empty-desc">Investigate IOCs to build a timeline.</div>
      </div>
    );
  }

  return (
    <div style={{ position: "relative", paddingLeft: 24 }}>
      {timeline.map(([day, entries]) => (
        <div key={day} style={{ marginBottom: 16, position: "relative" }}>
          <div style={{
            position: "absolute", left: -20, top: 4, width: 12, height: 12,
            borderRadius: "50%", background: palette.blue, border: `2px solid ${palette.panel}`,
          }} />
          <div className="text-muted text-sm" style={{ fontWeight: 700, marginBottom: 6, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5 }}>
            {day}
          </div>
          {entries.map((h, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: 8, padding: "4px 0",
              borderLeft: `1px solid ${palette.line}`, paddingLeft: 12, marginLeft: 6,
            }}>
              <SeverityTag severity={h.severity} small />
              <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, wordBreak: "break-all" }}>
                {h.ioc}
              </span>
              <span className="text-muted" style={{ fontSize: 10 }}>
                {h.ioc_type?.toUpperCase()}
              </span>
              <span className="text-muted" style={{ fontSize: 10, marginLeft: "auto" }}>
                {h.report?.threat_category || "-"}
              </span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
