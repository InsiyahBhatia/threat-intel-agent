import React from "react";
import { useTheme } from "./ThemeContext";

export default function SeverityTag({ severity, small }) {
  const { palette } = useTheme();
  const config = {
    CRITICAL: { color: palette.red, bg: palette.redBg, label: "Critical" },
    HIGH: { color: palette.amber, bg: palette.amberBg, label: "High" },
    LOW: { color: palette.teal, bg: palette.tealBg, label: "Low" },
    CLEAN: { color: palette.accent, bg: palette.accentBg, label: "Clean" },
    UNKNOWN: { color: palette.muted, bg: palette.panelSoft, label: "Unknown" },
  };
  const c = config[severity] || config.UNKNOWN;
  return (
    <span className={`tag ${small ? "tag-sm" : ""}`}
      style={{ color: c.color, background: c.bg }}>
      {c.label}
    </span>
  );
}
