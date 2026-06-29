import React from "react";
import { useTheme } from "./ThemeContext";

const ICONS = {
  x: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
};

export default function Toast({ message, type, onClose }) {
  const { palette } = useTheme();
  const colors = { error: palette.redBg, success: palette.accentBg, info: palette.blueBg };
  const borderColors = { error: palette.red, success: palette.accent, info: palette.blue };
  const textColors = { error: palette.red, success: palette.accent, info: palette.blue };
  return (
    <div style={{
      position: "fixed", bottom: 24, right: 24, zIndex: 9999,
      background: colors[type] || colors.info,
      border: `1px solid ${borderColors[type] || borderColors.info}`,
      borderLeft: `3px solid ${borderColors[type] || borderColors.info}`,
      borderRadius: 6, padding: "10px 16px", fontSize: 12, fontWeight: 500,
      color: textColors[type] || textColors.info,
      display: "flex", alignItems: "center", gap: 10,
      boxShadow: "0 4px 16px rgba(0,0,0,0.12)", animation: "slideIn 0.3s ease",
    }}>
      <span>{message}</span>
      <button onClick={onClose}
        style={{ color: palette.muted, display: "flex", padding: 4, borderRadius: 3 }}
        dangerouslySetInnerHTML={{ __html: ICONS.x }} />
    </div>
  );
}
