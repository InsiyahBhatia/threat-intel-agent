import React, { createContext, useContext, useState, useEffect, useCallback } from "react";

const THEME_KEY = "tia-theme";

const lightPalette = {
  ink: "#eef0f5", surface: "#e2e5ed", panel: "#f7f8fc", panelSoft: "#f1f2f7",
  line: "#c9cdd8", text: "#0b0e14", muted: "#3d4459", faint: "#7c85a0",
  blue: "#0061bd", blueBg: "#e6f0fa", teal: "#0097a8", tealBg: "#e6f6f8",
  amber: "#b87a00", amberBg: "#fef7e6", red: "#b01e2a", redBg: "#fce9ea",
  purple: "#5b3ee0", green: "#157340", accent: "#5a932e", accentBg: "#eef6e5",
};

const darkPalette = {
  ink: "#131315", surface: "#1f1f21", panel: "#1f1f21", panelSoft: "#1b1b1d",
  line: "#45464d", text: "#e4e2e4", muted: "#c6c6cd", faint: "#909097",
  blue: "#7bd0ff", blueBg: "rgba(123,208,255,0.08)", teal: "#80cbc4", tealBg: "rgba(128,203,196,0.08)",
  amber: "#ffe082", amberBg: "rgba(255,224,130,0.08)", red: "#ff4444", redBg: "rgba(255,68,68,0.10)",
  purple: "#bcc7de", green: "#4caf50", accent: "#4caf50", accentBg: "rgba(76,175,80,0.10)",
};

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => {
    try { return localStorage.getItem(THEME_KEY) !== "light"; } catch { return true; }
  });

  const palette = dark ? darkPalette : lightPalette;

  useEffect(() => {
    try { localStorage.setItem(THEME_KEY, dark ? "dark" : "light"); } catch {}
    document.body.style.background = palette.ink;
    document.body.style.color = palette.text;
    document.documentElement.classList.toggle("dark", dark);
  }, [dark, palette]);

  const toggleTheme = useCallback(() => setDark(p => !p), []);

  return (
    <ThemeContext.Provider value={{ dark, palette, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
