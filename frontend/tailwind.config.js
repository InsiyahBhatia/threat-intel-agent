/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "IBM Plex Mono", "monospace"],
      },
      colors: {
        surface: {
          DEFAULT: "#111827",
          light: "#1f2937",
          hover: "#374151",
        },
        ink: "#0f172a",
        border: "#374151",
        primary: {
          DEFAULT: "#ef4444",
          hover: "#dc2626",
          light: "rgba(239,68,68,0.12)",
        },
        success: { DEFAULT: "#22c55e", light: "rgba(34,197,94,0.12)" },
        warning: { DEFAULT: "#f59e0b", light: "rgba(245,158,11,0.12)" },
        danger: { DEFAULT: "#dc2626", light: "rgba(220,38,38,0.12)" },
        muted: { DEFAULT: "#94a3b8", faint: "#64748b" },
        text: { DEFAULT: "#f8fafc", secondary: "#cbd5e1" },
      },
      borderRadius: {
        xl: "12px",
        "2xl": "16px",
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-out",
        "slide-up": "slideUp 0.3s ease-out",
        "scale-in": "scaleIn 0.2s ease-out",
      },
      keyframes: {
        fadeIn: { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        slideUp: { from: { opacity: "0", transform: "translateY(12px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        scaleIn: { from: { opacity: "0", transform: "scale(0.95)" }, to: { opacity: "1", transform: "scale(1)" } },
      },
    },
  },
  plugins: [],
};
