import { useEffect } from "react";

export default function useKeyboardShortcuts(handlers) {
  useEffect(() => {
    function handler(e) {
      const ctrl = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (ctrl && key === "enter" && handlers.investigate) {
        e.preventDefault();
        handlers.investigate();
      }
      if (ctrl && key === "h" && handlers.hunt) {
        e.preventDefault();
        handlers.hunt();
      }
      if (ctrl && key === "b" && handlers.blocklist) {
        e.preventDefault();
        handlers.blocklist();
      }
      if (ctrl && key === "d" && handlers.dashboard) {
        e.preventDefault();
        handlers.dashboard();
      }
      if (ctrl && key === "l" && handlers.toggleTheme) {
        e.preventDefault();
        handlers.toggleTheme();
      }
      if (key === "escape" && handlers.escape) {
        e.preventDefault();
        handlers.escape();
      }
    }
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handlers]);
}
