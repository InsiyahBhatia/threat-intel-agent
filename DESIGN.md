---
name: threat-intel-agent
colors:
  surface: '#131315'
  surface-dim: '#131315'
  surface-bright: '#39393b'
  surface-container-lowest: '#0e0e10'
  surface-container-low: '#1b1b1d'
  surface-container: '#1f1f21'
  surface-container-high: '#2a2a2b'
  surface-container-highest: '#353436'
  on-surface: '#e4e2e4'
  on-surface-variant: '#c6c6cd'
  inverse-surface: '#e4e2e4'
  inverse-on-surface: '#303032'
  outline: '#909097'
  outline-variant: '#45464d'
  surface-tint: '#bec6e0'
  primary: '#bec6e0'
  on-primary: '#283044'
  primary-container: '#0f172a'
  on-primary-container: '#798098'
  inverse-primary: '#565e74'
  secondary: '#bcc7de'
  on-secondary: '#263143'
  secondary-container: '#3e495d'
  on-secondary-container: '#aeb9d0'
  tertiary: '#7bd0ff'
  on-tertiary: '#00354a'
  tertiary-container: '#001a27'
  on-tertiary-container: '#008abb'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#dae2fd'
  primary-fixed-dim: '#bec6e0'
  on-primary-fixed: '#131b2e'
  on-primary-fixed-variant: '#3f465c'
  secondary-fixed: '#d8e3fb'
  secondary-fixed-dim: '#bcc7de'
  on-secondary-fixed: '#111c2d'
  on-secondary-fixed-variant: '#3c475a'
  tertiary-fixed: '#c4e7ff'
  tertiary-fixed-dim: '#7bd0ff'
  on-tertiary-fixed: '#001e2c'
  on-tertiary-fixed-variant: '#004c69'
  background: '#131315'
  on-background: '#e4e2e4'
  surface-variant: '#353436'
typography:
  headline-lg:
    fontFamily: Hanken Grotesk
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Hanken Grotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-sm:
    fontFamily: Hanken Grotesk
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.08em
  headline-lg-mobile:
    fontFamily: Hanken Grotesk
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  container-margin: 24px
  gutter: 16px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
  sidebar-width: 240px
  panel-right-width: 400px
---

## Brand & Style
The design system is engineered for high-stakes Security Operations Center (SOC) environments. It prioritizes "mission-critical" clarity, evoking a sense of calm authority and technical precision. The visual narrative combines **Corporate Modern** structure with **Cyberpunk-inflected Minimalism** to differentiate between administrative UI and urgent threat data.

The system targets cybersecurity analysts who require rapid pattern recognition. The aesthetic is "Dark-first," utilizing deep charcoal and navy surfaces to reduce eye strain during long shifts. High-chroma neon accents are reserved strictly for status signaling and data visualization, creating a functional hierarchy where the most dangerous threats literally glow against the muted background.

## Colors
The palette is built on a "Total Dark" foundation. 
- **Surfaces:** Use `#0F172A` (Primary Deep Navy) for the base background and `#1E293B` (Secondary) for elevated containers like cards and sidebars.
- **Triage Status:** Vibrant neons must be used for urgency. **Critical** (`#FF4D4D`) should be used sparingly for immediate threats. **High** (`#F97316`), **Medium** (`#FBBF24`), and **Low** (`#22C55E`) follow a traditional traffic light system but with increased saturation to pop against the dark UI.
- **AI/Machine Learning:** Use `#A855F7` (Purple) to distinguish AI-generated insights, scoring, and automated summaries.
- **Interactive:** Actions and links utilize `#38BDF8` (Sky Blue) to provide a clear path for user interaction without conflicting with threat levels.

## Typography
The typography strategy employs a dual-font system to separate UI navigation from raw data analysis.
- **UI & Content:** **Hanken Grotesk** provides a clean, modern edge for headlines and navigation. **Inter** is used for body text and descriptions due to its exceptional legibility at small sizes.
- **Technical Data:** **JetBrains Mono** is mandatory for all machine-generated content, including IP addresses, SHA-256 hashes, log entries, and code snippets. This ensures character alignment and prevents confusion between similar characters (e.g., 0 and O).
- **Labels:** Use `label-caps` for table headers and section metadata to create a structured, "heads-up display" (HUD) feel.

## Layout & Spacing
The layout uses a **Fixed Grid** approach for internal dashboard modules to ensure data density remains consistent. 
- **Shell:** A persistent left sidebar (`240px`) handles primary navigation. On complex analysis pages (Incidents, Triage), a right-hand detail panel (`400px`) should be used for deep-dive forensic data.
- **Data Density:** Use a 4px base unit. For tables and log views, use compact spacing (`8px` vertical padding) to maximize information visibility on a single screen. 
- **Responsive Behavior:** On tablet, the right panel becomes an overlay drawer. On mobile, the grid collapses to a single-column view with horizontal scrolling enabled specifically for data tables and timelines.

## Elevation & Depth
This design system avoids traditional drop shadows in favor of **Tonal Layering** and **Backdrop Blurs**.
- **Base:** The primary background is the lowest level.
- **Surfaces:** Cards and modules use a slightly lighter fill (`#1E293B`) with a subtle 1px border (`#334155`) to define boundaries.
- **Overlays:** Modals and tooltips use **Glassmorphism** (backdrop-filter: blur(12px)) with a 60% opacity fill of the primary color. This maintains context of the data underneath.
- **Glow:** For "Critical" status elements, a subtle outer glow (box-shadow: 0 0 12px rgba(255, 77, 77, 0.3)) can be applied to draw immediate focus.

## Shapes
The shape language is **Soft (0.25rem)**, leaning towards a technical, utilitarian aesthetic. 
- **Buttons & Inputs:** Use the standard `rounded` (4px) for a crisp, professional look. 
- **Status Tags/Chips:** May use `rounded-lg` (8px) to soften the appearance of metadata.
- **Node-Link Graphs:** Nodes should be circular for users/assets and hexagonal for threats/techniques to provide an immediate visual distinction between entity types.

## Components
- **Threat Cards:** Must include a "Risk Score" gauge and a color-coded severity bar. AI-analyzed cards should feature a purple gradient border.
- **Forensic Timelines:** Vertical lines with node-points. High-severity events on the timeline should pulse or use the neon status colors.
- **Data Tables:** Zebra-striping is discouraged. Use 1px bottom borders. Hover states should highlight the entire row in a translucent blue (`rgba(56, 189, 248, 0.1)`).
- **Action Buttons:**
    - **Primary:** Solid blue fill.
    - **SOAR/Automation:** Secondary outline with a lightning bolt icon.
    - **Destructive (Isolate/Block):** Solid red fill.
- **Node-Link Graphs:** Use thin, 1px lines (edges) with directional arrows. Highlight selected paths with a secondary blue glow.
- **Input Fields:** Dark fill with a 1px border. Focus state should change the border color to the primary blue (`#38BDF8`) with no glow.