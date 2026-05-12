---
name: NextSSL Design System
colors:
  abyss: '#000000'
  carbon: '#050505'
  border: '#3d3a39'
  green: '#00d992'
  mint: '#2fd6a1'
  snow: '#ffffff'
  parchment: '#ffffff'
  slate: '#ffffff'
typography:
  primary: 'Roboto Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
  fallback: 'Liberation Mono, Courier New, monospace'
rounded:
  sm: 4px
  md: 6px
  lg: 8px
  xl: 10px
  pill: 9999px
spacing:
  base: 8px
  section: 96px
  container-max: 1280px
---

# NextSSL Design System

## 1. Visual Theme & Atmosphere

NextSSL's visual identity is that of a low-level engineering tool: no decoration, no gradients, no gradients trying to look like decoration. The surface is pure black (`#000000`) with a faint dot-grid texture at 3% opacity, the same kind of graph paper engineers sketch on. The only color that breaks the silence is Signal Green (`#00d992`), used exactly where a circuit board uses green: to show which signal is live.

The monospace-everywhere rule is intentional and firm. `Roboto Mono` is the single typeface across all roles (headings, body, labels, code). This creates a terminal-like uniformity that reinforces the library's nature: C source code compiled to 29 binary targets, no runtime surprises, no hidden behavior. If the interface looks like a compiled output, the library probably behaves like one too.

**Key characteristics:**

- Pure black canvas (`#000000`) with warm charcoal containment (`#3d3a39`)
- Single chromatic accent: Signal Green (`#00d992`) as the only non-neutral color
- One typeface system-wide: Roboto Mono for every typographic role
- Tight compressed line-heights (1.0 for display, 1.11 for section headings)
- No decorative shadows; depth comes from border weight and border-color shifts
- OpenType features `"calt"` and `"rlig"` enabled globally

---

## 2. Color Palette & Roles

### Brand Accent

- **Signal Green** (`#00d992`): The single chromatic signal in the system. Used for active borders, glow effects, overline labels, icon strokes, counter values, and the highest-priority interactive accents. Never used as a background fill on large surfaces.
- **Mint** (`#2fd6a1`): A slightly warmer, more readable variant of Signal Green. Used exclusively for button text (`.btn-primary`, `.btn-hero-primary`) on dark surfaces where pure green would be too bright.

### Surface & Background

- **Abyss Black** (`#000000`): The page canvas. Pure black. The entire visual hierarchy rests on top of this.
- **Carbon Surface** (`#050505`): Cards, nav bar, code blocks, counter cells, buttons. One perceptible step above Abyss, creating contained elevation without a shadow.
- **Bento Dark** (`#020202`): Used for the bento feature section to create a slight section-level separation from the main Abyss.

### Text

- **Snow** (`#ffffff`): Primary text. Used for headings, hero title, counter numbers, card titles.
- **Parchment** (`#ffffff`): Secondary text (currently aliased to white). Body copy, card descriptions, nav links.
- **Slate** (`#ffffff`): Tertiary text (currently aliased to white). Counter labels, bento stat labels, small tag text.

> Note: All text variables currently resolve to `#ffffff`. The semantic naming is preserved for future tiered-contrast adjustments (e.g., `#f2f2f2` vs `#d8d8d8`) without touching call sites.

### Semantic

- **Profile pill — safest**: `rgba(0,217,146,0.07)` bg, `rgba(0,217,146,0.25)` border, `#00d992` text
- **Profile pill — useful**: `rgba(74,158,255,0.07)` bg, `rgba(74,158,255,0.25)` border, `#4a9eff` text
- **Profile pill — research**: `rgba(227,179,65,0.07)` bg, `rgba(227,179,65,0.25)` border, `#e3b341` text
- **Status badge — active**: green tint
- **Status badge — legacy**: blue tint
- **Status badge — new**: amber tint

### Gradient / Glow

- **Logo glow**: `drop-shadow(0 0 2px #00d992)` animating to `drop-shadow(0 0 8px #00d992)` on a 3-second ease-in-out loop.
- **Button hover glow**: `box-shadow: 0 0 20px rgba(0,217,146,0.15)` on `.btn-hero-primary:hover`.
- **Card hover accent**: `box-shadow: 0 0 24px rgba(0,217,146,0.05)` with border-color `rgba(0,217,146,0.25)` on `.bento-card:hover`.

---

## 3. Typography Rules

### Font Family

Single typeface everywhere: `'Roboto Mono', SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace`.

All four CSS variables (`--font-head`, `--font-body`, `--font-mono`, `--font-brand`) resolve to this stack.

### Hierarchy

| Role | Size | Weight | Line Height | Letter Spacing | Notes |
|------|------|--------|-------------|----------------|-------|
| Hero Display | `clamp(52px, 8vw, 100px)` | 700 | 1.0 | -2px | Maximum compression |
| Section Heading | `clamp(28px, 3vw, 36px)` | 400 | 1.11 | -0.9px | Light weight for authority |
| Overline | 12px | 600 | — | 2.5px | Uppercase, green |
| Feature Title | 18px | 600 | — | -0.2px | Card headings |
| Body | 16px | 400 | 1.5 | normal | General prose |
| Card Body | 14px | 400 | 1.65 | normal | Descriptions in cards |
| Counter | 36px | 700 | 1.0 | -1px | Monospace display |
| Bento Stat | 48px | 700 | 1.0 | -2px | Large numeric values |
| Bento Label | 10px | 700 | — | 1.8px | Uppercase, green |
| Tag / Badge | 10–12px | 500–600 | — | 0.3–1.5px | Pill-shaped labels |
| Nav Link | 14px | 500 | — | normal | Parchment, hover green |
| Hero Sub | `clamp(16px, 2vw, 20px)` | 300 | 1.4 | -0.2px | Light weight, softer |

### Principles

- **Monospace-only**: No serif, no geometric sans. Every character occupies the same column width, reinforcing the terminal aesthetic throughout.
- **Compression for authority**: Hero and section headings use tight line-heights (1.0, 1.11) and negative letter-spacing. Dense text blocks read as specifications, not marketing.
- **Uppercase is labeled**: Uppercase transforms appear only on small labels (overlines, section labels, counter labels, bento card labels) and are always paired with generous letter-spacing (1.5px–2.5px).
- **OpenType enabled**: `font-feature-settings: "calt", "rlig"` is set globally on `html`.

---

## 4. Component Stylings

### Buttons

**Primary CTA (`.btn-hero-primary`)**

- Background: Carbon Surface (`#050505`)
- Text: Mint (`#2fd6a1`)
- Border: `1px solid #00d992`
- Padding: `14px 28px`
- Radius: 6px
- Hover: background `#181818`, `box-shadow: 0 0 20px rgba(0,217,146,0.15)`

**Ghost / Outline (`.btn-hero-ghost`)**

- Background: transparent
- Text: Snow (`#ffffff`)
- Border: `1px solid #3d3a39`
- Padding: `14px 28px`
- Radius: 6px
- Hover: `background: rgba(255,255,255,0.04)`

**Nav Primary (`.btn-primary`)**

- Background: Carbon Surface (`#050505`)
- Text: Mint (`#2fd6a1`)
- Border: none
- Padding: `8px 16px`
- Radius: 6px
- Hover: `background: #181818`

**Nav Ghost (`.btn-ghost`)**

- Background: transparent
- Text: Snow (`#ffffff`)
- Border: `1px solid #3d3a39`
- Padding: `8px 16px`
- Radius: 6px
- Hover: `background: rgba(0,0,0,0.3)`, border-color shifts to Slate

**GitHub Star (`.gh-star`)**

- Background: Carbon Surface
- Text: Parchment, hover Mint
- Border: `1px solid #3d3a39`, hover `#00d992`
- Includes `<svg>` star icon (13×13px, `stroke: currentColor`)
- Font: `font-family: var(--font-mono); font-size: 12px; font-weight: 600; letter-spacing: 0.3px`

### Cards & Containers

**Why Cards (`.why-card`)**

- Background: Carbon Surface (`#050505`)
- Border: shared grid gap of `1px` Warm Charcoal
- Padding: `40px 32px`
- Hover: background `#131313`
- Icon: 40×40px container, 8px radius, Abyss bg, green stroke SVG

**Bento Cards (`.bento-card`)**

- Background: Carbon Surface
- Border: `1px solid #3d3a39`
- Radius: 10px
- Padding: `28px`
- Hover: border-color `rgba(0,217,146,0.25)`, box-shadow `0 0 24px rgba(0,217,146,0.05)`
- Variants: `.bento-large` (span 2 cols), `.bento-tall` (span 2 rows), `.bento-wide` (span 2 cols)

**Algorithm Table (`.algo-table`)**

- Full-width semantic `<table>` inside `.algo-table-shell`
- Sticky footer bar: `.algo-table-footer` with `position: sticky; bottom: 0`
- Status badges: `.status-badge` with colored tints per status type

**Counter Strip (`.hero-counters`)**

- Three adjacent `.counter-item` cells joined without gap
- First child: left-rounded (8px). Last child: right-rounded (8px). No left-border on 2nd/3rd.
- Background: Carbon Surface, Border: Warm Charcoal

### Navigation

- Fixed, top, full-width, `z-index: 100`
- Background: `rgba(5,5,7,0.92)` with `backdrop-filter: blur(12px)`
- Bottom border: `1px solid #3d3a39`
- Height: `64px`
- Logo: SVG mark with green glow animation + Roboto Mono wordmark
- Links: 14px, weight 500, Parchment color, hover Signal Green
- CTA area: GitHub star badge + GitHub button
- Mobile: collapses to hamburger at `<768px`

### Code Blocks (`.bento-mini-code`)

- Background: Abyss Black
- Border: `1px solid #3d3a39`
- Radius: 6px
- Padding: `14px`
- Font: `var(--font-mono); font-size: 11px; line-height: 1.7`
- Syntax colors: keywords `#ff7b72` (red), functions `#d2a8ff` (purple), strings `#a5d6ff` (blue), numbers `#79c0ff` (cyan)

### Timeline (`.tl-entry`)

- Grid layout with named areas: `"event dot context"` for odd, `"context dot event"` for even
- Event card: bordered, gradient background, green bottom accent bar
- Context card: transparent, borderless, tag cloud with `.tl-tag` pills
- Collapses to single column at `1024px`

---

## 5. Layout Principles

### Spacing System

- Base unit: `8px`
- Section padding: `96px 0`
- Container max-width: `1280px`, padding: `0 32px`
- Card gap in why-grid: `1px` (shared background creates the line)
- Bento gap: `12px`
- Hero actions gap: `16px`
- Nav inner gap: `16px` between zones; `28px` between links

### Grid & Container

- Why section: `grid-template-columns: repeat(3, 1fr)` with shared `#3d3a39` background as separator lines
- Bento: `repeat(3, 1fr)` with `12px` gap, supports 2-column and large span cards
- Use Cases: `repeat(3, 1fr)` card grid
- Algorithm table: full-container-width semantic table
- Timeline: 3-column grid with named areas for alternating layout
- Responsive: most grids collapse 3→2→1 at 900px and 600px breakpoints

### Background Texture

Body has a fixed SVG dot-grid pattern at 3% opacity. 5 dots per 80×80px cell. This adds technical depth without visual noise.

### Whitespace Philosophy

- **Section-level breathing room**: 96px vertical padding per section creates clear chapter breaks.
- **Dense within components**: Cards use compact padding (28–40px) with tight internal line-heights. Information is concentrated.
- **Border-as-separator**: The why-grid uses a `1px` gap on a `#3d3a39` background to create dividers without extra markup. Containment is expressed through border, not shadow or spacing alone.

---

## 6. Depth & Elevation

| Level | Treatment | Use |
|-------|-----------|-----|
| Flat (0) | No border, no shadow | Page canvas (`#000000`), section backgrounds |
| Contained (1) | `1px solid #3d3a39` | Standard cards, nav bar, counters, code blocks |
| Accent (2) | `1px solid #00d992` or `rgba(0,217,146,0.25)` | Active/highlighted cards, hero button border |
| Glow (3) | `box-shadow: 0 0 20–24px rgba(0,217,146,0.05–0.15)` | Button hover, bento card hover |
| Logo Pulse | `drop-shadow(0 0 2–8px #00d992)` animated 3s loop | Logo SVG mark only |

**Philosophy**: Depth is communicated through border color, not shadow. Shifting `border-color` from `#3d3a39` (neutral) to `rgba(0,217,146,0.25)` (active) is the primary elevation signal. Shadows are used only as subtle ambient glows, never as hard-edged depth indicators.

---

## 7. Do's and Don'ts

### Do

- Use `#000000` (Abyss) as the page background and `#050505` (Carbon) for all contained surfaces
- Reserve Signal Green (`#00d992`) for high-signal moments only: active states, overlines, accent borders, icon strokes
- Use Mint (`#2fd6a1`) for button text on dark backgrounds, it reads better than pure green
- Keep heading line-heights compressed (1.0 for hero, 1.11 for sections) with negative letter-spacing
- Use `#3d3a39` borders as the primary depth signal, not box-shadows
- Apply Roboto Mono to every element, including body copy — no exceptions to the monospace-only rule
- Keep uppercase text paired with wide letter-spacing (min 1.5px), never apply uppercase to headings
- Use semantic color tokens (`--green`, `--mint`, `--border`) rather than raw hex in new CSS

### Don't

- Don't introduce warm colors (orange, red, yellow) as decorative accents — reserve warm semantics for status-only (amber badges, warning states)
- Don't use Signal Green as a large surface fill or background
- Don't increase hero or section heading line-height above 1.2 — compression is core to the identity
- Don't add box-shadows for standard card elevation — border color shifts are the depth signal
- Don't mix in any serif or sans-serif typeface — monospace everywhere is a deliberate constraint
- Don't use border-radius above 10px on cards; pill (9999px) is reserved for tags and badges only
- Don't use em-dashes (—) in copy. Use colons, commas, or rewrite the sentence instead
- Don't write marketing superlatives ("Zero compromise", "Every algorithm"). Write like a spec sheet: specific, technical, measurable

---

## 8. Responsive Behavior

### Breakpoints

| Breakpoint | Width | Key Changes |
|------------|-------|-------------|
| Mobile | < 600px | Single column everything, hero canvas opacity reduced, counters stack |
| Tablet | 600–900px | 2-column bento, why-grid 2-col, timeline single-column |
| Desktop | 900–1280px | Full 3-column layouts, full nav |
| Wide | > 1280px | Max-width container centered, generous horizontal margins |

### Collapse Strategy

- **Navigation**: full horizontal nav collapses to hamburger at `768px`
- **Why grid**: 3-col → single-col (grid stacks, border-as-gap still works)
- **Bento**: 3-col → 2-col (at 900px) → 1-col (at 600px); span classes reset to `span 1`
- **Timeline**: 3-area named-grid → single column (both cards stack, dot stays)
- **Hero counters**: flex-wrap handles narrow viewports naturally
- **Code blocks**: horizontal scroll on narrow viewports, no line-wrapping

---

## 9. Agent Prompt Guide

### Quick Color Reference

- Brand Accent: Signal Green (`#00d992`)
- Button Text: Mint (`#2fd6a1`)
- Page Background: Abyss Black (`#000000`)
- Card Surface: Carbon Surface (`#050505`)
- Border / Containment: Warm Charcoal (`#3d3a39`)
- All Text: Snow (`#ffffff`)
- Active Border: `rgba(0,217,146,0.25)`

### Typeface

Everything uses: `'Roboto Mono', SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace`

### Example Component Prompts

- "Create a feature card on Carbon Surface (`#050505`) with a `1px solid #3d3a39` border and `10px` radius. Title in Roboto Mono at 18px weight 600, Snow (`#ffffff`). Body at 14px weight 400, line-height 1.65, also Snow. On hover, shift border to `rgba(0,217,146,0.25)` and add `box-shadow: 0 0 24px rgba(0,217,146,0.05)`."
- "Create a ghost button: transparent background, Snow text, `1px solid #3d3a39` border, `6px` radius, `14px 28px` padding. Hover: `background: rgba(255,255,255,0.04)`."
- "Create a primary CTA button: Carbon Surface background, Mint (`#2fd6a1`) text, `1px solid #00d992` border, `6px` radius, `14px 28px` padding. Hover: `background: #181818; box-shadow: 0 0 20px rgba(0,217,146,0.15)`."
- "Build a hero section on Abyss Black. Overline: 12px Roboto Mono uppercase, `2.5px` letter-spacing, Signal Green. Title: `clamp(52px,8vw,100px)` Roboto Mono, weight 700, line-height 1.0, letter-spacing -2px, Snow. The 'SSL' in the title is Signal Green. Subtitle: `clamp(16px,2vw,20px)` weight 300, line-height 1.4."
- "Add a logo mark with an SVG icon that has `filter: drop-shadow(0 0 2px #00d992)` and animates to `drop-shadow(0 0 8px #00d992)` over 3 seconds ease-in-out infinite."

### Iteration Guide

1. Reference specific CSS variable names alongside hex: "use `var(--green)` (`#00d992`)"
2. Border treatment communicates emphasis: switch from `#3d3a39` to `rgba(0,217,146,0.25)` for active state
3. Describe line-height and letter-spacing explicitly for heading changes — they define the aesthetic
4. Keep all copy in spec-sheet tone: specific, measurable, no superlatives
5. Never introduce a non-monospace typeface; if a new font-family property is needed, it must resolve to Roboto Mono
6. Animations should be slow and subtle: 3s for glows, 25–80s for marquee-like scrolling, no fast flashes
