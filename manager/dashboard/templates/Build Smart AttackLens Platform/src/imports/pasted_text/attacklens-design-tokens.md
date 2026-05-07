# AttackLens.ai — Complete Figma Design Prompt
### CTEM Platform · UX-First · Light Theme · Human Psychology Driven

---

## 0. Design Philosophy — Read This First

This is a tool people use for 6–8 hours a day under pressure. Every design decision
must serve the human using it, not impress someone looking at a screenshot.

**Three UX laws driving every decision here:**

**1. Fitts's Law** — The most important actions must be the largest and closest
to where the eye naturally lands. Primary CTAs are never hidden. The thing a user
will do 80% of the time should take 20% of the effort.

**2. Hick's Law** — Every extra option adds decision time. The raw data page has
21 sections — never show all 21 at once. Group, filter, collapse. Show what matters
first, let users reach the rest.

**3. Signal vs. Noise** — Color communicates only when it is rare. If red appears
everywhere, red means nothing. In this UI, red appears on exactly one type of thing:
something that requires immediate human action. Nothing else is red. This is non-
negotiable.

**The alert fatigue problem this design must solve:**
Dark SOC dashboards with constant red/orange/amber are scientifically linked to
analyst desensitization. Analysts stop seeing the color after 30–90 minutes. This
platform switches to a light base with surgical color — the red badge on a white
panel surface stops the eye every single time.

---

## 1. Brand Identity

**Product:** AttackLens.ai
**Category:** CTEM — Continuous Threat Exposure Management
**Tagline:** Continuous Threat Exposure Management

**Logo mark:**
A geometric "A" — two diagonal strokes meeting at a peak with a horizontal crossbar,
like a mountain or a targeting reticle. Clean, minimal, scalable to 16px. Rendered
in white on the brand orange (#E8581A) rounded square (6px radius). Never use the
mark without the orange background.

**Wordmark:** `attacklens.ai`
- `attack` — Inter 700, color: Gray-900 (#111827)
- `lens` — Inter 700, color: Brand orange (#E8581A)
- `.ai` — Inter 400, color: Gray-400 (#9CA3AF)
- Do not capitalize. Do not add a tagline inline with the wordmark.

---

## 2. Color System — Minimal and Intentional

### 2.1 Base Palette

Use these and only these. Do not introduce any additional colors.

**Neutrals (90% of the UI lives here):**

| Token            | Hex       | Usage                                      |
|------------------|-----------|--------------------------------------------|
| white            | #FFFFFF   | Page background, panel background          |
| gray-25          | #FAFAFA   | Alternate row bg, sidebar bg               |
| gray-50          | #F9FAFB   | Hover state on rows                        |
| gray-100         | #F3F4F6   | Tag backgrounds, disabled inputs           |
| gray-200         | #E5E7EB   | Borders, dividers, separators              |
| gray-300         | #D1D5DB   | Input borders, inactive toggles            |
| gray-400         | #9CA3AF   | Placeholder text, secondary icons          |
| gray-500         | #6B7280   | Metadata, timestamps, muted labels         |
| gray-600         | #4B5563   | Secondary body text                        |
| gray-700         | #374151   | Primary body text                          |
| gray-800         | #1F2937   | Panel headings, table headers              |
| gray-900         | #111827   | Page titles, primary headlines             |

**Brand (used sparingly — nav active state, primary CTA, logo):**

| Token            | Hex       | Usage                                      |
|------------------|-----------|--------------------------------------------|
| brand-orange     | #E8581A   | Logo, primary button, active nav, links    |
| brand-orange-50  | #FFF4EE   | Orange badge background                    |
| brand-orange-100 | #FFE4D0   | Orange hover state                         |
| brand-orange-700 | #C2410C   | Orange text on light bg (AA accessible)    |

**Semantic (reserved exclusively for status meaning — use nowhere else):**

| Token            | Hex       | Usage                                      |
|------------------|-----------|--------------------------------------------|
| red-50           | #FEF2F2   | Critical badge background                  |
| red-600          | #DC2626   | Critical badge text, critical icons        |
| red-700          | #B91C1C   | Critical text on hover                     |
| amber-50         | #FFFBEB   | High/warning badge background              |
| amber-600        | #D97706   | High/warning badge text                    |
| green-50         | #F0FDF4   | Safe/pass badge background                 |
| green-600        | #16A34A   | Safe/pass badge text, success states       |
| blue-50          | #EFF6FF   | Medium/info badge background               |
| blue-600         | #2563EB   | Medium/info badge text, links              |

### 2.2 Color Rules — Enforced

1. **Red is for critical only.** Not for decorative borders, not for brand moments,
   not for charts unless the data point is critical severity.
2. **The page background is always white.** Panels are white. Sidebars are gray-25.
   There is no dark mode in V1.
3. **Brand orange appears in:** logo, primary button, active navigation item,
   active tab underline, CTEM active stage indicator. That is all.
4. **Charts use a single blue (#2563EB) by default.** Multi-series charts use
   blue + amber. Never use more than 3 colors in a single chart.
5. **Borders are gray-200.** Never colored borders except semantic status cards.

---

## 3. Typography

**Primary font:** Inter (Google Fonts)
**Monospaced font:** JetBrains Mono (for all data values, IDs, hashes, commands)

| Style            | Font        | Weight | Size  | Line Height | Color     | Usage                        |
|------------------|-------------|--------|-------|-------------|-----------|------------------------------|
| Display          | Inter       | 700    | 24px  | 32px        | gray-900  | Page titles                  |
| Heading-1        | Inter       | 600    | 18px  | 28px        | gray-900  | Panel titles                 |
| Heading-2        | Inter       | 600    | 14px  | 20px        | gray-800  | Section headers              |
| Body             | Inter       | 400    | 13px  | 20px        | gray-700  | Primary body text            |
| Body-sm          | Inter       | 400    | 12px  | 18px        | gray-600  | Secondary body, descriptions |
| Label            | Inter       | 500    | 11px  | 16px        | gray-500  | Form labels, column headers  |
| Caption          | Inter       | 400    | 11px  | 16px        | gray-400  | Timestamps, metadata         |
| KPI-value        | Inter       | 700    | 28px  | 36px        | gray-900  | Dashboard KPI numbers        |
| KPI-label        | Inter       | 500    | 11px  | 16px        | gray-500  | KPI card labels              |
| Code             | JetBrains   | 400    | 12px  | 20px        | gray-800  | Data values, IDs, hashes     |
| Code-sm          | JetBrains   | 400    | 11px  | 18px        | gray-600  | Timestamps in tables         |
| Badge            | Inter       | 600    | 11px  | 16px        | semantic  | Status badges                |

**Letter spacing:** Labels and column headers use 0.4px letter spacing uppercase.
All other text: 0.

---

## 4. Spacing, Grid, Elevation

**Base unit:** 4px

**Spacing scale:** 4, 8, 12, 16, 20, 24, 32, 40, 48, 64px

**Page grid:** 1440px canvas, 16px side margins, 12-column grid, 16px gutters.

**Border radius:**
- Panels / cards: 8px
- Badges / chips: 4px
- Buttons: 6px
- Inputs: 6px
- Avatar: 50%
- Toggle: 12px

**Borders:** 1px solid gray-200 everywhere. No drop shadows on panels.
Use border for separation, not shadow. The one exception: modal overlays use
box-shadow: 0 8px 24px rgba(0,0,0,0.10).

**Elevation system (3 levels only):**
- Level 0: flat, border only (panels, cards, rows)
- Level 1: box-shadow 0 1px 3px rgba(0,0,0,0.08) — dropdowns, popovers
- Level 2: box-shadow 0 8px 24px rgba(0,0,0,0.10) — modals, drawers

---

## 5. Component Library — Design System Page

Build every component here before using it anywhere. Document variants.
All components use Auto Layout. All colors reference styles.

### 5.1 Severity Badge
Pill shape. 4px radius. 4px top/bottom padding, 8px left/right.
Inter 600 11px. Four variants:

| Variant  | Background | Text      | Usage                    |
|----------|------------|-----------|--------------------------|
| CRITICAL | red-50     | red-600   | Requires immediate action|
| HIGH     | amber-50   | amber-600 | Action within 24h        |
| MEDIUM   | blue-50    | blue-600  | Action within 7 days     |
| LOW      | gray-100   | gray-600  | Informational            |
| INFO     | gray-100   | gray-500  | Monitoring only          |

### 5.2 Intel Validation Badge
Same pill shape. Three variants:

| Variant | Background      | Text            | Label         |
|---------|-----------------|-----------------|---------------|
| KEV     | brand-orange-50 | brand-orange-700| KEV           |
| EDB     | blue-50         | blue-600        | EDB-XXXXX     |
| CVSS    | gray-100        | gray-700        | 9.8           |

### 5.3 CTEM Stage Chip
Pill, gray-100 bg, gray-600 text by default.
Active variant: brand-orange-50 bg, brand-orange-700 text.
Five labels: SCOPING / DISCOVERY / PRIORITIZATION / VALIDATION / MOBILIZATION.

### 5.4 Section Tag
Rounded pill, gray-100 bg, gray-500 text, JetBrains Mono 11px.
Used to label mac_intel data source sections.
Example: `connections` `packages` `security`

### 5.5 CIS Reference Tag
Same structure as Section Tag. Blue-50 bg, blue-600 text.
Example: `CIS-4.1` `CIS-7.3`

### 5.6 Panel
White background. 1px gray-200 border. 8px radius. No shadow.
Has: Panel Header slot (white bg, 12px 16px padding, 1px gray-200 bottom border)
and Panel Body slot (padding varies by content type).

### 5.7 Panel Header
Flex row, space-between, align-center.
Left: title text (Inter 600 14px gray-800).
Right: slot for meta text (Inter 400 12px gray-400), action button, or filter.

### 5.8 KPI Card
White bg, 1px gray-200 border, 8px radius, 16px padding.
Top: label (Inter 500 11px gray-500, uppercase, letter-spaced).
Middle: value (Inter 700 28px — colored only if semantic status).
Bottom: meta line (Inter 400 12px gray-500).
Top-right corner: delta chip (green-50/green-600 for positive, red-50/red-600
for negative, gray-100/gray-600 for neutral). Delta chip: +0.4 ▲ or -8% ▼.

**Color rule for KPI values:**
- Values that represent a risk score or count of problems: gray-900 (neutral).
  The KPI card itself is not colored. The severity badge NEXT to it carries color.
- Exception: CIS Pass Rate (34%) — this IS colored amber-600 because it is
  a compliance percentage where the color encodes the meaning directly.

### 5.9 Data Table
Column headers: Inter 500 11px gray-500, uppercase, 0.4px letter-spacing,
gray-25 background, 12px top/bottom padding, 16px left/right.
Rows: white bg, 1px gray-200 bottom border, 12px top/bottom, 16px left/right.
Hover: gray-50 bg.
Selected: blue-50 bg, blue-600 left border (3px).
Sort indicator: chevron icon gray-400, sorted column header gray-800.

### 5.10 Filter Bar
Horizontal scroll container. Contains:
- Search input (gray-200 border, 6px radius, search icon left, 320px wide)
- Filter chips: gray-100 bg, gray-700 text, gray-200 border, 6px radius.
  Active filter: brand-orange-50 bg, brand-orange-700 text, brand-orange-100 border.
- Right-aligned: "Export" text button (gray-600) + primary button (orange bg).

### 5.11 Finding Row (in lists)
Full width. 12px 16px padding. White bg. 1px gray-200 bottom border.
Hover: gray-50 bg. Cursor: pointer.

Row structure (flex, space-between):
- Left: Severity badge + Finding title (Inter 500 13px gray-800, truncate) + 
  Section tag + CIS tag
- Right: Intel badges (KEV / EDB / CVSS) + CTEM stage chip + timestamp
  (JetBrains 11px gray-400) + chevron icon

Two-line layout:
- Line 1: [CRITICAL] Title text here                    [KEV] [9.8] [VALIDATION]
- Line 2: connections  CIS-12                                         2 min ago ›

### 5.12 Status Chip (SLA)
Pill, 4px radius. Three variants:
- BREACHED: red-50 bg, red-600 text, 1px red-200 border
- AT RISK: amber-50 bg, amber-600 text, 1px amber-200 border
- ON TRACK: green-50 bg, green-600 text, 1px green-200 border

### 5.13 Sparkline Component
Minimal line chart, no axes, no labels. 80×24px.
Used inline in tables and cards for trend visualization.
Positive trend: green-600 line. Negative trend: red-600. Neutral: gray-400.

### 5.14 Mini Bar
Horizontal progress bar. Full width or fixed width variant.
Background: gray-100. Fill: semantic color based on value threshold.
Height: 4px, 2px radius.
Thresholds: 0–33%: green-600, 34–66%: amber-600, 67–100%: red-600.
Exception: CIS compliance bars are inverted (low % = red = bad).

### 5.15 Empty State
Centered in panel. Icon (gray-300, 40px), title (Inter 500 14px gray-500),
description (Inter 400 13px gray-400), optional action button.

### 5.16 Tooltip
Level 1 elevation. gray-900 bg, white text. 6px radius. 8px 12px padding.
Inter 400 12px. Max width 220px. Arrow pointer 6px.

### 5.17 Toggle Switch
Standard iOS-style toggle. On: brand-orange track. Off: gray-300.
Knob: white circle. 36×20px.

### 5.18 Tab Bar (two styles)
Style A — Underline tabs (for page-level navigation within a section):
Inter 500 13px. Active: gray-900 + 2px brand-orange underline.
Inactive: gray-500. Hover: gray-700. 16px padding bottom.

Style B — Pill tabs (for toggling view modes within a panel):
Active: white bg, gray-800 text, gray-200 border, 1px shadow.
Inactive: transparent, gray-500.

---

## 6. Navigation & Layout Shell

### 6.1 Left Sidebar Navigation (240px fixed)

**Top section:**
- Logo mark (28px) + wordmark, 20px padding, 24px bottom margin.
- "endpoint-macpro-01" label (Inter 500 12px gray-600) with green dot (live).

**Primary nav items** (each 36px height, 12px horizontal padding, 8px radius hover):
Icon (20px, gray-400) + label (Inter 500 13px gray-600).
Active state: brand-orange-50 bg, brand-orange-700 text, brand-orange icon.

Nav items:
```
🏠  Overview             (Dashboard home)
🔍  Findings             (Prioritization matrix)
🛡️  CIS Compliance       (Benchmark report)
📊  Raw Data             (21 sections — expandable)
🔗  Attack Chains        (Correlation view)
🤖  AI Remediation       (Remediation workspace)
```

**Raw Data nav item** — has expand chevron. When expanded shows sub-items
in a group (12px left indent, 11px font, gray-500):
```
  System Health
    metrics  connections  processes  ports
    network  battery  openfiles  storage
  Identity & Access
    users  services  tasks
  Software & Config
    apps  packages  binaries  sbom  configs
  Security Posture
    security  sysctl
  Hardware & Infra
    hardware  containers  mounts  arp
  Agent
    agent_health
```

**Bottom section (pinned):**
- Mode toggle: "Analyst" / "CISO" pill toggle (Inter 500 12px).
  CISO active: amber-50 bg, amber-700 text (because CISO mode = simplified view).
  Analyst active: gray-900 bg, white text.
- User avatar + name + "Settings" icon.

### 6.2 Top Header Bar (56px)

Fixed across all pages. White bg, 1px gray-200 bottom border.
Left: current page breadcrumb (Inter 400 13px gray-500 › Inter 500 13px gray-800).
Right cluster (16px gap):
- Time range selector (pill button: "Last 24h ▾" — opens dropdown with
  1h / 6h / 24h / 7d / 30d / Custom).
- Refresh indicator (green dot + "Updated 4s ago" in Inter 400 12px gray-400).
- Bell icon (notification) with red dot badge when critical findings.
- Avatar (32px circle, initials).

### 6.3 Main Content Area

Left of sidebar (240px) and right of page edge.
Top of content (56px header) and bottom of viewport.
Internal padding: 24px all sides.
Max content width: 1160px (centered within the content area).

---

## 7. Figma File — Page Structure

Build exactly 9 pages:

```
Page 1 — 🎨 Design System
Page 2 — 🏠 Dashboard Overview
Page 3 — 📋 Findings & Prioritization
Page 4 — 🛡️ CIS Compliance
Page 5 — 📊 Raw Data Hub
Page 6 — 🔍 Finding Detail (Drawer)
Page 7 — 🔗 Attack Chains
Page 8 — 🤖 AI Remediation
Page 9 — 👔 CISO Executive View
```

Each page: 1440×900px frame. Include nav sidebar and top header on every page
(use the same component, just variant for active state).

---

## 8. Page 2 — Dashboard Overview

### 8.1 CTEM Pipeline (below header, above KPIs)

Full-width bar. White bg, 1px gray-200 border, 8px radius. No fill colors.
Five equal sections with 1px gray-200 right dividers.

Each stage cell (flex column, 16px padding):
- Stage label (Inter 500 11px gray-400 uppercase, letter-spaced):
  `01 · SCOPING`
- Stage name (Inter 600 13px gray-800)
- Subtitle (Inter 400 12px gray-500)
- Count (Inter 700 20px gray-900)

**Active stage (Prioritization) only:**
Add 2px brand-orange bottom border on the cell.
No background color change — just the underline.
The count for active stage uses brand-orange-700 instead of gray-900.

Stage data:
- 01 SCOPING / Asset Surface / 21 sections monitored / **21**
- 02 DISCOVERY / Exposures Found / across 6 domains / **43**
- 03 PRIORITIZATION (active) / Action Queue / CVSS + EPSS scored / **12** orange
- 04 VALIDATION / Verified Active / exploit confirmed / **7**
- 05 MOBILIZATION / In Remediation / playbooks active / **3**

### 8.2 KPI Row (5 cards, equal width, 12px gap)

Using KPI Card component. Note: minimal color use.

| Label           | Value | Value Color | Meta                    | Delta    |
|-----------------|-------|-------------|-------------------------|----------|
| Risk Score      | 8.7   | gray-900    | / 10 · + CRITICAL badge | +0.4 red |
| Exposure Score  | 74    | gray-900    | KEV: 2 · EPSS avg: 61%  | +12 red  |
| Critical Findings | 7   | gray-900    | + CRITICAL badge · 3 new| +3 red   |
| CIS Pass Rate   | 34%   | amber-600   | 18 / 53 controls        | -8% red  |
| Remediated 30d  | 18    | gray-900    | + green badge · MTTR 6.2h| +3 green|

The CRITICAL / HIGH / PASSING badges appear NEXT to the value, not as the value
color. This keeps numbers readable while color communicates status separately.

### 8.3 Main Content Grid (2 columns: 1fr + 320px, 16px gap)

**Left column:**

**Panel A: CIS Benchmark Compliance Overview**
Header: "CIS Benchmark Compliance" + "macOS v8 · 53 controls" + 
"Full Report →" (text link, brand-orange-700) right-aligned.

3×2 grid (12px gap). Each CIS card:
Top row: "CIS-4" (Inter 600 12px gray-400) + percentage (Inter 700 18px, 
colored by compliance: <40% red-600, 40-70% amber-600, >70% green-600).
Control name (Inter 500 13px gray-800).
4px mini bar (colored same as percentage).
Fail detail line (Inter 400 11px gray-500, below bar).

Cards:
- CIS-1 / 60% amber / Asset Inventory / hardware · software · sbom · 4 fail
- CIS-2 / 45% amber / Software Asset Mgmt / apps · packages · binaries · 6 fail
- CIS-4 / 12% red  / Secure Configuration / SIP off · GK off · FV off · 9 fail
- CIS-5 / 25% red  / Account Management / UID-0 non-root account · 3 fail
- CIS-7 / 20% red  / Vulnerability Mgmt / 8 unpatched CVEs · 7 fail
- CIS-12/ 50% amber / Network Infrastructure / ports · connections · arp · 5 fail

Below grid: full-width overall bar. Left: "Overall CIS Score" gray-500 11px.
Bar: 34% red fill, gray-100 bg, 4px height. Right: "34% · FAILING" red-600 11px.

**Panel B: Security Domain Health**
Header: "Domain Health" + "6 domains · 21 sections".

Six domain rows (not cards — use rows for scannability):
Each row: Domain name (Inter 500 13px gray-800, 160px) + mini bar (flex 1) +
score (Inter 700 13px, colored) + pill counts (CRITICAL badge + HIGH badge).

Rows sorted highest-risk first:
- Security Controls / 94% bar red / 9.4 / 2 CRIT · 1 HIGH
- Network Exposure  / 91% bar red / 9.1 / 3 CRIT · 4 HIGH
- Persistence & Exec / 84% bar red / 8.4 / 1 CRIT · 5 HIGH
- Vuln Surface / 73% bar amber / 7.3 / 1 CRIT · 3 HIGH
- Identity & Access / 62% bar amber / 6.2 / 2 CRIT · 3 HIGH
- Behavioral / 41% bar blue / 4.1 / 0 CRIT · 2 HIGH

Below each row: section tags (small gray pills showing which sections feed it).

**Right column (4 stacked panels):**

**Panel 1: Exposure Score**
No ring gauge. Instead: large number display.
Inter 700 48px, gray-900: "8.7"
Below: "out of 10 · Critical" with CRITICAL badge.
Divider.
Factor table (5 rows):
- CVSS base      → 9.1  [red-600]
- EPSS top CVE   → 94%  [red-600]
- KEV matches    → 2    [amber-600]
- CIS pass rate  → 34%  [amber-600]
- SLA status     → BREACHED [red badge]

**Panel 2: EPSS Scores (30-day exploitation probability)**
Header: "EPSS — Exploitation Probability" + tooltip icon (ℹ) with tooltip:
"Probability this CVE will be exploited in the next 30 days. Source: FIRST.org."

Five rows using EPSS Row component. Columns:
CVE ID (JetBrains 12px, 110px) | Package (Inter 400 12px gray-600, flex 1) |
Mini bar (60px) | Percentage (Inter 600 12px, colored) | KEV badge (if applicable).

Rows:
- CVE-2024-44308 / curl 7.86.0       / 94% red  / [KEV]
- CVE-2023-32373 / openssl 3.1.2     / 87% red  / [KEV]
- CVE-2024-1086  / git 2.39.1        / 71% amber
- CVE-2023-44487 / python 3.11.2     / 58% amber
- CVE-2022-42916 / libxml2 2.9.13    / 34% blue

Below: "View all 8 CVEs →" text link.

**Panel 3: SLA Compliance**
Header: "SLA Compliance".
Four SLA rows using SLA Row component:
- CRITICAL / 4h target / 7 open / 42% bar red / [BREACHED]
- HIGH     / 24h       / 12 open / 65% bar amber / [3 AT RISK]
- MEDIUM   / 7d        / 18 open / 80% bar green / [ON TRACK]
- LOW      / 30d       / 6 open / 95% bar green / [OK]

**Panel 4: Threat Intel Feed Status**
Header: "Threat Intel Feeds" + "All feeds active" green dot + text.
Five rows:
Source (Inter 500 12px gray-700, 80px) | Count (Inter 600 12px gray-900, 32px) |
Bar (flex) | Status dot | Freshness (Inter 400 11px gray-400).

- CISA KEV   / 2 matches / red bar full  / green dot / updated 1h ago
- NVD / EPSS / 8 CVEs    / blue bar 90%  / green dot / live
- ExploitDB  / 5 entries / amber bar 80% / green dot / live
- Feodo C2   / 1 match   / red bar 20%   / green dot / updated 1h ago
- ET Rules   / 3 matches / gray bar 60%  / amber dot / updated 1h ago

### 8.4 Bottom Row (2 columns equal width, 16px gap)

**Left: Top Priority Findings**
Header: "Priority Findings" + filter chips: All / Critical / Unassigned.
+ "View all →" right-aligned text link.

Five finding rows using Finding Row component.
Show exactly these findings:
1. CRITICAL · Active C2 beacon — 185.220.101.47:4444 · [KEV][9.8] · connections · CIS-12 · VALIDATION
2. CRITICAL · SIP disabled — System Integrity Protection off · [KEV][9.1] · security · CIS-4.1 · MOBILIZATION
3. CRITICAL · SUID binary /tmp/.update/patcher · [EDB-51337][8.8] · binaries · CIS-2.6 · PRIORITIZATION
4. CRITICAL · CVE-2024-44308 · curl 7.86.0 · EPSS 94% · [KEV][EDB-51892][9.8] · packages · CIS-7.3
5. CRITICAL · UID-0 non-root account — sysbackup · [7.8] · users · CIS-5.2 · DISCOVERY

**Right: Attack Chain Correlations**
Header: "Attack Chains" + "3 active" with red badge count.
+ "View all →" text link.

Three chain blocks (16px padding each, gray-200 bottom border):
Each chain: Chain ID (JetBrains 11px gray-500) + score badge right.
Below: horizontal node flow.

Nodes: white bg, gray-200 border, 8px radius, 8px 12px padding.
Type label (Inter 400 10px gray-400 above) + value (Inter 500 12px gray-800).
Arrow between nodes: → gray-400 character, 12px.

Chains:
1. corr:c2_beacon_tool · 9.5 · CRITICAL badge
   [process: python3.11] → [connection: 185.220.101.47] → [feed: Feodo C2]
2. corr:defense_evasion_chain · 8.5 · HIGH badge
   [security: SIP off] → [app: unsigned] → [config: plist mod]
3. corr:privesc_execution · 8.0 · HIGH badge
   [binary: SUID /tmp] → [process: patcher] → [user: uid=0]

---

## 9. Page 3 — Findings & Prioritization

Full-width table page. No separate sidebar content — the table IS the content.

### 9.1 Page Header (within content area)
"Findings" Display title.
Subtitle: "43 total · 7 critical · Sorted by composite risk score".
Right: "Export CSV" text button + "Create Ticket" primary button (orange).

### 9.2 Filter Bar
Search (320px, "Search findings, CVEs, packages...") +
Filter chips: All Severities ▾ / Domain ▾ / CTEM Stage ▾ /
[KEV Only toggle] / [Has Exploit toggle] / [SLA Breached toggle] / [Unassigned toggle].
Right: Sort by ▾ (Composite Score / CVSS / EPSS / SLA / Date) + View toggle (Table/Board).

### 9.3 Findings Table

Column headers (gray-25 bg, 1px gray-200 border):
# | Severity | Finding | Domain | CVSS | EPSS | KEV | CIS Ref | Stage | Score | SLA | Assignee | ···

Column widths:
32px | 88px | flex(1, min 280px) | 120px | 56px | 72px | 56px | 72px | 120px | 64px | 110px | 96px | 40px

**Score column:** The composite score (0–10). Displayed as: number (Inter 700 13px)
colored by threshold: ≥8 red-600, 5-7.9 amber-600, <5 green-600.
This is the ONLY place the score number is colored. Everything else uses badges.

**EPSS column:** percentage + tiny 32px sparkline showing 7-day trend.

**SLA column:** Time remaining (Inter 400 12px gray-600) or status chip.
"2h left" in amber-600. "Overdue 2.1h" in red-600. "6d left" in gray-500.

Show 12 rows. Rows 1–7 are CRITICAL. Rows 8–12 are HIGH.

### 9.4 Right Summary Panel (240px, appears when NO row is selected)
Severity distribution: donut chart (gray-100 bg, 160px, segments: red/amber/blue/gray).
Below: count per severity with badge.
Below: "By Domain" mini bar list (6 rows).
Below: CTEM stage distribution (5 rows with counts).

### 9.5 Row Selected State
When a row is clicked: row gets blue-50 bg, blue-600 left border.
Right panel switches to "Quick Preview" — shows finding title, severity,
section evidence snippet (3 lines, JetBrains Mono), KEV/CVSS/EPSS, and
two buttons: "Open Detail ↗" (primary orange) + "Assign to me" (ghost button).

---

## 10. Page 4 — CIS Compliance

### 10.1 Header
"CIS macOS Benchmark v8" + "53 controls · last assessed 2 min ago".
Right: Overall score "34%" in red-600, Inter 700 24px + "FAILING" badge.
"Export PDF Report" button.

### 10.2 Summary Bar (4 KPI cards in a row)
Total Controls: 53 / Passing: 18 (green) / Failing: 27 (red) / N/A: 8 (gray).

### 10.3 Two-Column Layout (Left 360px list, right flex detail)

**Left — Control list:**
Grouped by CIS Control number, each with expand/collapse.
Group header: "CIS 4 · Secure Configuration" (Inter 600 13px gray-800) +
compliance % (colored) + chevron.

Each control item (expanded):
- Check name (Inter 400 12px gray-700)
- Pass ✓ (green-600) or Fail ✗ (red-600) icon
- mac_intel section tag (which section provides evidence)

Selected control: brand-orange-50 left border 2px.

**Right — Control Detail (when CIS-4 is selected):**
Title: "CIS Control 4.1 — Ensure System Integrity Protection Status" (Inter 600 16px).
Description: 2–3 lines plain language.
Current status: Large FAILING badge.

Evidence table:
Check Name | Expected | Actual | Section
SIP Status | enabled  | disabled (red) | security
Gatekeeper | enabled  | disabled (red) | security
FileVault  | enabled  | disabled (red) | security
Firewall   | enabled  | disabled (red) | security

Remediation steps (numbered, same style as Playbook):
Step 1: Re-enable SIP...
[code block with command]

"View related findings (9) →" link.
"Generate AI Remediation Plan" primary orange button.

---

## 11. Page 5 — Raw Data Hub

This page is the most complex. 21 sections, each showing live structured data
from the mac_intel agent. The key UX insight: different section types need
different visualization patterns.

### 11.1 Layout
Left: Section navigator (same expanded nav sidebar, Raw Data section active).
Top: Section name heading + last collected timestamp + refresh button.
Main area: section-specific view.

### 11.2 Section Groups and their Visualization Patterns

**GROUP A — System Health Metrics**
Sections: `metrics` `battery` `storage`

Visualization: Dashboard of gauges + sparklines. NO table.

Layout (3-column grid of metric cards):
Each metric card (white bg, border, 8px radius, 16px padding):
- Metric name (Inter 500 12px gray-500)
- Current value (Inter 700 24px gray-900)
- Mini sparkline (7-day trend, 80×24px)
- Threshold indicator: colored dot (green/amber/red) next to value

Metrics to show for `metrics` section:
CPU % | Memory % | Memory Used MB | Load 1m | Load 5m | Load 15m
Swap Used | Disk Read MB/s | Disk Write MB/s | Net In MB/s | Net Out MB/s

Battery card: Charge % (gauge arc, 0–100%) + Condition + Cycle count + 
Status chip (Charging / Discharging / Full).

Storage card: Per-mount bar chart. Horizontal bars, device name left,
GB used / total right, bar colored by % full.

**Time range filter** (header): 1h / 6h / 24h / 7d tabs.

---

**GROUP B — Network State**
Sections: `connections` `ports` `network` `arp`

Visualization: Filterable table + summary stats sidebar.

`connections` table columns:
Protocol | Local Address | Remote Address | State | PID | Process | Risk

Risk column: CRITICAL badge if remote IP matches threat feed, HIGH if
suspicious port, else gray dash.

Above table: stat chips showing counts:
[12 ESTABLISHED] [3 LISTEN] [2 CLOSE_WAIT] [1 ⚠ Threat Feed Match]

Filter bar: Protocol (TCP/UDP) | State | Risk level | Process name search.
Time filter: Snapshot / 1h trend.

`ports` table: Protocol | Port | Bind Address | PID | Process | Risk Assessment.
Risk assessment: badge if port matches known malicious list, else "normal" gray text.

`network` view: Two panels side by side.
Left: Interfaces list (name, IP, MAC, status dot green/gray).
Right: DNS servers list + WiFi SSID chip + gateway.

`arp` table: IP | MAC | Interface | State.
Flag rows where MAC has changed since last scan (amber row highlight + "Changed" amber badge).

---

**GROUP C — Process & Execution State**
Sections: `processes` `services` `tasks` `openfiles`

`processes` — High-density sortable table.
Columns: PID | Name | CPU% | Mem% | User | Status | Risk
Default sort: CPU% descending.
Risk column: badge if process matches known malicious patterns. 
Mini bar charts inline for CPU% and Mem% instead of raw numbers.

Top of page: 4 summary chips:
[247 total] [3 ⚠ suspicious] [CPU avg 34%] [Mem avg 61%]

Search: real-time filter by process name or PID.

`services` table: Name | Status | Enabled | PID | Type | Risk.
Status column: green dot "running" or gray dot "stopped".
Risk column: badge if service name matches suspicious patterns.
Filter: Running only / All / Suspicious only tabs.

`tasks` — Scheduled tasks. Clean list view (not table):
Each task item: Name + Type chip (LaunchDaemon/Cron/etc) + Schedule +
Command (JetBrains mono, truncated, expand on click) + User + Risk badge.
Suspicious items: amber-50 row background.

`openfiles` — Simple table. PID | Process | File Count.
Sorted by file count descending. Bar chart inline for count.

---

**GROUP D — Identity & Access**
Sections: `users` `hardware` `containers`

`users` — Card grid (3 columns).
Each user card (white bg, border, 8px radius, 12px padding):
- Avatar circle (initials, gray-200 bg)
- Username (Inter 600 13px) + UID (JetBrains 11px gray-400)
- Shell tag + Admin badge (if admin) + Locked badge (if locked)
- Risk indicator: CRITICAL badge if UID=0 and not root.

Filter: All / Admin only / Locked / Suspicious.

`hardware` — Inventory table. Bus | Name | Vendor | Serial.
Group by Bus type (USB / PCI / Thunderbolt — collapsible group headers).

`containers` — Status table. ID | Name | Image | Status | Runtime.
Status: green dot "running" or gray dot "stopped".

---

**GROUP E — Software & Supply Chain**
Sections: `apps` `packages` `binaries` `sbom` `configs`

`apps` — Rich table with inline risk signals.
Columns: Name | Version | Bundle ID | Signed | Notarized | Risk | Action.
Signed column: ✓ green / ✗ red icon.
Notarized: same.
Risk: badge if unsigned or unnotarized.

`packages` — The most important section for vulnerability management.
Columns: Manager | Name | Version | Outdated | CVE | CVSS | EPSS | KEV | Action.
CVE column: if found, show CVE ID as blue link. If KEV, add KEV badge.
EPSS: inline mini bar + percentage.
Filter: All / Has CVE / KEV Only / Outdated only.
"Update all patchable" action button.

`binaries` — Security-critical table.
Columns: Path | SHA256 (truncated, copy button) | SUID | SGID | World Writable | Risk.
SUID/SGID/World Writable columns: ✓ red if true (these are risk indicators),
dash gray if false.
Risk column: CRITICAL badge if SUID outside /usr/bin.
Filter: All / SUID only / World Writable / Suspicious paths.

`sbom` — Software Bill of Materials.
Columns: Type | Name | Version | PURL | License | Risk.
Filter: By license type / By risk.

`configs` — Configuration files.
Columns: Path | Type | Hash | Suspicious | Last Changed.
Suspicious: amber row if flagged. Hash in JetBrains mono, 8 chars shown + copy.

---

**GROUP F — Security Posture**
Sections: `security` `sysctl`

`security` — This is the most important layout decision on the whole page.
DO NOT use a table. Use a pass/fail checklist layout.

Layout: 2 columns of check items.
Each check item (flex row, 16px padding, gray-200 bottom border):
- Check name (Inter 500 13px gray-800, flex 1)
- Expected value (Inter 400 12px gray-500, 80px)
- Status icon: ✓ circle green-600 or ✗ circle red-600
- Actual value (Inter 600 12px, colored: red if failing, green if passing)
- CIS reference tag (blue-50)

Security checks to show:
✗ System Integrity Protection  | expected: enabled | actual: disabled | CIS-4.1
✗ Gatekeeper                   | expected: enabled | actual: disabled | CIS-4.2
✗ FileVault                    | expected: enabled | actual: disabled | CIS-2.1
✗ Firewall                     | expected: enabled | actual: disabled | CIS-4.6
✓ Secure Boot                  | expected: enabled | actual: enabled  | CIS-5.1
✗ Remote Login (SSH)           | expected: disabled| actual: enabled  | CIS-4.5
✓ Screen Lock                  | expected: enabled | actual: enabled  | CIS-5.6
✗ Automatic Updates            | expected: enabled | actual: disabled | CIS-7.5

Summary at top: "2 / 8 checks passing" with progress bar (25% red).

`sysctl` — Table. Key | Value | Security Relevant | Recommendation.
Security Relevant column: amber badge if true.
Filter: Security relevant only toggle.

---

**GROUP G — Infrastructure**
Sections: `mounts` `arp` `network`

(ARP and network also appear in Network State above — same view, just accessed
from different nav path. Mount and additional infra views here.)

`mounts` — Table. Device | Mountpoint | Filesystem Type | Space gauge.
Inline space gauge (mini bar) showing % used.

---

**GROUP H — Agent Health**
Section: `agent_health`

This is a system health view for the agent itself.

Layout: Status summary + metrics + circuit breaker states.

Top: Large status indicator. "HEALTHY" green badge or "DEGRADED" amber badge.
Below: 4 KPI cards: Uptime | Last Heartbeat | Payload Send Rate | Queue Size.

Circuit breaker table:
Section | Status | Failures | Last Failure | Recovery.
Status column: green dot "CLOSED" / red dot "OPEN" / amber dot "HALF-OPEN".

Below: Mini sparkline grid (one 80×24px sparkline per section) showing
send rate over last hour.

---

**Global Raw Data Controls (appear on every section):**

Top-right of every section: 
- Time range picker (for historical sections): Last 1h / 6h / 24h / 7d.
- Refresh button (circular arrow icon).
- "View Raw JSON" toggle (opens bottom drawer with raw NDJSON, JetBrains mono).
- Export dropdown (CSV / JSON / Copy).

---

## 12. Page 6 — Finding Detail (Drawer)

Shown as an overlay on top of Page 3 (Findings).
Background: dim overlay (gray-900, 40% opacity).
Drawer: slides in from right, 520px wide, full viewport height.
White bg, left border 1px gray-200. Level 2 shadow.
Internal scroll. Fixed header and footer.

### Drawer Header (60px, fixed)
Left: ← Back chevron button + finding title (Inter 600 14px gray-900, truncate).
Right: Severity badge + CTEM stage chip + ✕ close button.
Bottom: 1px gray-200 border.

### Drawer Body (scrollable, 16px padding)

**Section 1: Evidence**
Label: "EVIDENCE" (Inter 500 11px gray-400, uppercase, letter-spaced) + section tag.
Content: code block (gray-25 bg, 1px gray-200 border, 8px radius, 12px padding).
JetBrains Mono 12px gray-800. Key-value pairs formatted cleanly.
"Copy" button top-right of code block (gray-400 icon, tooltip "Copy to clipboard").

**Section 2: Intel Validation**
Three equal-width cards in a row (12px gap):

KEV Card: brand-orange-50 bg, brand-orange-100 border.
"CISA KEV" label (Inter 600 11px brand-orange-700) + "CONFIRMED" green badge.
CVE ID (JetBrains 12px gray-800). Date added. Short description.

CVSS Card: gray-25 bg, gray-200 border.
"CVSS 3.1" label + score (Inter 700 20px, colored).
Vector string in JetBrains 10px gray-500.
4 sub-scores: Attack Vector / Complexity / Privileges / User Interaction.

EPSS Card: gray-25 bg, gray-200 border.
"EPSS" label + percentage (Inter 700 20px red-600 if >50%).
"30-day exploitation probability" subtitle.
"99th percentile" chip.
7-day sparkline trend.

**Section 3: CIS Control Mapping**
Row: CIS reference tag + control name + FAILING badge.
One-line: "This finding violates CIS macOS Benchmark control 4.1 (Secure
Configuration of Enterprise Assets)."
"View control detail →" blue text link.

**Section 4: Prioritization Scores**
Five horizontal bars (label left, bar center, value right):
- EPSS Exploitation Probability / 94% / red bar
- CVSS Base Score / 9.8 / red bar
- KEV Catalog Match / Yes / red badge
- Asset Criticality / High / amber text
- SLA Urgency / Breached / red chip

Composite score: "8.7 / 10 · CRITICAL" displayed prominently.

**Section 5: Remediation**
Two-tab panel (Tab A style):
Tab "Playbook" | Tab "AI Guidance"

**Playbook tab:**
Numbered steps. Each step:
Step number circle (gray-100, Inter 600 12px) + Step title (Inter 600 13px gray-800).
Description (Inter 400 12px gray-600, 1–2 lines).
Command block (gray-25 bg, JetBrains mono, copy button).
Validation note (Inter 400 11px gray-500, italic).
Estimated time (Inter 400 11px gray-400, right-aligned).

Example steps for C2 beacon finding:
1. Identify and kill the process
   `sudo kill -9 4821`
   Validate: `ps aux | grep 4821` should return empty. · ~30s

2. Block the C2 IP at host firewall
   `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add 185.220.101.47`
   · ~1 min

3. Audit for additional C2 connections
   `netstat -an | grep ESTABLISHED | grep -v 127.0.0.1`
   · ~5 min

4. Check for persistence mechanisms
   `launchctl list | grep -v apple`
   · ~10 min

5. Validate resolution (re-run mac_intel scan)
   Trigger manual collection from agent dashboard. · ~2 min

**AI Guidance tab:**
Context banner (green-50 bg, green-100 border, 8px radius):
"Context loaded: macOS 13.6 · connections section · CIS-12 · Feodo C2 match"
Green dot + "Auto-injected from mac_intel telemetry" label.

AI response card (white, border, 8px radius):
Small logo mark (orange) + "AttackLens AI" (Inter 600 13px gray-800) +
"Powered by Claude" (Inter 400 10px gray-400).
Response text in Inter 400 13px gray-700, line-height 20px.
Inline code blocks for commands.

Input area (fixed, bottom of tab area, border-top):
Textarea "Ask a follow-up..." (gray-200 border, 6px radius, 4 rows) +
Send button (orange) + character count (gray-400 mono 10px).

### Drawer Footer (56px, fixed)
SOC workflow bar. Flex row:
Status dropdown (current: "new") | Assignee picker | "Add Note" ghost button |
"Resolve" primary button (green bg, white text, only if status allows).

---

## 13. Page 7 — Attack Chains

### 13.1 Header
"Attack Chain Correlations" + "3 active chains · Jarvis correlation engine" +
"All Resolved" ghost button.

### 13.2 Left chain list (280px)
Three chain rows (similar to finding rows):
Chain ID (JetBrains 12px gray-600) + score badge + arrow.
Active chain: blue-50 bg, blue-600 left border.

### 13.3 Main chain canvas (flex)

**Chain header:**
Chain ID (Inter 600 16px gray-800) + score (CRITICAL/HIGH badge) + 
"Created 12 min ago" caption.

**Visual chain flow (large, horizontal):**
Nodes are larger than in the overview: 120×64px cards.
White bg, gray-200 border, 8px radius.
Type label (Inter 400 11px gray-400, top).
Value (Inter 600 14px gray-800, center).
Section tag (Inter 400 10px, bottom).

Arrow between nodes: orange, 24px, with label above:
"Correlated via process→connection match".

**Chain evidence panel (below chain flow):**
Two-column grid. Left: all contributing findings (list of finding rows).
Right: correlation rule description (what rule triggered, required conditions,
confidence score).

**Timeline panel (below evidence):**
Horizontal timeline. Events plotted as dots on a line.
Each dot: timestamp above, event label below.
Orange dots for this chain's events. Gray dots for context events.

---

## 14. Page 8 — AI Remediation

Full-page remediation workspace. Not a drawer.

### 14.1 Three-panel layout
Left: 320px finding context (read-only, scrollable).
Center: 480px AI chat workspace.
Right: 280px playbook and resources.

**Left panel (Finding Context):**
Finding title + severity + section + CTEM stage.
Intel cards (KEV / CVSS / EPSS) stacked vertically, compact version.
CIS mapping.
"Switch finding ↓" dropdown to switch context without leaving the page.

**Center panel (AI Chat):**
Header: "AI Remediation Guidance" + "Powered by Claude" gray label + Settings icon.

Context banner (same as drawer AI tab but full-width).

Chat history area (scrollable):
User messages: right-aligned, blue-50 bg, blue border, Inter 13px gray-800.
AI messages: left-aligned, white bg, gray-200 border, Inter 13px gray-700.
Code blocks in AI responses: gray-25 bg, JetBrains mono, copy button.

Typing indicator when waiting: three dots animation, gray-300.

Input area (fixed bottom):
Full-width textarea, send button, model info (gray-400: "claude-sonnet-4").

Suggested follow-ups (above input, horizontal scroll chips):
"What if kill fails?" / "How to monitor for recurrence?" / 
"Generate a ticket description" / "Explain to a non-technical stakeholder"

**Right panel (Playbook):**
Header: "Remediation Playbook" + "5 steps" + progress (2/5 complete).

Step list with checkboxes:
☑ Step 1 (checked, green)
☑ Step 2 (checked, green)
☐ Step 3 (current, blue border left)
☐ Step 4
☐ Step 5

"Mark step complete" primary button.

Below: Resources section. Link cards:
- "CIS-4.1 Documentation" (external link icon)
- "Feodo Tracker — IP 185.220.101.47" (external link)
- "Apple SIP Documentation" (external link)

---

## 15. Page 9 — CISO Executive View

Same shell (sidebar + header) but CISO toggle active in sidebar.

**The CISO mode design principle:**
Remove all technical IDs (no CVEs, no PIDs, no hex hashes, no section names).
Replace with business language. Increase white space 40%. Larger type.
The CISO should finish reading in 90 seconds and know exactly what to approve.

### 15.1 Executive Brief Banner (prominent, full-width)
amber-50 bg, amber-200 border, 8px radius, 20px padding.
Left side: "Action Required" (Inter 700 16px amber-700) + date.
Three bullet points (Inter 400 13px gray-700, line-height 24px):
• "Active data exfiltration attempt detected. Endpoint isolation recommended."
• "2 software vulnerabilities are being actively exploited in the wild (CISA confirmed)."
• "Security hardening compliance at 34% — below acceptable threshold. Immediate remediation required."

Right side (160px): Large risk number "8.7 / 10" (Inter 700 32px red-600) +
"CRITICAL RISK" caption + "Download Brief PDF" button.

### 15.2 Business Risk Summary (3 equal cards)
Cards are larger, more white space, bigger type.

Card 1 (red-50 bg, red-200 border):
"Immediate Action Required"
Number: 3 (Inter 700 36px red-600)
"Critical threats needing response today"
Below: 3 brief descriptions in plain language (bullets, gray-700).

Card 2 (amber-50 bg, amber-200 border):
"Patch This Week"
Number: 5 (Inter 700 36px amber-600)
"Known exploits available, patches exist"
Below: Packages to update, plain names only (curl, openssl, git).

Card 3 (blue-50 bg, blue-200 border):
"Under Monitoring"
Number: 8 (Inter 700 36px blue-600)
"Tracked, no immediate action needed"

### 15.3 Two-column main content

**Left: Top Risks in Plain Language**
Three risk cards (no CVE IDs):
1. "Unauthorized Remote Connection" — CRITICAL badge.
   Plain: "A process is communicating with a known malicious server.
   This may indicate data theft or remote attacker control."
   Recommended owner: SecOps. Timeline: Immediate.

2. "Critical Security Feature Disabled" — CRITICAL badge.
   Plain: "macOS System Integrity Protection is off. This allows
   attackers to modify protected system files without restriction."
   Recommended owner: IT. Timeline: Today.

3. "High-Risk Software Vulnerabilities" — HIGH badge.
   Plain: "3 software packages have known exploits being used in
   attacks globally. Updates are available."
   Recommended owner: IT. Timeline: This week.

**Right: Metrics a CISO cares about**

Remediation Velocity: 
"18 threats resolved in last 30 days" with trend arrow ↑ green.
MTTR: "Average 6.2 hours to resolve" — benchmark comparison:
"Industry avg: 14.6h · You are 2.4× faster" (green text).

SLA Compliance:
Same SLA table but larger text, no technical labels.
CRITICAL: "Overdue — 1 threat past 4h window" [BREACHED].
HIGH: "3 threats approaching 24h deadline" [AT RISK].

Risk Trend chart (30-day line):
X: dates. Y: risk score 0–10. One line, blue-600.
Annotations: "Patch applied" (green dot), "New finding" (red dot).
Clean, no grid lines except horizontal guide at y=5 (threshold line, dashed gray).

---

## 16. Prototyping Connections

Wire these interactions:

| From | Trigger | To | Transition |
|---|---|---|---|
| Any finding row | Click | Page 6 Drawer overlay | Slide in from right |
| Drawer close ✕ | Click | Remove overlay | Slide out right |
| CIS card (Dashboard) | Click | Page 4 CIS Compliance | Instant |
| Full CIS Report → | Click | Page 4 CIS Compliance | Instant |
| Attack chain (Dashboard) | Click | Page 7 Attack Chains | Instant |
| AI Guidance tab (Drawer) | Click | Open AI tab in drawer | Tab switch |
| Generate AI Plan (CIS) | Click | Page 8 AI Remediation | Instant |
| View all findings → | Click | Page 3 Findings | Instant |
| Nav: Raw Data sections | Click | Page 5 correct section | Instant |
| ANALYST / CISO toggle | Click | Variant swap | Instant |
| CISO mode any page | Toggle | Page 9 variant | Instant |
| Finding row (Page 3) | Click | Right panel quick preview | In-place |

---

## 17. Figma Delivery Checklist

**Components:**
☐ All components built in Design System page with documented variants
☐ Auto Layout on every component — nothing hardcoded
☐ All colors reference styles (zero hardcoded hex values in components)
☐ All text references text styles
☐ Responsive constraints set (min/max widths on panels)

**Pages:**
☐ 9 pages, all at 1440×900
☐ Navigation sidebar component reused across all pages (variant for active state)
☐ Top header component reused across all pages
☐ CISO mode variant built for Page 9 (not a separate design — same components,
   different variant state)

**Accessibility:**
☐ All text contrast ≥ 4.5:1 against background (WCAG AA)
☐ Color is never the ONLY indicator of status — always paired with text label
☐ Interactive elements have visible focus state (2px brand-orange outline, 2px offset)
☐ Minimum tap target 44×44px on all interactive elements

**Naming:**
☐ All layers named (no "Frame 47" or "Rectangle 12")
☐ Components named: ComponentName/Variant=State
☐ Pages named with emoji prefix as specified

**Export:**
☐ Icons as SVG (24px and 20px sizes)
☐ Logo mark as SVG (multiple sizes: 16, 20, 28, 40px)
☐ Color tokens exportable via Variables (Figma Variables, not just styles)
☐ All frames set to export at @2x PNG for handoff

---

*Prompt version: v3.0 — UX-first rewrite, light theme, human psychology centered*
*AttackLens.ai CTEM Platform — mac_intel agent integration*
*9 pages · Design System + 8 product pages · Full prototyping spec*