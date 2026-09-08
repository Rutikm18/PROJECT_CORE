/**
 * Canonical URL → page mapping for AttackLens dashboard.
 *
 * Used by: router/index.tsx (route definitions)
 *          Sidebar.tsx        (NavLink targets)
 *          TopHeader.tsx      (breadcrumb lookup)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PATH                          PAGE FILE               TAB/SECTION
 * ─────────────────────────────────────────────────────────────────────────────
 * /                             → redirect /dashboard
 * /login                        auth/login/index.tsx
 *
 * /dashboard                    operations/dashboard/    Dashboard
 * /findings                     operations/findings/     ThreatQueue
 * /incidents                    operations/incidents/    Incidents
 *
 * /terrain/origin               terrain/origin/          VulnerabilitySurface
 * /terrain/vector               terrain/vector/          NetworkThreats
 * /terrain/citadels             terrain/citadels/        ExecutionThreats
 * /terrain/mesh                 terrain/mesh/            MeshThreats
 * /terrain/identity             terrain/identity/        IdentityTerrain
 * /terrain/posture              terrain/posture/         PostureTerrain
 * /terrain/persistence          terrain/persistence/     PersistenceBackdoors  (disabled)
 *
 * /posture/overview             posture/overview/        SecurityPosture       (disabled)
 * /posture/compliance           posture/compliance/      CISCompliance
 *
 * /intelligence/:tab            ThreatIntelligence.tsx   ioc|cve|kev|hunt|feeds
 *   /intelligence/ioc           ↳ IOC Triage tab
 *   /intelligence/cve           ↳ CVE Intel tab
 *   /intelligence/kev           ↳ KEV Mandates tab
 *   /intelligence/hunt          ↳ Hunt Queries tab
 *   /intelligence/feeds         ↳ Feed Status tab
 *
 * /assets                       inventory/assets/        AssetRegistry
 * /timeline                     inventory/timeline/      Timeline
 *
 * /analysis/deep                analysis/deep/           DeepAnalysis
 * /analysis/accuracy            analysis/accuracy/       Accuracy
 * /analysis/coverage            analysis/coverage/       DetectionCoverage
 *
 * /settings/:section            Settings.tsx             org|license|roles|platform|validation|pipeline|retention|ai
 *   /settings/org               ↳ Organisation Details
 *   /settings/license           ↳ License & Validity
 *   /settings/roles             ↳ Role Access Matrix
 *   /settings/platform          ↳ Platform Config
 *   /settings/validation        ↳ Finding Validation (thresholds)
 *   /settings/pipeline          ↳ Validation Pipeline (stages, accuracy, debug)
 *   /settings/customers         ↳ Customer Dashboards (portal provisioning)
 *   /settings/retention         ↳ Data Retention
 *   /settings/ai                ↳ AI Configuration
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * All paths are served by FastAPI's SPA catch-all (server.py `spa_fallback`)
 * which returns index.html for any path that doesn't match /api/* or /static/*.
 */

export const ROUTES = {
  dashboard:  "/dashboard",
  findings:   "/findings",
  incidents:  "/incidents",

  terrain: {
    root:        "/terrain",
    origin:      "/terrain/origin",
    vector:      "/terrain/vector",
    citadels:    "/terrain/citadels",
    mesh:        "/terrain/mesh",
    persistence: "/terrain/persistence",
    identity:    "/terrain/identity",
    posture:     "/terrain/posture",
  },

  posture: {
    root:       "/posture",
    overview:   "/posture/overview",
    compliance: "/posture/compliance",
  },

  intelligence: {
    root:  "/intelligence",
    ioc:   "/intelligence/ioc",
    cve:   "/intelligence/cve",
    kev:   "/intelligence/kev",
    hunt:  "/intelligence/hunt",
    feeds: "/intelligence/feeds",
  },

  assets:   "/assets",
  timeline: "/timeline",
  reports:  "/reports",

  analysis: {
    root:     "/analysis",
    deep:     "/analysis/deep",
    deepmesh: "/analysis/deepmesh",
    accuracy: "/analysis/accuracy",
    coverage: "/analysis/coverage",
  },

  settings: {
    root:       "/settings",
    org:        "/settings/org",
    license:    "/settings/license",
    roles:      "/settings/roles",
    platform:   "/settings/platform",
    validation: "/settings/validation",
    pipeline:   "/settings/pipeline",
    customers:  "/settings/customers",
    retention:  "/settings/retention",
    ai:         "/settings/ai",
  },

  auth: {
    login: "/login",
  },
} as const;

export type AppRoute = typeof ROUTES[keyof typeof ROUTES] extends string
  ? typeof ROUTES[keyof typeof ROUTES]
  : string;
