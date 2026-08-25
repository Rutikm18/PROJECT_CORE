/**
 * Route tree for AttackLens dashboard.
 *
 * Architecture:
 *   RootLayout (AuthProvider + RBACProvider — wraps every route)
 *   ├─ /login                     → LoginPage (public)
 *   └─ /  (ProtectedRoute + AppShell)
 *      ├─ /dashboard
 *      ├─ /findings
 *      ├─ /incidents
 *      ├─ /terrain/:page
 *      ├─ /posture/:page
 *      ├─ /intelligence/:tab      (ioc | cve | kev | hunt | feeds)
 *      ├─ /assets
 *      ├─ /timeline
 *      ├─ /analysis/:page
 *      └─ /settings/:section      (org | license | roles | platform | validation | retention | ai)
 *
 * The SPA catch-all in server.py returns index.html for every non-API path,
 * so bookmarking or refreshing any deep URL works correctly.
 */

import { createBrowserRouter, Navigate, Outlet } from "react-router";
import { lazy, Suspense } from "react";
import { AuthProvider } from "../context/AuthContext";
import { RBACProvider, RequireAdmin } from "../context/RBACContext";
import { ProtectedRoute } from "./guards";
import AppShell from "../layouts/AppShell";
import LoginPage from "../pages/LoginPage";
import { CIS_COMPLIANCE_LIVE, CUSTOMER_PORTAL_LIVE } from "../featureFlags";
import {
  PortalProtectedRoute, PortalSessionProvider, PortalShell,
} from "../portal/PortalShell";
import { ComingSoon } from "../components/ComingSoon";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { RouteErrorPage } from "../components/RouteErrorPage";
import { Building2, ClipboardList } from "lucide-react";

// ── Root layout: one Auth + RBAC context shared by ALL routes ─────────────────
function RootLayout() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <RBACProvider>
          <Outlet />
        </RBACProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

// ── Lazy page imports ─────────────────────────────────────────────────────────
const Dashboard          = lazy(() => import("../pages/Dashboard"));
const ThreatQueue        = lazy(() => import("../pages/ThreatQueue"));
const Incidents          = lazy(() => import("../pages/Incidents"));
const VulnerabilitySurface = lazy(() => import("../pages/VulnerabilitySurface"));
const NetworkThreats     = lazy(() => import("../pages/NetworkThreats"));
const ExecutionThreats   = lazy(() => import("../pages/ExecutionThreats"));
const MeshThreats        = lazy(() => import("../pages/MeshThreats"));
const IdentityTerrain    = lazy(() => import("../pages/IdentityTerrain"));
const PostureTerrain     = lazy(() => import("../pages/PostureTerrain"));
const PersistenceBackdoors = lazy(() => import("../pages/PersistenceBackdoors"));
const IdentityAccess     = lazy(() => import("../pages/IdentityAccess"));
const SecurityPosture    = lazy(() => import("../pages/SecurityPosture"));
const CISCompliance      = CIS_COMPLIANCE_LIVE ? lazy(() => import("../pages/CISCompliance")) : null;
const ThreatIntelligence = lazy(() => import("../pages/ThreatIntelligence"));
const AssetRegistry      = lazy(() => import("../pages/AssetRegistry"));
const Timeline           = lazy(() => import("../pages/Timeline"));
const DeepAnalysis       = lazy(() => import("../pages/DeepAnalysis"));
const DeepMesh           = lazy(() => import("../pages/DeepMesh"));
const Accuracy           = lazy(() => import("../pages/Accuracy"));
const DetectionCoverage       = lazy(() => import("../pages/DetectionCoverage"));
const CustomCorrelationRules  = lazy(() => import("../pages/CustomCorrelationRules"));
const Settings                = lazy(() => import("../pages/Settings"));

// ── Customer portal ───────────────────────────────────────────────────────────
const PortalLogin         = lazy(() => import("../portal/PortalAuthPages").then(m => ({ default: m.PortalLogin })));
const PortalAcceptInvite  = lazy(() => import("../portal/PortalAuthPages").then(m => ({ default: m.PortalAcceptInvite })));
const PortalDashboard     = lazy(() => import("../portal/PortalPages").then(m => ({ default: m.PortalDashboard })));
const PortalFindings      = lazy(() => import("../portal/PortalPages").then(m => ({ default: m.PortalFindings })));
const PortalFindingDetail = lazy(() => import("../portal/PortalPages").then(m => ({ default: m.PortalFindingDetail })));
const PortalAgents        = lazy(() => import("../portal/PortalPages").then(m => ({ default: m.PortalAgents })));
const PortalSettings      = lazy(() => import("../portal/PortalPages").then(m => ({ default: m.PortalSettings })));

// ── Suspense wrapper ──────────────────────────────────────────────────────────
function PageLoading() {
  return (
    <div className="flex items-center justify-center py-32">
      <span className="w-3.5 h-3.5 border-2 border-gray-200 border-t-orange-400 rounded-full animate-spin" />
    </div>
  );
}
function S({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageLoading />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

const PortalComingSoon = () => (
  <div className="min-h-screen bg-[--gray-50] flex items-center justify-center p-5">
    <ComingSoon
      icon={<Building2 className="w-6 h-6 text-[--gray-400]" />}
      title="Customer Portal"
      description="Scoped, read-only dashboards for your customers are built and ready, and will be enabled here shortly. Contact your AttackLens administrator if you need early access."
    />
  </div>
);

const CompliancePage = CIS_COMPLIANCE_LIVE && CISCompliance
  ? () => <S><CISCompliance /></S>
  : () => (
      <ComingSoon
        icon={<ClipboardList className="w-6 h-6 text-[--gray-400]" />}
        title="CIS Compliance"
        description="CIS Benchmark compliance scoring is coming soon — will track macOS hardening against the CIS macOS Benchmark."
      />
    );

// ── Route tree ────────────────────────────────────────────────────────────────
export const router = createBrowserRouter([
  // ── Customer portal ────────────────────────────────────────────────────────
  //
  // Deliberately a SIBLING of the operator tree, not a child. It must not sit
  // under RootLayout: that provides AuthProvider and RBACProvider, which resolve
  // the *operator* session — mounting the portal inside them would have a
  // customer's page quietly holding an operator principal, and a redirect on
  // 401 would send them to the operator login.
  //
  // The bundle is shared on purpose. The React code is not the secret; the
  // server refusing an aud=portal token on every operator route is the control,
  // and sharing the design system is what makes the portal look like the same
  // product rather than a stripped-down clone.
  {
    path: "portal/login",
    element: CUSTOMER_PORTAL_LIVE ? <S><PortalLogin /></S> : <PortalComingSoon />,
    errorElement: <RouteErrorPage />,
  },
  {
    path: "portal/accept-invite",
    element: CUSTOMER_PORTAL_LIVE ? <S><PortalAcceptInvite /></S> : <PortalComingSoon />,
    errorElement: <RouteErrorPage />,
  },
  {
    path: "portal",
    errorElement: <RouteErrorPage />,
    element: CUSTOMER_PORTAL_LIVE ? (
      <PortalSessionProvider>
        <PortalProtectedRoute>
          <PortalShell />
        </PortalProtectedRoute>
      </PortalSessionProvider>
    ) : <PortalComingSoon />,
    // The customer sees the SAME pages as an operator. Scope is applied
    // server-side (TenantScopeMiddleware + FindingQuery.tenant_agent_ids), so
    // these components need no tenant awareness at all — they issue the same
    // requests and receive only this customer's rows.
    //
    // Settings is the sole divergence: the operator Settings page configures
    // the platform, so the portal substitutes its own, limited to this
    // customer's dashboard preferences.
    children: [
      { index: true,                 element: <S><Dashboard /></S> },
      { path: "findings",            element: <S><ThreatQueue /></S> },
      { path: "incidents",           element: <S><Incidents /></S> },
      { path: "terrain/origin",      element: <S><VulnerabilitySurface /></S> },
      { path: "terrain/vector",      element: <S><NetworkThreats /></S> },
      { path: "terrain/citadels",    element: <S><ExecutionThreats /></S> },
      { path: "terrain/mesh",        element: <S><MeshThreats /></S> },
      { path: "terrain/identity",    element: <S><IdentityTerrain /></S> },
      { path: "terrain/posture",     element: <S><PostureTerrain /></S> },
      { path: "intelligence",        element: <S><ThreatIntelligence /></S> },
      { path: "timeline",            element: <S><Timeline /></S> },
      { path: "analysis",            element: <S><DeepAnalysis /></S> },
      { path: "deepmesh",            element: <S><DeepMesh /></S> },
      { path: "agents",              element: <S><AssetRegistry /></S> },
      { path: "settings",            element: <S><PortalSettings /></S> },
    ],
  },
  {
    // Root layout: provides shared auth + RBAC context
    element: <RootLayout />,
    // Route-level error boundary — replaces React Router's default "Unexpected
    // Application Error!" overlay. Catches render errors in any child route.
    errorElement: <RouteErrorPage />,
    children: [

      // ── Public ─────────────────────────────────────────────────────────────
      {
        path: "login",
        element: <LoginPage onSuccess={() => {}} />,
        errorElement: <RouteErrorPage />,
      },

      // ── Authenticated shell ─────────────────────────────────────────────────
      {
        path: "/",
        element: (
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        ),
        errorElement: <RouteErrorPage />,
        children: [

          // Root redirect
          { index: true, element: <Navigate to="/dashboard" replace /> },

          // ── Operations ─────────────────────────────────────────────────────
          { path: "dashboard",  element: <S><Dashboard /></S> },
          { path: "findings",   element: <S><ThreatQueue /></S> },
          { path: "incidents",  element: <S><Incidents /></S> },

          // ── Attack Terrain ──────────────────────────────────────────────────
          {
            path: "terrain",
            children: [
              { index: true,          element: <Navigate to="/terrain/origin" replace /> },
              { path: "origin",       element: <S><VulnerabilitySurface /></S> },
              { path: "vector",       element: <S><NetworkThreats /></S> },
              { path: "citadels",     element: <S><ExecutionThreats /></S> },
              { path: "mesh",         element: <S><MeshThreats /></S> },
              { path: "identity",     element: <S><IdentityTerrain /></S> },
              { path: "posture",      element: <S><PostureTerrain /></S> },
              // { path: "persistence",  element: <S><PersistenceBackdoors /></S> },
            ],
          },

          // ── Posture ─────────────────────────────────────────────────────────
          {
            path: "posture",
            children: [
              // { index: true,         element: <Navigate to="/posture/overview" replace /> },
              { index: true,         element: <Navigate to="/posture/compliance" replace /> },
              // { path: "overview",    element: <S><SecurityPosture /></S> },
              { path: "compliance",  element: <CompliancePage /> },
            ],
          },

          // ── Intelligence (/intelligence/:tab?) ─────────────────────────────
          {
            path: "intelligence",
            children: [
              { index: true, element: <Navigate to="/intelligence/ioc" replace /> },
              { path: "feeds", element: <Navigate to="/intelligence/ioc" replace /> },
              { path: ":tab", element: <S><ThreatIntelligence /></S> },
            ],
          },

          // ── Inventory ───────────────────────────────────────────────────────
          { path: "assets",    element: <S><AssetRegistry /></S> },
          { path: "timeline",  element: <S><Timeline /></S> },

          // ── Analysis (/analysis/deep|accuracy|coverage|custom-rules) ──────────
          {
            path: "analysis",
            children: [
              { index: true,          element: <Navigate to="/analysis/deep" replace /> },
              { path: "deep",         element: <S><DeepAnalysis /></S> },
              { path: "deepmesh",     element: <S><DeepMesh /></S> },
              // Back-compat: the page was briefly shipped as /analysis/surface.
              { path: "surface",      element: <Navigate to="/analysis/deepmesh" replace /> },
              { path: "custom-rules", element: <S><CustomCorrelationRules /></S> },
              // { path: "accuracy",     element: <S><Accuracy /></S> },
              // { path: "coverage",     element: <S><DetectionCoverage /></S> },
            ],
          },

          // ── Settings (/settings/:section?) ──────────────────────────────────
          {
            path: "settings",
            children: [
              { index: true,        element: <Navigate to="/settings/org" replace /> },
              // Settings manages keys, retention, org identity and customer
              // dashboards — administrator-only for now.
              { path: ":section",   element: <S><RequireAdmin><Settings /></RequireAdmin></S> },
            ],
          },

          // Unknown paths fall back to dashboard
          { path: "*", element: <Navigate to="/dashboard" replace /> },
        ],
      },
    ],
  },
]);
