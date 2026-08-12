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
import { RBACProvider } from "../context/RBACContext";
import { ProtectedRoute } from "./guards";
import AppShell from "../layouts/AppShell";
import LoginPage from "../pages/LoginPage";
import { CIS_COMPLIANCE_LIVE } from "../featureFlags";
import { ComingSoon } from "../components/ComingSoon";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { RouteErrorPage } from "../components/RouteErrorPage";
import { ClipboardList } from "lucide-react";

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
              // { path: "persistence",  element: <S><PersistenceBackdoors /></S> },
              // { path: "identity",     element: <S><IdentityAccess /></S> },
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
              { path: ":section",   element: <S><Settings /></S> },
            ],
          },

          // Unknown paths fall back to dashboard
          { path: "*", element: <Navigate to="/dashboard" replace /> },
        ],
      },
    ],
  },
]);
