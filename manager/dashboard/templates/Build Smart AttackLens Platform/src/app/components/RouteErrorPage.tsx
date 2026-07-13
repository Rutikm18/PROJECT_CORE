/**
 * RouteErrorPage — displayed by React Router when a route throws during render.
 * React Router v6.4+ (createBrowserRouter) has its own route-level error
 * boundary that PRECEDES React class-based ErrorBoundary components in the tree.
 * Adding this as `errorElement` on the root route gives us control over the UI
 * instead of the default "Unexpected Application Error!" dev overlay.
 */
import { useRouteError, isRouteErrorResponse, useNavigate } from "react-router";
import { AlertTriangle, RefreshCw, Home } from "lucide-react";

export function RouteErrorPage() {
  const error = useRouteError();
  const navigate = useNavigate();

  let heading = "Something went wrong";
  let message = "This page encountered an unexpected error.";
  let detail  = "";

  if (isRouteErrorResponse(error)) {
    heading = `${error.status} — ${error.statusText || "Error"}`;
    message = typeof error.data === "string" ? error.data : "The page you requested could not be found.";
  } else if (error instanceof Error) {
    message = error.message;
    if (import.meta.env.DEV) detail = error.stack ?? "";
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-8 bg-gray-50">
      <div className="max-w-md w-full text-center">
        <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-100 flex items-center justify-center mx-auto mb-5">
          <AlertTriangle className="w-7 h-7 text-red-400" />
        </div>
        <h2 className="text-base font-semibold text-gray-900 mb-1.5">{heading}</h2>
        <p className="text-[13px] text-gray-500 mb-6 leading-relaxed">{message}</p>
        <div className="flex gap-2.5 justify-center">
          <button
            onClick={() => navigate(0)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium rounded-lg border border-gray-200 text-gray-700 bg-white hover:bg-gray-50 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reload page
          </button>
          <button
            onClick={() => navigate("/dashboard")}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium rounded-lg bg-gray-900 text-white hover:bg-gray-800 transition-colors"
          >
            <Home className="w-3.5 h-3.5" />
            Go to dashboard
          </button>
        </div>
        {detail && (
          <details className="mt-6 text-left">
            <summary className="text-[11px] text-gray-400 cursor-pointer hover:text-gray-600">
              Stack trace (dev only)
            </summary>
            <pre className="mt-2 text-[10px] text-red-500 bg-red-50 p-3 rounded-lg overflow-auto max-h-40 whitespace-pre-wrap">
              {detail}
            </pre>
          </details>
        )}
      </div>
    </div>
  );
}
