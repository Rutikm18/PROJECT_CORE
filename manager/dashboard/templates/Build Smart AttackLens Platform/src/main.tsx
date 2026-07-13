
  import { createRoot } from "react-dom/client";
  import { RouterProvider } from "react-router";
  import { router } from "./app/router/index";
  import "./styles/index.css";
  import { initTimezone } from "./app/context/timezoneStore";
  import { ErrorBoundary } from "./app/components/ErrorBoundary";

  // Kick off server timezone sync immediately — non-blocking.
  // useTimezone() hooks initialise from localStorage/default synchronously;
  // this corrects them once the API responds (~100ms on LAN).
  void initTimezone();

  // Outer ErrorBoundary catches catastrophic failures (router bootstrap crash,
  // React itself failing). Inner route-level errorElement handles page errors.
  createRoot(document.getElementById("root")!).render(
    <ErrorBoundary>
      <RouterProvider router={router} />
    </ErrorBoundary>
  );
