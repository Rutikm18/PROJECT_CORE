/**
 * App.tsx — kept for backward compatibility; the real entry point is
 * src/main.tsx which mounts RouterProvider directly.
 *
 * If anything still imports App, it gets the RouterProvider.
 */
import { RouterProvider } from "react-router";
import { router } from "./router/index";

export default function App() {
  return <RouterProvider router={router} />;
}
