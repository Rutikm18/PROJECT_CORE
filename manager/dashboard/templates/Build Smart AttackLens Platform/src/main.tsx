
  import { createRoot } from "react-dom/client";
  import { RouterProvider } from "react-router";
  import { router } from "./app/router/index";
  import "./styles/index.css";

  createRoot(document.getElementById("root")!).render(
    <RouterProvider router={router} />
  );
