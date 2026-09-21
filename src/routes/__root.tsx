import { Toaster } from "sonner";
import { createRootRoute, Outlet } from "@tanstack/react-router";
import { Shell } from "@/components/shell";

export const Route = createRootRoute({
  component: () => (
    <>
      <Shell>
        <Outlet />
      </Shell>
      <Toaster position="bottom-right" closeButton richColors theme="system" />
    </>
  ),
});
