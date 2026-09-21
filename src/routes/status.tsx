import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/status")({
  beforeLoad: () => {
    throw redirect({ to: "/" });
  },
});
