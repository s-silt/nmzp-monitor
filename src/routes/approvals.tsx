import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/approvals")({
  beforeLoad: () => {
    throw redirect({ to: "/audit" });
  },
});
