import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // today's measured coverage; raise these, never lower them
      thresholds: { lines: 97, statements: 97, functions: 99, branches: 95 },
    },
  },
});
