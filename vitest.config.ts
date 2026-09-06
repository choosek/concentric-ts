import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig((_config) => ({
  plugins: [tsconfigPaths()],
  test: {
    testTimeout: 80000,
    coverage: {
      enabled: true,
      provider: "v8",
      all: true,
      include: ["src/**/*.ts"], // Ignore built distribution bundles.
      exclude: ["**/*.d.ts"],
      reporter: ["text", "json-summary", "json", "lcov"],
      reportOnFailure: true,
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
}));
