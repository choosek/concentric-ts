import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/lib.ts" },
  // esm and cjs for Node/bundler consumers; iife for direct use in a browser
  // via a <script> tag, which exposes the library as a `Concentric` global.
  format: ["esm", "cjs", "iife"],
  globalName: "Concentric",
  clean: true,
  dts: true,
});
