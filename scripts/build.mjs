import { build } from "esbuild";

await build({
  entryPoints: ["src/renderer.js"],
  bundle: true,
  outfile: "dist/renderer.js",
  format: "iife",
  platform: "browser",
  target: ["chrome120"],
  sourcemap: true,
  minify: false,
  logLevel: "info",
});
