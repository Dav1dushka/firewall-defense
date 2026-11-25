import { build } from "esbuild";
import { readdirSync, rmSync } from "node:fs";

await build({ entryPoints: ["src/main.ts"], outfile: "site/game.js", bundle: true, minify: true, format: "iife",
  target: "es2020", logLevel: "warning" });

if (process.argv.includes("--tests")) {
  rmSync(".test-build", { recursive: true, force: true });
  const entries = readdirSync("tests").filter((f) => f.endsWith(".test.ts")).map((f) => `tests/${f}`);
  await build({ entryPoints: entries, outdir: ".test-build", outExtension: { ".js": ".mjs" }, bundle: true,
    platform: "node", format: "esm", logLevel: "warning" });
}
