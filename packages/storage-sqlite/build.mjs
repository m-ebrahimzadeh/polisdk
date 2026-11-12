import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(__dirname, "dist");

if (fs.existsSync(distDir)) {
  fs.rmSync(distDir, { recursive: true, force: true });
}

const tscBin = path.resolve(
  __dirname,
  "..",
  "..",
  "node_modules",
  "typescript",
  "bin",
  "tsc",
);

execFileSync(process.execPath, [tscBin, "-p", path.join(__dirname, "tsconfig.json")], {
  stdio: "inherit",
});
