import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

mkdirSync("dist", { recursive: true });

await build({
  entryPoints: ["vault/src/main.ts"],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2022",
  minify: true,
  legalComments: "none",
  charset: "utf8",
  outfile: "dist/vault.js",
  logLevel: "info",
});

copyFileSync("vault/index.html", "dist/index.html");
copyFileSync("vault/vault.css", "dist/vault.css");
copyFileSync("vault/_headers", "dist/_headers");

const files = ["vault.js", "vault.css", "index.html"];
const lines = files.map((name) => {
  const hash = createHash("sha256").update(readFileSync("dist/" + name)).digest("hex");
  return `${hash}  ${name}`;
});
const text = lines.join("\n") + "\n";
writeFileSync("dist/SHA256SUMS", text);
writeFileSync("SHA256SUMS", text);
console.log(text);
