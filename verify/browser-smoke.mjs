import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, extname } from "node:path";
import { chromium } from "playwright";

const root = dirname(fileURLToPath(import.meta.url));
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
};

const server = http.createServer(async (req, res) => {
  let path = decodeURIComponent(req.url.split("?")[0]);
  if (path === "/") path = "/policy-bundle-verifier.html";
  try {
    const data = await readFile(join(root, path.replace(/^\//, "")));
    res.writeHead(200, { "Content-Type": MIME[extname(path)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });
  const ok = await page.evaluate(() => {
    const v = window.KineGrantVerifier;
    if (!v || typeof v !== "object") return false;
    if (v.canonicalJson({ b: 1, a: 2 }) !== '{"a":2,"b":1}') return false;
    return typeof v.verifyPolicyBundle === "function";
  });
  if (!ok) {
    console.error("BROWSER VERIFIER SMOKE FAILED");
    process.exit(1);
  }
  console.log("BROWSER VERIFIER SMOKE PASSED");
} finally {
  await browser.close();
  server.close();
}
