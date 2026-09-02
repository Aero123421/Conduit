import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const config = JSON.parse(readFileSync(resolve(root, "wrangler.jsonc"), "utf8"));
if (config.vars?.CLOUDFLARE_USAGE_PROFILE !== "free") throw new Error("deployment template must default to the Free usage profile");
if (JSON.stringify(config.triggers?.crons) !== JSON.stringify(["*/5 * * * *"])) throw new Error("Free backstop cron must run every five minutes");
if (config.observability?.logs?.head_sampling_rate > 0.25) throw new Error("Free log sampling exceeds 0.25");
if (config.observability?.traces?.head_sampling_rate > 0.01) throw new Error("Free trace sampling exceeds 0.01");
if (config.assets?.directory !== "./assets") throw new Error("Workers Static Assets directory is missing");
if (config.assets?.run_worker_first === true || Array.isArray(config.assets?.run_worker_first)) throw new Error("static assets must not invoke the Worker first");
for (const path of ["setup/index.html", "login/index.html", "device/index.html", "static/auth-browser.js", "static/device-enrollment.js", "_headers"]) readFileSync(resolve(root, "assets", path));
