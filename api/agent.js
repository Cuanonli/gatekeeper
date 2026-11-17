// Proof Gatekeeper agent — Vercel serverless entry.
// Same shared core as the local server (lib/gatekeeper.mjs), exposed as
// POST /api/agent. Register exactly https://<deployment>/api/agent in the
// Agent Games dashboard, then run the preflight from the dashboard.
//
// Vercel specifics:
//  - bodyParser is OFF: the raw request stream is read so HMAC verification
//    over the raw body matches what the platform signed.
//  - Hobby plan maxDuration is 10s, so the fail-closed guard fires at 8s
//    (proof generation itself takes ~1ms; the guard is only a safety net).
//  - Only vk.json ships in the bundle; gatekeeper.wasm + gatekeeper_final.zkey
//    are downloaded once at cold start from the competition's public artifact
//    host (SHA-256 verified, cached in /tmp) — see lib/gatekeeper.mjs.
//  - Serverless is stateless: the proof-tx seen-set lives in memory with a
//    best-effort /tmp file, so PROOF_REUSED detection is best-effort here
//    (a cold instance starts fresh; same-task_id retries stay idempotent).
//  - Secrets come from Vercel env vars only (AGENT_GAMES_HMAC_SECRET,
//    optional KURIER_API_KEY). Never commit a real value.

import { createCore, memorySeenStore, resolveArtifactDir } from "../lib/gatekeeper.mjs";

export const config = { api: { bodyParser: false } };

const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";

const core = HMAC_SECRET
  ? createCore({
      hmacSecret: HMAC_SECRET,
      kurierApiKey: KURIER_API_KEY,
      seenStore: memorySeenStore(),
      artifactDir: resolveArtifactDir(),
    })
  : null;

if (!core) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set — set it in Vercel env vars and redeploy.");
}

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "gatekeeper", time: new Date().toISOString() }));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }
  if (!core) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "server misconfigured: AGENT_GAMES_HMAC_SECRET not set" }));
    return;
  }

  let raw;
  try {
    raw = await readRaw(req);
  } catch {
    try { res.writeHead(400); res.end(); } catch {}
    return;
  }

  const sendSigned = (status, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      "content-type": "application/json",
      "x-agent-games-signature": core.hmacHex(Buffer.from(body, "utf8")),
    });
    res.end(body);
  };

  if (!core.verifyHmac(raw, req.headers["x-agent-games-signature"])) {
    sendSigned(401, { error: "bad signature" });
    return;
  }

  let env;
  try {
    env = JSON.parse(raw.toString("utf8"));
  } catch {
    sendSigned(400, { error: "invalid json" });
    return;
  }

  // 8s safety net (Hobby maxDuration is 10s): fail closed, never hang.
  let responded = false;
  const timer = setTimeout(() => {
    if (responded) return;
    responded = true;
    try { sendSigned(200, { decision: "REJECT", reason_code: core.REASONS.UNCERTAIN }); } catch {}
    console.log(`[task ${env?.task_id || "?"}] TIMEOUT GUARD -> REJECT UNCERTAIN`);
  }, 8000);

  try {
    const out = await core.handleEnvelope(env);
    if (responded) return;
    responded = true;
    clearTimeout(timer);
    sendSigned(200, out);
  } catch (e) {
    console.log(`[task ${env?.task_id || "?"}] handler error: ${String(e).slice(0, 200)}`);
    if (responded) return;
    responded = true;
    clearTimeout(timer);
    try { sendSigned(200, { decision: "REJECT", reason_code: core.REASONS.UNCERTAIN }); } catch {}
  }
}
