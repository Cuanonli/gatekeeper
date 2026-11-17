// Shared Proof Gatekeeper core — used by the local stdlib server (server.mjs)
// and the Vercel serverless function (api/agent.js). Transport-agnostic:
// the caller supplies the raw body + HMAC secret handling and signs replies.
//
// Protocol (from https://agentgames.zkverify.io/build, /rules, /guide,
// /events/proof-gatekeeper, /api/circuit-info):
//  - POST, HMAC-SHA256 hex in x-agent-games-signature over the RAW body,
//    verified BEFORE parsing. Every response is signed the same way.
//  - Preflight {"type":"agent-games.preflight.v1"} -> {"ok":true,"protocolVersion":"v1"}.
//  - Gatekeeper task {"type":"agent-games.proof-gatekeeper.v1", task_id, mode,
//    input:{registered_vk, proof_vk, minimum, public_balance, expiry_block,
//    current_block, recipient, condition_recipient, amount, max_transfer, proof_tx}}:
//    APPROVE only if every check passes; otherwise REJECT with the reason code.
//    A Groth16 proof (snarkjs, gatekeeper.wasm/.zkey) is generated locally for
//    every provable decision and returned as proof + public_signals.
//    PROOF_REUSED tasks carry no proof (platform excludes them from the proof
//    requirement) and are detected via a persistent local seen-set.
//  - Fail closed: any error/timeout/uncertainty -> REJECT UNCERTAIN, never crash.
//
// Circuit (GatekeeperEvaluation, Groth16/BN128, Circom 2.x), 13 inputs:
//   taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
//   salt (private nonce), decision (1=approve, 0=reject).
// The circuit enforces: decision == verdict (approve iff all checks pass).
// Public signals (13): [Poseidon(salt,taskId), registeredVkHash, proofVkHash,
//   minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, decision, taskId].
// vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0.
//
// Secrets: AGENT_GAMES_HMAC_SECRET (from dashboard "Rotate Secret") and
// KURIER_API_KEY come from the environment only. Never commit .env.
// The salt is generated fresh per proof and never logged.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";

const KURIER_URL = "https://api.kurier.xyz/api/v1";
// bn128 scalar field prime (for the taskId hash fallback only)
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const REASONS = {
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  PROOF_REUSED: "PROOF_REUSED",
  UNCERTAIN: "UNCERTAIN",
};

// Circuit artifacts can be fetched at runtime from the competition's own
// public artifact host when they are not bundled (Vercel deploys ship only
// the small vk.json; the 1.7 MB wasm + 304 KB zkey are too large to push
// through the deployment API's argument channel). Downloads are verified
// against the SHA-256 of the official files and cached in /tmp.
const ARTIFACT_BASE_URL = "https://agentgames.zkverify.io/circuits";
const ARTIFACT_SHA256 = {
  "gatekeeper.wasm": "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
  "gatekeeper_final.zkey": "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
};
const ARTIFACT_TMP_DIR = "/tmp/gatekeeper-artifacts";

// ------------------------------------------------------- artifact paths ---
// Only vk.json is needed synchronously (read at core creation); the wasm
// and zkey are resolved lazily (bundled when present, otherwise downloaded).
export function resolveArtifactDir() {
  const here = path.dirname(fileURLToPath(import.meta.url)); // .../lib
  const candidates = [
    path.join(here, "..", "artifacts"),
    path.join(process.cwd(), "artifacts"),
  ];
  for (const dir of candidates) {
    if (existsSync(path.join(dir, "vk.json"))) {
      return dir;
    }
  }
  return candidates[0];
}

// ------------------------------------------------------------- seen-set ---
// proof_tx (lowercased) -> { task_id, decision, reason_code, at }
// A proof_tx seen under a DIFFERENT task_id is a reuse. A retry of the same
// task_id is idempotent and is processed normally.
// Store interface: { load() -> object, save(obj) -> void } — save must never
// throw (serverless filesystems are read-only outside /tmp).

// File-backed store for the local server (atomic rename, persistent).
export function fileSeenStore(dataDir) {
  const seenPath = path.join(dataDir, "seen-proof-tx.json");
  return {
    load() {
      try {
        if (existsSync(seenPath)) return JSON.parse(readFileSync(seenPath, "utf8"));
      } catch { /* corrupted file -> start fresh, but keep going */ }
      return {};
    },
    save(seen) {
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(seenPath + ".tmp", JSON.stringify(seen));
      renameSync(seenPath + ".tmp", seenPath);
    },
  };
}

// In-memory store for serverless (stateless): best-effort /tmp persistence
// so a warm instance reuses what it saw; a cold instance starts fresh.
// PROOF_REUSED detection is therefore best-effort on Vercel — the platform
// retries a task_id idempotently, and the platform itself tracks reuse.
export function memorySeenStore() {
  let seen = {};
  let tmpLoaded = false;
  const tmpPath = "/tmp/seen-proof-tx.json";
  return {
    load() {
      if (!tmpLoaded) {
        tmpLoaded = true;
        try {
          if (existsSync(tmpPath)) seen = JSON.parse(readFileSync(tmpPath, "utf8"));
        } catch { /* ignore */ }
      }
      return seen;
    },
    save(next) {
      seen = next;
      try { writeFileSync(tmpPath, JSON.stringify(next)); } catch { /* ignore */ }
    },
  };
}

// ------------------------------------------------------------------ core --
export function createCore({ hmacSecret, kurierApiKey = "", seenStore, artifactDir }) {
  const dir = artifactDir || resolveArtifactDir();
  const VK_PATH = path.join(dir, "vk.json");
  const VK = JSON.parse(readFileSync(VK_PATH, "utf8"));

  // wasm/zkey: bundled when present, otherwise downloaded once from the
  // competition's public artifact host (SHA-256 verified) into /tmp.
  // Resolved lazily so a missing bundle never breaks startup; a failed
  // download fails the task closed (REJECT UNCERTAIN) via the caller's
  // try/catch, and the next task retries the download.
  let wasmPath = path.join(dir, "gatekeeper.wasm");
  let zkeyPath = path.join(dir, "gatekeeper_final.zkey");
  let artifactsReady = null;

  async function downloadArtifact(name) {
    const expected = ARTIFACT_SHA256[name];
    const dest = path.join(ARTIFACT_TMP_DIR, name);
    if (existsSync(dest)) {
      const h = createHash("sha256").update(readFileSync(dest)).digest("hex");
      if (h === expected) return dest;
      console.log(`[artifacts] cached ${name} hash mismatch, re-downloading`);
    }
    mkdirSync(ARTIFACT_TMP_DIR, { recursive: true });
    let lastErr = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 5000);
        const res = await fetch(`${ARTIFACT_BASE_URL}/${name}`, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const buf = Buffer.from(await res.arrayBuffer());
        const h = createHash("sha256").update(buf).digest("hex");
        if (h !== expected) throw new Error("SHA-256 mismatch");
        writeFileSync(dest + ".tmp", buf);
        renameSync(dest + ".tmp", dest);
        console.log(`[artifacts] downloaded ${name} (${buf.length} bytes, sha256 ok)`);
        return dest;
      } catch (e) {
        lastErr = e;
        console.log(`[artifacts] download ${name} attempt ${attempt} failed: ${String(e).slice(0, 120)}`);
      }
    }
    throw lastErr || new Error(`download failed: ${name}`);
  }

  function ensureArtifacts() {
    if (artifactsReady) return artifactsReady;
    artifactsReady = (async () => {
      if (existsSync(wasmPath) && existsSync(zkeyPath)) {
        return { wasmPath, zkeyPath };
      }
      const w = await downloadArtifact("gatekeeper.wasm");
      const z = await downloadArtifact("gatekeeper_final.zkey");
      wasmPath = w;
      zkeyPath = z;
      return { wasmPath, zkeyPath };
    })().catch((e) => { artifactsReady = null; throw e; });
    return artifactsReady;
  }

  function hmacHex(rawBody) {
    return createHmac("sha256", hmacSecret).update(rawBody).digest("hex");
  }

  function verifyHmac(rawBody, header) {
    if (!header || typeof header !== "string") return false;
    const expected = hmacHex(rawBody);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(header.trim().toLowerCase(), "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  function submitToKurier(proof, publicSignals, registeredVkHash) {
    if (!kurierApiKey) return;
    // Fire-and-forget: never blocks the task response. On serverless the
    // fetch may be cut off when the instance freezes — best-effort only.
    fetch(`${KURIER_URL}/submit-proof/${kurierApiKey}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: registeredVkHash },
      }),
    })
      .then(async (r) => {
        const body = await r.text().catch(() => "");
        console.log(`[kurier] status=${r.status} body=${body.slice(0, 200)}`);
      })
      .catch((e) => console.log(`[kurier] submit failed: ${String(e).slice(0, 200)}`));
  }

  function toBig(v) {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") return BigInt(v);
    const s = String(v).trim();
    return BigInt(s);
  }

  function taskIdToField(taskId) {
    const m = String(taskId).match(/\d+/);
    if (m) return BigInt(m[0]);
    // Fallback: deterministic hash of the id (should not happen for gk_<n>_* ids).
    const h = createHash("sha256").update(String(taskId)).digest("hex");
    return BigInt("0x" + h) % FIELD_P;
  }

  // Returns { decision: "APPROVE"|"REJECT", reason_code, reused: boolean }.
  // Pure deterministic checks, no I/O except the seen-set.
  function decide(task) {
    const input = task.input || {};
    const proofTx = typeof input.proof_tx === "string" ? input.proof_tx.toLowerCase() : "";
    const seen = seenStore.load();

    // 1. Proof reuse (different task, same proof reference).
    if (proofTx && seen[proofTx] && seen[proofTx].task_id !== task.task_id) {
      return { decision: "REJECT", reason_code: REASONS.PROOF_REUSED, reused: true, proofTx };
    }

    let reason = null;
    try {
      const registeredVk = toBig(input.registered_vk);
      const proofVk = toBig(input.proof_vk);
      const minimum = toBig(input.minimum);
      const publicBalance = toBig(input.public_balance);
      const expiryBlock = toBig(input.expiry_block);
      const currentBlock = toBig(input.current_block);
      const recipient = toBig(input.recipient);
      const conditionRecipient = toBig(input.condition_recipient);
      const amount = toBig(input.amount);
      const maxTransfer = toBig(input.max_transfer);

      if (proofVk !== registeredVk) reason = REASONS.VK_SUBSTITUTION;
      else if (publicBalance < minimum) reason = REASONS.THRESHOLD_MISMATCH;
      else if (currentBlock > expiryBlock) reason = REASONS.EXPIRED_CONDITION;
      else if (recipient !== conditionRecipient) reason = REASONS.RECIPIENT_MISMATCH;
      else if (amount > maxTransfer) reason = REASONS.AMOUNT_OVERFLOW;
    } catch {
      return { decision: "REJECT", reason_code: REASONS.UNCERTAIN, reused: false, proofTx };
    }

    const result = reason
      ? { decision: "REJECT", reason_code: reason, reused: false, proofTx }
      : { decision: "APPROVE", reason_code: "VALID_CONDITION", reused: false, proofTx };

    // Record the proof reference as seen (first-seen task wins).
    if (proofTx && !seen[proofTx]) {
      seen[proofTx] = { task_id: task.task_id, decision: result.decision, reason_code: result.reason_code, at: new Date().toISOString() };
      try { seenStore.save(seen); } catch (e) { console.log(`[seen] save failed: ${String(e).slice(0, 120)}`); }
    }
    return result;
  }

  function buildCircuitInput(task, decisionBit) {
    const input = task.input || {};
    let salt;
    do { salt = BigInt("0x" + randomBytes(31).toString("hex")); } while (salt === 0n);
    return {
      taskId: taskIdToField(task.task_id),
      minimum: toBig(input.minimum),
      publicBalance: toBig(input.public_balance),
      expiryBlock: toBig(input.expiry_block),
      currentBlock: toBig(input.current_block),
      recipient: toBig(input.recipient),
      conditionRecipient: toBig(input.condition_recipient),
      amount: toBig(input.amount),
      maxTransfer: toBig(input.max_transfer),
      registeredVkHash: toBig(input.registered_vk),
      proofVkHash: toBig(input.proof_vk),
      salt,
      decision: decisionBit,
    };
  }

  async function handleGatekeeper(task) {
    const t0 = Date.now();
    const decided = decide(task);
    if (decided.reused) {
      console.log(`[task ${task.task_id}] REJECT PROOF_REUSED (${Date.now() - t0}ms, no proof)`);
      const out = { decision: "REJECT", reason_code: REASONS.PROOF_REUSED };
      if (decided.proofTx) out.proof_tx = decided.proofTx;
      return out;
    }

    const decisionBit = decided.decision === "APPROVE" ? 1n : 0n;
    let proof = null;
    let publicSignals = null;
    try {
      const circuitInput = buildCircuitInput(task, decisionBit);
      const { wasmPath: wp, zkeyPath: zp } = await ensureArtifacts();
      const res = await snarkjs.groth16.fullProve(circuitInput, wp, zp);
      proof = res.proof;
      publicSignals = res.publicSignals;
      const ok = await snarkjs.groth16.verify(VK, publicSignals, proof).catch(() => false);
      if (!ok) console.log(`[task ${task.task_id}] WARNING: local proof verify returned false`);
    } catch (e) {
      // Circuit refused the decision (assert line 102) or proving failed:
      // fail closed. This should not happen when the verdict matches the
      // circuit's own rule; log it loudly.
      console.log(`[task ${task.task_id}] proof generation failed: ${String(e).slice(0, 200)}`);
      const out = { decision: "REJECT", reason_code: REASONS.UNCERTAIN };
      if (decided.proofTx) out.proof_tx = decided.proofTx;
      console.log(`[task ${task.task_id}] REJECT UNCERTAIN (${Date.now() - t0}ms)`);
      return out;
    }

    const out = { decision: decided.decision, reason_code: decided.reason_code, proof, public_signals: publicSignals };
    if (decided.proofTx) out.proof_tx = decided.proofTx;
    console.log(`[task ${task.task_id}] ${decided.decision} ${decided.reason_code} (${Date.now() - t0}ms, proof ok)`);
    submitToKurier(proof, publicSignals, task.input?.registered_vk);
    return out;
  }

  // Handles a parsed envelope. Returns the response object (always HTTP 200
  // at the transport layer for known/unknown types; auth/JSON errors are the
  // transport's job). Never throws for a well-formed envelope.
  async function handleEnvelope(env) {
    if (env.type === "agent-games.preflight.v1") {
      console.log(`[preflight ${env.agent_id || "?"}] ok`);
      return { ok: true, protocolVersion: "v1" };
    }
    if (env.type === "agent-games.proof-gatekeeper.v1") {
      return handleGatekeeper(env);
    }
    return { error: "unknown type" };
  }

  return { hmacHex, verifyHmac, decide, handleGatekeeper, handleEnvelope, REASONS };
}
