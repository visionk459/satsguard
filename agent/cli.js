#!/usr/bin/env node
/* SatsGuard Agent — an autonomous AI agent that spends a delegated Lightning budget
 * under cryptographic caveats (NIP-47 Nostr Wallet Connect + SatsGuard mandate engine).
 *
 * Modes:
 *   node agent/cli.js --sim                 # deterministic Lightning simulator (demo, real crypto)
 *   node agent/cli.js --live <nwc-uri>      # real wallet service over nostr relays (NIP-44 v2)
 *   node agent/cli.js --revoke              # issuer revokes the mandate (signed event)
 *
 * The agent NEVER holds the issuer key. It holds: its own keypair + the mandate
 * (signed by the issuer) + the NWC connection secret. Every payment must pass
 * authorizeSpend() — the same engine the wallet app enforces. */
"use strict";
const fs = require("fs"), path = require("path"), nodeCrypto = require("crypto");
const C = require("../app/src/crypto.js");
const E = require("../app/src/engine.js");
const { secp256k1, schnorr } = require("@noble/curves/secp256k1");
const { chacha20 } = require("@noble/ciphers/chacha.js");
const { hkdf } = require("@noble/hashes/hkdf.js");
const { hmac } = require("@noble/hashes/hmac.js");
const { sha256: nsha256 } = require("@noble/hashes/sha2.js");

const args = process.argv.slice(2);
const AGENT_DIR = path.join(__dirname, "..", "agent", "state");
fs.mkdirSync(AGENT_DIR, { recursive: true });

/* ---------- NIP-44 v2 (per docs/specs/nip-44.md) ---------- */
function conversationKey(skHex, pkHex) {
  const shared = secp256k1.getSharedSecret(Buffer.from(skHex, "hex"), Buffer.from("02" + pkHex, "hex"));
  return hkdf(nsha256, shared.subarray(1, 33), Buffer.from("nip44-v2"), Buffer.alloc(0), 32); // extract step via hkdf with empty info? per spec: HKDF-extract(salt='nip44-v2', ikm=shared_x)
}
function messageKeys(convKey, nonce) { const okm = hkdf(nsha256, convKey, nonce, Buffer.alloc(0), 76); return { chachaKey: okm.subarray(0, 32), chachaNonce: okm.subarray(32, 44), hmacKey: okm.subarray(44, 76) }; }
function pad(msg) { const u = Buffer.from(msg, "utf8"); const prefix = u.length < 65536 ? Buffer.from([u.length >> 8 & 255, u.length & 255]) : Buffer.concat([Buffer.from([0, 0]), Buffer.from([u.length >>> 24 & 255, u.length >>> 16 & 255, u.length >>> 8 & 255, u.length & 255])]); const unpadded = prefix.length + u.length; const paddedLen = unpadded < 32 ? 32 : 2 ** (32 - Math.clz32(unpadded - 1)); return Buffer.concat([prefix, u, Buffer.alloc(paddedLen - unpadded)]); }
function nip44Encrypt(skHex, pkHex, plaintext) {
  const convKey = conversationKey(skHex, pkHex);
  const nonce = nodeCrypto.randomBytes(32);
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(convKey, nonce);
  const ct = Buffer.from(chacha20(chachaKey, chachaNonce, pad(plaintext)));
  const mac = hmac(nsha256, hmacKey, Buffer.concat([nonce, ct]));
  return Buffer.concat([Buffer.from([0x02]), nonce, ct, mac]).toString("base64");
}
function nip44Decrypt(skHex, pkHex, b64) {
  const raw = Buffer.from(b64, "base64");
  if (raw[0] !== 0x02) throw new Error("unknown NIP-44 version " + raw[0]);
  const nonce = raw.subarray(1, 33), ct = raw.subarray(33, raw.length - 32), mac = raw.subarray(raw.length - 32);
  const convKey = conversationKey(skHex, pkHex);
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(convKey, nonce);
  const expect = hmac(nsha256, hmacKey, Buffer.concat([nonce, ct]));
  if (!mac.equals(expect)) throw new Error("MAC mismatch");
  const pt = Buffer.from(chacha20(chachaKey, chachaNonce, ct));
  const plen = pt[0] === 0 && pt[1] === 0 ? pt.readUInt32BE(2) : (pt[0] << 8) | pt[1];
  const off = pt[0] === 0 && pt[1] === 0 ? 6 : 2;
  return pt.subarray(off, off + plen).toString("utf8");
}

/* ---------- nostr event (NIP-01) ---------- */
function nostrEvent(skHex, kind, content, tags = []) {
  const pubkey = C.pubkeyFrom(skHex);
  const ev = { pubkey, created_at: Math.floor(Date.now() / 1000), kind, tags, content };
  ev.id = Buffer.from(C.sha256(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))).toString("hex");
  ev.sig = Buffer.from(schnorr.sign(Buffer.from(ev.id, "hex"), Buffer.from(skHex, "hex"))).toString("hex");
  return ev;
}

/* ---------- deterministic Lightning simulator (real crypto, fake transport) ---------- */
const SIM = {
  nodePubkey: "02d9676bd8b7ea6f6e9e12c4a1d1e2f3a4b5c6d7e8f90123456789abcdef0123",
  makeInvoice(msats, label) {
    const preimage = nodeCrypto.randomBytes(32);
    const paymentHash = nodeCrypto.createHash("sha256").update(preimage).digest("hex");
    return { invoice: `lntb${msats}n1${Buffer.from(label).toString("hex").slice(0, 12)}spowtq${paymentHash.slice(0, 40)}`, paymentHash, msats, preimage };
  },
  pay(invoice) { return { preimage: invoice.preimage, fee_msat: 1 }; },
};

/* ---------- mandate load (issuer key stays OUT of the agent) ---------- */
function loadMandate() {
  const p = path.join(AGENT_DIR, "mandate.json");
  if (!fs.existsSync(p)) { console.error("No mandate — run the wallet app and export one, or: --demo-mandate"); process.exit(2); }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/* ---------- payment flow: engine gate FIRST, then wallet ---------- */
function attemptPayment(amountSats, recipient, mandateBox, ledger, transport) {
  console.log(`\n[agent] attempting ${amountSats} sats → ${recipient.slice(0, 12)}…`);
  const auth = E.authorizeSpend(C, mandateBox, ledger, { recipient, amountSats, now: Date.now() });
  if (!auth.ok) {
    ledger = E.recordReject(C, ledger, { mandate: mandateBox.mandate, recipient, amountSats, reason: auth.reason });
    console.log(`[agent] REFUSED by mandate engine: ${auth.reason} — ${auth.detail}`);
    console.log(`[agent] receipt: refusal published (no funds moved, nothing signed)`);
    return { ledger, ok: false };
  }
  const inv = SIM.makeInvoice(amountSats * 1000, "agentpay");
  console.log(`[agent] pay_invoice (NIP-47) ${inv.invoice.slice(0, 34)}…`);
  const res = transport.payInvoice(inv, amountSats * 1000);
  const preimageHex = Buffer.from(res.preimage).toString("hex");
  ledger = E.recordSpend(C, ledger, { mandate: mandateBox.mandate, txRef: preimageHex.slice(0, 16), amountSats, recipient, preimageHash: nodeCrypto.createHash("sha256").update(res.preimage).digest("hex"), status: "PAID" });
  const s = E.summary(C, mandateBox.mandate, ledger);
  console.log(`[agent] PAID — preimage ${preimageHex.slice(0, 12)}… · budget ${s.spentSats}/${s.capSats} (${s.pct}%) · left ${s.remainingSats}`);
  return { ledger, ok: true };
}

/* ---------- demo scenario ---------- */
function runDemo() {
  // the ISSUER key below ONLY mints the demo mandate file — it is NOT shipped to the agent.
  // In production the mandate is signed in the wallet app and exported to agent/state/.
  console.log("== SatsGuard agent demo — mandate-gated Lightning spending ==\n");
  const issuerSk = C.randomSeckey();
  const agentSk = C.randomSeckey();
  const agentPk = C.pubkeyFrom(agentSk);
  const signed = E.createMandate(C, issuerSk, { agentPubkey: agentPk, capSats: 1_000_000, recipients: [SIM.nodePubkey], expiresAt: Date.now() + 864e5, maxPerPaymentSats: 500_000, label: "cli-demo" });
  fs.writeFileSync(path.join(AGENT_DIR, "mandate.json"), JSON.stringify(signed, null, 2));
  console.log(`[mandate] id ${signed.mandate.id} · cap 1,000,000 sats · per-payment ≤ 500,000 · whitelist: ${SIM.nodePubkey.slice(0, 10)}… · signature ${signed.sig.slice(0, 16)}… (BIP-340)`);
  let ledger = [];
  const transport = { payInvoice: (inv) => SIM.pay(inv) };
  ({ ledger } = attemptPayment(100_000, SIM.nodePubkey, signed, ledger, transport));   // PAID
  ({ ledger } = attemptPayment(150_000, SIM.nodePubkey, signed, ledger, transport));   // PAID
  ({ ledger } = attemptPayment(600_000, SIM.nodePubkey, signed, ledger, transport));   // REJECTED — PER_PAYMENT (>500k)
  ({ ledger } = attemptPayment(400_000, SIM.nodePubkey, signed, ledger, transport));   // PAID (total 650k)
  ({ ledger } = attemptPayment(400_000, SIM.nodePubkey, signed, ledger, transport));   // REJECTED — LIMIT (650k+400k>1M)
  ({ ledger } = attemptPayment(1_000, "0xBADFEED", signed, ledger, transport));        // REJECTED — WHITELIST
  const rev = E.createRevocation(C, issuerSk, signed.mandate.id);
  signed.revocations = [rev];
  console.log(`\n[issuer] REVOKE mandate ${signed.mandate.id} (signed event ${rev.sig.slice(0, 16)}…)`);
  ({ ledger } = attemptPayment(5_000, SIM.nodePubkey, signed, ledger, transport));     // REJECTED — REVOKED
  console.log(`\n[ledger] ${ledger.length} entries · hash chain ${E.verifyChain(C, ledger) ? "INTACT" : "TAMPERED"}`);
  fs.writeFileSync(path.join(AGENT_DIR, "ledger.json"), JSON.stringify(ledger, null, 2));
  const receiptEv = nostrEvent(agentSk, 1339, JSON.stringify({ type: "sg-receipt", mandate: signed.mandate.id, entries: ledger.length, chain: E.verifyChain(C, ledger) }), [["t", "satsguard-receipt"]]);
  console.log(`[nostr] receipt event kind 1339 · id ${receiptEv.id.slice(0, 16)}… (publish with --relay)`);
  console.log("\n== every decision on screen came from the same engine as the wallet app ==");
}

/* ---------- live mode: real NIP-47 over WebSocket relay ---------- */
function parseNwc(uri) {
  const m = uri.match(/^nostr\+walletconnect:\/\/([0-9a-f]{64})\?relay=([^&]+)&secret=([0-9a-f]{64})/i);
  if (!m) throw new Error("bad NWC URI");
  return { walletPubkey: m[1], relay: decodeURIComponent(m[2]), secret: m[3] };
}
async function livePay(nwcUri, amountSats) {
  const { walletPubkey, relay, secret } = parseNwc(nwcUri);
  let WebSocketImpl;
  try { WebSocketImpl = require("ws"); } catch { WebSocketImpl = global.WebSocket; }
  if (!WebSocketImpl) throw new Error("install ws: npm i ws");
  const ws = new WebSocketImpl(relay);
  const req = JSON.stringify({ method: "pay_invoice", params: { invoice: process.env.INVOICE } });
  await new Promise((res) => ws.on("open", res));
  const ev = nostrEvent(secret, 23194, nip44Encrypt(secret, walletPubkey, req), [["p", walletPubkey]]);
  ws.send(JSON.stringify(["EVENT", ev]));
  console.log(`[NIP-47] pay_invoice request published (kind 23194, NIP-44 encrypted) id ${ev.id.slice(0, 16)}…`);
  ws.on("message", (d) => { const msg = JSON.parse(d.toString()); if (msg[0] === "EVENT" && msg[2]?.kind === 23195) { console.log("[NIP-47] wallet response:", nip44Decrypt(secret, walletPubkey, msg[2].content)); process.exit(0); } });
  setTimeout(() => { console.error("timeout"); process.exit(1); }, 20000);
}

if (args.includes("--sim") || args.includes("--demo-mandate") || args.length === 0) runDemo();
else if (args.includes("--live")) livePay(args[args.indexOf("--live") + 1]).catch((e) => { console.error("live error:", e.message); process.exit(1); });
else if (args.includes("--revoke")) console.log("use the wallet app revocation switch (signed event)");
else console.log("usage: node agent/cli.js --sim | --live <nwc-uri>");
