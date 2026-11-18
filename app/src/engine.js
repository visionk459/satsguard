/* SatsGuard mandate engine — capability-based budget delegation for Lightning agents.
 * Model grounded in Birgisson et al., "Macaroons" (Google, 2014): a capability
 * carries CAVEATS (cap, whitelist, expiry, per-payment max) that the verifier
 * MUST re-check on every use. Revocation is an append-only public event.
 * Ledger integrity: append-only hash chain (each entry commits to its predecessor),
 * so any tampering with history is detectable by re-walking the chain.
 * Pure logic — crypto is injected (app/src/crypto.js or @noble in the agent CLI). */
"use strict";

const VERSION = 1;
const REASONS = { LIMIT: "LIMIT", PER_PAYMENT: "PER_PAYMENT", WHITELIST: "WHITELIST", EXPIRED: "EXPIRED", REVOKED: "REVOKED" };

/* canonical JSON: sorted keys, no whitespace — the bytes that get signed */
function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

function newId(rand32) { // 16 bytes → 32 hex chars
  const b = rand32.slice(0, 16);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/* create a signed mandate: the user (issuer) binds an agent to hard caveats */
function createMandate(crypto, issuerSk, opts) {
  const { agentPubkey, capSats, recipients, expiresAt, maxPerPaymentSats, period = "single", label = "" } = opts;
  if (!Number.isInteger(capSats) || capSats <= 0) throw new Error("capSats must be a positive integer");
  if (maxPerPaymentSats !== undefined && maxPerPaymentSats > capSats) throw new Error("maxPerPayment exceeds cap");
  if (!Array.isArray(recipients) || recipients.length === 0) throw new Error("whitelist required — mandate without recipients is invalid");
  if (!expiresAt || expiresAt <= Date.now()) throw new Error("expiresAt must be in the future");
  const mandate = {
    version: VERSION,
    id: newId(crypto.sha256(crypto.utf8(label + String(expiresAt) + crypto.bytesToHex(crypto.sha256(crypto.utf8(label + issuerSk)))))),
    issuer: crypto.pubkeyFrom(issuerSk),
    agent: agentPubkey,
    caveats: { cap_sats: capSats, recipients: [...recipients].sort(), expires_at: expiresAt, max_per_payment_sats: maxPerPaymentSats ?? capSats, period },
    created_at: Date.now(),
  };
  const msg = crypto.bytesToHex(crypto.sha256(crypto.utf8(canonicalize(mandate))));
  const sig = crypto.schnorrSign(msg, issuerSk);
  return { mandate, sig };
}

function verifyMandate(crypto, { mandate, sig }) {
  const msg = crypto.bytesToHex(crypto.sha256(crypto.utf8(canonicalize(mandate))));
  return crypto.schnorrVerify(msg, sig, mandate.issuer);
}

/* revocation: a signed, append-only event — no secret to erase, nothing to forget */
function createRevocation(crypto, issuerSk, mandateId) {
  const ev = { type: "sg-revoke", version: VERSION, mandate_id: mandateId, issuer: crypto.pubkeyFrom(issuerSk), revoked_at: Date.now() };
  const msg = crypto.bytesToHex(crypto.sha256(crypto.utf8(canonicalize(ev))));
  return { event: ev, sig: crypto.schnorrSign(msg, issuerSk) };
}

function verifyRevocation(crypto, { event, sig }) {
  const msg = crypto.bytesToHex(crypto.sha256(crypto.utf8(canonicalize(event))));
  return crypto.schnorrVerify(msg, sig, event.issuer);
}

/* ledger: append-only, hash-chained. entryHash = sha256(prevHash ‖ canonical(entry)) */
function genesisHash(crypto) { return crypto.bytesToHex(crypto.sha256(crypto.utf8("sg-genesis-v1"))); }
function chainHash(crypto, prevHash, entry) {
  return crypto.bytesToHex(crypto.sha256(crypto.utf8(prevHash + "|" + canonicalize(entry))));
}
function appendEntry(crypto, ledger, entry) {
  const prevHash = ledger.length ? ledger[ledger.length - 1].entryHash : genesisHash(crypto);
  const e = { ...entry, seq: ledger.length };
  return [...ledger, { ...e, entryHash: chainHash(crypto, prevHash, e) }];
}
/* re-walk the chain — returns false if history was tampered with */
function verifyChain(crypto, ledger) {
  let prev = genesisHash(crypto);
  for (let i = 0; i < ledger.length; i++) {
    const { entryHash, ...rest } = ledger[i];
    const { seq } = rest;
    if (seq !== i) return false;
    if (chainHash(crypto, prev, rest) !== entryHash) return false;
    prev = entryHash;
  }
  return true;
}

/* THE gate: authorize a spend against mandate caveats + ledger state.
 * Order matters: revoked → expired → whitelist → per-payment → cumulative cap. */
function authorizeSpend(crypto, { mandate, sig, revocations = [] }, ledger, { recipient, amountSats, now = Date.now() }) {
  if (!verifyMandate(crypto, { mandate, sig })) return { ok: false, reason: REASONS.REVOKED, detail: "mandate signature invalid" };
  if (revocations.some((r) => r.event.mandate_id === mandate.id && verifyRevocation(crypto, r))) return { ok: false, reason: REASONS.REVOKED, detail: "mandate revoked by issuer" };
  if (now >= mandate.caveats.expires_at) return { ok: false, reason: REASONS.EXPIRED, detail: "mandate expired at " + new Date(mandate.caveats.expires_at).toISOString() };
  if (!mandate.caveats.recipients.map((r) => r.toLowerCase()).includes(String(recipient).toLowerCase())) return { ok: false, reason: REASONS.WHITELIST, detail: "recipient not in issuer whitelist" };
  if (amountSats <= 0) return { ok: false, reason: REASONS.PER_PAYMENT, detail: "amount must be positive" };
  if (amountSats > mandate.caveats.max_per_payment_sats) return { ok: false, reason: REASONS.PER_PAYMENT, detail: `exceeds per-payment max (${mandate.caveats.max_per_payment_sats} sats)` };
  const spent = ledger.filter((e) => e.type === "spend" && e.mandate_id === mandate.id).reduce((s, e) => s + e.amount_sats, 0);
  if (spent + amountSats > mandate.caveats.cap_sats) return { ok: false, reason: REASONS.LIMIT, detail: `budget exceeded: ${spent} + ${amountSats} > cap ${mandate.caveats.cap_sats}`, spentSats: spent, remainingSats: Math.max(0, mandate.caveats.cap_sats - spent) };
  return { ok: true, spentSats: spent, remainingSats: mandate.caveats.cap_sats - spent - amountSats };
}

/* record a settled payment (or a refusal) into the ledger */
function recordSpend(crypto, ledger, { mandate, txRef, amountSats, recipient, preimageHash, status = "PAID", now = Date.now() }) {
  return appendEntry(crypto, ledger, { type: "spend", mandate_id: mandate.id, recipient, amount_sats: amountSats, status, tx_ref: txRef, preimage_hash: preimageHash, ts: now });
}
function recordReject(crypto, ledger, { mandate, recipient, amountSats, reason, now = Date.now() }) {
  return appendEntry(crypto, ledger, { type: "reject", mandate_id: mandate.id, recipient, amount_sats: amountSats, reason, ts: now });
}

function summary(crypto, mandate, ledger, now = Date.now()) {
  const spent = ledger.filter((e) => e.type === "spend" && e.mandate_id === mandate.id).reduce((s, e) => s + e.amount_sats, 0);
  const cap = mandate.caveats.cap_sats;
  return { capSats: cap, spentSats: spent, remainingSats: Math.max(0, cap - spent), pct: Math.min(100, Math.round((spent / cap) * 100)), expiresAt: mandate.caveats.expires_at, expired: now >= mandate.caveats.expires_at };
}

if (typeof module !== "undefined") module.exports = { VERSION, REASONS, canonicalize, createMandate, verifyMandate, createRevocation, verifyRevocation, genesisHash, chainHash, appendEntry, verifyChain, authorizeSpend, recordSpend, recordReject, summary };
