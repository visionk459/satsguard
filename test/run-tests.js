/* SatsGuard conformance + property tests (plain node runner, zero test deps)
 * 1. sha256 vs node:crypto on random inputs
 * 2. BIP-340 official vectors (test-vectors.csv — bitcoin/bips) for sign AND verify
 * 3. Cross-check our schnorr against @noble/curves (audited reference)
 * 4. Engine invariants: property fuzz of authorizeSpend + hash-chain tamper detection
 * Run: node test/run-tests.js   (cwd = agentpay/) */
"use strict";
const fs = require("fs"), path = require("path"), nodeCrypto = require("crypto");
const C = require("../app/src/crypto.js");
const E = require("../app/src/engine.js");
const { schnorr: nobleSchnorr } = require("@noble/curves/secp256k1");

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) { pass++; console.log("  ✓", name); } else { fail++; console.log("  ✗ FAIL:", name); } };
const randHex = () => nodeCrypto.randomBytes(32).toString("hex");

/* ---- 1. sha256 ---- */
console.log("[1] sha256 conformance");
for (let i = 0; i < 200; i++) {
  const b = nodeCrypto.randomBytes(1 + (i % 130));
  ok(Buffer.from(C.sha256(b)).equals(nodeCrypto.createHash("sha256").update(b).digest()), `sha256 len=${b.length}`);
}

/* ---- 2. BIP-340 official vectors ---- */
console.log("[2] BIP-340 official vectors (bitcoin/bips test-vectors.csv)");
const rows = fs.readFileSync(path.join(__dirname, "bip340-vectors.csv"), "utf8").trim().split("\n").slice(1)
  .map((l) => l.split(","));
for (const [idx, sk, pk, aux, msg, sig, result] of rows) {
  const res = result.trim().toUpperCase() === "TRUE";
  ok(C.schnorrVerify(msg, sig, pk) === res, `verify vector ${idx} → ${result.trim()}`);
  if (sk && aux) ok(C.schnorrSign(msg, sk, Buffer.from(aux, "hex")) === sig.toLowerCase(), `sign vector ${idx} reproduces official signature`);
}

/* ---- 3. cross-check vs @noble/curves ---- */
console.log("[3] cross-check vs @noble/curves (audited reference)");
for (let i = 0; i < 50; i++) {
  const sk = randHex();
  const msg = nodeCrypto.randomBytes(32); // BIP-340 standard message size
  const aux = nodeCrypto.randomBytes(32); // same aux → deterministic comparison
  const mine = C.schnorrSign(Buffer.from(msg).toString("hex"), sk, aux);
  ok(nobleSchnorr.verify(mine, msg, C.pubkeyFrom(sk)), `noble verifies our sig #${i}`);
  const theirs = Buffer.from(nobleSchnorr.sign(msg, Buffer.from(sk, "hex"), aux)).toString("hex");
  ok(C.schnorrVerify(Buffer.from(msg).toString("hex"), theirs, C.pubkeyFrom(sk)), `we verify noble sig #${i}`);
  ok(theirs === mine, `byte-identical signatures #${i} (same aux)`);
}

/* ---- 4. engine invariants (seeded PRNG fuzz) ---- */
console.log("[4] mandate engine invariants");
let seed = 0x5a7c0ffee;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
const issuerSk = randHex(), agentPk = C.pubkeyFrom(randHex()), outsiderPk = C.pubkeyFrom(randHex());
const m = E.createMandate(C, issuerSk, { agentPubkey: agentPk, capSats: 100000, recipients: [agentPk, "02aabb"], expiresAt: Date.now() + 864e5, maxPerPaymentSats: 30000, label: "demo" });
ok(E.verifyMandate(C, m), "mandate signature verifies");
ok(!E.verifyMandate(C, { mandate: { ...m.mandate, cap_sats: 1, caveats: { ...m.mandate.caveats, cap_sats: 1 } }, sig: m.sig }), "tampered mandate rejected");
ok(E.verifyChain(C, []), "empty chain valid");

let ledger = [];
const now = Date.now();
let paidTotal = 0, rejected = { LIMIT: 0, PER_PAYMENT: 0, WHITELIST: 0 };
for (let i = 0; i < 500; i++) {
  const amount = 1 + Math.floor(rnd() * 40000);
  const recipient = rnd() < 0.6 ? agentPk : "02aabb"; // whitelisted
  const auth = E.authorizeSpend(C, m, ledger, { recipient, amountSats: amount, now });
  if (auth.ok) {
    paidTotal += amount;
    ledger = E.recordSpend(C, ledger, { mandate: m.mandate, txRef: "sim-tx-" + i, amountSats: amount, recipient, preimageHash: nodeCrypto.randomBytes(32).toString("hex"), now });
    const s = E.summary(C, m.mandate, ledger, now);
    if (s.spentSats > s.capSats) { ok(false, "CAP VIOLATION"); break; }
  } else {
    rejected[auth.reason] = (rejected[auth.reason] || 0) + 1;
    ledger = E.recordReject(C, ledger, { mandate: m.mandate, recipient, amountSats: amount, reason: auth.reason, now });
  }
}
const sum = E.summary(C, m.mandate, ledger, now);
ok(sum.spentSats <= 100000, `cap invariant holds after 500 fuzz spends (spent=${sum.spentSats}/${sum.capSats})`);
ok(E.verifyChain(C, ledger), "ledger chain intact after 500 ops");
ok(rejected.LIMIT > 0, `cap refusal observed (${rejected.LIMIT}×)`);
ok(E.authorizeSpend(C, m, ledger, { recipient: outsiderPk, amountSats: 1, now }).reason === "WHITELIST", "non-whitelisted recipient refused");
ok(E.authorizeSpend(C, m, ledger, { recipient: agentPk, amountSats: 1, now: now + 864e5 + 1000 }).reason === "EXPIRED", "expired mandate refused");

/* tamper detection */
const tampered = ledger.map((e, i) => i === 2 ? { ...e, amount_sats: e.amount_sats + 1 } : e);
ok(!E.verifyChain(C, tampered), "tampered ledger entry detected by chain re-walk");

/* revocation */
const rev = E.createRevocation(C, issuerSk, m.mandate.id);
ok(E.verifyRevocation(C, rev), "revocation event verifies");
ok(E.authorizeSpend(C, { ...m, revocations: [rev] }, ledger, { recipient: agentPk, amountSats: 1, now }).reason === "REVOKED", "spend refused after revocation");

/* per-payment ceiling */
const m2 = E.createMandate(C, issuerSk, { agentPubkey: agentPk, capSats: 1000000, recipients: [agentPk], expiresAt: Date.now() + 864e5, maxPerPaymentSats: 5000 });
ok(E.authorizeSpend(C, m2, [], { recipient: agentPk, amountSats: 5001, now }).reason === "PER_PAYMENT", "per-payment ceiling enforced");
ok(E.authorizeSpend(C, m2, [], { recipient: agentPk, amountSats: 5000, now }).ok === true, "payment at ceiling accepted");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
