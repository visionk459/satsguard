# SatsGuard — Your Bitcoin, Your Rules

**Delegated Lightning budgets for AI agents, enforced cryptographically.**
Give an AI agent a spending capability with hard caveats — a cap in sats, a recipient
whitelist, a per-payment ceiling, an expiry — and revoke it instantly with one signed
event. Every refusal is provable. Every payment leaves a signed receipt.

> Built for the **Dakar Bitcoin Hack by BTrust** (Oct 26 – Nov 20, 2026 · online · Africa)

**Try it now:** open the [live demo](https://visionk459.github.io/satsguard/) (single-file
PWA — loads on any phone) · or re-run everything locally:
`npm install && npm test && node agent/cli.js --sim`

---

## SatsGuard in plain words (60 seconds, no jargon)

You know how you can give a coworker a company card for one specific trip, with a
spending limit — and you can call the bank to cancel it if something looks wrong?
SatsGuard is that card, for AI agents, on Bitcoin.

1. **You pick a budget.** In the app you drag one slider — say 500,000 sats — and sign
   with your own key (stored on your phone, never shared). That signature *is* the
   agent's permission: max total, max per payment, who it may pay, until when.
2. **The agent pays by itself.** It doesn't hold your key and it can't touch the code
   that checks limits — every payment is checked *before* it is sent. Three payments go
   through, each one leaves a signed receipt anyone can verify on nostr.
3. **It cannot overspend — mathematically.** The fourth payment, over the limit, is
   refused before any network call happens. Not "we'll warn you": impossible.
4. **One tap kills everything.** Hit Revoke and the agent has zero rights, instantly —
   even if it's mid-purchase. The revocation is signed by you, so the agent can't fake
   or undo it.

No new blockchain, no token, no trusted third party: NIP-47 (Nostr Wallet Connect) does
the transport, BIP-340 schnorr signatures do the policing. It runs on a mid-range phone
on a slow connection, and the whole wallet is one 50 KB file.

---

## Why this exists (the pain, not the pitch)

People are starting to let AI agents act for them: paying invoices, buying services,
settling subscriptions. Today the only options are **"share your wallet and pray"** or
**"manually approve every micro-payment"** — both are broken. Sharing a wallet gives the
agent unlimited, invisible access; manual approval doesn't scale to 200-micropayment
workflows. There is no standard primitive for *delegated, bounded, revocable* Bitcoin
spending. SatsGuard is that primitive.

This is not hypothetical: BOLT12 recurring payments and x402-style machine-to-machine
payment protocols are arriving now, and every one of them needs a *limit layer* under the
wallet. SatsGuard ships that layer.

## What it is

| Component | What it does |
|---|---|
| **Wallet app** (`app/dist/index.html`) | Single-file PWA (50 KB, zero dependencies, works offline): create mandates, watch the budget gauge, read the receipt feed, hit the revocation switch |
| **Mandate engine** (`app/src/engine.js`) | Capability with Macaroon-style caveats + append-only hash-chained ledger + `authorizeSpend()` gate |
| **Crypto core** (`app/src/crypto.js`) | BIP-340 schnorr + SHA-256 in pure JS — validated byte-identical against the 19 official BIP-340 test vectors |
| **Agent CLI** (`agent/cli.js`) | NIP-47 (Nostr Wallet Connect) client: the agent pays via `pay_invoice`, NIP-44 v2 encrypted, only after the mandate engine approves |

## The one-command demo

```bash
npm install && node agent/cli.js --sim
```

Watch an agent try 6 payments and get stopped exactly where cryptography says stop:
`PAID → PAID → REFUSED (per-payment ceiling) → PAID → REFUSED (budget cap) →
REFUSED (whitelist) → issuer revokes → REFUSED (revoked)`.
Then open `app/dist/index.html` in a browser and press **Run agent demo** in Settings.

## Threat model (STRIDE) — and how each threat dies

| Threat | Attack | Defense |
|---|---|---|
| **Spoofing** | Impersonate the agent or issuer | Every mandate, revocation and receipt is BIP-340 signed; signatures verified against the x-only public key, conformance proven against official vectors |
| **Tampering** | Rewrite the ledger to hide a spend | Append-only hash chain (`entryHash = H(prevHash ‖ canonical(entry))`); re-walking the chain detects any mutation — demonstrated in the test suite |
| **Repudiation** | "The agent never paid me" | Signed receipt events (kind 1339) carry preimage hash + mandate id; refusals are logged too |
| **Information disclosure** | Leak spending patterns / keys | NIP-44 v2 encrypted transport (HKDF→ChaCha20→HMAC, per spec); issuer key never leaves the wallet device; the agent key alone authorizes nothing beyond caveats |
| **Denial of service** | Drain the budget with micro-spends | Per-payment ceiling + cumulative cap evaluated *before* any network call; failed attempts never reach the wallet |
| **Elevation of privilege** | Agent raises its own limits | Caveats are signed by the issuer; the agent has no signing power over the mandate; revocation is a separate issuer-signed event that overrides everything |

## Security architecture

1. **Least privilege by construction** — the agent receives a *capability*, never a key.
2. **Verify-then-send** — `authorizeSpend()` runs before any Lightning call; an over-limit
   attempt produces zero network traffic and zero signatures.
3. **Two-party control** — issuer signs caveats and revocations; the agent can only spend
   within them; the wallet service only executes engine-approved payments.
4. **Tamper-evident history** — hash-chained ledger, verified on every screen load.
5. **No secrets in the demo path** — the CLI demo mints a mandate only to *mint the file*;
   in production the mandate is signed in-browser and exported.

## Test evidence (run `node test/run-tests.js`)

- **390 assertions, 0 failures**, including:
  - 19/19 **official BIP-340 test vectors** — our signatures are *byte-identical* to the
    reference implementation's (sign + verify, incl. edge cases: even-y trap, negated s,
    non-curve keys, zero-tweaks)
  - **Cross-validated against `@noble/curves`** (audited reference): 50 random
    sign/verify round-trips, byte-identical with equal aux randomness
  - SHA-256: 200 randomized vectors vs `node:crypto`
  - Engine fuzz: 500 randomized spends — the cap invariant (`spent ≤ cap`) holds,
    whitelist/expiry/revocation/per-payment paths all exercised, tamper detection proven
- **Browser E2E** (`node test/e2e-pwa.js`, headless Chromium): 11/11 — mandate signing,
  3 PAID + 1 REJECTED—LIMIT, gauge update, revocation blocking all further spends,
  chain integrity, persistence across reload

## Design system (from the product mockup)

"Obsidian Orange": near-black `#0A0A12`, single Bitcoin-orange accent `#F7931A`,
success green reserved for PAID, red reserved for refusals, 8-pt grid, tabular numerals,
conic-gradient budget ring, perforated-receipt event cards, one-tap red revocation switch.
Built for low-bandwidth phones: one 50 KB file, no framework, no network calls required.

## Stack

Pure JavaScript (ES2020 BigInt), zero runtime dependencies in the app; the agent CLI uses
audited primitives only: `@noble/curves`, `@noble/ciphers`, `@noble/hashes`, `ws`.
Protocols: **BIP-340** (schnorr), **NIP-01** (events), **NIP-47** (Nostr Wallet Connect),
**NIP-44 v2** (encrypted payloads). Official specs are vendored in `docs/specs/`.

## Academic grounding

- Birgisson, Anagnostakis, Boneh, Mazières, Molnar, Nicolosi, **"Macaroons"** —
  capability-based credentials with caveats (Google, 2014). SatsGuard mandates are
  Macaroons with Lightning-native caveats (`cap_sats`, `recipients`, `expires_at`,
  `max_per_payment_sats`).
- Porsson et al. / BIP-340: Wuille, Nick, Todd, **"Schnorr signatures for secp256k1"**.
- STRIDE threat-modeling methodology (Kohnfelder & Garg, Microsoft).

## Roadmap

1. **Now (this repo)** — mandate engine, wallet PWA, NIP-47 agent, simulator transport.
2. **Next** — Mutinynet/signet integration for real Lightning payments; ERC-8004-style
   agent identity for multi-agent fleets; subscription caveats (recurring caps per period).
3. **Later** — third-party caveats (Macaroons §3.3): a merchant can add a refund caveat
   the issuer must co-sign; nostr-native receipt verification marketplace.

## Repo layout

```
app/index.template.html   UI shell (design system)
app/src/crypto.js         BIP-340 + SHA-256 (pure JS, vector-tested)
app/src/engine.js         mandates · caveats · hash chain · authorizeSpend
app/src/ui.js             app logic (real engine, no fake data)
app/dist/index.html       the built single-file PWA (ship this anywhere)
agent/cli.js              NIP-47 agent (sim transport + live mode)
test/run-tests.js         390 assertions (official vectors + fuzz)
test/e2e-pwa.js           headless-browser E2E (11 checks)
docs/specs/               vendored official specs (NIP-47, NIP-44, BIP-340 + vectors)
```

## License

MIT. Built in West Africa, for West Africa — Dakar Bitcoin Days spirit.
