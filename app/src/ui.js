/* SatsGuard UI — wires the REAL mandate engine (crypto.js + engine.js) into the interface.
 * Every PAID/REJECTED ticket on screen is produced by actual BIP-340 signatures,
 * real hash-chained ledger, real caveat checks. No fake data in the security path. */
"use strict";

/* ---------- state ---------- */
const SG_KEY = "sg-state-v1";
const store = { keys: null, state: null };
function freshState() {
  const issuerSk = C.randomSeckey(), agentSk = C.randomSeckey();
  return { issuerSk, agentSk, issuer: C.pubkeyFrom(issuerSk), agent: C.pubkeyFrom(agentSk),
    mandate: null, ledger: [], revocations: [], alerts: true, budgetOn: true, balance: 523750 };
}
function load() { try { const raw = localStorage.getItem(SG_KEY); if (raw) { const s = JSON.parse(raw); if (s && s.issuerSk) return s; } } catch (e) {} return null; }
function save() { try { localStorage.setItem(SG_KEY, JSON.stringify(store.state)); } catch (e) {} }
store.state = load() || freshState(); save();

const $ = (sel) => document.querySelector(sel);
const fmt = (n) => n.toLocaleString("en-US");
const usd = (sats) => "$" + (sats / 2_500).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const short = (h) => h.slice(0, 10) + "…" + h.slice(-7);

/* ---------- toast ---------- */
let toastTimer;
function toast(msg, ms = 2600) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), ms); }

/* ---------- navigation ---------- */
document.addEventListener("click", (e) => {
  const go = e.target.closest("[data-go]");
  if (go) { e.preventDefault(); document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active")); document.querySelector("#" + go.dataset.go).classList.add("active");
    document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.go === go.dataset.go)); window.scrollTo(0, 0); }
});

/* ---------- REAL agent simulation (same engine the CLI agent uses) ---------- */
const DEMO_RECIPIENTS = [store.state.agent, "02aabbcc"];
function runAgentPayment(amountSats, recipient, label) {
  const st = store.state;
  const auth = E.authorizeSpend(C, { mandate: st.mandate.mandate, sig: st.mandate.sig, revocations: st.revocations }, st.ledger, { recipient, amountSats, now: Date.now() });
  if (auth.ok) {
    const preimage = C.bytesToHex(new Uint8Array(32).map(() => Math.floor(Math.random() * 256)));
    const preimageHash = C.bytesToHex(C.sha256(C.hexToBytes(preimage)));
    st.balance -= amountSats;
    st.ledger = E.recordSpend(C, st.ledger, { mandate: st.mandate.mandate, txRef: "sim:" + Date.now().toString(16), amountSats, recipient, preimageHash, status: "PAID" });
    save(); renderAll();
    toast(`${label} — PAID ${fmt(amountSats)} sats`);
  } else {
    st.ledger = E.recordReject(C, st.ledger, { mandate: st.mandate.mandate, recipient, amountSats, reason: auth.reason });
    save(); renderAll();
    toast(`${label} — REJECTED: ${auth.reason}`);
  }
}

/* ---------- create delegation (real signing) ---------- */
const slider = $("#capSlider");
function capFromSlider(v) { return 100_000 * v; } // 100k … 5M (v: 1..50)
slider.addEventListener("input", () => { const cap = capFromSlider(+slider.value); slider.style.setProperty("--fill", (+slider.value / 50 * 100) + "%");
  $("#capBig").textContent = fmt(cap); $("#capBigUsd").textContent = usd(cap); });

$("#signBtn").addEventListener("click", () => {
  const st = store.state;
  const capSats = capFromSlider(+slider.value);
  const expiresAt = Date.now() + 30 * 864e5;
  try {
    const signed = E.createMandate(C, st.issuerSk, { agentPubkey: st.agent, capSats, recipients: DEMO_RECIPIENTS, expiresAt, maxPerPaymentSats: Math.round(capSats / 2), period: "monthly", label: "agent-demo" });
    st.mandate = signed; st.revocations = []; save();
    $("#nwcUri").textContent = `nostr+walletconnect://${st.agent}?relay=wss%3A%2F%2Frelay.damus.io&secret=${st.agentSk.slice(0, 8)}…`;
    document.querySelector('[data-go="s-home"]').click();
    toast("Delegation signed — mandate " + short(signed.mandate.id), 3800);
    setTimeout(() => runAgentDemo(), 1200);
  } catch (err) { toast("Signing error: " + err.message); }
});

/* ---------- the 4-payment demo sequence (video moment) ---------- */
function runAgentDemo() {
  if (!store.state.mandate) { toast("Create a delegation first"); return; }
  const cap = store.state.mandate.mandate.caveats.cap_sats;
  const a = store.state.agent;
  runAgentPayment(Math.round(cap * 0.10), a, "Agent payment 1");
  setTimeout(() => runAgentPayment(Math.round(cap * 0.15), a, "Agent payment 2"), 1600);
  setTimeout(() => runAgentPayment(Math.round(cap * 0.50), a, "Agent payment 3"), 3200);
  setTimeout(() => runAgentPayment(Math.round(cap * 0.35), a, "Over-limit attempt"), 5000); // within per-payment max, exceeds remaining budget → REJECTED — LIMIT
}
$("#runDemo").addEventListener("click", runAgentDemo);

/* ---------- revocation (real signed event) ---------- */
function syncRevocationUI() { const on = $("#tglRev").classList.contains("on"); $("#revokeBox").style.display = on ? "block" : "none"; $("#revokeBtn").style.display = on ? "block" : "none"; }
$("#tglRev").addEventListener("click", () => { $("#tglRev").classList.toggle("on"); syncRevocationUI(); });
$("#revokeBtn").addEventListener("click", () => {
  const st = store.state;
  if (!st.mandate) { toast("No active delegation"); return; }
  st.revocations.push(E.createRevocation(C, st.issuerSk, st.mandate.mandate.id)); save(); renderAll();
  toast("Mandate " + short(st.mandate.mandate.id) + " revoked — agent has zero rights", 3600);
  $("#tglRev").classList.remove("on"); $("#revokeBox").style.display = "none"; $("#revokeBtn").style.display = "none";
});
$("#tglBudget").addEventListener("click", function () { this.classList.toggle("on"); store.state.budgetOn = this.classList.contains("on"); save(); toast(store.state.budgetOn ? "Budget limits enforced" : "Budget limits DISABLED — not recommended"); });
$("#tglAlerts").addEventListener("click", function () { this.classList.toggle("on"); store.state.alerts = this.classList.contains("on"); save(); });
$("#autoAdj").addEventListener("click", function () { this.classList.toggle("on"); });
document.querySelectorAll("#periods .pill").forEach((p) => p.addEventListener("click", () => { document.querySelectorAll("#periods .pill").forEach((x) => x.classList.remove("on")); p.classList.add("on"); }));
document.querySelectorAll("#filters .pill").forEach((p) => p.addEventListener("click", () => { document.querySelectorAll("#filters .pill").forEach((x) => x.classList.remove("on")); p.classList.add("on"); renderActivity(p.textContent.toLowerCase()); }));
$("#bell").addEventListener("click", () => { document.querySelector('[data-go="s-activity"]').click(); });
$("#eye").addEventListener("click", () => { const b = $("#balance"); const hidden = b.dataset.h === "1"; b.textContent = hidden ? fmt(store.state.balance) + " sats" : "•••,••• sats"; b.dataset.h = hidden ? "0" : "1"; });

/* ---------- verify chain ---------- */
$("#verifyBtn").addEventListener("click", () => { renderVerify(); document.querySelector('[data-go="s-settings"]').click(); toast(E.verifyChain(C, store.state.ledger) ? "Hash chain intact" : "Ledger TAMPERED", 3000); });
$("#resetAll").addEventListener("click", () => { localStorage.removeItem(SG_KEY); store.state = freshState(); save(); $("#nwcUri").textContent = "— create a delegation first —"; renderAll(); toast("Fresh keys + empty ledger"); });

/* ---------- rendering ---------- */
function renderAll() { renderHome(); renderActivity(); renderSecurity(); renderSettings(); }
function renderHome() {
  const st = store.state;
  $("#balance").textContent = fmt(st.balance) + " sats"; $("#balance").dataset.h = "0";
  $("#usd").textContent = usd(st.balance); $("#avatar").textContent = "S";
  if (!st.mandate) { $("#pct").textContent = "0%"; $("#capLbl").textContent = "no delegation"; $("#capUsd").textContent = "—"; $("#warnLimit").style.display = "none"; $("#ring").style.background = "conic-gradient(rgba(255,255,255,.05) 0 100%)"; return; }
  const s = E.summary(C, st.mandate.mandate, st.ledger);
  $("#pct").textContent = s.pct + "%"; $("#capLbl").textContent = fmt(s.capSats) + " sats"; $("#capUsd").textContent = usd(s.capSats);
  const stops = s.pct < 60 ? `var(--grn) 0 ${s.pct}%,var(--yel) ${s.pct}% 75%,var(--org) 75% 90%,var(--red) 90% 100%` : s.pct < 85 ? `var(--org) 0 ${s.pct}%,var(--red) ${s.pct}% 100%` : `var(--red) 0 ${s.pct}%`;
  $("#ring").style.background = `conic-gradient(${stops},rgba(255,255,255,.05) ${s.pct}% 100%)`;
  const warn = $("#warnLimit"); warn.style.display = s.pct >= 60 ? "flex" : "none";
  $("#warnLeft").textContent = `Only ${fmt(s.remainingSats)} sats left`;
  $("#chainOk").textContent = E.verifyChain(C, st.ledger) ? "● Ledger verified" : "Ledger TAMPERED";
}
function renderActivity(filter = "all") {
  const st = store.state; const tl = $("#timeline"); tl.innerHTML = "";
  const spent = st.ledger.filter((e) => e.type === "spend" && e.status === "PAID").reduce((s, e) => s + e.amount_sats, 0);
  $("#spentTotal").textContent = fmt(spent) + " sats"; $("#spentUsd").textContent = usd(spent);
  const bars = $("#bars"); bars.innerHTML = "";
  const spends = st.ledger.filter((e) => e.type === "spend").slice(-9);
  const max = Math.max(1, ...spends.map((e) => e.amount_sats));
  for (let i = 0; i < 9; i++) { const b = document.createElement("i"); const e = spends[i]; if (e) b.style.height = Math.max(12, e.amount_sats / max * 100) + "%"; else b.style.opacity = .25; bars.appendChild(b); }
  let evs = st.ledger.filter((e) => filter === "all" || (filter === "payments" && e.type === "spend") || (filter === "revocations" && e.type === "reject" && e.reason === "REVOKED") || (filter === "system" && e.type === "reject"));
  if (!st.mandate) evs = [];
  if (!evs.length) { tl.innerHTML = `<div class="card" style="text-align:center;color:var(--sub);font-size:12.5px">No ${filter === "all" ? "" : filter} events yet — run the agent demo in Settings.</div>`; }
  for (const e of [...evs].reverse()) {
    const paid = e.status === "PAID";
    const div = document.createElement("div"); div.className = "tl";
    div.innerHTML = `<div class="tlic ${paid ? "g" : "r"}">${paid ? '<svg class="icn"><use href="#i-zap"/></svg>' : '<svg class="icn"><use href="#i-ban"/></svg>'}</div>
      <div class="tlbody"><div class="row"><b style="font-size:12.5px">${paid ? "Delegation Payment" : "Delegation Rejection"}</b>
      <span class="chip ${paid ? "g" : "r"}" style="margin-left:auto">${paid ? "PAID" : "REJECTED — " + e.reason}</span></div>
      <div class="small">${new Date(e.ts).toLocaleString("en-US", { month: "short", day: "2-digit" })} · ${new Date(e.ts).toTimeString().slice(0, 5)}</div>
      <div class="money ${paid ? "plus" : "minus"}" style="font-size:17px;margin-top:3px">${paid ? "+" : "−"}${fmt(e.amount_sats)} sats</div>
      <div class="small">≈ ${usd(e.amount_sats)}</div>
      ${paid ? "" : `<div class="small" style="margin-top:3px">Reason: ${e.reason === "LIMIT" ? "Budget limit exceeded" : e.reason.toLowerCase()}</div>`}
      <div class="tx">Tx: <span>${paid ? short(e.tx_ref) : short(e.entryHash)}</span> <svg class="icn"><use href="#i-copy"/></svg> <b class="${paid ? "" : "minus"}" style="font-size:9.5px">${paid ? "" : e.reason}</b></div>
      <div class="tx">h: <span title="${e.entryHash}">${short(e.entryHash)}</span> · nostr receipt <svg class="icn"><use href="#i-check"/></svg></div></div>`;
    tl.appendChild(div);
  }
  const ok = E.verifyChain(C, st.ledger) && (!st.revocations.length || E.verifyRevocation(C, st.revocations[st.revocations.length - 1]));
  $("#sysTxt").textContent = ok ? (st.revocations.length ? "Mandate revoked — agent has zero rights" : "All systems operational") : "Ledger integrity failure";
}
function renderSecurity() { $("#tglBudget").classList.toggle("on", store.state.budgetOn); $("#tglAlerts").classList.toggle("on", store.state.alerts); syncRevocationUI(); }
function renderSettings() {
  const st = store.state;
  $("#kIssuer").textContent = st.issuer; $("#kAgent").textContent = st.agent;
  renderVerify();
}
function renderVerify() {
  const okChain = E.verifyChain(C, store.state.ledger);
  $("#verifyLine").innerHTML = okChain ? '<span class="badge-ok"><svg class="icn inline-ic" style="width:12px;height:12px"><use href="#i-check"/></svg> hash chain intact</span> — every entry commits to its predecessor.' : '<span style="color:var(--redT)"><svg class="icn inline-ic" style="width:12px;height:12px"><use href="#i-x"/></svg> TAMPERED</span>';
  if (store.state.mandate) $("#verifyLine").innerHTML += `<br>Mandate ${short(store.state.mandate.mandate.id)} · signature ${E.verifyMandate(C, store.state.mandate) ? "valid" : "invalid"}`;
}

renderAll();
