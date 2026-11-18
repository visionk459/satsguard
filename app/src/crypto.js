/* SatsGuard — minimal BIP-340 schnorr + sync sha256 (validated against official vectors)
 * Pure BigInt, zero dependencies — safe to inline in the PWA.
 * Conformance: bitcoin/bips bip-0340.mediawiki (downloaded in docs/specs/). */
"use strict";

/* ---------- hex helpers ---------- */
const hexToBytes = (h) => { if (h.length % 2) throw new Error("hex: odd length"); const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; };
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s) => new TextEncoder().encode(s);

/* ---------- sha256 (sync, compact, FIPS 180-4) ---------- */
function sha256(...chunks) {
  let data = chunks.reduce((acc, c) => { const u = c instanceof Uint8Array ? c : utf8(c); const n = new Uint8Array(acc.length + u.length); n.set(acc); n.set(u, acc.length); return n; }, new Uint8Array(0));
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const bitLen = data.length * 8;
  const k = (((55 - data.length) % 64) + 64) % 64; // zeros so len(data)+1+k ≡ 56 (mod 64)
  data = new Uint8Array([...data, 0x80, ...Array(k).fill(0), 0, 0, 0, 0, (bitLen >>> 24) & 255, (bitLen >>> 16) & 255, (bitLen >>> 8) & 255, bitLen & 255]);
  const w = new Int32Array(64);
  for (let off = 0; off < data.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = (data[off + 4 * i] << 24) | (data[off + 4 * i + 1] << 16) | (data[off + 4 * i + 2] << 8) | data[off + 4 * i + 3];
    for (let i = 16; i < 64; i++) { const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0; }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H = [H[0] + a | 0, H[1] + b | 0, H[2] + c | 0, H[3] + d | 0, H[4] + e | 0, H[5] + f | 0, H[6] + g | 0, H[7] + h | 0];
  }
  return new Uint8Array(H.flatMap((x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255]));
}

/* ---------- secp256k1 (affine, BigInt) ---------- */
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const mod = (a, m = P) => ((a % m) + m) % m;
const pow = (a, b, m = P) => { let r = 1n; a = mod(a, m); while (b > 0n) { if (b & 1n) r = r * a % m; a = a * a % m; b >>= 1n; } return r; };
const inv = (a, m = P) => pow(a, m - 2n, m); // p, n prime → Fermat
const ptAdd = (p1, p2) => {
  if (!p1) return p2; if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const lam = p1 === p2 ? mod(3n * x1 * x1) * inv(2n * y1) : mod(y2 - y1) * inv(mod(x2 - x1));
  const x3 = mod(lam * lam - x1 - x2), y3 = mod(lam * (x1 - x3) - y1);
  return [x3, y3];
};
const ptMul = (k, pt = [Gx, Gy]) => { let r = null, a = pt; while (k > 0n) { if (k & 1n) r = ptAdd(r, a); a = ptAdd(a, a); k >>= 1n; } return r; };
const liftX = (x) => { if (x >= P) return null; const c = mod(x * x % P * x + 7n); let y = pow(c, (P + 1n) / 4n); if (mod(y * y) !== c) return null; return [x, (y & 1n) === 0n ? y : P - y]; };

/* ---------- BIP-340 tagged hash ---------- */
const taggedHash = (tag, ...bytes) => { const t = sha256(utf8(tag)); return sha256(t, t, ...bytes); };
const b32 = (x) => hexToBytes(x.toString(16).padStart(64, "0"));

/* ---------- schnorr (BIP-340) ---------- */
function schnorrSign(msg32, seckeyHex, auxRand32) {
  const m = hexToBytes(msg32); const d0 = BigInt("0x" + seckeyHex);
  if (d0 === 0n || d0 >= N) throw new Error("invalid seckey");
  const Pd = ptMul(d0); if (!Pd) throw new Error("implied point at infinity");
  const [px, py] = Pd; const d = (py & 1n) === 0n ? d0 : N - d0;
  const aux = auxRand32 || crypto.getRandomValues(new Uint8Array(32));
  const t = d ^ BigInt("0x" + bytesToHex(taggedHash("BIP0340/aux", aux)));
  const rand = taggedHash("BIP0340/nonce", b32(t), b32(px), m);
  let k = BigInt("0x" + bytesToHex(rand)) % N; if (k === 0n) throw new Error("nonce zero");
  const R = ptMul(k); const [rx, ry] = R;
  const k_ = (ry & 1n) === 0n ? k : N - k;
  const e = BigInt("0x" + bytesToHex(taggedHash("BIP0340/challenge", b32(rx), b32(px), m))) % N;
  return bytesToHex(b32(rx)) + bytesToHex(b32(mod(k_ + e * d, N)));
}
function schnorrVerify(msg32OrBytes, sigHex, pubHex) {
  const m = msg32OrBytes instanceof Uint8Array ? msg32OrBytes : hexToBytes(msg32OrBytes);
  const sig = hexToBytes(sigHex), pub = hexToBytes(pubHex);
  if (sig.length !== 64 || pub.length !== 32) return false;
  const r = BigInt("0x" + bytesToHex(sig.slice(0, 32))), s = BigInt("0x" + bytesToHex(sig.slice(32)));
  if (r >= P || s >= N) return false;
  const Pt = liftX(BigInt("0x" + bytesToHex(pub))); if (!Pt) return false;
  const e = BigInt("0x" + bytesToHex(taggedHash("BIP0340/challenge", b32(r), b32(Pt[0]), m))) % N;
  const R = ptAdd(ptMul(s), ptMul(N - e, Pt)); if (!R) return false;
  return R[0] === r && (R[1] & 1n) === 0n; // BIP-340: x(R)==r AND has_even_y(R)
}
/* pubkey derivation (x-only, BIP-340) */
const pubkeyFrom = (seckeyHex) => bytesToHex(b32(ptMul(BigInt("0x" + seckeyHex))[0]));
/* keygen */
const randomSeckey = () => { const a = crypto.getRandomValues(new Uint8Array(32)); const h = bytesToHex(a); return BigInt("0x" + h) >= N || BigInt("0x" + h) === 0n ? randomSeckey() : h; };

if (typeof module !== "undefined") module.exports = { sha256, schnorrSign, schnorrVerify, pubkeyFrom, randomSeckey, taggedHash, hexToBytes, bytesToHex, utf8 };
