/* Build the SatsGuard single-file PWA: inject src modules into the HTML template.
 * Node gets module.exports; the browser gets window.C / window.E bindings. */
"use strict";
const fs = require("fs"), path = require("path");
const root = path.join(__dirname, "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");

const C_SRC = read("app/src/crypto.js"), E_SRC = read("app/src/engine.js"), UI_SRC = read("app/src/ui.js");
const TPL = read("app/index.template.html");

const cBindings = `window.C = { sha256, schnorrSign, schnorrVerify, pubkeyFrom, randomSeckey, taggedHash, hexToBytes, bytesToHex, utf8 };`;
const eBindings = `window.E = { VERSION, REASONS, canonicalize, createMandate, verifyMandate, createRevocation, verifyRevocation, genesisHash, chainHash, appendEntry, verifyChain, authorizeSpend, recordSpend, recordReject, summary };`;

const out = TPL
  .replace("/*__CRYPTO__*/", C_SRC.replace(/if \(typeof module[^\n]+\n/, "") + "\n" + cBindings)
  .replace("/*__ENGINE__*/", E_SRC.replace(/if \(typeof module[^\n]+\n/, "") + "\n" + eBindings)
  .replace("/*__UI__*/", UI_SRC);

if (/__CRYPTO__|__ENGINE__|__UI__/.test(out)) { console.error("INJECTION FAILED"); process.exit(1); }
fs.mkdirSync(path.join(root, "app/dist"), { recursive: true });
fs.writeFileSync(path.join(root, "app/dist/index.html"), out);
fs.mkdirSync("/home/z/my-project/download", { recursive: true });
fs.writeFileSync("/home/z/my-project/download/satsguard.html", out);
console.log("built app/dist/index.html + download/satsguard.html —", (out.length / 1024).toFixed(1), "KB");
