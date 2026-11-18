// Test suite for the crypto layer of the ECDH Secure Chat (run: node tests.mjs)
// The functions below are identical to those in index.html.
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder(), dec = new TextDecoder();
const toHex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const toB64 = b => Buffer.from(new Uint8Array(b)).toString("base64");
const fromB64 = s => new Uint8Array(Buffer.from(s, "base64"));

const generateKeyPair = () => subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
const exportPublic = k => subtle.exportKey("raw", k);
const importPublic = raw => subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
async function deriveSessionKey(priv, pub) {
  const secret = await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  const hk = await subtle.importKey("raw", secret, "HKDF", false, ["deriveKey", "deriveBits"]);
  const p = { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("ecdh-chat-v1") };
  const id = await subtle.deriveBits({ ...p, info: enc.encode("key-id") }, hk, 64);
  const aesKey = await subtle.deriveKey(p, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { aesKey, keyId: toHex(id) };
}
async function encrypt(k, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, k, enc.encode(text));
  return { iv: toB64(iv), ct: toB64(ct) };
}
const decrypt = async (k, p) => dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: fromB64(p.iv) }, k, fromB64(p.ct)));

let pass = 0, fail = 0;
const check = (id, name, ok, info = "") => { ok ? pass++ : fail++; console.log(`${ok ? "PASS" : "FAIL"}  ${id}  ${name}${info ? "  -> " + info : ""}`); };
const fails = async f => { try { await f(); return false; } catch { return true; } };

// Key setup
const A = await generateKeyPair(), B = await generateKeyPair(), E = await generateKeyPair();
const Apub = await exportPublic(A.publicKey), Bpub = await exportPublic(B.publicKey);
const sA = await deriveSessionKey(A.privateKey, await importPublic(Bpub));
const sB = await deriveSessionKey(B.privateKey, await importPublic(Apub));

check("T1", "Public key is a 65-byte uncompressed P-256 point (prefix 0x04)",
  Apub.byteLength === 65 && new Uint8Array(Apub)[0] === 4, `length=${Apub.byteLength}, prefix=0x0${new Uint8Array(Apub)[0]}`);
check("T2", "Private key is non-extractable", !A.privateKey.extractable, `extractable=${A.privateKey.extractable}`);
check("T3", "Alice and Bob derive the same session key", sA.keyId === sB.keyId, `key ID=${sA.keyId}`);

const msg = "Hello Bob, this is a secret message!";
const pkt = await encrypt(sA.aesKey, msg);
check("T4", "Bob decrypts Alice's message correctly", (await decrypt(sB.aesKey, pkt)) === msg, `ct length=${fromB64(pkt.ct).length} bytes (plaintext ${msg.length} + 16-byte tag)`);

const p1 = await encrypt(sA.aesKey, msg), p2 = await encrypt(sA.aesKey, msg);
check("T5", "Same plaintext gives different IV and ciphertext each time", p1.iv !== p2.iv && p1.ct !== p2.ct);

const t = fromB64(pkt.ct); t[0] ^= 1;
check("T6", "Bit-flipped ciphertext is rejected (GCM authentication)", await fails(() => decrypt(sB.aesKey, { iv: pkt.iv, ct: toB64(t) })));

const tag = fromB64(pkt.ct); tag[tag.length - 1] ^= 1;
check("T7", "Corrupted authentication tag is rejected", await fails(() => decrypt(sB.aesKey, { iv: pkt.iv, ct: toB64(tag) })));

const iv = fromB64(pkt.iv); iv[0] ^= 1;
check("T8", "Wrong IV is rejected", await fails(() => decrypt(sB.aesKey, { iv: toB64(iv), ct: pkt.ct })));

const sE = await deriveSessionKey(E.privateKey, await importPublic(Apub));
check("T9", "Eavesdropper Eve (own key pair) cannot decrypt", sE.keyId !== sA.keyId && await fails(() => decrypt(sE.aesKey, pkt)), `Eve key ID=${sE.keyId}`);

// MITM: Mallory replaces both public keys with her own
const M = await generateKeyPair(); const Mpub = await exportPublic(M.publicKey);
const aliceKey = await deriveSessionKey(A.privateKey, await importPublic(Mpub));   // Alice thinks Mpub is Bob's
const bobKey = await deriveSessionKey(B.privateKey, await importPublic(Mpub));     // Bob thinks Mpub is Alice's
const malA = await deriveSessionKey(M.privateKey, await importPublic(Apub));
const malB = await deriveSessionKey(M.privateKey, await importPublic(Bpub));
const mitmPkt = await encrypt(aliceKey.aesKey, "Transfer 500 to account X");
const read = await decrypt(malA.aesKey, mitmPkt);
check("T10", "MITM (unauthenticated ECDH): Mallory reads Alice's message", read === "Transfer 500 to account X" && aliceKey.keyId !== bobKey.keyId,
  `Alice-key=${aliceKey.keyId}, Bob-key=${bobKey.keyId} (differ, so a visible fingerprint mismatch exposes the attack)`);

// Performance
let t0 = performance.now();
for (let i = 0; i < 50; i++) { const a = await generateKeyPair(), b = await generateKeyPair();
  await deriveSessionKey(a.privateKey, await importPublic(await exportPublic(b.publicKey))); }
const hs = (performance.now() - t0) / 50;
t0 = performance.now();
for (let i = 0; i < 1000; i++) { const q = await encrypt(sA.aesKey, msg); await decrypt(sB.aesKey, q); }
const mt = (performance.now() - t0) / 1000;
check("T11", "Performance", true, `handshake (2 key pairs + derive) ~ ${hs.toFixed(2)} ms; encrypt+decrypt per message ~ ${mt.toFixed(3)} ms`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
