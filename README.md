# ECDH-based Secure Chat using Web Crypto API

| | |
|---|---|
| **Name** | Sheetal Gupta |
| **Roll No.** | 23ESKCS802 |
| **Class / Batch** | [your batch, e.g. CS-D-G1] |
| **Project Code** | CSL-G10 |
| **Course** | Cyber Security Lab (7CS4-22), B.Tech VII Semester, SKIT Jaipur |
| **Linked syllabus experiment** | Exp 2 - Diffie-Hellman Key Exchange |

## About

A browser chat in which two peers (Alice and Bob) derive a shared key with
**ECDH (curve P-256)** and encrypt every message with **AES-256-GCM**, using only the
built-in Web Crypto API. No external libraries are used.

How it works:

1. Each peer generates an ephemeral ECDH key pair.
2. Only the public keys are exchanged.
3. Both peers compute the same shared secret, which goes through HKDF-SHA-256 to give an AES-256 key.
4. Each message is encrypted with a fresh random 96-bit IV. The AES-GCM tag detects tampering.

## Files

| File | Purpose |
|---|---|
| `index.html` | The chat application (interface, crypto functions, handshake) |
| `tests.mjs` | Automated test suite (11 test cases, includes a man-in-the-middle demo) |
| `README.md` | This file |

## Requirements

- A modern browser (Chrome, Edge, Firefox or Safari) to run the chat.
- Node.js 20 or newer, only if you want to run the tests.
- No installation, build step or `npm install` is needed.

## How to run the chat

1. Download or clone this repository.
2. Double-click `index.html` to open it in a browser.
   (Web Crypto works on `file://` in most browsers. If your browser blocks it, run
   `python -m http.server 8000` in this folder and open `http://localhost:8000`.)
3. Click **Generate keys and exchange**.
4. Both peers now show the same **Shared key ID**. The key itself is never sent.
5. Type a message as Alice or Bob. The panel **"What an eavesdropper sees"** shows only
   public keys, IVs and ciphertext.
6. Tick **Tamper with next ciphertext** and send a message to see AES-GCM reject it.

## How to run the tests

```
node tests.mjs
```

Expected result: 11 tests pass (`11 passed, 0 failed`).

## Ethical note

All messages are dummy test data. The man-in-the-middle demonstration runs inside the
test script on key pairs it creates itself. No external system or network was targeted.
