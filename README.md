# Solfray encryption

This is the public lock for Solfray. It is MIT licensed and not yet audited.

The package `@solfray/e2e` is the envelope, the key derivation, and the vault blob. `dist/` is the static key vault. Solfray serves that build at `https://keys.solfray.com` and shows the `vault.js` SHA-256 on the Keyring page. Rebuild `dist/` and compare it with `SHA256SUMS` and with that page. A live vault whose hash differs is not this source.

Publishing this repo does not prove the Solfray website is honest. The site can still ask the vault to unlock the message on screen. The vault does not hand over the seed or the 12 words.

## Deploy keys.solfray.com

This hostname is its own static-assets Worker, `solfray-keys`, defined in `wrangler.jsonc`. It has no script. It is not part of `solfray-web` or the main Solfray Worker.

1. Run `deploy.bat`. It typechecks, runs the self-test, rebuilds `dist/`, refuses if the rebuild differs from the commit, then runs `wrangler deploy`. `dist/_headers` sets the CSP and the other headers.
2. In the dashboard, open Workers & Pages, then `solfray-keys`, then Settings, then Domains & Routes. Add the custom domain `keys.solfray.com`. Cloudflare writes the DNS record and the certificate.
3. On the same screen, disable the `workers.dev` route so only `keys.solfray.com` serves the vault.
4. Do not add `keys.solfray.com` to the `solfray-web` project. Do not route that hostname through the main Solfray Worker.

The vault is a static page. It does not call the Solfray API and it must not see the login cookie. Deploy this project before the website that frames it, or the site will show that the vault did not answer. There is no fallback that keeps the seed on `solfray.com`.

To rebuild instead of publishing the committed `dist/`:

```sh
npm ci
npm run build:vault
```

`npm test` runs the crypto self-test. `npm run typecheck` checks the package and the vault page.

## What stays in the vault

The page accepts `postMessage` only from `https://solfray.com`, and the site accepts replies only from `https://keys.solfray.com`.

The frame holds the seed, the 12 words, and the unwrapped chat keys. Phrase entry, the paper quiz, and the one-time device-link code are drawn inside the frame. IndexedDB on this origin stores the seed under a non-extractable AES key when the person leaves the key unlocked.

The parent receives public keys, sigils, wrapped epoch keys, envelopes, and the plaintext of messages it asked to open. It does not receive the seed or the 12 words.

## Envelope

A locked message is the string `e2e1:` plus base64url of JSON:

```json
{ "v": 1, "e": 1, "a": "<author wallet>", "n": "<nonce>", "c": "<ciphertext>", "s": "<signature>" }
```

`n`, `c`, and `s` are base64url. The nonce is 24 bytes. The signature is 64 bytes. Plaintext inside `c` is JSON `{ "text", "mentions"?, "reply_to"? }` encrypted with XChaCha20-Poly1305. Associated data is UTF-8 `solfray-e2e-v1|<room>|<epoch>|<author wallet>`. The signature covers that associated data, then the nonce, then the ciphertext, and it is an Ed25519 signature from the author's encryption key.

The account key is 16 bytes, shown as 12 BIP-39 words. HKDF-SHA256 with an empty salt derives the X25519 key (`solfray-x25519-v1`) and the Ed25519 key (`solfray-ed25519-v1`).

Pictures use the bytes `SF2E`, version `0x01`, a 24-byte nonce, and ciphertext. Associated data is `solfray-e2e-img-v1|<room>|<epoch>`.

Epoch wraps and the vault blob are documented in `src/box.ts` and `src/vault.ts`. A third-party client can implement this format. Solfray does not ship that client.
