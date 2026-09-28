/** Bytes helpers. No DOM, so the worker and the browser can both import this. */

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesToB64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64URL[(n >> 18) & 63];
    out += B64URL[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += B64URL[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += B64URL[n & 63];
  }
  return out;
}

export function b64urlToBytes(s: string): Uint8Array {
  if (typeof s !== "string" || s.length === 0 || /[^A-Za-z0-9\-_]/.test(s)) {
    throw new Error("bad_b64url");
  }
  // A valid base64url string is never 1 mod 4. Two leftover chars need two
  // zero pads; three leftover chars need one. 'A' is index 0, so the pad
  // bits stay zero and the length math drops them.
  if (s.length % 4 === 1) throw new Error("bad_b64url");
  const pad = (4 - (s.length % 4)) % 4;
  const src = s + "A".repeat(pad);
  // Padding chars we added are the index of 'A' (0), so the tail bits are zero.
  const outLen = Math.floor((s.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let o = 0;
  for (let i = 0; i < src.length; i += 4) {
    const n =
      (B64URL.indexOf(src[i]) << 18) |
      (B64URL.indexOf(src[i + 1]) << 12) |
      (B64URL.indexOf(src[i + 2]) << 6) |
      B64URL.indexOf(src[i + 3]);
    if (n < 0) throw new Error("bad_b64url");
    if (o < outLen) out[o++] = (n >> 16) & 255;
    if (o < outLen) out[o++] = (n >> 8) & 255;
    if (o < outLen) out[o++] = n & 255;
  }
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  // Standard base64, for wallet signatures the browser already produced.
  const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += std[(n >> 18) & 63] + std[(n >> 12) & 63];
    out += i + 1 < bytes.length ? std[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? std[n & 63] : "=";
  }
  return out;
}

export function b64ToBytes(s: string): Uint8Array {
  const clean = s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return b64urlToBytes(clean);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
