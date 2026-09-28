import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { argon2idAsync } from "@noble/hashes/argon2";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { b64urlToBytes, bytesToB64url } from "./codec.js";

/**
 * Argon2id parameters for the backup blob. Spike 0.4's target is under
 * two seconds on a mid-range phone. These are the OWASP memory figure
 * (19 MiB) at t=2, p=1, which pure JS finishes in about a second on a
 * desktop and stays the same number in every client. `m` is kibibytes,
 * the unit @noble/hashes uses. Vault unlock is client-only.
 */
export const VAULT_ARGON = { m: 19456, t: 2, p: 1, dkLen: 32 } as const;

const VAULT_AAD = utf8ToBytes("solfray-vault-v1");

export interface VaultBlob {
  v: 1;
  kdf: "argon2id";
  m: number;
  t: number;
  p: number;
  salt: string;
  n: string;
  c: string;
  lock: "passphrase" | "wallet";
}

async function derive(
  password: Uint8Array,
  salt: Uint8Array,
  mem: number = VAULT_ARGON.m,
  t: number = VAULT_ARGON.t,
  p: number = VAULT_ARGON.p
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, { m: mem, t, p, dkLen: 32 });
}

export async function sealVault(seed: Uint8Array, password: Uint8Array, lock: VaultBlob["lock"]): Promise<string> {
  if (seed.length !== 16) throw new Error("bad_seed");
  const salt = randomBytes(16);
  const key = await derive(password, salt);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce, VAULT_AAD).encrypt(seed);
  const blob: VaultBlob = {
    v: 1,
    kdf: "argon2id",
    m: VAULT_ARGON.m,
    t: VAULT_ARGON.t,
    p: VAULT_ARGON.p,
    salt: bytesToB64url(salt),
    n: bytesToB64url(nonce),
    c: bytesToB64url(ct),
    lock,
  };
  const json = JSON.stringify(blob);
  if (json.length > 16_384) throw new Error("vault_too_big");
  return json;
}

export async function openVault(json: string, password: Uint8Array): Promise<Uint8Array> {
  const blob = JSON.parse(json) as VaultBlob;
  if (!blob || blob.v !== 1 || blob.kdf !== "argon2id") throw new Error("bad_vault");
  if (blob.m > 65536 || blob.t > 8 || blob.p > 4) throw new Error("bad_vault");
  const salt = b64urlToBytes(blob.salt);
  const nonce = b64urlToBytes(blob.n);
  const ct = b64urlToBytes(blob.c);
  const key = await derive(password, salt, blob.m, blob.t, blob.p);
  const seed = xchacha20poly1305(key, nonce, VAULT_AAD).decrypt(ct);
  if (seed.length !== 16) throw new Error("bad_vault");
  return seed;
}

/** Passphrase bytes. The wallet lock hashes the signature first, then
 *  runs the same Argon2id, so the signature is a password, not the key. */
export function passphrasePassword(phrase: string): Uint8Array {
  return utf8ToBytes(phrase.normalize("NFKC"));
}

export function walletSignaturePassword(sig: Uint8Array): Uint8Array {
  return sha256(sig);
}

export function vaultLockOf(json: string): VaultBlob["lock"] | null {
  try {
    const o = JSON.parse(json) as VaultBlob;
    return o.lock === "wallet" || o.lock === "passphrase" ? o.lock : null;
  } catch {
    return null;
  }
}
