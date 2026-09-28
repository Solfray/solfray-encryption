import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { base58Decode, base58Encode } from "./base58.js";
import { b64ToBytes } from "./codec.js";

export const SEED_LEN = 16;

const X_INFO = utf8ToBytes("solfray-x25519-v1");
const E_INFO = utf8ToBytes("solfray-ed25519-v1");

export interface AccountKey {
  seed: Uint8Array;
  phrase: string;
  x25519Secret: Uint8Array;
  x25519Pub: Uint8Array;
  ed25519Secret: Uint8Array;
  ed25519Pub: Uint8Array;
}

/** 16 new random bytes, with the Forge scribble mixed in. The random bytes
 *  are the entropy. The scribble is ceremony: it is hashed in so the screen
 *  the person drew on actually touches the seed. */
export function forgeSeed(scribble: Uint8Array = new Uint8Array()): Uint8Array {
  const rnd = randomBytes(SEED_LEN);
  const mixed = sha256(concatSeed(rnd, scribble));
  return mixed.slice(0, SEED_LEN);
}

function concatSeed(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function phraseFromSeed(seed: Uint8Array): string {
  if (seed.length !== SEED_LEN) throw new Error("bad_seed");
  return entropyToMnemonic(seed, wordlist);
}

export function seedFromPhrase(phrase: string): Uint8Array {
  const cleaned = phrase.trim().toLowerCase().split(/\s+/).join(" ");
  if (!validateMnemonic(cleaned, wordlist)) throw new Error("bad_phrase");
  const seed = mnemonicToEntropy(cleaned, wordlist);
  if (seed.length !== SEED_LEN) throw new Error("bad_phrase");
  return seed;
}

export function deriveAccount(seed: Uint8Array): AccountKey {
  if (seed.length !== SEED_LEN) throw new Error("bad_seed");
  const x25519Secret = hkdf(sha256, seed, new Uint8Array(), X_INFO, 32);
  const ed25519Secret = hkdf(sha256, seed, new Uint8Array(), E_INFO, 32);
  return {
    seed,
    phrase: phraseFromSeed(seed),
    x25519Secret,
    x25519Pub: x25519.getPublicKey(x25519Secret),
    ed25519Secret,
    ed25519Pub: ed25519.getPublicKey(ed25519Secret),
  };
}

export function accountFromPhrase(phrase: string): AccountKey {
  return deriveAccount(seedFromPhrase(phrase));
}

/** Quiz words are 1-indexed: 3, 7, and 11. */
export function quizWords(phrase: string): { n: number; word: string }[] {
  const words = phrase.trim().split(/\s+/);
  if (words.length !== 12) throw new Error("bad_phrase");
  return [3, 7, 11].map((n) => ({ n, word: words[n - 1] }));
}

export function quizMatches(phrase: string, answers: Record<number, string>): boolean {
  const want = quizWords(phrase);
  return want.every((q) => (answers[q.n] ?? "").trim().toLowerCase() === q.word);
}

export function pubB58(pub: Uint8Array): string {
  return base58Encode(pub);
}

/** Six BIP-39 words and a color, both from the encryption public key.
 *  Comparing sigils is how two people check they have the same key. */
export function sigilOf(edPub: Uint8Array): { words: string[]; color: string } {
  const h = sha256(edPub);
  const words: string[] = [];
  for (let i = 0; i < 6; i++) words.push(wordlist[elevenBits(h, i * 11)]);
  const hue = (h[12] * 360) / 255;
  const color = `hsl(${Math.round(hue)} 62% 46%)`;
  return { words, color };
}

function elevenBits(h: Uint8Array, bit: number): number {
  const byte = bit >> 3;
  const shift = bit & 7;
  const v = ((h[byte] << 16) | ((h[byte + 1] ?? 0) << 8) | (h[byte + 2] ?? 0)) >>> (13 - shift);
  return v & 2047;
}

/** Fixed text the wallet signs to bind this encryption key to the wallet.
 *  This signature is not the vault password. */
export function attestationText(wallet: string, xPub: Uint8Array, edPub: Uint8Array, createdIso: string): string {
  return (
    "Solfray encryption key v1\n" +
    `wallet: ${wallet}\n` +
    `x25519: ${base58Encode(xPub)}\n` +
    `ed25519: ${base58Encode(edPub)}\n` +
    `created: ${createdIso}\n` +
    "Only sign this on solfray.com.\n"
  );
}

/** Wallet-signed "this key is dead." Every device shares the key, so this
 *  signs every device out. It does not unread history. */
export function revokeText(wallet: string, edPub: Uint8Array): string {
  return (
    "Solfray encryption revoke v1\n" +
    `wallet: ${wallet}\n` +
    `ed25519: ${base58Encode(edPub)}\n` +
    "Only sign this on solfray.com.\n"
  );
}

export function rotateText(
  wallet: string,
  oldEd: Uint8Array,
  newX: Uint8Array,
  newEd: Uint8Array,
  createdIso: string
): string {
  return (
    "Solfray encryption rotate v1\n" +
    `wallet: ${wallet}\n` +
    `old_ed25519: ${base58Encode(oldEd)}\n` +
    `new_x25519: ${base58Encode(newX)}\n` +
    `new_ed25519: ${base58Encode(newEd)}\n` +
    `created: ${createdIso}\n` +
    "Only sign this on solfray.com.\n"
  );
}

/** The optional vault password. Signing this does not show the 12 words.
 *  A site that obtains this signature learns the password for the backup
 *  stored on Solfray, and together with that backup can read the words. */
export const VAULT_SIGN_TEXT =
  "Solfray vault backup v1\n" +
  "This signature is the password for the encrypted backup stored on Solfray. It does not show your 12 words.\n" +
  "Only sign this on solfray.com.\n";

export const WALLET_BACKUP_WARNING =
  "Less safe than the copy in this browser and the 12 words on paper. If another site gets you to sign the same sentence, it learns the password for the backup stored on Solfray. You still write the 12 words down.";

/** Verify a wallet ed25519 signature over the exact UTF-8 of `message`.
 *  Phantom signs those bytes. A wallet that prefixes them will fail here. */
export function verifyWalletSig(walletPk: string, message: string, sigB64: string): boolean {
  try {
    const pub = base58Decode(walletPk);
    if (pub.length !== 32) return false;
    const sig = b64ToBytes(sigB64);
    if (sig.length !== 64) return false;
    return ed25519.verify(sig, utf8ToBytes(message), pub);
  } catch {
    return false;
  }
}

export function signEncryption(secret: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secret);
}

export function verifyEncryption(pub: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, message, pub);
  } catch {
    return false;
  }
}
