import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { signEncryption, verifyEncryption } from "./account.js";
import { base58Decode } from "./base58.js";
import { b64urlToBytes, bytesToB64url, concatBytes } from "./codec.js";

const WRAP_INFO_V1 = utf8ToBytes("solfray-wrap-v1");
const WRAP_INFO_V2 = utf8ToBytes("solfray-wrap-v2");

/** Wraps and epoch signatures are version 2 since 2026-10-10. Version 1
 *  wraps carried no room, epoch, or member binding, and the version 1 epoch
 *  signature did not cover the wrap list, so a server could move a wrap
 *  between epochs or swap one. Clients read v1 only to rekey away from it. */
export const EPOCH_SIG_V = 2;

/** Plaintext is padded to this many bytes before encryption so ciphertext
 *  length reveals only a bucket, not the exact message length. Same bucket
 *  size Signal uses. */
export const PAD_BLOCK = 160;

function utf8FromBytes(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** A chat is its id. A channel is `ch:<owner pk>:<channel id>` so two
 *  Servers cannot share an envelope. */
export function chatRoom(chatId: string): string {
  return chatId;
}

export function channelRoom(ownerPk: string, channelId: number): string {
  return `ch:${ownerPk}:${channelId}`;
}

export function aadBytes(roomId: string, epoch: number, authorPk: string): Uint8Array {
  return utf8ToBytes(`solfray-e2e-v1|${roomId}|${epoch}|${authorPk}`);
}

/** What a wrap is bound to. A wrap made for one room, epoch, and member
 *  opens nowhere else, so the server cannot present an old epoch's wrap
 *  (a key a removed member still holds) as the current one. */
export interface WrapContext {
  roomId: string;
  epoch: number;
  memberPk: string;
}

export function wrapAad(ctx: WrapContext): Uint8Array {
  return utf8ToBytes(`solfray-wrap-v2|${ctx.roomId}|${ctx.epoch}|${ctx.memberPk}`);
}

/** Seal a 32-byte epoch key to one member's X25519 public key, bound to
 *  the room, epoch, and member (v2). Layout: ephPub (32) || nonce (24) ||
 *  ciphertext. Returned as base64url. The KDF salt covers both public keys
 *  so the derived key is bound to the recipient as well. */
export function wrapEpochKey(epochKey: Uint8Array, memberXPub: Uint8Array, ctx: WrapContext): string {
  if (epochKey.length !== 32) throw new Error("bad_epoch_key");
  if (memberXPub.length !== 32) throw new Error("bad_x25519");
  const eph = randomBytes(32);
  const ephPub = x25519.getPublicKey(eph);
  const shared = x25519.getSharedSecret(eph, memberXPub);
  const key = hkdf(sha256, shared, concatBytes(ephPub, memberXPub), WRAP_INFO_V2, 32);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce, wrapAad(ctx)).encrypt(epochKey);
  return bytesToB64url(concatBytes(ephPub, nonce, ct));
}

export function unwrapEpochKey(wrappedB64: string, xSecret: Uint8Array, ctx: WrapContext): Uint8Array {
  const raw = b64urlToBytes(wrappedB64);
  if (raw.length < 32 + 24 + 16) throw new Error("bad_wrap");
  const ephPub = raw.slice(0, 32);
  const nonce = raw.slice(32, 56);
  const ct = raw.slice(56);
  const myPub = x25519.getPublicKey(xSecret);
  const shared = x25519.getSharedSecret(xSecret, ephPub);
  const key = hkdf(sha256, shared, concatBytes(ephPub, myPub), WRAP_INFO_V2, 32);
  const opened = xchacha20poly1305(key, nonce, wrapAad(ctx)).decrypt(ct);
  if (opened.length !== 32) throw new Error("bad_wrap");
  return opened;
}

/** Open a version 1 wrap (no binding). Only for reading epochs made before
 *  2026-10-10 so a member can rekey the room onto v2. Never used to seal. */
export function unwrapEpochKeyV1(wrappedB64: string, xSecret: Uint8Array): Uint8Array {
  const raw = b64urlToBytes(wrappedB64);
  if (raw.length < 32 + 24 + 16) throw new Error("bad_wrap");
  const ephPub = raw.slice(0, 32);
  const nonce = raw.slice(32, 56);
  const ct = raw.slice(56);
  const shared = x25519.getSharedSecret(xSecret, ephPub);
  const key = hkdf(sha256, shared, ephPub, WRAP_INFO_V1, 32);
  const opened = xchacha20poly1305(key, nonce).decrypt(ct);
  if (opened.length !== 32) throw new Error("bad_wrap");
  return opened;
}

export interface EpochWrap {
  member_pk: string;
  wrapped: string;
}

/** One hash over the whole wrap list, sorted by member, so the epoch
 *  signature covers every wrap and every recipient. */
export function wrapsDigest(wraps: EpochWrap[]): string {
  const lines = [...wraps]
    .sort((a, b) => (a.member_pk < b.member_pk ? -1 : a.member_pk > b.member_pk ? 1 : 0))
    .map((w) => `${w.member_pk}:${w.wrapped}`);
  return bytesToB64url(sha256(utf8ToBytes(lines.join("\n"))));
}

export function newEpochKey(): Uint8Array {
  return randomBytes(32);
}

export interface PlainMessage {
  text: string;
  mentions?: string[];
  reply_to?: number;
}

/** Plaintext inside the envelope is capped like any other Solfray message. */
export const MAX_PLAINTEXT = 4000;

/** What the server stores. A 4000-character message, once it is JSON,
 *  encrypted, and base64url'd twice (the fields, then the whole object),
 *  lands around 8 KB. 12000 leaves room for mentions and a reply id.
 *  The plan's "about 5800" was a short estimate that does not fit the
 *  4000-character plaintext cap, so the stored cap is this. */
export const MAX_ENVELOPE_LEN = 12000;

export const ENVELOPE_PREFIX = "e2e1:";

export interface EnvelopeParts {
  epoch: number;
  authorPk: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  signature: Uint8Array;
}

export function sealMessage(
  roomId: string,
  epoch: number,
  authorPk: string,
  edSecret: Uint8Array,
  epochKey: Uint8Array,
  plain: PlainMessage
): string {
  if (plain.text.length > MAX_PLAINTEXT) throw new Error("content_too_long");
  const body: PlainMessage = { text: plain.text };
  if (plain.mentions && plain.mentions.length) body.mentions = plain.mentions.slice(0, 10);
  if (typeof plain.reply_to === "number") body.reply_to = plain.reply_to;
  const pt = padPlain(utf8ToBytes(JSON.stringify(body)));
  const nonce = randomBytes(24);
  const aad = aadBytes(roomId, epoch, authorPk);
  const ciphertext = xchacha20poly1305(epochKey, nonce, aad).encrypt(pt);
  const signature = signEncryption(edSecret, concatBytes(aad, nonce, ciphertext));
  const packed = {
    v: 1,
    e: epoch,
    a: authorPk,
    n: bytesToB64url(nonce),
    c: bytesToB64url(ciphertext),
    s: bytesToB64url(signature),
  };
  const out = ENVELOPE_PREFIX + bytesToB64url(utf8ToBytes(JSON.stringify(packed)));
  if (out.length > MAX_ENVELOPE_LEN) throw new Error("content_too_long");
  return out;
}

export function parseEnvelope(content: string): EnvelopeParts | null {
  if (typeof content !== "string" || !content.startsWith(ENVELOPE_PREFIX)) return null;
  if (content.length > MAX_ENVELOPE_LEN) return null;
  try {
    const json = utf8FromBytes(b64urlToBytes(content.slice(ENVELOPE_PREFIX.length)));
    const o = JSON.parse(json) as Record<string, unknown>;
    if (o.v !== 1 || typeof o.e !== "number" || !Number.isInteger(o.e) || o.e < 1) return null;
    if (typeof o.a !== "string" || o.a.length < 32 || o.a.length > 44) return null;
    if (typeof o.n !== "string" || typeof o.c !== "string" || typeof o.s !== "string") return null;
    const nonce = b64urlToBytes(o.n);
    const ciphertext = b64urlToBytes(o.c);
    const signature = b64urlToBytes(o.s);
    if (nonce.length !== 24 || signature.length !== 64 || ciphertext.length < 16) return null;
    return { epoch: o.e, authorPk: o.a, nonce, ciphertext, signature };
  } catch {
    return null;
  }
}

export function verifyEnvelope(content: string, roomId: string, edPub: Uint8Array): EnvelopeParts | null {
  const parts = parseEnvelope(content);
  if (!parts) return null;
  const aad = aadBytes(roomId, parts.epoch, parts.authorPk);
  const ok = verifyEncryption(edPub, concatBytes(aad, parts.nonce, parts.ciphertext), parts.signature);
  return ok ? parts : null;
}

export function openMessage(
  content: string,
  roomId: string,
  epochKey: Uint8Array,
  edPub: Uint8Array
): PlainMessage | null {
  const parts = verifyEnvelope(content, roomId, edPub);
  if (!parts) return null;
  try {
    const aad = aadBytes(roomId, parts.epoch, parts.authorPk);
    const pt = xchacha20poly1305(epochKey, parts.nonce, aad).decrypt(parts.ciphertext);
    const o = JSON.parse(utf8FromBytes(unpadPlain(pt))) as PlainMessage;
    if (!o || typeof o.text !== "string") return null;
    return o;
  } catch {
    return null;
  }
}

/** ISO 7816-4 padding: one 0x80 byte, then zeros, up to a PAD_BLOCK
 *  boundary. A message made before padding existed ends in `}` and is left
 *  alone by unpadPlain. */
export function padPlain(pt: Uint8Array): Uint8Array {
  const len = Math.ceil((pt.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(len);
  out.set(pt);
  out[pt.length] = 0x80;
  return out;
}

export function unpadPlain(pt: Uint8Array): Uint8Array {
  let end = pt.length;
  while (end > 0 && pt[end - 1] === 0) end--;
  if (end > 0 && pt[end - 1] === 0x80) return pt.slice(0, end - 1);
  return pt;
}

/** Version 2 epoch announcement. The signer's encryption key signs the
 *  room, the epoch number, the sorted member list, and the digest of the
 *  wrap list. A server that replaces or moves one wrap breaks the digest. */
export function epochSignBytesV2(roomId: string, epoch: number, wraps: EpochWrap[]): Uint8Array {
  const members = wraps.map((w) => w.member_pk).sort().join(",");
  return utf8ToBytes(
    "Solfray chat epoch v2\n" +
      `room: ${roomId}\n` +
      `epoch: ${epoch}\n` +
      `members: ${members}\n` +
      `wraps: ${wrapsDigest(wraps)}\n`
  );
}

export function signEpochV2(edSecret: Uint8Array, roomId: string, epoch: number, wraps: EpochWrap[]): string {
  return bytesToB64url(signEncryption(edSecret, epochSignBytesV2(roomId, epoch, wraps)));
}

export function verifyEpochV2(
  sigB64: string,
  edPub: Uint8Array,
  roomId: string,
  epoch: number,
  wraps: EpochWrap[]
): boolean {
  try {
    return verifyEncryption(edPub, epochSignBytesV2(roomId, epoch, wraps), b64urlToBytes(sigB64));
  } catch {
    return false;
  }
}

/** Version 1 epoch announcement (before 2026-10-10). Members are the
 *  wallet public keys, sorted, comma-joined. The wrap list was not signed.
 *  Kept so old rows can be recognized; nothing new is signed this way. */
export function epochSignBytes(roomId: string, epoch: number, memberPks: string[]): Uint8Array {
  const members = [...memberPks].sort().join(",");
  return utf8ToBytes(
    "Solfray chat epoch v1\n" + `room: ${roomId}\n` + `epoch: ${epoch}\n` + `members: ${members}\n`
  );
}

export function signEpoch(edSecret: Uint8Array, roomId: string, epoch: number, memberPks: string[]): string {
  return bytesToB64url(signEncryption(edSecret, epochSignBytes(roomId, epoch, memberPks)));
}

export function verifyEpoch(
  sigB64: string,
  edPub: Uint8Array,
  roomId: string,
  epoch: number,
  memberPks: string[]
): boolean {
  try {
    return verifyEncryption(edPub, epochSignBytes(roomId, epoch, memberPks), b64urlToBytes(sigB64));
  } catch {
    return false;
  }
}

export function offVoteBytes(roomId: string, epoch: number): Uint8Array {
  return utf8ToBytes(`Solfray encryption off v1\nroom: ${roomId}\nepoch: ${epoch}\n`);
}

export function signOffVote(edSecret: Uint8Array, roomId: string, epoch: number): string {
  return bytesToB64url(signEncryption(edSecret, offVoteBytes(roomId, epoch)));
}

export function verifyOffVote(sigB64: string, edPub: Uint8Array, roomId: string, epoch: number): boolean {
  try {
    return verifyEncryption(edPub, offVoteBytes(roomId, epoch), b64urlToBytes(sigB64));
  } catch {
    return false;
  }
}

const IMG_MAGIC = utf8ToBytes("SF2E");

/** Encrypt picture bytes before upload. The blob is not an image file:
 *  it starts with SF2E so it cannot be served as a picture Solfray looks at. */
export function sealBytes(roomId: string, epoch: number, epochKey: Uint8Array, plain: Uint8Array): Uint8Array {
  const nonce = randomBytes(24);
  const aad = utf8ToBytes(`solfray-e2e-img-v1|${roomId}|${epoch}`);
  const ct = xchacha20poly1305(epochKey, nonce, aad).encrypt(plain);
  return concatBytes(IMG_MAGIC, new Uint8Array([1]), nonce, ct);
}

export function openBytes(roomId: string, epoch: number, epochKey: Uint8Array, blob: Uint8Array): Uint8Array | null {
  if (blob.length < 4 + 1 + 24 + 16) return null;
  if (blob[0] !== IMG_MAGIC[0] || blob[1] !== IMG_MAGIC[1] || blob[2] !== IMG_MAGIC[2] || blob[3] !== IMG_MAGIC[3]) {
    return null;
  }
  if (blob[4] !== 1) return null;
  const nonce = blob.slice(5, 29);
  const ct = blob.slice(29);
  try {
    const aad = utf8ToBytes(`solfray-e2e-img-v1|${roomId}|${epoch}`);
    return xchacha20poly1305(epochKey, nonce, aad).decrypt(ct);
  } catch {
    return null;
  }
}

export function isOpaqueImage(bytes: Uint8Array): boolean {
  return (
    bytes.length >= 4 &&
    bytes[0] === IMG_MAGIC[0] &&
    bytes[1] === IMG_MAGIC[1] &&
    bytes[2] === IMG_MAGIC[2] &&
    bytes[3] === IMG_MAGIC[3]
  );
}

/** Look up an attested encryption public key from its base58 form. */
export function edPubFromB58(s: string): Uint8Array | null {
  try {
    const b = base58Decode(s);
    return b.length === 32 ? b : null;
  } catch {
    return null;
  }
}
