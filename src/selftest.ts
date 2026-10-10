import assert from "node:assert/strict";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
import {
  accountFromPhrase,
  attestationText,
  deriveAccount,
  fingerprintOf,
  forgeSeed,
  phraseFromSeed,
  quizMatches,
  quizWords,
  rotateText,
  sigilOf,
  signEncryption,
  verifyKeyRow,
  verifyWalletSig,
} from "./account.js";
import { base58Encode } from "./base58.js";
import { bytesToB64 } from "./codec.js";
import {
  PAD_BLOCK,
  chatRoom,
  newEpochKey,
  openBytes,
  openMessage,
  padPlain,
  parseEnvelope,
  sealBytes,
  sealMessage,
  signEpoch,
  signEpochV2,
  unpadPlain,
  unwrapEpochKey,
  unwrapEpochKeyV1,
  verifyEpoch,
  verifyEpochV2,
  wrapEpochKey,
  wrapsDigest,
} from "./box.js";
import { openVault, passphrasePassword, sealVault, walletSignaturePassword } from "./vault.js";

const seed = forgeSeed(utf8ToBytes("scribble"));
assert.equal(seed.length, 16);
const phrase = phraseFromSeed(seed);
assert.equal(phrase.split(" ").length, 12);
const again = deriveAccount(seed);
const fromWords = accountFromPhrase(phrase);
assert.deepEqual(again.ed25519Pub, fromWords.ed25519Pub);
assert.deepEqual(again.x25519Pub, fromWords.x25519Pub);

const quiz = quizWords(phrase);
const answers: Record<number, string> = {};
for (const q of quiz) answers[q.n] = q.word;
assert.equal(quizMatches(phrase, answers), true);
answers[3] = "notaword";
assert.equal(quizMatches(phrase, answers), false);

const sigil = sigilOf(again.ed25519Pub);
assert.equal(sigil.words.length, 6);
assert.equal(sigilOf(again.ed25519Pub).words.join(" "), sigil.words.join(" "));
assert.match(fingerprintOf(again.ed25519Pub), /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/);

// Wraps (v2) are bound to room, epoch, and member.
const room = chatRoom("11111111-1111-1111-1111-111111111111");
const bob = deriveAccount(forgeSeed());
const epochKey = newEpochKey();
const bobCtx = { roomId: room, epoch: 1, memberPk: "bob" };
const wrapped = wrapEpochKey(epochKey, bob.x25519Pub, bobCtx);
assert.deepEqual(unwrapEpochKey(wrapped, bob.x25519Secret, bobCtx), epochKey);
assert.throws(() => unwrapEpochKey(wrapped, bob.x25519Secret, { ...bobCtx, epoch: 2 }));
assert.throws(() => unwrapEpochKey(wrapped, bob.x25519Secret, { ...bobCtx, roomId: "other" }));
assert.throws(() => unwrapEpochKey(wrapped, bob.x25519Secret, { ...bobCtx, memberPk: "eve" }));
assert.throws(() => unwrapEpochKey(wrapped, again.x25519Secret, bobCtx));
assert.throws(() => unwrapEpochKeyV1(wrapped, bob.x25519Secret));

// Messages: padded to a bucket, signed by the author, bound to the room.
const walletSecret = randomBytes(32);
const wallet = base58Encode(ed25519.getPublicKey(walletSecret));
const env = sealMessage(room, 1, wallet, again.ed25519Secret, epochKey, {
  text: "hello locked",
  reply_to: 4,
});
assert.ok(env.startsWith("e2e1:"));
const parts = parseEnvelope(env);
assert.ok(parts);
assert.equal((parts!.ciphertext.length - 16) % PAD_BLOCK, 0);
const short = sealMessage(room, 1, wallet, again.ed25519Secret, epochKey, { text: "a" });
const longer = sealMessage(room, 1, wallet, again.ed25519Secret, epochKey, { text: "a".repeat(100) });
assert.equal(parseEnvelope(short)!.ciphertext.length, parseEnvelope(longer)!.ciphertext.length);
const opened = openMessage(env, room, epochKey, again.ed25519Pub);
assert.equal(opened?.text, "hello locked");
assert.equal(opened?.reply_to, 4);
assert.equal(openMessage(env, room, epochKey, bob.ed25519Pub), null);
assert.equal(openMessage(env, "other-room", epochKey, again.ed25519Pub), null);
const legacy = utf8ToBytes('{"text":"x"}');
assert.deepEqual(unpadPlain(legacy), legacy);
assert.deepEqual(unpadPlain(padPlain(legacy)), legacy);
const edge = new Uint8Array(PAD_BLOCK - 1).fill(0x41);
assert.equal(padPlain(edge).length, PAD_BLOCK);
assert.deepEqual(unpadPlain(padPlain(edge)), edge);

// Epoch signature (v2) covers the wrap list.
const members = [wallet, base58Encode(bob.ed25519Pub)];
const wraps = [
  { member_pk: members[0], wrapped: wrapEpochKey(epochKey, again.x25519Pub, { roomId: room, epoch: 1, memberPk: members[0] }) },
  { member_pk: members[1], wrapped: wrapEpochKey(epochKey, bob.x25519Pub, { roomId: room, epoch: 1, memberPk: members[1] }) },
];
assert.equal(wrapsDigest(wraps), wrapsDigest([wraps[1], wraps[0]]));
const sig2 = signEpochV2(again.ed25519Secret, room, 1, wraps);
assert.equal(verifyEpochV2(sig2, again.ed25519Pub, room, 1, wraps), true);
assert.equal(verifyEpochV2(sig2, again.ed25519Pub, room, 2, wraps), false);
assert.equal(verifyEpochV2(sig2, bob.ed25519Pub, room, 1, wraps), false);
const swapped = [wraps[0], { member_pk: members[1], wrapped: wrapEpochKey(newEpochKey(), bob.x25519Pub, { roomId: room, epoch: 1, memberPk: members[1] }) }];
assert.equal(verifyEpochV2(sig2, again.ed25519Pub, room, 1, swapped), false);
assert.equal(verifyEpochV2(sig2, again.ed25519Pub, room, 1, [wraps[0]]), false);
const epochSig = signEpoch(again.ed25519Secret, room, 1, members);
assert.equal(verifyEpoch(epochSig, again.ed25519Pub, room, 1, members), true);
assert.equal(verifyEpoch(epochSig, again.ed25519Pub, room, 2, members), false);

const picture = utf8ToBytes("not-really-a-jpeg");
const blob = sealBytes(room, 1, epochKey, picture);
assert.equal(String.fromCharCode(blob[0], blob[1], blob[2], blob[3]), "SF2E");
assert.deepEqual(openBytes(room, 1, epochKey, blob), picture);
assert.equal(openBytes(room, 2, epochKey, blob), null);

// Wallet attestation, and the directory row check every client runs.
const created = "2026-09-27T00:00:00.000Z";
const signed = attestationText(wallet, again.x25519Pub, again.ed25519Pub, created);
const sig = signEncryption(walletSecret, utf8ToBytes(signed));
assert.equal(verifyWalletSig(wallet, signed, bytesToB64(sig)), true);
assert.equal(verifyWalletSig(wallet, signed + "x", bytesToB64(sig)), false);
const row = {
  pk: wallet,
  x25519_pub: base58Encode(again.x25519Pub),
  ed25519_pub: base58Encode(again.ed25519Pub),
  attestation: bytesToB64(sig),
  created_at: created,
};
assert.equal(verifyKeyRow(row), true);
assert.equal(verifyKeyRow({ ...row, x25519_pub: base58Encode(bob.x25519Pub) }), false);
assert.equal(verifyKeyRow({ ...row, pk: base58Encode(bob.ed25519Pub) }), false);
const rotated = rotateText(wallet, again.ed25519Pub, bob.x25519Pub, bob.ed25519Pub, created);
const rsig = signEncryption(walletSecret, utf8ToBytes(rotated));
const rrow = {
  pk: wallet,
  x25519_pub: base58Encode(bob.x25519Pub),
  ed25519_pub: base58Encode(bob.ed25519Pub),
  attestation: bytesToB64(rsig),
  created_at: created,
  prev_ed25519: base58Encode(again.ed25519Pub),
};
assert.equal(verifyKeyRow(rrow), true);
assert.equal(verifyKeyRow({ ...rrow, prev_ed25519: null }), false);

const vault = await sealVault(seed, passphrasePassword("correct horse battery"), "passphrase");
assert.deepEqual(await openVault(vault, passphrasePassword("correct horse battery")), seed);
await assert.rejects(() => openVault(vault, passphrasePassword("nope")));

const wsig = signEncryption(walletSecret, utf8ToBytes("Solfray vault backup v1\n"));
const wvault = await sealVault(seed, walletSignaturePassword(wsig), "wallet");
assert.deepEqual(await openVault(wvault, walletSignaturePassword(wsig)), seed);

console.log("e2e selftest ok");
