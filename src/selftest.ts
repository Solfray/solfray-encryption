import assert from "node:assert/strict";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
import {
  accountFromPhrase,
  attestationText,
  deriveAccount,
  forgeSeed,
  phraseFromSeed,
  quizMatches,
  quizWords,
  sigilOf,
  signEncryption,
  verifyWalletSig,
} from "./account.js";
import { base58Encode } from "./base58.js";
import { bytesToB64 } from "./codec.js";
import {
  chatRoom,
  newEpochKey,
  openBytes,
  openMessage,
  sealBytes,
  sealMessage,
  signEpoch,
  unwrapEpochKey,
  verifyEpoch,
  wrapEpochKey,
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

const bob = deriveAccount(forgeSeed());
const epochKey = newEpochKey();
const wrapped = wrapEpochKey(epochKey, bob.x25519Pub);
assert.deepEqual(unwrapEpochKey(wrapped, bob.x25519Secret), epochKey);

const room = chatRoom("11111111-1111-1111-1111-111111111111");
const walletSecret = randomBytes(32);
const wallet = base58Encode(ed25519.getPublicKey(walletSecret));
const env = sealMessage(room, 1, wallet, again.ed25519Secret, epochKey, {
  text: "hello locked",
  reply_to: 4,
});
assert.ok(env.startsWith("e2e1:"));
const opened = openMessage(env, room, epochKey, again.ed25519Pub);
assert.equal(opened?.text, "hello locked");
assert.equal(opened?.reply_to, 4);
assert.equal(openMessage(env, room, epochKey, bob.ed25519Pub), null);
assert.equal(openMessage(env, "other-room", epochKey, again.ed25519Pub), null);

const members = [wallet, base58Encode(bob.ed25519Pub)];
const epochSig = signEpoch(again.ed25519Secret, room, 1, members);
assert.equal(verifyEpoch(epochSig, again.ed25519Pub, room, 1, members), true);
assert.equal(verifyEpoch(epochSig, again.ed25519Pub, room, 2, members), false);

const picture = utf8ToBytes("not-really-a-jpeg");
const blob = sealBytes(room, 1, epochKey, picture);
assert.equal(String.fromCharCode(blob[0], blob[1], blob[2], blob[3]), "SF2E");
assert.deepEqual(openBytes(room, 1, epochKey, blob), picture);
assert.equal(openBytes(room, 2, epochKey, blob), null);

const signed = attestationText(wallet, again.x25519Pub, again.ed25519Pub, "2026-09-27T00:00:00.000Z");
const sig = signEncryption(walletSecret, utf8ToBytes(signed));
assert.equal(verifyWalletSig(wallet, signed, bytesToB64(sig)), true);
assert.equal(verifyWalletSig(wallet, signed + "x", bytesToB64(sig)), false);

const vault = await sealVault(seed, passphrasePassword("correct horse battery"), "passphrase");
assert.deepEqual(await openVault(vault, passphrasePassword("correct horse battery")), seed);
await assert.rejects(() => openVault(vault, passphrasePassword("nope")));

const wsig = signEncryption(walletSecret, utf8ToBytes("Solfray vault backup v1\n"));
const wvault = await sealVault(seed, walletSignaturePassword(wsig), "wallet");
assert.deepEqual(await openVault(wvault, walletSignaturePassword(wsig)), seed);

console.log("e2e selftest ok");
