// The key vault for https://keys.solfray.com.
// The seed, the 12 words, and the epoch keys stay in this frame.
// postMessage replies carry public keys, locked bytes, and plaintext the
// parent asked to unlock. They never carry the seed or the words.

import { encode } from "uqr";
import { sha256 } from "@noble/hashes/sha2";
import { utf8ToBytes } from "@noble/hashes/utils";
import {
  accountFromPhrase,
  b64ToBytes,
  bytesToB64url,
  deriveAccount,
  edPubFromB58,
  forgeSeed,
  newEpochKey,
  openBytes,
  openMessage,
  openVault,
  parseEnvelope,
  passphrasePassword,
  phraseFromSeed,
  pubB58,
  quizMatches,
  sealBytes,
  sealMessage,
  sealVault,
  signEpoch,
  signOffVote,
  sigilOf,
  unwrapEpochKey,
  walletSignaturePassword,
  wrapEpochKey,
  type AccountKey,
} from "../../src/index.ts";

const PARENT = "https://solfray.com";
const DB_NAME = "solfray-e2e";
const STORE = "kv";

type Panel = "none" | "words" | "unlock" | "link-make" | "link-take";

interface OpenKey {
  x25519: string;
  ed25519: string;
  sigil: { words: string[]; color: string };
}

interface WrapIn {
  epoch: number;
  wrapped: string;
}

let wallet = "";
let account: AccountKey | null = null;
let pending: AccountKey | null = null;
let quizzed = false;
let linkCode = "";
let linkPending: AccountKey | null = null;
let panel: Panel = "none";
let showQuiz = false;
let quizError = "";
let phraseError = "";
let linkError = "";
let stay = true;
let idleMin = 0;
let lastActive = Date.now();
const epochs = new Map<string, Map<number, Uint8Array>>();

const app = document.querySelector("#app");
if (!app) throw new Error("missing app");

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props?: { className?: string; text?: string },
  children?: Node[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props?.className) node.className = props.className;
  if (props?.text) node.textContent = props.text;
  if (children) for (const child of children) node.appendChild(child);
  return node;
}

function publicOf(key: AccountKey): OpenKey {
  return {
    x25519: pubB58(key.x25519Pub),
    ed25519: pubB58(key.ed25519Pub),
    sigil: sigilOf(key.ed25519Pub),
  };
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function lockFlag(pk: string): string {
  return "sf-e2e-lock:" + pk;
}

function isSessionLocked(pk: string): boolean {
  try {
    return sessionStorage.getItem(lockFlag(pk)) === "1";
  } catch {
    return false;
  }
}

function markSessionLocked(pk: string): void {
  try {
    sessionStorage.setItem(lockFlag(pk), "1");
  } catch {
    /* private mode */
  }
}

function clearSessionLock(pk: string): void {
  try {
    sessionStorage.removeItem(lockFlag(pk));
  } catch {
    /* private mode */
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb_open"));
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => resolve(req.result as T | undefined);
      req.onerror = () => reject(req.error ?? new Error("idb_get"));
    });
  } finally {
    db.close();
  }
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("idb_set"));
    });
  } finally {
    db.close();
  }
}

async function wrappingKey(): Promise<CryptoKey> {
  const existing = await idbGet<CryptoKey>("aes");
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idbSet("aes", key);
  return key;
}

async function readStoredSeed(pk: string): Promise<Uint8Array | null> {
  if (!pk) return null;
  if ((await idbGet<boolean>("stay:" + pk)) !== true) return null;
  const row = await idbGet<{ iv: number[]; ct: number[] }>("seed:" + pk);
  if (!row || !Array.isArray(row.iv) || !Array.isArray(row.ct)) return null;
  try {
    const key = await wrappingKey();
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(row.iv) },
      key,
      new Uint8Array(row.ct)
    );
    const seed = new Uint8Array(plain);
    return seed.length === 16 ? seed : null;
  } catch {
    return null;
  }
}

async function writeStoredSeed(pk: string, seed: Uint8Array, stayOn: boolean): Promise<void> {
  const key = await wrappingKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, seed));
  await idbSet("seed:" + pk, { iv: [...iv], ct: [...ct] });
  await idbSet("stay:" + pk, stayOn);
  if (stayOn) clearSessionLock(pk);
}

function post(target: Window, origin: string, data: unknown): void {
  target.postMessage(data, origin);
}

function ui(name: string, extra?: Record<string, unknown>): void {
  if (window.parent === window) return;
  post(window.parent, PARENT, { t: "ui", name, ...extra });
}

function roomMap(roomId: string): Map<number, Uint8Array> {
  let map = epochs.get(roomId);
  if (!map) {
    map = new Map();
    epochs.set(roomId, map);
  }
  return map;
}

function drawQr(canvas: HTMLCanvasElement, text: string): void {
  const qr = encode(text, { ecc: "M", border: 2 });
  const scale = 4;
  canvas.width = qr.size * scale;
  canvas.height = qr.size * scale;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.fillStyle = "#f4f1ea";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#161616";
  for (let y = 0; y < qr.size; y++) {
    const row = qr.data[y] ?? [];
    for (let x = 0; x < qr.size; x++) {
      if (row[x]) ctx.fillRect(x * scale, y * scale, scale, scale);
    }
  }
}

function render(): void {
  app!.replaceChildren();
  if (window.parent === window) {
    app!.append(
      el("p", {
        text: "This is the Solfray key vault. It opens inside solfray.com. The 12 words are typed here, and they are not sent back to the site.",
      })
    );
    return;
  }
  if (panel === "none") {
    app!.append(el("p", { className: "quiet", text: "Solfray key vault" }));
    return;
  }
  if (panel === "words") {
    if (!pending) {
      app!.append(el("p", { text: "There is no new key to write down." }));
      return;
    }
    const phrase = phraseFromSeed(pending.seed);
    app!.append(
      el("p", {
        text: "Write these 12 words on paper. This is the backup. Solfray cannot show them again later.",
      }),
      el("p", { className: "words", text: phrase })
    );
    if (!showQuiz) {
      const wrote = el("button", { text: "I wrote them down" });
      wrote.addEventListener("click", () => {
        showQuiz = true;
        quizError = "";
        render();
      });
      app!.append(el("div", { className: "row" }, [wrote]));
      return;
    }
    app!.append(el("p", { text: "Type words 3, 7, and 11 from the paper." }));
    const inputs = new Map<number, HTMLInputElement>();
    for (const n of [3, 7, 11]) {
      const input = el("input");
      input.autocomplete = "off";
      input.spellcheck = false;
      inputs.set(n, input);
      const span = el("span", { text: "Word " + n });
      app!.append(el("label", undefined, [span, input]));
    }
    if (quizError) app!.append(el("p", { className: "err", text: quizError }));
    const check = el("button", { text: "Check" });
    check.addEventListener("click", () => {
      const answers: Record<number, string> = {};
      for (const [n, input] of inputs) answers[n] = input.value;
      if (!quizMatches(phrase, answers)) {
        quizError = "Those words did not match. Check the paper and try again.";
        render();
        return;
      }
      quizError = "";
      quizzed = true;
      ui("quiz-ok");
    });
    app!.append(el("div", { className: "row" }, [check]));
    return;
  }
  if (panel === "unlock") {
    app!.append(el("p", { text: "Type the 12 words. They stay on this page." }));
    const area = el("textarea");
    area.rows = 3;
    area.autocomplete = "off";
    area.spellcheck = false;
    const button = el("button", { text: "Unlock" });
    button.addEventListener("click", () => {
      void (async () => {
        try {
          if (!wallet) throw new Error("e2e_locked");
          const next = accountFromPhrase(area.value);
          account = next;
          pending = null;
          quizzed = false;
          epochs.clear();
          await writeStoredSeed(wallet, next.seed, stay);
          clearSessionLock(wallet);
          lastActive = Date.now();
          phraseError = "";
          area.value = "";
          ui("unlocked", { account: publicOf(next) });
        } catch {
          phraseError = "Those words did not match. Check the paper and try again.";
          render();
        }
      })();
    });
    app!.append(area);
    if (phraseError) app!.append(el("p", { className: "err", text: phraseError }));
    app!.append(el("div", { className: "row" }, [button]));
    return;
  }
  if (panel === "link-make") {
    app!.append(
      el("p", {
        text: "This code works once, for five minutes. The other device can paste it. Both screens should show the same sigil.",
      })
    );
    if (!linkCode) {
      app!.append(el("p", { className: "quiet", text: "Making the code…" }));
      return;
    }
    app!.append(el("p", { className: "words", text: linkCode }));
    const canvas = el("canvas");
    drawQr(canvas, linkCode);
    app!.append(canvas);
    return;
  }
  if (panel === "link-take") {
    app!.append(el("p", { text: "Paste the code from the other device." }));
    const input = el("input");
    input.autocomplete = "off";
    input.spellcheck = false;
    const button = el("button", { text: "Use this code" });
    button.addEventListener("click", () => {
      const code = input.value.trim();
      if (code.length < 8 || code.length > 128) {
        linkError = "That code is not valid.";
        render();
        return;
      }
      linkCode = code;
      linkError = "";
      ui("link-hash", { codeHash: hex(sha256(utf8ToBytes(code))) });
    });
    app!.append(input);
    if (linkError) app!.append(el("p", { className: "err", text: linkError }));
    app!.append(el("div", { className: "row" }, [button]));
  }
}

function asRecord(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object") return {};
  return body as Record<string, unknown>;
}

function needAccount(): AccountKey {
  if (!account) throw new Error("e2e_locked");
  return account;
}

async function onRpc(op: string, raw: unknown): Promise<unknown> {
  const body = asRecord(raw);
  if (op === "boot") {
    wallet = typeof body.wallet === "string" ? body.wallet : "";
    account = null;
    pending = null;
    quizzed = false;
    epochs.clear();
    if (!wallet) return { account: null, stay: false, idle: 0 };
    if (body.sessionLocked === true) markSessionLocked(wallet);
    stay = (await idbGet<boolean>("stay:" + wallet)) === true;
    const idleRaw = await idbGet<number>("idle:" + wallet);
    idleMin = typeof idleRaw === "number" && idleRaw > 0 ? idleRaw : 0;
    if (isSessionLocked(wallet) || !stay) return { account: null, stay, idle: idleMin };
    const seed = await readStoredSeed(wallet);
    if (!seed) return { account: null, stay, idle: idleMin };
    account = deriveAccount(seed);
    lastActive = Date.now();
    return { account: publicOf(account), stay, idle: idleMin };
  }
  if (op === "forge") {
    if (!wallet) throw new Error("e2e_locked");
    const scribble = body.scribble instanceof Uint8Array ? body.scribble.slice(0, 2_000_000) : new Uint8Array();
    pending = deriveAccount(forgeSeed(scribble));
    quizzed = false;
    showQuiz = false;
    quizError = "";
    return { account: publicOf(pending) };
  }
  if (op === "panel") {
    const next = body.panel;
    panel = next === "words" || next === "unlock" || next === "link-make" || next === "link-take" ? next : "none";
    if (panel !== "words") showQuiz = false;
    quizError = "";
    phraseError = "";
    linkError = "";
    render();
    return { ok: true };
  }
  if (op === "commit") {
    if (!pending || !quizzed) throw new Error("e2e_locked");
    if (!wallet) throw new Error("e2e_locked");
    account = pending;
    pending = null;
    quizzed = false;
    stay = true;
    await writeStoredSeed(wallet, account.seed, true);
    clearSessionLock(wallet);
    lastActive = Date.now();
    const pub = publicOf(account);
    ui("unlocked", { account: pub });
    return { account: pub };
  }
  if (op === "discard") {
    pending = null;
    quizzed = false;
    linkPending = null;
    linkCode = "";
    showQuiz = false;
    render();
    return { ok: true };
  }
  if (op === "lock") {
    account = null;
    pending = null;
    quizzed = false;
    linkPending = null;
    linkCode = "";
    epochs.clear();
    if (wallet) markSessionLocked(wallet);
    ui("locked");
    render();
    return { ok: true };
  }
  if (op === "touch") {
    lastActive = Date.now();
    return { ok: true };
  }
  if (op === "prefs") {
    return { stay, idle: idleMin };
  }
  if (op === "setStay") {
    if (!wallet) throw new Error("e2e_locked");
    stay = body.stay === true;
    await idbSet("stay:" + wallet, stay);
    if (stay) clearSessionLock(wallet);
    return { stay };
  }
  if (op === "setIdle") {
    if (!wallet) throw new Error("e2e_locked");
    const n = typeof body.minutes === "number" ? body.minutes : 0;
    idleMin = n > 0 ? Math.min(24 * 60, Math.floor(n)) : 0;
    await idbSet("idle:" + wallet, idleMin);
    return { idle: idleMin };
  }
  if (op === "sealBackup") {
    const seed = quizzed && pending ? pending.seed : account?.seed;
    if (!seed) throw new Error("e2e_locked");
    if (typeof body.sig !== "string") throw new Error("bad_attestation");
    const blob = await sealVault(seed, walletSignaturePassword(b64ToBytes(body.sig)), "wallet");
    return { blob };
  }
  if (op === "hold") {
    if (typeof body.roomId !== "string" || !Array.isArray(body.wraps)) throw new Error("bad_request");
    const map = roomMap(body.roomId);
    if (account) {
      for (const wrap of body.wraps as WrapIn[]) {
        if (!wrap || typeof wrap.epoch !== "number" || typeof wrap.wrapped !== "string") continue;
        if (map.has(wrap.epoch)) continue;
        try {
          map.set(wrap.epoch, unwrapEpochKey(wrap.wrapped, account.x25519Secret));
        } catch {
          /* a wrap for a key this vault does not hold */
        }
      }
    }
    return { epochs: [...map.keys()] };
  }
  if (op === "seal") {
    const key = needAccount();
    if (typeof body.roomId !== "string" || typeof body.epoch !== "number" || typeof body.authorPk !== "string") {
      throw new Error("bad_request");
    }
    if (typeof body.text !== "string") throw new Error("bad_request");
    const epochKey = epochs.get(body.roomId)?.get(body.epoch);
    if (!epochKey) throw new Error("e2e_locked");
    const mentions = Array.isArray(body.mentions) ? body.mentions.filter((m): m is string => typeof m === "string") : undefined;
    const content = sealMessage(body.roomId, body.epoch, body.authorPk, key.ed25519Secret, epochKey, {
      text: body.text,
      ...(mentions && mentions.length ? { mentions } : {}),
      ...(typeof body.replyTo === "number" ? { reply_to: body.replyTo } : {}),
    });
    return { content };
  }
  if (op === "openMany") {
    if (!Array.isArray(body.items)) throw new Error("bad_request");
    const items = [];
    for (const item of body.items.slice(0, 40) as Record<string, unknown>[]) {
      const id = typeof item.id === "string" ? item.id : "";
      const roomId = typeof item.roomId === "string" ? item.roomId : "";
      const envelope = typeof item.envelope === "string" ? item.envelope : "";
      const authors = Array.isArray(item.authors) ? item.authors.filter((s): s is string => typeof s === "string") : [];
      const parts = parseEnvelope(envelope);
      const epochKey = parts ? epochs.get(roomId)?.get(parts.epoch) : undefined;
      let opened: { text: string; mentions?: string[]; reply_to?: number; epoch: number } | null = null;
      if (parts && epochKey) {
        for (const author of authors) {
          const ed = edPubFromB58(author);
          if (!ed) continue;
          const plain = openMessage(envelope, roomId, epochKey, ed);
          if (plain) {
            opened = { text: plain.text, mentions: plain.mentions, reply_to: plain.reply_to, epoch: parts.epoch };
            break;
          }
        }
      }
      items.push(
        opened
          ? {
              id,
              locked: false,
              text: opened.text,
              mentions: opened.mentions ?? [],
              replyTo: typeof opened.reply_to === "number" ? opened.reply_to : null,
              epoch: opened.epoch,
            }
          : { id, locked: true, text: "", mentions: [], replyTo: null, epoch: null }
      );
    }
    return { items };
  }
  if (op === "sealFile") {
    needAccount();
    if (typeof body.roomId !== "string" || typeof body.epoch !== "number" || !(body.bytes instanceof Uint8Array)) {
      throw new Error("bad_request");
    }
    if (body.bytes.byteLength > 5_000_000) throw new Error("content_too_long");
    const epochKey = epochs.get(body.roomId)?.get(body.epoch);
    if (!epochKey) throw new Error("e2e_locked");
    return { bytes: sealBytes(body.roomId, body.epoch, epochKey, body.bytes) };
  }
  if (op === "openFile") {
    if (typeof body.roomId !== "string" || !(body.bytes instanceof Uint8Array) || !Array.isArray(body.epochs)) {
      throw new Error("bad_request");
    }
    const map = epochs.get(body.roomId);
    if (!map) throw new Error("e2e_locked");
    for (const epoch of body.epochs) {
      if (typeof epoch !== "number") continue;
      const epochKey = map.get(epoch);
      if (!epochKey) continue;
      const plain = openBytes(body.roomId, epoch, epochKey, body.bytes);
      if (plain) return { bytes: plain };
    }
    throw new Error("e2e_locked");
  }
  if (op === "buildEpoch") {
    const key = needAccount();
    if (typeof body.roomId !== "string" || typeof body.epoch !== "number" || !Array.isArray(body.members)) {
      throw new Error("bad_request");
    }
    const reason = body.reason;
    if (reason !== "on" && reason !== "rekey" && reason !== "join" && reason !== "leave") throw new Error("bad_request");
    const members = body.members as { pk?: unknown; x25519?: unknown }[];
    const pks: string[] = [];
    const epochKey = newEpochKey();
    const wraps = members.map((member) => {
      if (typeof member.pk !== "string" || typeof member.x25519 !== "string") throw new Error("e2e_member_keyless");
      const pub = edPubFromB58(member.x25519);
      if (!pub) throw new Error("e2e_member_keyless");
      pks.push(member.pk);
      return { member_pk: member.pk, wrapped: wrapEpochKey(epochKey, pub) };
    });
    roomMap(body.roomId).set(body.epoch, epochKey);
    const olderEpochs = Array.isArray(body.olderEpochs) ? body.olderEpochs.filter((n): n is number => typeof n === "number") : [];
    const olderFor = Array.isArray(body.olderFor) ? body.olderFor.filter((s): s is string => typeof s === "string") : [];
    const older = [];
    const map = epochs.get(body.roomId)!;
    for (const epoch of olderEpochs) {
      if (epoch >= body.epoch) continue;
      const old = map.get(epoch);
      if (!old) continue;
      const wrapped = [];
      for (const pk of olderFor) {
        const member = members.find((m) => m.pk === pk);
        if (!member || typeof member.x25519 !== "string") throw new Error("e2e_member_keyless");
        const pub = edPubFromB58(member.x25519);
        if (!pub) throw new Error("e2e_member_keyless");
        wrapped.push({ member_pk: pk, wrapped: wrapEpochKey(old, pub) });
      }
      if (wrapped.length) older.push({ epoch, wraps: wrapped });
    }
    return {
      epoch: body.epoch,
      wraps,
      signature: signEpoch(key.ed25519Secret, body.roomId, body.epoch, pks),
      reason,
      ...(older.length ? { older } : {}),
    };
  }
  if (op === "signOff") {
    const key = needAccount();
    if (typeof body.roomId !== "string" || typeof body.epoch !== "number") throw new Error("bad_request");
    return { signature: signOffVote(key.ed25519Secret, body.roomId, body.epoch) };
  }
  if (op === "linkSeal") {
    const key = needAccount();
    const raw = crypto.getRandomValues(new Uint8Array(16));
    linkCode = bytesToB64url(raw);
    const blob = await sealVault(key.seed, passphrasePassword(linkCode), "passphrase");
    const codeHash = hex(sha256(utf8ToBytes(linkCode)));
    panel = "link-make";
    render();
    return { codeHash, blob };
  }
  if (op === "openLink") {
    if (!linkCode || typeof body.blob !== "string") throw new Error("bad_phrase");
    const seed = await openVault(body.blob, passphrasePassword(linkCode));
    linkPending = deriveAccount(seed);
    return { sigil: sigilOf(linkPending.ed25519Pub) };
  }
  if (op === "acceptLink") {
    if (!linkPending || !wallet) throw new Error("e2e_locked");
    account = linkPending;
    linkPending = null;
    linkCode = "";
    epochs.clear();
    await writeStoredSeed(wallet, account.seed, stay);
    clearSessionLock(wallet);
    lastActive = Date.now();
    const pub = publicOf(account);
    ui("unlocked", { account: pub });
    return { account: pub };
  }
  throw new Error("bad_request");
}

window.addEventListener("message", (ev: MessageEvent) => {
  if (ev.origin !== PARENT) return;
  const data = ev.data as { t?: string; id?: string; op?: string; body?: unknown } | null;
  if (!data || data.t !== "rpc" || typeof data.id !== "string" || typeof data.op !== "string") return;
  const source = ev.source;
  if (!source || !("postMessage" in source)) return;
  const target = source as Window;
  void onRpc(data.op, data.body)
    .then((body) => post(target, ev.origin, { t: "rpc", id: data.id, ok: true, body }))
    .catch((err: unknown) => {
      const error = err instanceof Error && err.message ? err.message : "failed";
      post(target, ev.origin, { t: "rpc", id: data.id, ok: false, error });
    });
});

window.addEventListener("pointerdown", () => {
  lastActive = Date.now();
});
window.addEventListener("keydown", () => {
  lastActive = Date.now();
});
window.setInterval(() => {
  if (!account || idleMin <= 0) return;
  if (Date.now() - lastActive >= idleMin * 60_000) {
    account = null;
    pending = null;
    quizzed = false;
    linkPending = null;
    linkCode = "";
    epochs.clear();
    if (wallet) markSessionLocked(wallet);
    ui("locked");
    render();
  }
}, 15_000);

render();
if (window.parent !== window) post(window.parent, PARENT, { t: "vault-ready" });
