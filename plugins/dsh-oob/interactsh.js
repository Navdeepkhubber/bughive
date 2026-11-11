/**
 * Self-hosted Interactsh client (register / poll / deregister).
 *
 * This is NOT the ProjectDiscovery `interactsh-client` binary. That CLI's `-auth`
 * flag defaults to "true" (cmd/interactsh-client/main.go, interactsh
 * b9fea16e57ea1c7eba13ca3f345fdfdd7caa156d, version constant 1.4.1). The default
 * calls options.AuthWithPDCP before client.New. AuthWithPDCP calls
 * pdcp.CheckNValidateCredentials (projectdiscovery/utils v0.11.6,
 * auth/pdcp/auth.go), which GETs https://api.projectdiscovery.io/v1/user
 * (DefaultApiServer) and os.Exit(0) on success — so a default client never
 * reaches a self-hosted /poll. The same client defaults ServerURL to the public
 * oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me list and walks that
 * list on registration failure.
 *
 * This module dials only the URL the caller passed. Public oast.* hosts,
 * projectdiscovery.io, interact.sh, and comma-separated server lists are
 * refused before any socket. There is no PDCP client and no default server.
 *
 * Crypto matches pkg/client/client.go decryptMessage and pkg/storage/util.go
 * AESEncrypt: RSA-OAEP SHA-256 (empty label) wrapping a 32-byte key, AES-256-CTR
 * with the IV prepended. Poll rows are whatever the server returned. An empty
 * poll is an empty list — this module does not invent interactions.
 */

import {
  constants,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { appendFileSync } from "node:fs";

export const PUBLIC_OAST_SUFFIXES = Object.freeze([
  "oast.pro",
  "oast.live",
  "oast.site",
  "oast.online",
  "oast.fun",
  "oast.me",
  "interact.sh",
  "projectdiscovery.io",
]);

const XID = "0123456789abcdefghijklmnopqrstuv";
const ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769";

function refused(message) {
  const error = new Error(message);
  error.code = "COLLABORATOR_REFUSED";
  return error;
}

export function hostIsForbidden(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.+$/, "");
  if (!host) return false;
  return PUBLIC_OAST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/** Accept only an explicit http(s) collaborator. Never a public OAST default. */
export function assertSelfHostedCollaborator(raw) {
  const text = String(raw || "").trim();
  if (!text) throw refused("collaborator URL is empty");
  if (text.includes(",")) {
    throw refused("refusing comma-separated collaborator list (public OAST fallback)");
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    throw refused(`collaborator URL is not absolute: ${text}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw refused(`collaborator URL scheme is not http(s): ${url.protocol}`);
  }
  const hostname = url.hostname.toLowerCase().replace(/\.+$/, "");
  if (hostIsForbidden(hostname)) {
    throw refused(`refusing public OAST or ProjectDiscovery Cloud host: ${hostname}`);
  }
  const path = url.pathname || "/";
  return {
    href: url.href,
    origin: url.origin,
    hostname,
    port: url.port,
    serverRoot: path === "/" || path === "",
  };
}

function fromAlphabet(alphabet, length) {
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function oaep(key) {
  return {
    key,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    oaepLabel: Buffer.alloc(0),
  };
}

/** Server-side seal. Tests and a local fixture use this; the client only decrypts. */
export function sealInteractions(publicKeyB64, aesKey, events) {
  const pem = Buffer.from(publicKeyB64, "base64").toString("utf8");
  const wrapped = publicEncrypt(oaep(createPublicKey(pem)), aesKey);
  const data = (events || []).map((event) => {
    const iv = randomBytes(16);
    const cipher = createCipheriv("aes-256-ctr", aesKey, iv);
    const plaintext = Buffer.from(JSON.stringify(event));
    return Buffer.concat([iv, cipher.update(plaintext), cipher.final()]).toString("base64");
  });
  return { data, aes_key: wrapped.toString("base64"), extra: [], tlddata: [] };
}

export class InteractshClient {
  constructor(options = {}) {
    const pinned = assertSelfHostedCollaborator(options.serverUrl);
    this.pinned = pinned;
    this.apiBase = pinned.origin;
    this.token = options.token || "";
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    this.logPath = options.logPath || "";
    this.correlationId = options.correlationId || fromAlphabet(XID, 20);
    this.secretKey = options.secretKey || randomUUID();
    this.publicKeyB64 = options.publicKeyB64 || null;
    this.privateKeyPem = options.privateKeyPem || null;
    this.privateKey = this.privateKeyPem ? createPrivateKey(this.privateKeyPem) : null;
  }

  static resume(session, options = {}) {
    if (!session?.serverUrl || !session.correlationId || !session.secretKey || !session.privateKeyPem) {
      throw new Error("session is missing collaborator fields");
    }
    return new InteractshClient({
      serverUrl: session.serverUrl,
      token: session.token || "",
      fetchImpl: options.fetchImpl,
      logPath: options.logPath || "",
      correlationId: session.correlationId,
      secretKey: session.secretKey,
      publicKeyB64: session.publicKeyB64,
      privateKeyPem: session.privateKeyPem,
    });
  }

  session() {
    return {
      serverUrl: this.pinned.serverRoot ? `${this.apiBase}/` : this.pinned.href,
      token: this.token,
      correlationId: this.correlationId,
      secretKey: this.secretKey,
      publicKeyB64: this.publicKeyB64,
      privateKeyPem: this.privateKeyPem,
    };
  }

  headers(extra = {}) {
    const headers = { ...extra };
    if (this.token) headers.Authorization = this.token;
    return headers;
  }

  async request(url, init) {
    const target = new URL(url);
    const allowed = new URL(this.apiBase);
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      throw new Error(`refusing non-http request to ${target.href}`);
    }
    if (target.hostname !== allowed.hostname || String(target.port) !== String(allowed.port)) {
      throw new Error(`refusing request to ${target.host}; collaborator is pinned to ${allowed.host}`);
    }
    if (hostIsForbidden(target.hostname)) {
      throw new Error(`refusing public OAST or ProjectDiscovery Cloud host: ${target.hostname}`);
    }
    const headers = { ...(init?.headers || {}), Connection: "close" };
    return this.fetchImpl(url, { ...init, headers });
  }

  async register() {
    if (!this.pinned.serverRoot) {
      throw new Error("collaborator URL is a payload, not an Interactsh server root");
    }
    if (!this.privateKey) {
      const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
      this.privateKey = pair.privateKey;
      this.privateKeyPem = pair.privateKey.export({ type: "pkcs1", format: "pem" });
      this.publicKeyB64 = Buffer.from(pair.publicKey.export({ type: "spki", format: "pem" })).toString("base64");
    }
    const body = JSON.stringify({
      "public-key": this.publicKeyB64,
      "secret-key": this.secretKey,
      "correlation-id": this.correlationId,
    });
    const response = await this.request(`${this.apiBase}/register`, {
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body,
    });
    const text = await response.text();
    if (response.status === 400 && /already exists/i.test(text)) return { ok: true, resumed: true };
    if (!response.ok) throw new Error(`register failed: ${response.status} ${text}`);
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`register failed: ${text}`);
    }
    if (parsed.message !== "registration successful") throw new Error(`register failed: ${text}`);
    return { ok: true };
  }

  mintPayload() {
    const id = `${this.correlationId}${fromAlphabet(ZBASE32, 13)}`;
    const host = this.pinned.hostname;
    const numeric = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || numeric;
    if (loopback) {
      return {
        token: this.correlationId,
        correlationId: this.correlationId,
        url: `${this.apiBase}/${id}`,
        dnsName: null,
        payload: id,
      };
    }
    const dnsName = `${id}.${host}`;
    const scheme = new URL(this.apiBase).protocol;
    return {
      token: this.correlationId,
      correlationId: this.correlationId,
      url: `${scheme}//${dnsName}/`,
      dnsName,
      payload: dnsName,
    };
  }

  decrypt(aesKeyB64, messageB64) {
    const aesKey = privateDecrypt(oaep(this.privateKey), Buffer.from(aesKeyB64, "base64"));
    const cipherText = Buffer.from(messageB64, "base64");
    if (cipherText.length < 16) throw new Error("ciphertext block size is too small");
    const iv = cipherText.subarray(0, 16);
    const data = cipherText.subarray(16);
    const decipher = createDecipheriv("aes-256-ctr", aesKey, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  normalize(event) {
    const unique = String(event?.["unique-id"] || event?.unique_id || "");
    const full = String(event?.["full-id"] || event?.full_id || "");
    const protocol = String(event?.protocol || "").toLowerCase();
    if (!protocol) return null;
    if (!unique.startsWith(this.correlationId) && !full.includes(this.correlationId)) return null;
    return {
      token: this.correlationId,
      kind: protocol,
      protocol,
      unique_id: unique,
      full_id: full,
      path: full,
      source_ip: event["remote-address"] || event.remote_address || "",
      ts: event.timestamp || new Date().toISOString(),
      raw_request: event["raw-request"] || event.raw_request || "",
      recorded: true,
    };
  }

  decodePoll(body) {
    const events = [];
    if (body?.aes_key && Array.isArray(body.data)) {
      for (const item of body.data) {
        try {
          events.push(JSON.parse(this.decrypt(body.aes_key, item).toString("utf8")));
        } catch {
          // Undecryptable ciphertext is dropped. It is not turned into a hit.
        }
      }
    }
    for (const plain of [...(body?.extra || []), ...(body?.tlddata || [])]) {
      try {
        events.push(typeof plain === "string" ? JSON.parse(plain) : plain);
      } catch {
        /* skip malformed plaintext rows */
      }
    }
    return events.map((event) => this.normalize(event)).filter(Boolean);
  }

  async poll() {
    const url = `${this.apiBase}/poll?id=${encodeURIComponent(this.correlationId)}&secret=${encodeURIComponent(this.secretKey)}`;
    const response = await this.request(url, { method: "GET", headers: this.headers() });
    const text = await response.text();
    if (!response.ok) throw new Error(`poll failed: ${response.status} ${text}`);
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`poll failed: ${text}`);
    }
    const interactions = this.decodePoll(body);
    if (this.logPath) {
      for (const row of interactions) appendFileSync(this.logPath, `${JSON.stringify(row)}\n`);
    }
    return interactions;
  }

  async deregister() {
    const body = JSON.stringify({
      "correlation-id": this.correlationId,
      "secret-key": this.secretKey,
    });
    const response = await this.request(`${this.apiBase}/deregister`, {
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`deregister failed: ${response.status} ${text}`);
    return { ok: true };
  }
}
