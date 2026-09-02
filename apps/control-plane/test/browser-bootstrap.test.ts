import { exports } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { describe, expect, it } from "vitest";
import { base64url, canonicalJson } from "../src/crypto.ts";

function cborHead(major: number, value: number): number[] {
  if (value < 24) return [(major << 5) | value];
  if (value < 256) return [(major << 5) | 24, value];
  if (value < 65_536) return [(major << 5) | 25, value >> 8, value & 0xff];
  throw new Error("CBOR test value is too large");
}

function cbor(value: unknown): number[] {
  if (typeof value === "number" && Number.isInteger(value)) return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === "string") {
    const bytes = [...new TextEncoder().encode(value)];
    return [...cborHead(3, bytes.length), ...bytes];
  }
  if (value instanceof Uint8Array) return [...cborHead(2, value.length), ...value];
  if (value instanceof Map) {
    const entries = [...value.entries()];
    return [...cborHead(5, entries.length), ...entries.flatMap(([key, item]) => [...cbor(key), ...cbor(item)])];
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) return cbor(new Map(Object.entries(value)));
  throw new Error("Unsupported CBOR test value");
}

function cookiePair(response: Response): { cookie: string; csrf: string } {
  const header = response.headers.get("set-cookie") ?? "";
  const session = header.match(/__Host-conduit_session=([^;,]+)/)?.[1];
  const csrf = header.match(/__Host-conduit_csrf=([^;,]+)/)?.[1];
  if (session === undefined || csrf === undefined) throw new Error(`Missing browser cookies: ${header}`);
  return { cookie: `__Host-conduit_session=${session}; __Host-conduit_csrf=${csrf}`, csrf };
}

function derEcdsaSignature(signature: Uint8Array): Uint8Array {
  if (signature[0] === 0x30) return signature;
  const integer = (bytes: Uint8Array) => {
    let offset = 0;
    while (offset < bytes.length - 1 && bytes[offset] === 0) offset += 1;
    const value = bytes.slice(offset);
    return value[0]! >= 0x80 ? Uint8Array.from([0, ...value]) : value;
  };
  const r = integer(signature.slice(0, 32));
  const s = integer(signature.slice(32, 64));
  return Uint8Array.from([0x30, 4 + r.length + s.length, 0x02, r.length, ...r, 0x02, s.length, ...s]);
}

async function assertionBody(ceremony: { challengeId: string; options: { challenge: string } }, credentialId: string, privateKey: CryptoKey, counter: number) {
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: ceremony.options.challenge, origin: "https://conduit.example.com", crossOrigin: false }));
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("conduit.example.com")));
  const authenticatorData = Uint8Array.from([...rpIdHash, 0x05, counter >>> 24, counter >>> 16, counter >>> 8, counter]);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, Uint8Array.from([...authenticatorData, ...clientDataHash])));
  return { challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, response: { id: credentialId, rawId: credentialId, type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: {}, response: { clientDataJSON: base64url(clientDataJSON), authenticatorData: base64url(authenticatorData), signature: base64url(derEcdsaSignature(rawSignature)), userHandle: null } } };
}

describe.sequential("clean browser bootstrap", () => {
  it("registers the Owner, logs in again, approves enrollment, polls the receipt, and connects the Node", async () => {
    const setupPage = await exports.default.fetch(new Request("https://conduit.example.com/setup"));
    expect(await setupPage.text()).toContain("id=passkey-setup");
    const browserScript = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/browser.js"));
    expect(await browserScript.text()).toContain("navigator.credentials.create");
    const bootstrapSecret = "test-bootstrap-secret";
    const optionsResponse = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/setup/options", { method: "POST", headers: { origin: "https://conduit.example.com", "content-type": "application/json" }, body: JSON.stringify({ displayName: "Owner", bootstrapSecret }) }));
    expect(optionsResponse.status, await optionsResponse.clone().text()).toBe(200);
    const ceremony = await optionsResponse.json<{ challengeId: string; options: { challenge: string } }>();
    const credentialIdBytes = crypto.getRandomValues(new Uint8Array(32));
    const credentialId = base64url(credentialIdBytes);
    const passkey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey("raw", passkey.publicKey) as ArrayBuffer);
    const cose = new Map<unknown, unknown>([[1, 2], [3, -7], [-1, 1], [-2, rawPublic.slice(1, 33)], [-3, rawPublic.slice(33, 65)]]);
    const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("conduit.example.com")));
    const authData = Uint8Array.from([...rpIdHash, 0x45, 0, 0, 0, 0, ...new Uint8Array(16), credentialIdBytes.length >> 8, credentialIdBytes.length & 0xff, ...credentialIdBytes, ...cbor(cose)]);
    const attestationObject = Uint8Array.from(cbor(new Map<unknown, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]])));
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: ceremony.options.challenge, origin: "https://conduit.example.com", crossOrigin: false }));
    const setup = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/setup/verify", { method: "POST", headers: { origin: "https://conduit.example.com", "content-type": "application/json" }, body: JSON.stringify({ challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, bootstrapSecret, displayName: "Owner", label: "Owner passkey", transports: ["internal"], response: { id: credentialId, rawId: credentialId, type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: {}, response: { clientDataJSON: base64url(clientDataJSON), attestationObject: base64url(attestationObject), transports: ["internal"] } } }) }));
    expect(setup.status, await setup.clone().text()).toBe(201);
    const firstSession = cookiePair(setup);

    const logout = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/logout", { method: "POST", headers: { cookie: firstSession.cookie, origin: "https://conduit.example.com", "x-csrf-token": firstSession.csrf, "content-type": "application/json" }, body: "{}" }));
    expect(logout.status, await logout.clone().text()).toBe(200);
    const loginOptions = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/login/options", { method: "POST", headers: { origin: "https://conduit.example.com", "content-type": "application/json" }, body: "{}" }));
    const loginCeremony = await loginOptions.json<{ challengeId: string; options: { challenge: string } }>();
    const login = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/login/verify", { method: "POST", headers: { origin: "https://conduit.example.com", "content-type": "application/json" }, body: JSON.stringify(await assertionBody(loginCeremony, credentialId, passkey.privateKey, 1)) }));
    expect(login.status, await login.clone().text()).toBe(200);
    let session = cookiePair(login);

    const nodeKey = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const nodeJwk = await crypto.subtle.exportKey("jwk", nodeKey.publicKey) as JsonWebKey;
    const keyId = "dkey_browser_bootstrap01";
    const claims = { hostnameLabel: "clean-node", os: "linux", arch: "x86_64", nodeVersion: "0.1.0", protocolVersion: "conduit.node/1" };
    const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const transcript = `conduit.enrollment.v1\n${canonicalJson({ claims, keyId, publicJwk: { kty: "OKP", crv: "Ed25519", x: nodeJwk.x }, clientNonce })}`;
    const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", nodeKey.privateKey, new TextEncoder().encode(transcript))));
    const enrolled = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/device-enrollments", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ claims, keyId, publicJwk: { kty: "OKP", crv: "Ed25519", x: nodeJwk.x }, clientNonce, signature }) }));
    expect(enrolled.status, await enrolled.clone().text()).toBe(201);
    const enrollment = await enrolled.json<{ enrollmentId: string; deviceCode: string; userCode: string }>();
    const pending = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/device-enrollments/pending?userCode=${encodeURIComponent(enrollment.userCode)}`, { headers: { cookie: session.cookie } }));
    await expect(pending.json()).resolves.toMatchObject({ enrollmentId: enrollment.enrollmentId, fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/), claims: { hostnameLabel: "clean-node" } });

    const stepOptions = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/step-up/options", { method: "POST", headers: { cookie: session.cookie, origin: "https://conduit.example.com", "x-csrf-token": session.csrf, "content-type": "application/json" }, body: "{}" }));
    const stepCeremony = await stepOptions.json<{ challengeId: string; options: { challenge: string } }>();
    const step = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/step-up/verify", { method: "POST", headers: { cookie: session.cookie, origin: "https://conduit.example.com", "x-csrf-token": session.csrf, "content-type": "application/json" }, body: JSON.stringify(await assertionBody(stepCeremony, credentialId, passkey.privateKey, 2)) }));
    expect(step.status, await step.clone().text()).toBe(200);
    session = cookiePair(step);
    const approved = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/device-enrollments/${enrollment.enrollmentId}/decision`, { method: "POST", headers: { cookie: session.cookie, origin: "https://conduit.example.com", "x-csrf-token": session.csrf, "content-type": "application/json" }, body: JSON.stringify({ decision: "approve" }) }));
    expect(approved.status, await approved.clone().text()).toBe(200);
    const approval = await approved.json<{ deviceId: string }>();
    const poll = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/device-enrollments/poll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ deviceCode: enrollment.deviceCode }) }));
    await expect(poll.json()).resolves.toMatchObject({ state: "completed", deviceId: approval.deviceId, keyId });

    const connected = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${approval.deviceId}/connect`, { headers: { upgrade: "websocket" } }));
    expect(connected.status).toBe(101);
    const socket = connected.webSocket!;
    socket.accept();
    const queued: string[] = [];
    const waiters: Array<(message: string) => void> = [];
    socket.addEventListener("message", (event) => {
      const waiter = waiters.shift();
      if (waiter === undefined) queued.push(String(event.data)); else waiter(String(event.data));
    });
    const next = () => queued.length > 0 ? Promise.resolve(queued.shift()!) : new Promise<string>((resolve) => waiters.push(resolve));
    const connectionNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const challengePending = next();
    socket.send(JSON.stringify({ type: "device.hello", deviceId: approval.deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "1".repeat(64), clientNonce: connectionNonce, nodeBootId: "node-boot-browser-bootstrap01" }));
    const connectionChallenge = parseWireDocumentText(schemaIds.nodeV1, await challengePending);
    if (connectionChallenge.type !== "device.challenge") throw new Error("expected device.challenge");
    const connectionTranscript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce: connectionNonce, connectionId: connectionChallenge.connectionId, deviceId: approval.deviceId, keyId, protocol: connectionChallenge.selectedProtocol, serverNonce: connectionChallenge.serverNonce, serverTime: connectionChallenge.serverTime });
    const connectionSignature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", nodeKey.privateKey, new TextEncoder().encode(connectionTranscript))));
    const acceptedPending = next();
    socket.send(JSON.stringify({ type: "device.proof", connectionId: connectionChallenge.connectionId, deviceId: approval.deviceId, keyId, signature: connectionSignature }));
    const accepted = parseWireDocumentText(schemaIds.nodeV1, await acceptedPending);
    expect(accepted).toMatchObject({ type: "transport.accepted", deviceId: approval.deviceId });
    socket.close(1000, "bootstrap_complete");
  });
});
