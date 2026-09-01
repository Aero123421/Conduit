import { keyedHash, newId, nowIso, randomToken } from "../crypto.ts";
import { PublicError } from "../errors.ts";

export interface SessionRow {
  id: string;
  principal_id: string;
  verifier_hash: string;
  csrf_hash: string;
  kind: "owner" | "recovery";
  status: "active" | "revoked" | "expired";
  authenticated_at: string;
  fresh_authenticated_at: string | null;
  last_activity_at: string;
  expires_at: string;
  user_verified: number;
}

export interface PasskeyRow {
  id: string;
  principal_id: string;
  credential_id: string;
  public_key: ArrayBuffer;
  relying_party_id: string;
  sign_count: number;
  status: "active" | "revoked";
  transports_json: string;
}

export class AuthRepository {
  constructor(private readonly db: D1Database, private readonly pepper: string) {}

  async owner(): Promise<{ id: string; display_name: string; status: string } | null> {
    return this.db.prepare("SELECT id, display_name, status FROM owner_principals ORDER BY created_at LIMIT 1").first();
  }

  async createChallenge(input: { kind: string; principalId?: string; sessionId?: string; challenge: string; bindingDigest?: string; origin: string; rpId: string; state?: unknown }): Promise<string> {
    const id = newId("chal");
    const now = new Date();
    await this.db.prepare(
      "INSERT INTO auth_challenges(id,kind,principal_id,session_id,challenge_hash,binding_digest,expected_origin,expected_rp_id,state_json,expires_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
    ).bind(id, input.kind, input.principalId ?? null, input.sessionId ?? null, await keyedHash(this.pepper, input.challenge), input.bindingDigest ?? null, input.origin, input.rpId, JSON.stringify(input.state ?? {}), new Date(now.getTime() + 300_000).toISOString(), now.toISOString()).run();
    return id;
  }

  async consumeChallenge(id: string, challenge: string, expectedKind: string): Promise<{ principal_id: string | null; session_id: string | null; expected_origin: string; expected_rp_id: string; state_json: string }> {
    const hash = await keyedHash(this.pepper, challenge);
    const now = nowIso();
    const row = await this.db.prepare(
      "SELECT principal_id,session_id,expected_origin,expected_rp_id,state_json FROM auth_challenges WHERE id=?1 AND kind=?2 AND challenge_hash=?3 AND consumed_at IS NULL AND expires_at>?4 LIMIT 1",
    ).bind(id, expectedKind, hash, now).first<{ principal_id: string | null; session_id: string | null; expected_origin: string; expected_rp_id: string; state_json: string }>();
    if (row === null) throw new PublicError("authentication_required", 401, "Challenge is invalid or expired");
    const result = await this.db.prepare("UPDATE auth_challenges SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL").bind(now, id).run();
    if (result.meta.changes !== 1) throw new PublicError("authentication_required", 401, "Challenge was already consumed");
    return row;
  }

  async createOwnerAndPasskey(input: { displayName: string; credentialId: string; publicKey: Uint8Array; rpId: string; label?: string; transports: string[]; signCount: number }): Promise<string> {
    if (await this.owner() !== null) throw new PublicError("invalid_request", 409, "Owner already exists");
    const principalId = newId("prin");
    const passkeyId = newId("pkey");
    const now = nowIso();
    await this.db.batch([
      this.db.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES (?1,?2,'active',?3,?3)").bind(principalId, input.displayName, now),
      this.db.prepare("INSERT INTO passkeys(id,principal_id,credential_id,public_key,relying_party_id,label,transports_json,sign_count,status,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9)").bind(passkeyId, principalId, input.credentialId, input.publicKey, input.rpId, input.label ?? null, JSON.stringify(input.transports), input.signCount, now),
      this.db.prepare("INSERT INTO security_events(id,event_type,principal_id,metadata_json,created_at) VALUES (?1,'owner.bootstrap',?2,?3,?4)").bind(newId("sevt"), principalId, JSON.stringify({ passkeyId }), now),
    ]);
    return principalId;
  }

  async passkeys(principalId?: string): Promise<PasskeyRow[]> {
    const statement = principalId === undefined
      ? this.db.prepare("SELECT id,principal_id,credential_id,public_key,relying_party_id,sign_count,status,transports_json FROM passkeys WHERE status='active'")
      : this.db.prepare("SELECT id,principal_id,credential_id,public_key,relying_party_id,sign_count,status,transports_json FROM passkeys WHERE principal_id=?1 AND status='active'").bind(principalId);
    return (await statement.all<PasskeyRow>()).results;
  }

  async passkeyByCredential(credentialId: string): Promise<PasskeyRow> {
    const row = await this.db.prepare("SELECT id,principal_id,credential_id,public_key,relying_party_id,sign_count,status,transports_json FROM passkeys WHERE credential_id=?1 AND status='active' LIMIT 1").bind(credentialId).first<PasskeyRow>();
    if (row === null) throw new PublicError("authentication_required", 401, "Passkey is not active");
    return row;
  }

  async notePasskeyUse(id: string, counter: number): Promise<void> {
    await this.db.prepare("UPDATE passkeys SET sign_count=?1,last_used_at=?2 WHERE id=?3 AND status='active'").bind(counter, nowIso(), id).run();
  }

  async createSession(principalId: string, kind: "owner" | "recovery", userVerified: boolean): Promise<{ id: string; token: string; csrf: string; expiresAt: string }> {
    const id = newId("bsess");
    const token = randomToken();
    const csrf = randomToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (kind === "owner" ? 7 * 86_400_000 : 15 * 60_000)).toISOString();
    await this.db.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES (?1,?2,?3,?4,?5,'active',?6,?7,?6,?8,?9)")
      .bind(id, principalId, await keyedHash(this.pepper, token), await keyedHash(this.pepper, csrf), kind, now.toISOString(), userVerified ? now.toISOString() : null, expiresAt, userVerified ? 1 : 0).run();
    return { id, token, csrf, expiresAt };
  }

  async session(token: string): Promise<SessionRow> {
    const now = nowIso();
    const row = await this.db.prepare("SELECT * FROM owner_sessions WHERE verifier_hash=?1 AND status='active' AND expires_at>?2 AND last_activity_at>?3 LIMIT 1")
      .bind(await keyedHash(this.pepper, token), now, new Date(Date.now() - 86_400_000).toISOString()).first<SessionRow>();
    if (row === null) throw new PublicError("authentication_required", 401, "Browser session is invalid or expired");
    await this.db.prepare("UPDATE owner_sessions SET last_activity_at=?1 WHERE id=?2").bind(now, row.id).run();
    return row;
  }

  async verifyCsrf(session: SessionRow, token: string): Promise<void> {
    if (await keyedHash(this.pepper, token) !== session.csrf_hash) throw new PublicError("csrf_failed", 403, "CSRF validation failed");
  }

  requireFresh(session: SessionRow): void {
    if (!session.user_verified || session.fresh_authenticated_at === null || Date.parse(session.fresh_authenticated_at) < Date.now() - 300_000) {
      throw new PublicError("fresh_authentication_required", 403, "Fresh passkey authentication is required");
    }
  }

  async generateRecoveryCodes(principalId: string): Promise<string[]> {
    const batchId = newId("recbatch");
    const now = nowIso();
    const codes = Array.from({ length: 10 }, () => randomToken(18));
    const hashes = await Promise.all(codes.map((code) => keyedHash(this.pepper, code)));
    await this.db.batch(codes.map((_, index) => this.db.prepare("INSERT INTO recovery_codes(id,principal_id,verifier_hash,batch_id,created_at) VALUES (?1,?2,?3,?4,?5)").bind(newId("recovery"), principalId, hashes[index]!, batchId, now)));
    return codes;
  }

  async consumeRecoveryCode(code: string): Promise<string> {
    const hash = await keyedHash(this.pepper, code);
    const now = nowIso();
    const row = await this.db.prepare("SELECT id,principal_id FROM recovery_codes WHERE verifier_hash=?1 AND consumed_at IS NULL AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?2) LIMIT 1").bind(hash, now).first<{ id: string; principal_id: string }>();
    if (row === null) throw new PublicError("authentication_required", 401, "Recovery code is invalid");
    const result = await this.db.prepare("UPDATE recovery_codes SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL").bind(now, row.id).run();
    if (result.meta.changes !== 1) throw new PublicError("authentication_required", 401, "Recovery code was already used");
    return row.principal_id;
  }

  async audit(eventType: string, metadata: Record<string, unknown>, principalId?: string, clientId?: string, deviceId?: string, reasonCode?: string): Promise<void> {
    await this.db.prepare("INSERT INTO security_events(id,event_type,principal_id,client_id,device_id,reason_code,metadata_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")
      .bind(newId("sevt"), eventType, principalId ?? null, clientId ?? null, deviceId ?? null, reasonCode ?? null, JSON.stringify(metadata), nowIso()).run();
  }
}

export function sessionCookie(token: string, expiresAt: string): string {
  return `__Host-conduit_session=${token}; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=${new Date(expiresAt).toUTCString()}`;
}

export function readCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie");
  if (cookie === null) return null;
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}
