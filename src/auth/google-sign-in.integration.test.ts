import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, it, vi } from "vitest";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { hashPassword } from "better-auth/crypto";
import {
  createDatabase,
  createPostgresQueryRuntime,
  testDatabaseLocks,
  testDatabaseRuntime,
} from "../db/test-utils/runtime.js";
import type { RegistrationMode } from "./instance-policy.js";
import { accountStateSchema, type AccountState } from "./organization-contract.js";
import { createAuthServer, type AuthServer } from "./server.js";
import { composeEntitlements } from "./entitlements.js";

const APP_URL = "http://localhost:3000";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE = { clientId: "google-client-id", clientSecret: "google-client-secret" };

interface GoogleProfile {
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string;
}

describe("Google sign-in boundary", () => {
  let postgres: StartedPostgreSqlContainer;
  const running: Array<() => Promise<void>> = [];

  beforeAll(async () => {
    postgres = await new PostgreSqlContainer("postgres:17-alpine").start();
  }, 120_000);

  afterAll(async () => {
    await postgres.stop();
  }, 120_000);

  afterEach(async () => {
    vi.unstubAllGlobals();
    await Promise.all(running.splice(0).map((close) => close()));
  });

  it("exposes no Google surface when the client is not configured", async () => {
    const hub = await startHub("open");
    await hub.seedPasswordUser("existing@example.test", { emailVerified: true });
    assert.equal((await hub.beginSignIn()).status, 404);
    const callback = await hub.auth.handle(
      new Request(`${APP_URL}/api/auth/callback/google?code=code&state=state`),
    );
    assert.equal(callback.status, 404);
    const state = await hub.state("");
    assert.equal(state.status, "signedOut");
    assert.equal("googleSignIn" in state, false);
  });

  it("advertises Google sign-in and refuses to start it from a foreign origin", async () => {
    const hub = await startHub("open", GOOGLE);
    await hub.seedPasswordUser("existing@example.test", { emailVerified: true });
    const state = await hub.state("");
    assert.equal(state.status === "signedOut" && state.googleSignIn, true);
    assert.equal((await hub.beginSignIn({ origin: "https://attacker.example" })).status, 403);
    assert.equal((await hub.beginSignIn({ origin: null })).status, 403);
    const start = await hub.beginSignIn();
    assert.equal(start.status, 303);
    const authorization = new URL(start.headers.get("location")!);
    assert.equal(authorization.origin, "https://accounts.google.com");
    assert.equal(authorization.searchParams.get("client_id"), GOOGLE.clientId);
    assert.equal(
      authorization.searchParams.get("redirect_uri"),
      `${APP_URL}/api/auth/callback/google`,
    );
  });

  it("creates a Google account in open mode only for a verified Google email", async () => {
    const hub = await startHub("open", GOOGLE);
    const unverified = await hub.googleSignIn({
      sub: "google-unverified",
      email: "unverified@example.test",
      emailVerified: false,
      name: "Unverified",
    });
    assert.equal(unverified.error, "email_not_verified");
    assert.equal(await hub.userCount(), 0);

    const verified = await hub.googleSignIn({
      sub: "google-open",
      email: "Open@Example.test",
      emailVerified: true,
      name: "Open",
    });
    assert.equal(verified.location, `${APP_URL}/`);
    const state = await hub.state(verified.cookie);
    assert.equal(state.status, "organizationRequired");
    assert.equal(state.account.email, "open@example.test");
  });

  it("admits new Google accounts in invite-only mode only through a matching invitation", async () => {
    const hub = await startHub("invite_only", GOOGLE);
    const invitation = await hub.seedInvitation("invited@example.test");
    const profile = {
      sub: "google-invited",
      email: "invited@example.test",
      emailVerified: true,
      name: "Invited",
    };

    assert.equal((await hub.googleSignIn(profile)).error, "registration_closed");
    const mismatched = await hub.googleSignIn(
      { ...profile, sub: "google-other", email: "other@example.test" },
      invitation,
    );
    assert.equal(mismatched.error, "registration_closed");
    assert.equal(
      mismatched.location,
      `${APP_URL}/?invitation=${invitation}&auth=google-sign-in&error=registration_closed`,
    );
    assert.equal(await hub.userCount(), 1);

    const admitted = await hub.googleSignIn(profile, invitation);
    assert.equal(admitted.location, `${APP_URL}/?invitation=${invitation}`);
    const state = await hub.state(admitted.cookie, invitation);
    assert.equal(state.status, "organizationRequired");
    assert.equal(state.invitation?.id, invitation);
    assert.equal(await hub.userCount(), 2);
  });

  it("closes Google account creation when registration is disabled", async () => {
    const hub = await startHub("disabled", GOOGLE);
    const invitation = await hub.seedInvitation("closed@example.test");
    const result = await hub.googleSignIn(
      { sub: "google-closed", email: "closed@example.test", emailVerified: true, name: "Closed" },
      invitation,
    );
    assert.equal(result.error, "registration_closed");
    assert.equal(await hub.userCount(), 1);
  });

  it("links a verified Google email to the existing password account", async () => {
    const hub = await startHub("invite_only", GOOGLE);
    const owner = await hub.seedPasswordUser("owner@example.test", { emailVerified: true });
    const result = await hub.googleSignIn({
      sub: "google-owner",
      email: "owner@example.test",
      emailVerified: true,
      name: "Google Name",
    });
    assert.equal(result.location, `${APP_URL}/`);
    const state = await hub.state(result.cookie);
    assert.equal(state.status, "organizationRequired");
    assert.equal(state.account.id, owner);
    assert.equal(state.account.name, "Seeded");
    assert.deepEqual(await hub.providers(owner), ["credential", "google"]);
    assert.equal(await hub.userCount(), 1);
    assert.equal((await hub.passwordSignIn("owner@example.test")).status, 200);

    const again = await hub.googleSignIn({
      sub: "google-owner",
      email: "owner@example.test",
      emailVerified: true,
      name: "Google Name",
    });
    assert.equal((await hub.state(again.cookie)).status, "organizationRequired");
    assert.deepEqual(await hub.providers(owner), ["credential", "google"]);
  });

  it("refuses to link when either side has not verified the email", async () => {
    const hub = await startHub("open", GOOGLE);
    const unverifiedGoogle = await hub.seedPasswordUser("verified@example.test", {
      emailVerified: true,
    });
    const result = await hub.googleSignIn({
      sub: "google-unverified-link",
      email: "verified@example.test",
      emailVerified: false,
      name: "Attacker",
    });
    assert.equal(result.error, "account_not_linked");
    assert.deepEqual(await hub.providers(unverifiedGoogle), ["credential"]);

    const unverifiedLocal = await hub.seedPasswordUser("unverified-local@example.test", {
      emailVerified: false,
    });
    const local = await hub.googleSignIn({
      sub: "google-unverified-local",
      email: "unverified-local@example.test",
      emailVerified: true,
      name: "Local",
    });
    assert.equal(local.error, "account_not_linked");
    assert.deepEqual(await hub.providers(unverifiedLocal), ["credential"]);
  });

  it("keeps a required password change in front of a Google sign-in", async () => {
    const hub = await startHub("invite_only", GOOGLE);
    await hub.seedPasswordUser("bootstrap@example.test", {
      emailVerified: true,
      mustChangePassword: true,
    });
    const result = await hub.googleSignIn({
      sub: "google-bootstrap",
      email: "bootstrap@example.test",
      emailVerified: true,
      name: "Bootstrap",
    });
    assert.equal((await hub.state(result.cookie)).status, "passwordChangeRequired");
  });

  it("leaves invited password sign-up working alongside Google", async () => {
    const hub = await startHub("invite_only", GOOGLE);
    const invitation = await hub.seedInvitation("password@example.test");
    const url = new URL(`${APP_URL}/api/auth/sign-up/email`);
    url.searchParams.set("invitation", invitation);
    const response = await hub.auth.handle(
      new Request(url, {
        method: "POST",
        headers: { origin: APP_URL, "content-type": "application/json" },
        body: JSON.stringify({
          name: "Password",
          email: "password@example.test",
          password: "long-password-123",
        }),
      }),
    );
    assert.equal(response.status, 200);
    assert.equal(await hub.userCount(), 2);
  });

  async function startHub(registrationMode: RegistrationMode, google?: typeof GOOGLE) {
    const url = new URL(postgres.getConnectionUri());
    url.pathname = `/google_${randomUUID().replaceAll("-", "")}`;
    const database = await createDatabase(url.toString());
    const entitlements = composeEntitlements(database, testDatabaseRuntime(database));
    const auth = createAuthServer({
      database: testDatabaseRuntime(database),
      locks: testDatabaseLocks(database),
      entitlements: entitlements.service,
      secret: "google-sign-in-secret-at-least-32-characters",
      baseURL: APP_URL,
      policy: { registrationMode, organizationCreation: "disabled", bootstrap: undefined },
      ...(google === undefined ? {} : { google }),
    });
    running.push(async () => {
      await auth.close();
      await entitlements.close();
      await database.close();
    });
    return new GoogleHub(auth, url.toString());
  }
});

class GoogleHub {
  private readonly profiles = new Map<string, GoogleProfile>();

  constructor(
    readonly auth: AuthServer,
    private readonly url: string,
  ) {
    vi.stubGlobal("fetch", this.fetch(globalThis.fetch));
  }

  beginSignIn(options: { origin?: string | null; invitation?: string } = {}): Promise<Response> {
    const headers = new Headers({ "content-type": "application/x-www-form-urlencoded" });
    const origin = options.origin === undefined ? APP_URL : options.origin;
    if (origin !== null) headers.set("origin", origin);
    return this.auth.handle(
      new Request(`${APP_URL}/api/auth/sign-in/google`, {
        method: "POST",
        headers,
        body: new URLSearchParams(
          options.invitation === undefined ? {} : { invitation: options.invitation },
        ),
      }),
    );
  }

  async googleSignIn(
    profile: GoogleProfile,
    invitation?: string,
  ): Promise<{ location: string; cookie: string; error: string | null }> {
    const start = await this.beginSignIn(invitation === undefined ? {} : { invitation });
    assert.equal(start.status, 303);
    const state = new URL(start.headers.get("location")!).searchParams.get("state");
    assert.ok(state);
    const code = randomUUID();
    this.profiles.set(code, profile);
    const callback = await this.auth.handle(
      new Request(`${APP_URL}/api/auth/callback/google?code=${code}&state=${state}`, {
        headers: { cookie: cookieHeader(start) },
      }),
    );
    assert.equal(callback.status, 302);
    const location = callback.headers.get("location")!;
    return {
      location,
      cookie: cookieHeader(callback),
      error: new URL(location).searchParams.get("error"),
    };
  }

  async passwordSignIn(email: string): Promise<Response> {
    return this.auth.handle(
      new Request(`${APP_URL}/api/auth/sign-in/email`, {
        method: "POST",
        headers: { origin: APP_URL, "content-type": "application/json" },
        body: JSON.stringify({ email, password: "long-password-123" }),
      }),
    );
  }

  async state(cookie: string, invitation?: string): Promise<AccountState> {
    const url = new URL(`${APP_URL}/api/auth/paseo/state`);
    if (invitation !== undefined) url.searchParams.set("invitation", invitation);
    const response = await this.auth.handle(new Request(url, { headers: { cookie } }));
    assert.equal(response.status, 200);
    return accountStateSchema.parse(await response.json());
  }

  async seedPasswordUser(
    email: string,
    options: { emailVerified: boolean; mustChangePassword?: boolean },
  ): Promise<string> {
    const id = randomUUID();
    await this.query(
      `insert into "user" (id, name, email, email_verified, must_change_password)
       values ($1, 'Seeded', $2, $3, $4)`,
      [id, email, options.emailVerified, options.mustChangePassword ?? false],
    );
    await this.query(
      `insert into account (id, account_id, provider_id, user_id, password)
       values ($1, $2, 'credential', $2, $3)`,
      [randomUUID(), id, await hashPassword("long-password-123")],
    );
    return id;
  }

  async seedInvitation(email: string): Promise<string> {
    const id = randomUUID();
    const organizationId = `org-${id}`;
    const inviterId = `user-${id}`;
    await this.query(`insert into organization (id, name, slug) values ($1, 'Invites', $1)`, [
      organizationId,
    ]);
    await this.query(
      `insert into "user" (id, name, email, email_verified) values ($1, 'Inviter', $2, true)`,
      [inviterId, `inviter-${id}@example.test`],
    );
    await this.query(
      `insert into member (id, organization_id, user_id, role) values ($1, $2, $3, 'owner')`,
      [`member-${id}`, organizationId, inviterId],
    );
    await this.query(
      `insert into invitation (id, organization_id, email, role, status, expires_at, inviter_id)
       values ($1, $2, $3, 'member', 'pending', now() + interval '1 day', $4)`,
      [id, organizationId, email, inviterId],
    );
    return id;
  }

  async userCount(): Promise<number> {
    const rows = await this.query<{ count: number }>(
      `select count(*)::integer as count from "user"`,
    );
    return rows[0]!.count;
  }

  async providers(userId: string): Promise<string[]> {
    const rows = await this.query<{ provider_id: string }>(
      `select provider_id from account where user_id = $1 order by provider_id`,
      [userId],
    );
    return rows.map((row) => row.provider_id);
  }

  private fetch(original: typeof fetch): typeof fetch {
    return async (input, init) => {
      const request = new Request(input, init);
      if (request.url !== GOOGLE_TOKEN_ENDPOINT) return original(input, init);
      const body = new URLSearchParams(await request.text());
      assert.equal(body.get("redirect_uri"), `${APP_URL}/api/auth/callback/google`);
      const profile = this.profiles.get(body.get("code") ?? "");
      if (profile === undefined) return Response.json({ error: "invalid_grant" }, { status: 400 });
      return Response.json({
        access_token: `access-${profile.sub}`,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid email profile",
        id_token: unsignedIdToken(profile),
      });
    };
  }

  private async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values: unknown[] = [],
  ): Promise<TRow[]> {
    const client = await createPostgresQueryRuntime(this.url);
    try {
      return (await client.query<TRow>(text, values)).rows;
    } finally {
      await client.close();
    }
  }
}

function unsignedIdToken(profile: GoogleProfile): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  return [
    encode({ alg: "none", typ: "JWT" }),
    encode({
      iss: "https://accounts.google.com",
      aud: "google-client-id",
      sub: profile.sub,
      email: profile.email,
      email_verified: profile.emailVerified,
      name: profile.name,
      iat: now,
      exp: now + 3600,
    }),
    "",
  ].join(".");
}

function cookieHeader(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";", 1)[0]!)
    .filter((cookie) => !cookie.endsWith("="))
    .join("; ");
}
