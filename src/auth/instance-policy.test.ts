import assert from "node:assert/strict";
import { describe, it } from "vitest";

import { readInstanceAuthPolicy } from "./instance-policy.js";

describe("readInstanceAuthPolicy password sign-in", () => {
  it("keeps password sign-in enabled when the switch is unset or blank", () => {
    assert.equal(readInstanceAuthPolicy({}).passwordSignIn, "enabled");
    assert.equal(
      readInstanceAuthPolicy({ PASEO_HUB_PASSWORD_SIGN_IN: "  " }).passwordSignIn,
      "enabled",
    );
    assert.equal(
      readInstanceAuthPolicy({ PASEO_HUB_PASSWORD_SIGN_IN: "enabled" }).passwordSignIn,
      "enabled",
    );
  });

  it("rejects a value other than enabled or disabled", () => {
    assert.throws(
      () => readInstanceAuthPolicy({ PASEO_HUB_PASSWORD_SIGN_IN: "off" }),
      /^Error: PASEO_HUB_PASSWORD_SIGN_IN must be one of: enabled, disabled$/,
    );
  });

  it("accepts a bootstrap owner without a password when password sign-in is disabled", () => {
    assert.deepEqual(
      readInstanceAuthPolicy({
        PASEO_HUB_PASSWORD_SIGN_IN: "disabled",
        PASEO_BOOTSTRAP_ORGANIZATION: "Drieam",
        PASEO_BOOTSTRAP_OWNER_EMAIL: "Owner@Example.test",
      }),
      {
        registrationMode: "invite_only",
        organizationCreation: "disabled",
        passwordSignIn: "disabled",
        bootstrap: {
          organizationName: "Drieam",
          ownerEmail: "owner@example.test",
          ownerPassword: undefined,
        },
      },
    );
  });

  it("refuses a bootstrap password when password sign-in is disabled", () => {
    assert.throws(
      () =>
        readInstanceAuthPolicy({
          PASEO_HUB_PASSWORD_SIGN_IN: "disabled",
          PASEO_BOOTSTRAP_ORGANIZATION: "Drieam",
          PASEO_BOOTSTRAP_OWNER_EMAIL: "owner@example.test",
          PASEO_BOOTSTRAP_OWNER_PASSWORD: "temporary-owner-password",
        }),
      /^Error: PASEO_BOOTSTRAP_OWNER_PASSWORD must be unset when PASEO_HUB_PASSWORD_SIGN_IN is disabled$/,
    );
  });

  it("requires the organization and owner email together when password sign-in is disabled", () => {
    assert.throws(
      () =>
        readInstanceAuthPolicy({
          PASEO_HUB_PASSWORD_SIGN_IN: "disabled",
          PASEO_BOOTSTRAP_OWNER_EMAIL: "owner@example.test",
        }),
      /^Error: PASEO_BOOTSTRAP_ORGANIZATION and PASEO_BOOTSTRAP_OWNER_EMAIL must be supplied together$/,
    );
  });
});
