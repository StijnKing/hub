import assert from "node:assert/strict";
import { describe, it } from "vitest";

import { readGoogleSignInConfig } from "./google-sign-in.js";

describe("readGoogleSignInConfig", () => {
  it("returns undefined when neither credential is set", () => {
    assert.equal(readGoogleSignInConfig({}), undefined);
  });

  it("returns undefined when both credentials are blank", () => {
    assert.equal(
      readGoogleSignInConfig({
        PASEO_HUB_GOOGLE_CLIENT_ID: " ",
        PASEO_HUB_GOOGLE_CLIENT_SECRET: "",
      }),
      undefined,
    );
  });

  it("returns the trimmed client when both credentials are set", () => {
    assert.deepEqual(
      readGoogleSignInConfig({
        PASEO_HUB_GOOGLE_CLIENT_ID: " 123.apps.googleusercontent.com ",
        PASEO_HUB_GOOGLE_CLIENT_SECRET: " GOCSPX-secret ",
      }),
      { clientId: "123.apps.googleusercontent.com", clientSecret: "GOCSPX-secret" },
    );
  });

  it("throws when only the client ID is set", () => {
    assert.throws(
      () =>
        readGoogleSignInConfig({ PASEO_HUB_GOOGLE_CLIENT_ID: "123.apps.googleusercontent.com" }),
      /^Error: PASEO_HUB_GOOGLE_CLIENT_SECRET is required when PASEO_HUB_GOOGLE_CLIENT_ID is set$/,
    );
  });

  it("throws when only the client secret is set", () => {
    assert.throws(
      () => readGoogleSignInConfig({ PASEO_HUB_GOOGLE_CLIENT_SECRET: "GOCSPX-secret" }),
      /^Error: PASEO_HUB_GOOGLE_CLIENT_ID is required when PASEO_HUB_GOOGLE_CLIENT_SECRET is set$/,
    );
  });
});
