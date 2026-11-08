export interface GoogleSignInConfig {
  clientId: string;
  clientSecret: string;
}

const CLIENT_ID = "PASEO_HUB_GOOGLE_CLIENT_ID";
const CLIENT_SECRET = "PASEO_HUB_GOOGLE_CLIENT_SECRET";

/** Undefined keeps sign-in to email and password: no Google routes, provider, or button. */
export function readGoogleSignInConfig(
  environment: Record<string, string | undefined> = process.env,
): GoogleSignInConfig | undefined {
  const clientId = environment[CLIENT_ID]?.trim() ?? "";
  const clientSecret = environment[CLIENT_SECRET]?.trim() ?? "";
  if (clientId.length === 0 && clientSecret.length === 0) return undefined;
  if (clientSecret.length === 0) {
    throw new Error(`${CLIENT_SECRET} is required when ${CLIENT_ID} is set`);
  }
  if (clientId.length === 0) {
    throw new Error(`${CLIENT_ID} is required when ${CLIENT_SECRET} is set`);
  }
  return { clientId, clientSecret };
}
