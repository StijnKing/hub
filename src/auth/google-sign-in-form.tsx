import { AuthActions } from "../components/app/auth-form.js";
import { Button } from "../components/ui/button.js";
import { Input } from "../components/ui/input.js";

const GOOGLE_SIGN_IN_ERRORS: Record<string, string> = {
  registration_closed:
    "Hub has no account for this Google email address and isn't accepting it as a new one. Ask an organization owner to invite that address.",
  email_not_verified:
    "Google hasn't verified this account's email address, so Hub can't sign you in with it.",
  account_not_linked:
    "Hub couldn't link this Google account to the existing account with the same email. Sign in with your password instead.",
  access_denied: "Google sign-in was canceled.",
};

/**
 * A plain form post, not a server function: Hub answers with a redirect to Google, and the
 * browser has to follow it as a navigation for Google's consent screen to load.
 */
export function GoogleSignInForm({ invitation, busy }: { invitation?: string; busy: boolean }) {
  return (
    <form method="post" action="/api/auth/sign-in/google" aria-label="Continue with Google">
      {invitation === undefined ? null : (
        <Input type="hidden" name="invitation" value={invitation} />
      )}
      <AuthActions>
        <Button type="submit" size="lg" variant="outline" disabled={busy}>
          Continue with Google
        </Button>
      </AuthActions>
    </form>
  );
}

export function readGoogleSignInError(): string | undefined {
  if (typeof window === "undefined") return undefined;
  const search = new URLSearchParams(window.location.search);
  if (search.get("auth") !== "google-sign-in") return undefined;
  const error = search.get("error") ?? "";
  return GOOGLE_SIGN_IN_ERRORS[error] ?? "Google sign-in didn't complete. Try again.";
}

export function leaveGoogleSignInError(): void {
  const url = new URL(window.location.href);
  url.searchParams.delete("auth");
  url.searchParams.delete("error");
  url.searchParams.delete("error_description");
  window.history.replaceState(window.history.state, "", url);
}
