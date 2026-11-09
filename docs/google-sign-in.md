# Google sign-in

Optional. Hub signs people in with email and password only until both
`PASEO_HUB_GOOGLE_CLIENT_ID` and `PASEO_HUB_GOOGLE_CLIENT_SECRET` are set. With neither set there
is no Google button, no Google route, and no Google provider. Setting only one of them fails
startup with an error that names the missing variable.

## Create the Google OAuth client

1. In the [Google Cloud console](https://console.cloud.google.com/), select or create a project for
   Hub.
2. Open **Google Auth Platform** (previously **APIs & Services → OAuth consent screen**) and
   configure the app: a name, a support email, and an audience. Choose **Internal** to limit
   sign-in to your Google Workspace organization, or **External** for any Google account. Hub
   requests only the `openid`, `email`, and `profile` scopes, which need no Google verification.
   An External app in **Testing** admits only its listed test users; publish it to let everyone
   else sign in.
3. Open **Clients** (previously **Credentials**), choose **Create client**, and pick the
   application type **Web application**.
4. Under **Authorized redirect URIs**, add Hub's callback, built from `PASEO_HUB_APP_URL`:

   ```text
   https://hub.example.com/api/auth/callback/google
   ```

   It must match exactly: the same scheme and host as `PASEO_HUB_APP_URL`, no trailing slash.
   **Authorized JavaScript origins** are not needed; the whole exchange happens on the server.

5. Copy the client ID and client secret.

## Configure Hub

```dotenv
PASEO_HUB_APP_URL=https://hub.example.com
PASEO_HUB_GOOGLE_CLIENT_ID=1234567890-example.apps.googleusercontent.com
PASEO_HUB_GOOGLE_CLIENT_SECRET=GOCSPX-example
```

Set `PASEO_HUB_APP_URL` explicitly. Hub sends Google the redirect URI
`${PASEO_HUB_APP_URL}/api/auth/callback/google`, and Google refuses any URI that is not registered on
the client. Restart Hub after changing these values.

## Who can sign in

Google sign-in follows the same rules as email and password sign-in. It adds a way in; it never
widens who gets in.

- **Existing accounts.** The first Google sign-in with the same email links Google to the existing
  account, keeping its name, memberships, and password. Hub links only when Google reports the
  email as verified and the Hub account's email is verified too. The bootstrap owner and the
  first-run operator are verified. Password accounts are verified when the instance has email
  delivery (`RESEND_API_KEY`). Without email delivery, password sign-ups stay unverified, and
  their owners keep using their password: linking an unverified account would let whoever
  registered the address first keep a password into the Google user's account. An operator who
  has confirmed that a person controls their address can mark it verified:

  ```sql
  update "user" set email_verified = true where lower(email) = 'person@example.com';
  ```

- **New accounts.** Google must report the email as verified. After that,
  `PASEO_REGISTRATION_MODE` decides, exactly as for a password sign-up: `open` accepts any
  address, `invite_only` accepts only an address with a pending invitation reached through its
  invitation link, and `disabled` accepts none.
- **Invitations.** Open the invitation link and choose **Continue with Google** with the invited
  address. Hub creates the account and shows the invitation to accept. A Google account with a
  different address is refused.
- **Temporary passwords.** A bootstrap owner who has not yet replaced
  `PASEO_BOOTSTRAP_OWNER_PASSWORD` is still asked to replace it after signing in with Google. The
  temporary password stays a valid way in until it is replaced, so signing in with Google does not
  waive the change. With password sign-in disabled there is nothing to replace, and Hub does not
  ask.
- **First run.** A pristine instance still creates its operator with email and password. Link
  Google afterwards by signing in with it, or bootstrap a Google-only owner as described below.

An account created through Google has no password. On an instance with email delivery, its owner
can set one with **Forgot password?**.

When Google sign-in fails, Hub returns to the sign-in card and says why, for example that the
address has no invitation or that Google has not verified it.

## Google-only sign-in

Set `PASEO_HUB_PASSWORD_SIGN_IN=disabled` to make Google the only way to sign in. The default,
`enabled`, also applies when the variable is unset or blank; any other value fails startup.

```dotenv
PASEO_HUB_PASSWORD_SIGN_IN=disabled
PASEO_HUB_GOOGLE_CLIENT_ID=1234567890-example.apps.googleusercontent.com
PASEO_HUB_GOOGLE_CLIENT_SECRET=GOCSPX-example
PASEO_BOOTSTRAP_ORGANIZATION=My organization
PASEO_BOOTSTRAP_OWNER_EMAIL=me@example.com
```

- Startup fails unless both Google variables are set, so the switch cannot lock everyone out.
- The sign-in and invitation cards show only **Continue with Google**. Password sign-in, sign-up,
  password change, password reset, and email verification answer 404, and Hub refuses them
  however they are reached.
- Existing passwords are kept but cannot be used. Setting the variable back to `enabled`, or
  removing it, restores them.
- No one is asked to replace a temporary password.
- Bootstrap takes `PASEO_BOOTSTRAP_ORGANIZATION` and `PASEO_BOOTSTRAP_OWNER_EMAIL` without a
  password. On a fresh instance Hub creates the owner with a verified email and no password, and
  the owner's first Google sign-in links to it. Browser first-run setup needs a password, so a fresh
  instance without these two values refuses to start. An instance whose bootstrap already
  completed keeps its owner; that owner's email is verified, so their first Google sign-in links
  too.
- `PASEO_BOOTSTRAP_OWNER_PASSWORD` must be unset. Hub refuses to start with it rather than ignore
  it, because it would become a working password the moment password sign-in was turned back on.
- An existing account whose email Hub has not verified cannot link Google, and with passwords off
  it has no other way in. Verify the address with the SQL above once you have confirmed the person
  controls it.

## Routes

| Route                           | Purpose                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| `POST /api/auth/sign-in/google` | Same-origin form post from the sign-in card. Redirects the browser to Google.         |
| `GET /api/auth/callback/google` | Google's redirect back. Signs in, links, or creates the account, then returns to `/`. |

Both answer 404 when Google sign-in is not configured. With password sign-in disabled, they are,
apart from `GET /api/auth/get-session` and `POST /api/auth/sign-out`, the only Better Auth routes
Hub serves. Hub keeps the tokens Google returns on the
linked account, with the access token encrypted, and does not use them after sign-in.
