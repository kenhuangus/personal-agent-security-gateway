# OAuth App Registration Runbook — Personal Agent Security Gateway (Ken's checklist)

AOQ-9 says these registrations are Ken-owned developer apps and that platform
verification lead times are the likeliest schedule risk. Of the three providers,
only **Google has a real lead-time question**. Microsoft and GitHub registrations
are instant with no verification for own-account use. So the work splits into:
create all three app registrations now (15–20 minutes total), and make one team
decision about Google's scope tier.

## The one decision (for the build team, before M2 connectors are wired)

The MVP email connector includes `email.read` and `email.search` (docs/02-design.md),
which need message bodies. On Google that means a **Restricted** scope
(`gmail.readonly` — Restricted tier; `gmail.send` is only Sensitive tier;
Calendar scopes are Sensitive tier). Google's tiers:

- **Testing mode (unpublished app, Ken as test user):** no verification, no cost —
  but refresh tokens expire every **7 days**, so the gateway needs a weekly
  re-consent. Workable for a personal gateway; a weekly 30-second chore.
- **Production with Restricted scopes:** brand verification **plus** an annual
  CASA security assessment by a Google-approved lab (hundreds–thousands of
  $/year, annual re-verification, weeks–months lead time).

Options: (a) stay in Testing mode and accept weekly re-consent; (b) go production
and budget the CASA timeline/cost; (c) descope Gmail read to send-only
(`gmail.send` is Sensitive — verification without CASA) and read mail via the
Microsoft connector instead, if Ken's mail lives there too. The team should pick
before writing the Google connector.

Redirect URIs depend on the hosting decision (Fly.io vs Cloud Run, still open —
AOQ-4), so register the apps **now** and add redirect URIs later. `localhost`
redirects work for local dev testing in the meantime.

## 1. Google (console.cloud.google.com)

1. Create a new Cloud project (e.g. "personal-agent-gateway").
2. Enable APIs: Gmail API, Google Calendar API (APIs & Services → Library).
3. OAuth consent screen → **External** user type. App name: avoid anything that
   looks like an official Google product. Add Ken's Gmail as a **test user**.
   Add privacy-policy/homepage URLs later if going to production.
4. Credentials → Create OAuth client ID → **Web application**. Add redirect URIs
   later (hosting decision pending); use `http://localhost` for dev now.
5. Save the client ID + secret for the gateway vault config.

## 2. Microsoft (entra.microsoft.com, personal Microsoft account)

1. App registrations → New registration. Supported account types:
   "Accounts in any organizational directory and personal Microsoft accounts".
2. Redirect URI: Web — fill in after the hosting decision.
3. API permissions → Microsoft Graph **delegated**: `Mail.Read`, `Mail.Send`,
   `Calendars.ReadWrite` (least privilege per FR-013b; add nothing broader).
4. For own-account personal use there is no publisher verification step; user
   consent works immediately. Create a client secret under Certificates & secrets
   when the gateway needs it.

## 3. GitHub (github.com → Settings → Developer settings)

No verification or lead time — instant. Two options; the team picks:
- **GitHub App** (recommended): fine-grained permissions — Contents read/write,
  Pull requests read/write as the connector needs; install on Ken's own
  account only. Least-privilege by construction.
- **OAuth App**: simpler, but the classic `repo` scope is broad.
Register now with a placeholder callback URL; update it after hosting is decided.

## Sources checked 2026-10-12

- Google scope tiers (`gmail.readonly`/`gmail.modify` Restricted → CASA;
  `gmail.send`, Calendar scopes Sensitive):
  https://github.com/aware-aeco/aware/blob/HEAD/docs/google-oauth-verification/aware-aeco-drive-readonly.md
  https://github.com/k08200/klorn/blob/HEAD/docs/launch/google-oauth-verification.md
  https://github.com/kittypaw-app/kitty/blob/HEAD/docs/superpowers/specs/2026-05-04-connect-gmail-oauth-design.md
- Testing-mode 7-day token lifetime:
  https://github.com/pacphi/emailibrium/blob/HEAD/docs/oauth-setup-guide.md
