# ScopeGrip AI

A runnable Next.js 16 App Router MVP for multi-tenant Google Workspace OAuth permission audits. TypeScript, Tailwind, Supabase Auth/Postgres, Googleapis, OpenAI `gpt-4o-mini`, and Stripe.

## Delivery status

The v0.2 MVP uses Next.js 16.3.5 and React 19.3.0, replacing the unsupported original framework. It includes authentication/recovery, tenant-isolated auditing, Google consent, revocation, billing, CI, and container deployment configuration. It is ready for configuration and staging validation; it has not been deployed or connected to live provider accounts. See `VALIDATION.md` for the exact checks completed. Your API credentials must be supplied separately, and real provider acceptance checks remain necessary before onboarding paying customers.

The dashboard uses real Supabase records. There are no fabricated audit findings or mock payment successes.

## Local setup

1. Install Node.js 22 or newer. Extract the project, then run `npm ci`.
2. Create a Supabase project. Execute `schema.sql` once in its SQL editor. This migration targets a new schema and is transactional; it is not intended to be rerun over an existing installation. Existing v0.1 databases need no SQL changes for this release.
3. In Supabase Auth, enable email/password authentication and email confirmation. Set the site URL to `http://localhost:3000` for local development and configure your production site URL before launch. Allow `/auth/callback` on each configured origin as a redirect URL. Configure the confirmation email link as `{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=signup` and the recovery email link as `{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=recovery`. Keep those complete URLs in your Supabase email templates. Password recovery supports both these token-hash links and a PKCE callback. Password changes sign out all sessions. Configure SMTP for real email delivery. The signup UI requires a 12-character password; also enforce that minimum in Supabase Auth settings.
4. Copy `.env.example` to `.env.local` if the file is absent, fill it using the table below, and run `npm run check:env`. Never commit `.env.local`. The checker reports missing/invalid configuration without printing secrets.
5. Configure Google OAuth and Stripe as described below.
6. Run `npm run dev`, open `http://localhost:3000`, create an account, confirm your email, and sign in.
7. Create a workspace, connect a Google Workspace super administrator, subscribe using Stripe test mode, wait for the webhook, and run an audit.

## Environment variables

| Variable | Value/source |
| --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase public anon key; RLS protects database access |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service-role secret, server only |
| `APP_URL` | Exact application origin, initially `http://localhost:3000`; HTTPS in production |
| `GOOGLE_CLIENT_ID` | Google Cloud web OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Same OAuth client's secret |
| `TOKEN_ENCRYPTION_KEY` | Base64-encoded random 32-byte key; generate with `openssl rand -base64 32` |
| `OPENAI_API_KEY` | OpenAI API project key with access to `gpt-4o-mini` and sufficient quota |
| `STRIPE_SECRET_KEY` | Stripe test secret initially; live secret only after validation |
| `STRIPE_WEBHOOK_SECRET` | Endpoint signing secret, or Stripe CLI listener secret during local development |
| `STRIPE_PRICE_ID` | Active recurring licensed USD price: 4900 cents every one month |

Your ChatGPT Plus subscription does not supply the application's OpenAI API credential. Configure API billing separately. Keep all server secrets out of `NEXT_PUBLIC_*`. The encryption key must be backed up: losing it requires every tenant to reconnect Google. Key rotation requires re-encrypting existing credentials; do not simply replace it in an active deployment.

## Google OAuth setup

1. In Google Cloud, enable **Admin SDK API**.
2. Configure an OAuth consent screen. A SaaS serving multiple organizations needs an external audience and any verification Google requires for the requested scopes. In testing mode, add the administrator as a test user; testing refresh-token lifetimes can affect reconnect frequency.
3. Create an OAuth web application client. Register exactly `http://localhost:3000/api/google/callback`, plus the matching HTTPS production callback when ready.
4. Request `openid`, `email`, `https://www.googleapis.com/auth/admin.directory.user.readonly`, and `https://www.googleapis.com/auth/admin.directory.user.security`.
5. Connect using a Google Workspace super administrator. Google Workspace API controls may require the organization's administrator to trust the OAuth client.

This implementation uses per-tenant administrator OAuth consent and an encrypted offline refresh token. It does not use a global service account or require domain-wide delegation. The callback verifies the ID token, checks super administrator status with Directory, binds the Google customer ID to the local workspace, and prevents the same Google customer from being attached to another local workspace. Reconnection may refresh credentials for the same customer; customer reassignment is rejected.

Only app grant metadata is read. The Directory token resource does not expose users' bearer-token secrets. `users.list` is paginated, then `tokens.list` is called for each directory user. `tokens.delete` revokes one user's authorization for one client ID. It does not block future consent and does not delete data already shared with that app. ScopeGrip's own client is protected from in-app revocation to avoid disabling the active connection.

## Stripe setup

1. In Stripe test mode, create a product and a recurring **USD $49/month** price, quantity one, licensed usage. Put its `price_...` ID into `STRIPE_PRICE_ID`. Checkout validates the price server-side.
2. Enable the hosted customer portal, including cancellation and payment-method updates. Avoid enabling plan/quantity changes unless corresponding application entitlement rules are added.
3. Forward local events with `stripe listen --forward-to localhost:3000/api/stripe/webhook`; copy the displayed signing secret into `.env.local` and restart the dev server.
4. Register the production webhook at `/api/stripe/webhook` for `customer.subscription.created`, `customer.subscription.updated`, and `customer.subscription.deleted`.
5. Complete a test checkout using Stripe's documented test payment methods. The success redirect never grants access: only a verified webhook updates subscription entitlement. Refresh the dashboard after processing.

Checkout creates/reuses a workspace customer with idempotency, refuses a second nonterminal subscription, and reuses an open checkout session. Webhooks verify the raw request signature, retrieve the subscription's current state, validate customer/workspace linkage and the configured price, and reject older state updates using event timestamps. Repeated event delivery is harmless. A canceled or expired billing period cannot scan. Owners can still revoke permissions when their subscription is inactive.

The $49 price is USD and does not include any configured tax calculation; this MVP does not configure Stripe Tax. The selected hosting plan must support the scan route's duration.

## Tenant and authorization design

- `workspaces`, `workspace_members`, `scans`, and `oauth_grants` have RLS. Members can read only their tenant's records. Authenticated clients have no direct write privileges on these tables.
- A security-definer membership helper prevents recursive membership policies. Its search path is fixed, it uses `auth.uid()`, and only the authenticated role may call it.
- Workspace creation is an authenticated, atomic RPC that creates the workspace, its owner membership, and billing record. A user can create at most five workspaces.
- An owner can connect Google, scan, revoke, and manage billing. Viewers can read dashboard results. Every sensitive route verifies the Supabase user server-side and the required workspace membership.
- Google credentials, OAuth states, and operation locks are unavailable to browser database roles. Refresh tokens use AES-256-GCM with the workspace ID as authenticated additional data, so ciphertext cannot be moved between tenants.
- Mutation routes require an exact same-origin header. Google OAuth state is random, bound to the signed-in user and workspace, expires in ten minutes, and is consumed atomically.
- The service-role key is imported only by server modules. Composite foreign keys prevent an OAuth grant from referencing another tenant's scan.
- Scan and revoke share a ten-minute database lease. Re-scans have a five-minute cooldown. Scan results become visible only through an atomic completion RPC. Partial failures retain the last complete snapshot.
- Revocations record a pending audit event before the Google call and a completed event with local updates after success. Google 404 is treated as already revoked. If local persistence fails after Google succeeds, the UI explicitly asks for a reconciliation retry.

Membership invitations, user removal, and ownership transfer are outside this MVP. To provision a viewer, a trusted operator can insert a known Supabase user UUID into `workspace_members` using the SQL editor after verifying organizational approval. Never expose that operation to an untrusted client. Owners receive no unrestricted membership-edit endpoint.

## Bounded scan model

This synchronous MVP supports **50 directory users and 500 user/app grants per scan**, with a 240-second application budget and `maxDuration=300`. Google requests time out after 15 seconds; OpenAI after 12 seconds. Workspaces exceeding a bound fail explicitly and preserve previous complete results. The limits are product constraints, not claims that all tenants will finish in that time. A killed request may leave a scan marked `running`; it can be retried after the ten-minute lock expires.

Move scanning into a durable queue/worker before supporting larger tenants or hosting runtimes with short request limits. Add provider backoff, checkpointing, cancellation, and job recovery in that expansion. This code does not silently truncate a directory or publish partial results.

The model receives app display names and scope strings only; email addresses and Google refresh tokens are not sent to OpenAI. Display names are untrusted input. Strict JSON Schema and runtime validation constrain output; deterministic rules impose a minimum risk rating and supply a fallback when the model is unavailable. AI-generated summaries remain advisory. Unknown scopes receive at least MEDIUM risk. Possible AI is an unverified name-based inference, not verified software inventory or confirmed Shadow AI. OAuth visibility does not cover direct website visits, personal accounts, API keys, browser activity, or employee uploads without Workspace OAuth.

## Deploying the MVP

Use a Node.js host with HTTPS, secure runtime environment variables, and a request timeout of at least 300 seconds. Keep the explicit 50-user / 500-grant scope limit for this release. Vercel can use the Next.js preset, but the selected plan must support the scan duration. A container/Node host behind an HTTPS proxy is also supported.

For a container build, pass the **public** Supabase URL and anon key as build arguments; these are embedded into the browser bundle. Supply all server secrets at runtime. Never pass server secrets as build arguments or bake `.env.local` into the image. The `.dockerignore` excludes all environment files. The runner uses an unprivileged user.

```bash
docker build \
  --build-arg NEXT_PUBLIC_SUPABASE_URL="$NEXT_PUBLIC_SUPABASE_URL" \
  --build-arg NEXT_PUBLIC_SUPABASE_ANON_KEY="$NEXT_PUBLIC_SUPABASE_ANON_KEY" \
  -t scopegrip-ai .
docker run --rm -p 3000:3000 --env-file .env.local scopegrip-ai
```

Use `/api/health` for process liveness. It does not claim the external providers are healthy. Set `APP_URL` to the exact public HTTPS origin. Apply HTTPS redirection, HSTS, request limits, and platform rate limits at the hosting edge. The app adds CSP, frame denial, MIME-sniffing protection, and private/no-store handling for authenticated responses.

The GitHub Actions workflow installs the lockfile, runs security and API tests, builds the app, and fails on high/critical production dependency advisories. Dependabot opens dependency update proposals. CI does not require real provider secrets.

## Source repository

Source: https://github.com/adamshah123/scopegrip-ai

Clone the repository, copy `.env.example` to `.env.local`, and follow the setup steps above. Environment secrets and generated build output are excluded from version control. Repository visibility is controlled in GitHub settings.

## Commands and verification

```bash
npm ci
npm test
npm run typecheck
npm run build
npm start
```

The API suite exercises the actual route handlers with mocked provider boundaries, including genuine Stripe test-signature verification. It checks CSRF, authentication, owner-only actions, malformed/oversized requests, cross-customer revocation denial, already-revoked reconciliation, failed persistence, unpaid scans, and invalid-price entitlement rejection.

The security suite runs the migration inside embedded Postgres (PGlite) with Supabase-style auth roles. It checks cross-tenant reads and writes, secret-table denial, owner escalation denial, composite tenant keys, atomic scan failure, operation exclusion/cooldown, revocation recording, stale billing events, encryption tampering, and risk floors. This is stronger than string-matching SQL policies, but it does not replace integration tests against your deployed Supabase instance and real providers.

Before a live launch, complete these integration checks:

- Create two unrelated accounts/tenants; confirm each can see only its own data and cannot call another tenant's mutation routes. Provision a viewer and verify owner-only actions return 403.
- Connect an actual Google test organization. Check multi-user enumeration and revoke a disposable test app. Verify revocation in Google Admin and confirm another user's app authorization remains intact.
- Deny a requested consent scope, replay an OAuth state, and try a nonadministrator account; the connection must fail.
- Send invalid Stripe signatures, replay valid events, cancel the subscription, and verify entitlement changes. Verify success-URL navigation alone cannot activate scanning.
- Interrupt a scan and simulate provider failures; ensure a previous completed snapshot remains visible. Confirm the hosting request deadline accommodates the configured budget.
- Configure retention/deletion for stored user emails, grants, scan history and expired OAuth-state rows; backups and operational alerting belong to your deployment.

## Release scope

The release intentionally keeps synchronous bounded scans, owner/viewer access, and operator-provisioned memberships. It is not a complete enterprise access governance platform. Customer self-service invitations, large-tenant background workers, and retention automation are follow-on product work; they are not hidden behind unfinished buttons.

## Main files

- `schema.sql`: tenant tables, protected credential/billing/audit tables, RLS and atomic RPCs.
- `.env.local` / `.env.example`: complete variable list with empty credential fields.
- `lib/supabase/server.ts`, `lib/supabase/client.ts`, `proxy.ts`: Supabase authentication wrappers and cookie refresh and a per-request CSP nonce.
- `app/api/google/connect/route.ts`, `app/api/google/callback/route.ts`: administrator onboarding.
- `app/api/workspace/scan/route.ts`: directory enumeration, AI risk scoring and atomic persistence.
- `app/api/workspace/revoke/route.ts`: scoped authorization revocation and audit trail.
- `app/api/stripe/checkout/route.ts`, `portal/route.ts`, `webhook/route.ts`: billing lifecycle.
- `app/page.tsx`: authenticated dashboard entry; `app/dashboard.tsx`: interactive dark Tailwind dashboard.
- `tests/security.test.ts`: database and cryptographic security tests.

## Official implementation references

- Google token listing: https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list
- Google token deletion: https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/delete
- Google Directory scope definitions: https://developers.google.com/workspace/admin/directory/v1/guides/authorizing
- Supabase SSR clients: https://supabase.com/docs/guides/auth/server-side/creating-a-client
- OpenAI structured outputs: https://platform.openai.com/docs/guides/structured-outputs
- Stripe subscription webhooks: https://docs.stripe.com/billing/subscriptions/webhooks
- Next.js support policy: https://nextjs.org/support-policy
