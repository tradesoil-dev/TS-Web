# Tradesoil — Supabase Edge Functions

Server-side code that secures the RFQ / contact form on tradesoil.com.
These deploy to **Supabase** (Deno runtime), not to Vercel. They are kept
here in Git for backup and version history; `.vercelignore` keeps them out
of the public website.

## Functions

- **`submit-rfq`** — the single hardened endpoint the contact form posts to.
  Layers: origin allowlist, POST-only + size cap, honeypot, HMAC-signed
  timing token, rate limit (Upstash, log-only until configured), Turnstile
  (dormant until configured), Zod validation, spam scoring, server-side DB
  insert with the service role, hardened Resend email, structured logging.
- **`form-token`** — issues the short-lived HMAC-signed timestamp the form
  loads on page open (used by the timing check in `submit-rfq`).

## Deploy

From the repo root, logged in via `npx supabase login`:

```bash
npx supabase functions deploy form-token --project-ref gsllwoyolnglbimjufjb --no-verify-jwt
npx supabase functions deploy submit-rfq --project-ref gsllwoyolnglbimjufjb --no-verify-jwt
```

`--no-verify-jwt` is intentional: these are public form endpoints that do
their own gating (origin, honeypot, timing, validation, spam, rate limit).

## Secrets (Supabase → Edge Functions → Secrets)

| Secret | Purpose | Required |
|---|---|---|
| `FORM_HMAC_SECRET` | signs the timing token | yes |
| `RESEND_API_KEY` | sends the enquiry email | yes |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | server-side DB insert | auto-provided |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | enable rate limiting | optional |
| `TURNSTILE_SECRET_KEY` | enable Cloudflare Turnstile captcha | optional |

## Database

Table `contact_submissions` has Row Level Security enabled with no public
policies, so only the service role (used by `submit-rfq`) can write. The
public API key cannot insert directly.
