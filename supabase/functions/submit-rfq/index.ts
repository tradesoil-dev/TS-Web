// submit-rfq — the single hardened path for the tradesoil.com RFQ form.
//
// Layered defenses, cheapest first:
//   1. Origin allowlist + POST-only + content-type + body-size cap
//   2. Honeypot (silently discarded)
//   3. HMAC-signed timing token (min fill time, max age)
//   4. Rate limiting (Upstash; log-only until configured)
//   5. Turnstile server verify (dormant until TURNSTILE_SECRET_KEY is set)
//   6. Strict Zod validation (trim, lengths, control-char + email checks)
//   7. Conservative spam scoring (reject high, flag medium)
//   8. Server-side DB insert (service role — never the public key)
//   9. Hardened Resend email (escaped HTML, sanitized subject, text alt)
//  10. Structured logs with a correlation id; secrets never logged
//
// Every failure returns a GENERIC message to the client; the real reason is
// only ever written to the server log.

import { z } from "npm:zod@3.23.8";
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = new Set([
  "https://www.tradesoil.com",
  "https://tradesoil.com",
]);
const MAX_BODY_BYTES = 16 * 1024;
const MIN_FILL_MS = 3000; // reject submits faster than 3s
const MAX_TOKEN_AGE_MS = 60 * 60 * 1000; // token valid for 1 hour
const RATE_MAX = 3; // submissions per IP per window
const RATE_WINDOW_S = 900; // 15 minutes
const SPAM_REJECT = 5;
const SPAM_FLAG = 3;
const RESEND_FROM = "enquiries@tradesoil.com";
const RESEND_TO = "info@tradesoil.com";

function cors(origin: string | null) {
  const allow = origin && ALLOWED_ORIGINS.has(origin)
    ? origin
    : "https://www.tradesoil.com";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "content-type, apikey, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
function json(body: unknown, status: number, origin: string | null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors(origin), "Content-Type": "application/json" },
  });
}
const OK = { ok: true }; // identical body for success AND silent discards

const enc = new TextEncoder();
async function hmacHex(secret: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function sanitizeSubject(s: string): string {
  return s.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 120);
}
// Reject C0/C1 control characters. A char-code scan avoids embedding raw
// control bytes in this source file.
function noControl(s: string): boolean {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || (c >= 127 && c <= 159)) {
      return false;
    }
  }
  return true;
}

const schema = z.object({
  name: z.string().trim().min(2).max(100).refine(noControl),
  company: z.string().trim().min(2).max(150).refine(noControl),
  email: z.string().trim().max(254).email(),
  product: z.string().trim().max(150).refine(noControl).optional().default(""),
  volume: z.string().trim().max(100).refine(noControl).optional().default(""),
  destination: z.string().trim().max(100).refine(noControl).optional().default(
    "",
  ),
  message: z.string().trim().min(10).max(3000).refine(noControl),
});
type Rfq = z.infer<typeof schema>;

const DISPOSABLE = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "10minutemail.com",
  "tempmail.com",
  "trashmail.com",
  "yopmail.com",
  "sharklasers.com",
  "getnada.com",
]);

// A "word" reads as random consonant noise (e.g. "Kbwamdwm") when it is long
// yet has essentially no vowels. Real names/companies almost always have vowels,
// so this stays conservative and does not target non-English names.
function gibberishWord(w: string): boolean {
  const letters = w.replace(/[^a-z]/gi, "");
  if (letters.length < 5) return false;
  const vowels = (letters.match(/[aeiou]/gi) || []).length;
  if (vowels === 0) return true;
  if (letters.length >= 7 && vowels / letters.length < 0.15) return true;
  return false;
}
function spamScore(d: Rfq): { score: number; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];
  const nameWords = d.name.split(/\s+/).filter(Boolean);
  if (nameWords.length && nameWords.every(gibberishWord)) {
    score += 3;
    reasons.push("name_gibberish");
  }
  if (d.company.split(/\s+/).filter(Boolean).some(gibberishWord)) {
    score += 2;
    reasons.push("company_gibberish");
  }
  if (/(.)\1{4,}/.test(d.name + d.company + d.message)) {
    score += 2;
    reasons.push("repeat_chars");
  }
  const links = (d.message.match(/https?:\/\//gi) || []).length;
  if (links >= 3) {
    score += 2;
    reasons.push("many_links");
  } else if (links === 2) {
    score += 1;
    reasons.push("links");
  }
  const vals = [d.name, d.company, d.message].map((v) => v.toLowerCase());
  if (new Set(vals).size < vals.length) {
    score += 2;
    reasons.push("duplicated_fields");
  }
  const randAlnum = (s: string) =>
    (s.match(/\b[a-z0-9]{16,}\b/gi) || []).some((t) =>
      /[0-9]/.test(t) && /[a-z]/i.test(t)
    );
  if (randAlnum(d.message) || randAlnum(d.name) || randAlnum(d.company)) {
    score += 2;
    reasons.push("random_string");
  }
  if (!d.product && nameWords.some(gibberishWord)) {
    score += 1;
    reasons.push("blank_product");
  }
  const domain = (d.email.split("@")[1] || "").toLowerCase();
  if (DISPOSABLE.has(domain)) {
    score += 1;
    reasons.push("disposable_email"); // signal only, never a sole reject
  }
  return { score, reasons };
}

function clientIp(req: Request): string {
  // Supabase Edge sits behind a trusted proxy; the left-most x-forwarded-for
  // entry is the real client. We do not trust any other forwarded header.
  const xff = req.headers.get("x-forwarded-for") || "";
  return xff.split(",")[0].trim() || "unknown";
}
function ipPrefix(ip: string): string {
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".") + ".x";
  if (ip.includes(":")) return ip.split(":").slice(0, 3).join(":") + "::x";
  return "unknown";
}

// Distributed rate limit via Upstash Redis REST. Returns configured:false when
// no Upstash creds are set, so the limiter is a no-op (log-only) until you add
// them — never an in-memory limiter, which is useless on serverless.
async function rateLimit(
  ip: string,
): Promise<{ configured: boolean; limited: boolean; count: number }> {
  const url = Deno.env.get("UPSTASH_REDIS_REST_URL");
  const token = Deno.env.get("UPSTASH_REDIS_REST_TOKEN");
  if (!url || !token || ip === "unknown") {
    return { configured: false, limited: false, count: 0 };
  }
  const key = `rfq:${ip}`;
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify([["INCR", key], ["EXPIRE", key, RATE_WINDOW_S, "NX"]]),
  });
  const out = await res.json();
  const count = Array.isArray(out) ? Number(out[0]?.result ?? 0) : 0;
  return { configured: true, limited: count > RATE_MAX, count };
}

// Dormant until TURNSTILE_SECRET_KEY is set. Once set, a valid token becomes
// mandatory. (Option 1 ships without a captcha; this is the drop-in hook.)
async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
  const secret = Deno.env.get("TURNSTILE_SECRET_KEY");
  if (!secret) return true;
  if (!token) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (ip && ip !== "unknown") body.set("remoteip", ip);
  const res = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    { method: "POST", body },
  );
  const out = await res.json();
  return !!out.success;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  const cid = crypto.randomUUID();
  const log = (event: string, extra: Record<string, unknown> = {}) =>
    console.log(JSON.stringify({
      cid,
      fn: "submit-rfq",
      event,
      ip: ipPrefix(clientIp(req)),
      ...extra,
    }));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: cors(origin) });
  }
  if (req.method !== "POST") {
    log("reject_method", { method: req.method });
    return json({ error: "Method not allowed" }, 405, origin);
  }
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    log("reject_origin", { origin });
    return json({ error: "Forbidden" }, 403, origin);
  }
  if (!(req.headers.get("content-type") || "").includes("application/json")) {
    log("reject_content_type");
    return json({ error: "Bad request" }, 400, origin);
  }

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) {
    log("reject_size", { bytes: raw.length });
    return json({ error: "Payload too large" }, 413, origin);
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw);
  } catch {
    log("reject_json");
    return json({ error: "Bad request" }, 400, origin);
  }

  // 1. Honeypot — a real user never fills this. Silent success so bots learn nothing.
  const hp = payload.contact_reference;
  if (typeof hp === "string" && hp.trim() !== "") {
    log("honeypot");
    return json(OK, 200, origin);
  }

  // 2. Timing token
  const ts = Number(payload.ts);
  const sig = String(payload.sig || "");
  const hmacSecret = Deno.env.get("FORM_HMAC_SECRET") || "";
  if (!ts || !sig || !hmacSecret) {
    log("reject_token_missing");
    return json({ error: "Please reload the page and try again." }, 400, origin);
  }
  if (!timingSafeEqual(sig, await hmacHex(hmacSecret, String(ts)))) {
    log("reject_token_signature");
    return json({ error: "Please reload the page and try again." }, 400, origin);
  }
  const age = Date.now() - ts;
  if (age < MIN_FILL_MS) {
    log("reject_too_fast", { age });
    return json(OK, 200, origin); // silent discard
  }
  if (age > MAX_TOKEN_AGE_MS) {
    log("reject_token_expired", { age });
    return json({ error: "Please reload the page and try again." }, 400, origin);
  }

  // 3. Rate limit (log-only until Upstash is configured)
  const ip = clientIp(req);
  const rl = await rateLimit(ip);
  if (rl.configured && rl.limited) {
    log("rate_limited", { count: rl.count });
    return json({ error: "Too many requests. Please try again later." }, 429, origin);
  }
  if (!rl.configured) log("rate_limit_skipped");

  // 4. Turnstile (dormant in Option 1)
  if (!(await verifyTurnstile(String(payload.turnstile_token || ""), ip))) {
    log("turnstile_fail");
    return json({ error: "Verification failed. Please try again." }, 400, origin);
  }

  // 5. Validation
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    log("validation_fail", {
      fields: parsed.error.issues.map((i) => i.path.join(".")),
    });
    return json({ error: "Please check your details and try again." }, 400, origin);
  }
  const d = parsed.data;

  // 6. Spam scoring
  const { score, reasons } = spamScore(d);
  if (score >= SPAM_REJECT) {
    log("spam_reject", { score, reasons });
    return json(OK, 200, origin); // silent discard
  }
  const flagged = score >= SPAM_FLAG;

  // 7. Store server-side with the service role (bypasses RLS; public key cannot).
  try {
    const sb = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const { error } = await sb.from("contact_submissions").insert([{
      name: d.name,
      company: d.company,
      email: d.email,
      product: d.product,
      volume: d.volume,
      destination: d.destination,
      message: d.message,
    }]);
    if (error) log("db_error", { code: error.code });
  } catch {
    log("db_exception");
  }

  // 8. Hardened email
  try {
    const subject = sanitizeSubject(
      `${flagged ? "[Possible Spam] " : ""}New RFQ — ${d.name} (${d.company})`,
    );
    const row = (k: string, v: string) =>
      `<tr><td style="padding:6px 10px;font-weight:600">${escapeHtml(k)}</td>` +
      `<td style="padding:6px 10px">${escapeHtml(v || "—")}</td></tr>`;
    const html =
      `<h2 style="color:#1D9E75;font-family:sans-serif">New RFQ from tradesoil.com</h2>` +
      `<table cellpadding="0" style="font-family:sans-serif;font-size:14px;border-collapse:collapse">` +
      row("Name", d.name) + row("Company", d.company) + row("Email", d.email) +
      row("Product", d.product) + row("Volume", d.volume) +
      row("Destination", d.destination) + row("Message", d.message) +
      `</table>` +
      `<p style="color:#888;font-size:12px;margin-top:20px">Submitted via tradesoil.com/contact · ref ${cid}` +
      `${flagged ? " · flagged: possible spam" : ""}</p>`;
    const text = `New RFQ from tradesoil.com${flagged ? " [Possible Spam]" : ""}\n\n` +
      `Name: ${d.name}\nCompany: ${d.company}\nEmail: ${d.email}\n` +
      `Product: ${d.product || "-"}\nVolume: ${d.volume || "-"}\n` +
      `Destination: ${d.destination || "-"}\n\nMessage:\n${d.message}\n\nref ${cid}`;

    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${Deno.env.get("RESEND_API_KEY")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: [RESEND_TO],
        reply_to: d.email, // visitor address goes in Reply-To, never From
        subject,
        html,
        text,
      }),
    });
    if (!res.ok) {
      log("email_error", { status: res.status });
      return json(
        { error: "We could not send your enquiry right now. Please email info@tradesoil.com." },
        502,
        origin,
      );
    }
  } catch {
    log("email_exception");
    return json(
      { error: "We could not send your enquiry right now. Please email info@tradesoil.com." },
      502,
      origin,
    );
  }

  log("success", { flagged, score });
  return json(OK, 200, origin);
});
