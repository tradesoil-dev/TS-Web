// form-token — issues a short-lived, HMAC-signed timestamp when the RFQ form
// loads. The signature proves the timestamp was minted by the server, so the
// submit-rfq function can enforce a minimum fill time without trusting a
// client-supplied clock. No user data touches this endpoint.

const ALLOWED_ORIGINS = new Set([
  "https://www.tradesoil.com",
  "https://tradesoil.com",
]);

function cors(origin: string | null) {
  const allow = origin && ALLOWED_ORIGINS.has(origin)
    ? origin
    : "https://www.tradesoil.com";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "content-type, apikey, x-client-info",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}

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

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: cors(origin) });
  }
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return new Response(JSON.stringify({ error: "Forbidden" }), {
      status: 403,
      headers: { ...cors(origin), "Content-Type": "application/json" },
    });
  }
  const secret = Deno.env.get("FORM_HMAC_SECRET");
  if (!secret) {
    // Do not leak which env var is missing to the client.
    console.log(JSON.stringify({ fn: "form-token", event: "misconfigured" }));
    return new Response(JSON.stringify({ error: "Service unavailable" }), {
      status: 500,
      headers: { ...cors(origin), "Content-Type": "application/json" },
    });
  }
  const ts = Date.now();
  const sig = await hmacHex(secret, String(ts));
  return new Response(JSON.stringify({ ts, sig }), {
    headers: {
      ...cors(origin),
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
});
