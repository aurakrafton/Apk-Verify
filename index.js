/*  Payment Worker — screenshot relay + temporary-key issuer
 *
 *  Routes:
 *    POST /upload      -> app sends screenshot; stored in your Telegram channel; returns a URL
 *    GET  /img/<id>    -> streams the image back (admin <img src>)
 *    POST /grantkey    -> app asks for a temporary key after "I've paid".
 *                         Worker issues  BOT-XXXXXXXX , writes it as a real (temporary) user,
 *                         enforces the per-device grant limit + block list, returns the key.
 *    GET  /chatid      -> helper to find your channel chat_id
 *
 *  Cloudflare Variables (Settings -> Variables):
 *    BOT_TOKEN      = BotFather token
 *    CHAT_ID        = your channel id (from /chatid)
 *    UPLOAD_SECRET  = long random string; the app sends it as the x-auth header
 *    FB_URL         = your RTDB base, e.g. https://xxx-default-rtdb.asia-southeast1.firebasedatabase.app
 *    GRANT_MAX      = (optional) default max temporary grants per device before admin must verify. 0 = unlimited.
 *
 *  DB access — set EITHER of these (service account preferred; firebase-admin does NOT run in Workers):
 *    (A) Service account (from your serviceAccountKey.json):
 *        FB_CLIENT_EMAIL = the JSON's  client_email
 *        FB_PRIVATE_KEY  = the JSON's  private_key  (paste the whole -----BEGIN...END----- block;
 *                          literal \n inside it are handled automatically)
 *    (B) Legacy secret (simpler, but Google is phasing these out):
 *        FB_SECRET       = a Realtime Database legacy secret
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "x-auth,content-type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    const J = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: { "content-type": "application/json", ...cors } });

    // --- helper: find channel chat_id ---
    if (path === "/chatid") {
      const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getUpdates`);
      return new Response(JSON.stringify(await r.json(), null, 2), { headers: { "content-type": "application/json", ...cors } });
    }

    // ========================= TEMPORARY KEY ISSUER =========================
    if (path === "/grantkey" && request.method === "POST") {
      if (env.UPLOAD_SECRET && request.headers.get("x-auth") !== env.UPLOAD_SECRET) return J({ ok: false, reason: "unauthorized" }, 401);
      if (!env.FB_URL) return J({ ok: false, reason: "server_not_configured" }, 500);
      try {
        const authQ = await fbAuthParam(env);
        if (!authQ) return J({ ok: false, reason: "server_not_configured", message: "Set FB_CLIENT_EMAIL+FB_PRIVATE_KEY or FB_SECRET" }, 500);
        const b = await request.json();
        const aid = String(b.android_id || "").trim();
        const pkgRaw = String(b.app_package || "").trim();
        if (!aid || !pkgRaw) return J({ ok: false, reason: "bad_request" }, 400);
        const pkg = pkgRaw.replace(/\./g, ",");                 // users are keyed by package with dots -> commas
        const dk = `${aid}__${pkg}`;                            // per-app device key (isolates apps)
        const fb = (p) => `${env.FB_URL}/${p}.json?${authQ}`;

        // --- per-device grant record (count / blocked) ---
        const gRes = await fetch(fb(`temp_grants/${dk}`));
        const g = (await gRes.json()) || {};
        if (g && g.blocked) return J({ ok: false, reason: "blocked", message: "This device is blocked by admin." });

        // --- server-authoritative settings: the LIMIT and the PASS LENGTH come from the database,
        //     NOT from the app request (so a leaked key can't ask for unlimited / forever access) ---
        let sg = {};
        try {
          const sRes = await fetch(fb(`public_data/settings/apps/${pkg}/get_key_advanced`));
          sg = (await sRes.json()) || {};
        } catch (e) { sg = {}; }

        const max = Number.isFinite(+sg.max_grants) ? +sg.max_grants : (+env.GRANT_MAX || 0);
        const used = +(g.count || 0);
        if (max > 0 && used >= max) return J({ ok: false, reason: "limit", count: used, max, message: "Access limit reached — wait for admin to verify your payment." });

        // --- compute expiry (IST date) + pass_until ms, using the admin's pass-validity settings ---
        const now = Date.now();
        const val = Math.max(1, +sg.confirm_value || +sg.confirm_days || 1);
        const unit = String(sg.confirm_unit || "days");
        let passUntil;
        if (unit === "hours") passUntil = now + val * 3600000;
        else if (unit === "today") { passUntil = istMidnightAfter(now); }
        else if (unit === "months" || unit === "years") {
          const d = new Date(now);
          if (unit === "years") d.setUTCFullYear(d.getUTCFullYear() + val);
          else d.setUTCMonth(d.getUTCMonth() + val);
          passUntil = d.getTime();
        }
        else passUntil = now + val * 86400000;
        const expiry = istDate(passUntil);                      // yyyy-MM-dd, verification compares against this

        // --- make the key ---
        const key = "BOT-" + rand(8);

        // --- write the temporary user (real record the normal verification accepts) ---
        const user = {
          android_id: aid,
          status: "active",
          expiry,
          temp: true,
          bot: true,
          issued: now,
          pass_until: passUntil,
          amount: +b.amount || 0,
          plan_value: +b.plan_value || 0,
          plan_unit: String(b.plan_unit || "days"),
          deviceName: b.deviceName || "",
          deviceModel: b.deviceModel || "",
          deviceBrand: b.deviceBrand || "",
          app_name: b.app_name || "",
          app_code: b.app_code || "",
          screenshot: b.screenshot || "",
          shot_path: b.shot_path || ""
        };
        await fetch(fb(`public_data/users/${pkg}/${key}`), { method: "PUT", body: JSON.stringify(user) });

        // --- bump the device grant record ---
        await fetch(fb(`temp_grants/${dk}`), {
          method: "PATCH",
          body: JSON.stringify({ count: used + 1, last_key: key, last_pass_until: passUntil, pkg: pkgRaw, blocked: false, verified: false, updated: now, android_id: aid })
        });

        // --- also drop the payment proof into pending_approvals (admin sees it) ---
        await fetch(fb(`pending_approvals/${dk}`), {
          method: "PATCH",
          body: JSON.stringify({ android_id: aid, app_package: pkgRaw, app_name: b.app_name || "", timestamp: now,
            payment: { amount: +b.amount || 0, plan_value: +b.plan_value || 0, plan_unit: String(b.plan_unit || "days"),
                       screenshot: b.screenshot || "", shot_path: b.shot_path || "", method: "upi", at: now,
                       pass_until: passUntil, temp_access: true, bot_key: key } })
        });

        return J({ ok: true, key, expiry, pass_until: passUntil, count: used + 1, max });
      } catch (e) {
        return J({ ok: false, reason: "error", message: String(e && e.message || e) }, 500);
      }
    }

    // ========================= "START VALIDITY ON FIRST LOGIN" ACTIVATOR =========================
    // Admin creates a key with activate_on_login:true + duration_days (expiry left blank). On the
    // FIRST successful login the app calls this; the server (not the client) sets expiry =
    // today(IST) + duration_days - 1, stamps activated_at, and binds the device. Idempotent.
    if (path === "/activate" && request.method === "POST") {
      if (env.UPLOAD_SECRET && request.headers.get("x-auth") !== env.UPLOAD_SECRET) return J({ ok: false, reason: "unauthorized" }, 401);
      if (!env.FB_URL) return J({ ok: false, reason: "server_not_configured" }, 500);
      try {
        const authQ = await fbAuthParam(env);
        if (!authQ) return J({ ok: false, reason: "server_not_configured" }, 500);
        const b = await request.json();
        const aid = String(b.android_id || "").trim();
        const pkgRaw = String(b.app_package || "").trim();
        const key = String(b.key || "").trim();
        if (!aid || !pkgRaw || !key || /[.#$\[\]\/]/.test(key)) return J({ ok: false, reason: "bad_request" }, 400);
        const pkg = pkgRaw.replace(/\./g, ",");
        const fb = (p) => `${env.FB_URL}/${p}.json?${authQ}`;
        const uRes = await fetch(fb(`public_data/users/${pkg}/${key}`));
        const u = await uRes.json();
        if (!u) return J({ ok: false, reason: "invalid" });
        if (u.expiry && !(u.activate_on_login && !u.activated_at)) return J({ ok: true, expiry: u.expiry, already: true });
        if (!u.activate_on_login) return J({ ok: false, reason: "not_activatable" });
        if (u.android_id && u.android_id !== aid) return J({ ok: false, reason: "mismatch" });
        const days = Math.max(1, parseInt(u.duration_days, 10) || 1);
        const now = Date.now();
        const expiry = istDate(now + (days - 1) * 86400000);   // 1 day = valid today only
        await fetch(fb(`public_data/users/${pkg}/${key}`), {
          method: "PATCH",
          body: JSON.stringify({ expiry, activated_at: now, android_id: aid })
        });
        return J({ ok: true, expiry, days });
      } catch (e) {
        return J({ ok: false, reason: "error", message: String(e && e.message || e) }, 500);
      }
    }

    // ========================= DEVICE-NAME LIST PROXY =========================
    // Google's official "supported devices" CSV (model code -> retail name) has no CORS header, so the
    // admin panel can't fetch it directly. We stream it through (cached 24h at the edge) and the admin
    // parses it in the browser. Protected by the same x-auth secret.
    if (path === "/devlist" && request.method === "GET") {
      if (env.UPLOAD_SECRET && request.headers.get("x-auth") !== env.UPLOAD_SECRET) return J({ ok: false, reason: "unauthorized" }, 401);
      try {
        const src = "https://storage.googleapis.com/play_public/supported_devices.csv";
        const cache = caches.default;
        const ck = new Request(src, { method: "GET" });
        let r = await cache.match(ck);
        if (!r) {
          const up = await fetch(src);
          if (!up.ok) return J({ ok: false, reason: "upstream_" + up.status }, 502);
          r = new Response(up.body, { headers: { "content-type": "text/csv; charset=utf-16le", "cache-control": "public, max-age=86400" } });
          try { await cache.put(ck, r.clone()); } catch (e) { }
        }
        return new Response(r.body, { headers: { "content-type": "text/csv; charset=utf-16le", ...cors } });
      } catch (e) {
        return J({ ok: false, reason: "error", message: String(e && e.message || e) }, 500);
      }
    }

    // ========================= COMMUNITY MODEL DB PROXY (MobileModels) =========================
    // Covers OPPO / vivo / realme / Xiaomi India variants that Google's list only knows as bare codes.
    // Streams the brand markdown files concatenated (small), cached 24h at the edge.
    if (path === "/devmm" && request.method === "GET") {
      if (env.UPLOAD_SECRET && request.headers.get("x-auth") !== env.UPLOAD_SECRET) return J({ ok: false, reason: "unauthorized" }, 401);
      try {
        const base = "https://raw.githubusercontent.com/KHwang9883/MobileModels/master/brands/";
        const files = ["oppo_global_en", "vivo_global_en", "realme_global_en", "xiaomi_en", "samsung_global_en", "oneplus_en", "honor_global_en", "google", "nothing"];
        const cache = caches.default;
        const ck = new Request("https://devmm.cache/" + files.join(","), { method: "GET" });
        let r = await cache.match(ck);
        if (!r) {
          const parts = await Promise.all(files.map(async f => {
            try { const x = await fetch(base + f + ".md"); return x.ok ? ("\n### " + f + "\n" + await x.text()) : ""; } catch (e) { return ""; }
          }));
          const body = parts.join("\n");
          if (body.trim().length < 1000) return J({ ok: false, reason: "upstream_empty" }, 502);
          r = new Response(body, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=86400" } });
          try { await cache.put(ck, r.clone()); } catch (e) { }
        }
        return new Response(r.body, { headers: { "content-type": "text/plain; charset=utf-8", ...cors } });
      } catch (e) {
        return J({ ok: false, reason: "error", message: String(e && e.message || e) }, 500);
      }
    }

    // --- upload screenshot ---
    if (path === "/upload" && request.method === "POST") {
      if (env.UPLOAD_SECRET && request.headers.get("x-auth") !== env.UPLOAD_SECRET) return new Response("unauthorized", { status: 401, headers: cors });
      try {
        let bytes, caption = url.searchParams.get("cap") || "";
        const ct = request.headers.get("content-type") || "";
        if (ct.includes("multipart/form-data")) {
          const form = await request.formData();
          const f = form.get("photo") || form.get("file");
          caption = form.get("caption") || caption;
          bytes = new Uint8Array(await f.arrayBuffer());
        } else if (ct.includes("application/json")) {
          const j = await request.json();
          caption = j.caption || caption;
          const b64 = (j.image || j.data || "").replace(/^data:image\/\w+;base64,/, "");
          bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        } else {
          bytes = new Uint8Array(await request.arrayBuffer());
        }
        if (!bytes || !bytes.length) return new Response("no image", { status: 400, headers: cors });
        const tg = new FormData();
        tg.append("chat_id", env.CHAT_ID);
        if (caption) tg.append("caption", caption.slice(0, 900));
        tg.append("photo", new Blob([bytes], { type: "image/jpeg" }), "p.jpg");
        const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`, { method: "POST", body: tg });
        const j = await r.json();
        if (!j.ok) return new Response(JSON.stringify(j), { status: 502, headers: { "content-type": "application/json", ...cors } });
        const photos = j.result.photo;
        const fileId = photos[photos.length - 1].file_id;
        return J({ ok: true, url: `${url.origin}/img/${fileId}`, file_id: fileId });
      } catch (e) {
        return new Response("error: " + e.message, { status: 500, headers: cors });
      }
    }

    // --- serve image ---
    if (path.startsWith("/img/")) {
      const fileId = decodeURIComponent(path.slice(5));
      try {
        const gf = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
        const gj = await gf.json();
        if (!gj.ok) return new Response("not found", { status: 404, headers: cors });
        const img = await fetch(`https://api.telegram.org/file/bot${env.BOT_TOKEN}/${gj.result.file_path}`);
        return new Response(img.body, { headers: { "content-type": "image/jpeg", "cache-control": "public, max-age=86400", ...cors } });
      } catch (e) {
        return new Response("error", { status: 500, headers: cors });
      }
    }

    return new Response("ok", { headers: cors });
  }
};

// BOT-XXXX random (no confusing chars)
function rand(n) { const a = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; let s = ""; for (let i = 0; i < n; i++) s += a[Math.floor(Math.random() * a.length)]; return s; }
// IST (UTC+5:30) date helpers
function istParts(ms) { const d = new Date(ms + 19800000); return { y: d.getUTCFullYear(), m: d.getUTCMonth(), day: d.getUTCDate() }; }
function istDate(ms) { const d = new Date(ms + 19800000); const p = (x) => String(x).padStart(2, "0"); return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`; }
function istMidnightAfter(ms) { const d = new Date(ms + 19800000); d.setUTCHours(24, 0, 0, 0); return d.getTime() - 19800000; }

/* ---- Firebase RTDB auth: service account (preferred) or legacy secret ---- */
let _fbTok = { v: null, exp: 0 };
async function fbAuthParam(env) {
  if (env.FB_CLIENT_EMAIL && env.FB_PRIVATE_KEY) {
    try { return "access_token=" + encodeURIComponent(await fbAccessToken(env)); } catch (e) { /* fall through */ }
  }
  if (env.FB_SECRET) return "auth=" + encodeURIComponent(env.FB_SECRET);
  return null;
}
async function fbAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (_fbTok.v && _fbTok.exp - 120 > now) return _fbTok.v;
  const scope = "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email";
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64url(JSON.stringify({ iss: env.FB_CLIENT_EMAIL, scope, aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const unsigned = header + "." + claim;
  const key = await importPkcs8(env.FB_PRIVATE_KEY.replace(/\\n/g, "\n"));
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(unsigned));
  const jwt = unsigned + "." + b64urlBytes(new Uint8Array(sig));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwt
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("token: " + JSON.stringify(j));
  _fbTok = { v: j.access_token, exp: now + (j.expires_in || 3600) };
  return _fbTok.v;
}
async function importPkcs8(pem) {
  const body = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), c => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
function b64url(str) { return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64urlBytes(bytes) { let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
