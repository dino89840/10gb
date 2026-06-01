// ======================= Lugyi Cloud =======================
// Cloudflare Pages Functions + Object Storage (single-file)
// Multi-user • Invite-code register • Per-user isolation
// PBKDF2 password hashing • 5-day session • Upload progress
// v2 — atomic metadata (etag CAS) • dark mode • bulk ops • rate-limit
// ==========================================================

const PER_USER_BYTES = 10 * 1024 * 1024 * 1024;          // user တစ်ယောက် 10 GB
const MAX_REMOTE_BYTES = Math.floor(1.5 * 1024 * 1024 * 1024); // 1.5 GB remote url
const LOCK_KEY = "__meta__/loginlock.json";              // login attempt lock
const REGLOCK_KEY = "__meta__/reglock.json";             // registration ip lock
const INVITE_KEY = "__meta__/invites.json";              // invite codes store
const APILOCK_KEY = "__meta__/apilock.json";             // generic api rate-limit
const SESSION_DAYS = 5;                                   // auto logout after 5 days
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const MAX_PARALLEL_UPLOAD = 3;
const PBKDF2_ITER = 100000;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const META_CAS_RETRIES = 6;                              // metadata compare-and-swap retries
const API_RATE_PER_MIN = 120;                            // mutating api calls / user / minute

// ---- Abuse-prevention settings (no mail / no OTP) ----
const REQUIRE_INVITE = false;          // true ဆိုရင် register လုပ်ဖို့ invite code လို
const MAX_REG_PER_IP_PER_DAY = 2;     // IP တစ်ခုကနေ နေ့တစ်ရက် အကောင့်အများဆုံး
const MAX_TOTAL_USERS = 500;          // စုစုပေါင်း အကောင့် cap (0 ဆိုရင် ကန့်သတ်မထား)
const STRICT_SHARE_FILENAME = false;  // true ဆိုရင် /s/{token}/{name} မှာ name မှန်မှ ဖွင့်ပေး

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-XSS-Protection": "1; mode=block",
  "Content-Security-Policy":
    "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " +
    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; " +
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; " +
    "form-action 'self'; frame-ancestors 'none'",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function html(body) {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS },
  });
}

// ---- constant-time compare ----
function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) {
    let diff = 1;
    const max = Math.max(a.length, b.length, 1);
    for (let i = 0; i < max; i++) diff |= (a.charCodeAt(i % a.length || 0) ^ b.charCodeAt(i % b.length || 0));
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---- PBKDF2 password hashing ----
function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" }, key, 256
  );
  return { salt: bufToHex(salt), hash: bufToHex(bits) };
}
async function verifyPassword(password, saltHex, hashHex) {
  const { hash } = await hashPassword(password, saltHex);
  return safeEqual(hash, hashHex);
}

// ---- HMAC sign / verify (session token) ----
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// token payload: user.exp.iat.ver  (ver = password version → ပြောင်းရင် old session invalid)
async function makeToken(env, user, ver) {
  const exp = Date.now() + SESSION_MS;
  const iat = Date.now();
  const payload = `${user}.${exp}.${iat}.${ver || 0}`;
  const sig = await hmac(env.SESSION_SECRET, payload);
  return `${btoa(payload).replace(/=+$/, "")}.${sig}`;
}

async function verifyToken(env, token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  let payload;
  try { payload = atob(parts[0]); } catch { return null; }
  const expected = await hmac(env.SESSION_SECRET, payload);
  if (!safeEqual(expected, parts[1])) return null;
  const seg = payload.split(".");
  const user = seg[0];
  const expStr = seg[1];
  const iatStr = seg[2];
  const verStr = seg[3];
  if (!expStr || Date.now() > Number(expStr)) return null;
  if (iatStr && Date.now() - Number(iatStr) > SESSION_MS) return null;
  return { user, ver: Number(verStr || 0) };
}

function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}

async function getAuthUser(request, env) {
  const tok = getCookie(request, "session");
  return await verifyToken(env, tok);
}

function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (origin) {
    try { if (new URL(origin).host !== url.host) return false; }
    catch { return false; }
    return true;
  }
  const ref = request.headers.get("Referer");
  if (ref) {
    try { return new URL(ref).host === url.host; } catch { return false; }
  }
  return false;
}

// ---- Per-user metadata (with etag-based atomic CAS) ----
function userMetaKey(username) {
  return `users/${username}/index.json`;
}
function emptyMeta() {
  return { totalBytes: 0, files: {}, folders: {} };
}
// loadMeta — etag ပါ ပြန်ပေး (CAS အတွက်)
async function loadMeta(env, username) {
  const obj = await env.R2.get(userMetaKey(username));
  if (!obj) return { meta: emptyMeta(), etag: null };
  try {
    const m = JSON.parse(await obj.text());
    m.files = m.files || {};
    m.folders = m.folders || {};
    m.totalBytes = m.totalBytes || 0;
    return { meta: m, etag: obj.etag };
  } catch { return { meta: emptyMeta(), etag: obj.etag }; }
}
// loadMetaPlain — etag မလိုတဲ့ read-only အတွက်
async function loadMetaPlain(env, username) {
  const { meta } = await loadMeta(env, username);
  return meta;
}
// putMeta — etag ကိုက်မှ ရေး (compare-and-swap)။ မကိုက်ရင် null ပြန်
async function putMeta(env, username, meta, etag) {
  const opts = {
    httpMetadata: { contentType: "application/json" },
  };
  if (etag === null) {
    // ပထမဆုံး create — file မရှိမှသာ ရေးမယ်
    opts.onlyIf = { etagDoesNotMatch: "*" };
  } else {
    opts.onlyIf = { etagMatches: etag };
  }
  try {
    const res = await env.R2.put(userMetaKey(username), JSON.stringify(meta), opts);
    return res; // null = condition failed
  } catch {
    // onlyIf မ support တဲ့ edge case — fallback plain put
    return await env.R2.put(userMetaKey(username), JSON.stringify(meta), {
      httpMetadata: { contentType: "application/json" },
    });
  }
}
// mutateMeta — load→modify→CAS-put ကို retry နဲ့ atomic လုပ်
// fn(meta) => modify meta in place; return value (e.g. {error}) ကို throw မလုပ်ဘဲ ပြန်ပေးချင်ရင်
//            fn ထဲကနေ {__abort: <Response/value>} ပြန်ပေးနိုင်
async function mutateMeta(env, username, fn) {
  for (let attempt = 0; attempt < META_CAS_RETRIES; attempt++) {
    const { meta, etag } = await loadMeta(env, username);
    const out = await fn(meta);
    if (out && out.__abort !== undefined) return out.__abort; // abort without write
    const res = await putMeta(env, username, meta, etag);
    if (res) return out === undefined ? true : out;            // success
    // CAS failed → တခြား write က ကြားဖြတ်ဝင်သွား → retry
    await sleep(40 * (attempt + 1) + Math.floor(Math.random() * 40));
  }
  throw new Error("meta_cas_conflict");
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// legacy saveMeta (etag မသိရင် plain put) — register/folder create မှာ သုံး
async function saveMetaPlain(env, username, meta) {
  await env.R2.put(userMetaKey(username), JSON.stringify(meta), {
    httpMetadata: { contentType: "application/json" },
  });
}

// ---- User account store ----
function userKey(username) {
  return `users/${username.toLowerCase()}/account.json`;
}
async function loadUser(env, username) {
  if (!username) return null;
  const obj = await env.R2.get(userKey(username));
  if (!obj) return null;
  try { return JSON.parse(await obj.text()); } catch { return null; }
}
async function saveUser(env, account) {
  await env.R2.put(userKey(account.username), JSON.stringify(account), {
    httpMetadata: { contentType: "application/json" },
  });
}

// ---- Login lock ----
async function loadLock(env) {
  const obj = await env.R2.get(LOCK_KEY);
  if (!obj) return {};
  try { return JSON.parse(await obj.text()); } catch { return {}; }
}
async function saveLock(env, lock) {
  await env.R2.put(LOCK_KEY, JSON.stringify(lock));
}

// ---- Generic API rate-limit (per user, sliding window per-minute) ----
async function checkApiRate(env, key) {
  const obj = await env.R2.get(APILOCK_KEY);
  let map = {};
  if (obj) { try { map = JSON.parse(await obj.text()); } catch { map = {}; } }
  const minute = Math.floor(Date.now() / 60000);
  const rec = map[key];
  let count = 1;
  if (rec && rec.m === minute) {
    count = (rec.c || 0) + 1;
  }
  // cleanup old entries (cheap)
  for (const k of Object.keys(map)) {
    if (map[k].m < minute - 1) delete map[k];
  }
  map[key] = { m: minute, c: count };
  await env.R2.put(APILOCK_KEY, JSON.stringify(map));
  return count <= API_RATE_PER_MIN;
}

// ---- Registration IP lock (abuse prevention) ----
async function loadRegLock(env) {
  const obj = await env.R2.get(REGLOCK_KEY);
  if (!obj) return {};
  try { return JSON.parse(await obj.text()); } catch { return {}; }
}
async function saveRegLock(env, lock) {
  await env.R2.put(REGLOCK_KEY, JSON.stringify(lock));
}

// ---- Invite codes store ----
async function loadInvites(env) {
  const obj = await env.R2.get(INVITE_KEY);
  if (!obj) return {};
  try { return JSON.parse(await obj.text()); } catch { return {}; }
}
async function saveInvites(env, inv) {
  await env.R2.put(INVITE_KEY, JSON.stringify(inv), {
    httpMetadata: { contentType: "application/json" },
  });
}

// ---- total user counter (atomic CAS) ----
const USERCOUNT_KEY = "__meta__/usercount.json";
async function loadUserCount(env) {
  const obj = await env.R2.get(USERCOUNT_KEY);
  if (!obj) return 0;
  try { return JSON.parse(await obj.text()).count || 0; } catch { return 0; }
}
async function bumpUserCount(env) {
  for (let attempt = 0; attempt < META_CAS_RETRIES; attempt++) {
    const obj = await env.R2.get(USERCOUNT_KEY);
    let c = 0, etag = null;
    if (obj) { try { c = JSON.parse(await obj.text()).count || 0; } catch {} etag = obj.etag; }
    const opts = { httpMetadata: { contentType: "application/json" } };
    opts.onlyIf = etag === null ? { etagDoesNotMatch: "*" } : { etagMatches: etag };
    let res;
    try { res = await env.R2.put(USERCOUNT_KEY, JSON.stringify({ count: c + 1 }), opts); }
    catch { res = await env.R2.put(USERCOUNT_KEY, JSON.stringify({ count: c + 1 })); }
    if (res) return c + 1;
    await sleep(40 * (attempt + 1));
  }
  // ဆုံးရှုံးရင်လည်း register ကို မပိတ်ဘဲ best-effort
  return null;
}

function nowMM() {
  const d = new Date(Date.now() + (6 * 60 + 30) * 60 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function todayKeyMM() {
  const d = new Date(Date.now() + (6 * 60 + 30) * 60 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
}

function randId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function cleanName(name, fallback) {
  let n = String(name == null ? "" : name);
  try { n = n.normalize("NFC"); } catch {}
  n = n.trim();
  n = n.replace(/[\/\\]/g, "_");
  n = n.replace(/[\x00-\x1f\x7f]/g, "");
  n = n.replace(/^\.+/, "");
  if (n.length > 200) {
    const dot = n.lastIndexOf(".");
    const ext = dot > -1 ? n.slice(dot) : "";
    n = n.slice(0, 200 - ext.length) + ext;
  }
  return n || fallback || "file";
}

// ---- AWS Signature V4 for presigned URL (per-user prefixed key) ----
// ⚠️ remote/presign အပိုင်း — မူရင်းအတိုင်း မထိ
async function sha256Hex(data) {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hmacRaw(key, msg) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
async function presignPut(env, objectKey, expiresSec = 3600) {
  const region = "auto";
  const service = "s3";
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const endpoint = `https://${host}/${env.R2_BUCKET}/${encodeURIComponent(objectKey).replace(/%2F/g, "/")}`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  const params = new URLSearchParams({
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${env.R2_ACCESS_KEY_ID}/${credentialScope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSec),
    "X-Amz-SignedHeaders": "host",
  });
  const canonicalUri = "/" + env.R2_BUCKET + "/" + encodeURIComponent(objectKey).replace(/%2F/g, "/");
  const canonicalQuery = [...params.entries()]
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .sort().join("&");
  const payloadHash = "UNSIGNED-PAYLOAD";
  const canonicalRequest = `PUT\n${canonicalUri}\n${canonicalQuery}\nhost:${host}\n\nhost\n${payloadHash}`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;

  let signingKey = await hmacRaw(enc.encode("AWS4" + env.R2_SECRET_ACCESS_KEY), dateStamp);
  signingKey = await hmacRaw(signingKey, region);
  signingKey = await hmacRaw(signingKey, service);
  signingKey = await hmacRaw(signingKey, "aws4_request");
  const sigKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = [...new Uint8Array(await crypto.subtle.sign("HMAC", sigKey, enc.encode(stringToSign)))]
    .map(b => b.toString(16).padStart(2, "0")).join("");

  return `${endpoint}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function parseRange(rangeHeader, size) {
  if (!rangeHeader) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!m) return null;
  let start = m[1] === "" ? null : parseInt(m[1], 10);
  let end = m[2] === "" ? null : parseInt(m[2], 10);
  if (start === null && end === null) return null;
  if (start === null) {
    start = Math.max(0, size - end);
    end = size - 1;
  } else if (end === null || end >= size) {
    end = size - 1;
  }
  if (start > end || start >= size) return "invalid";
  return { offset: start, length: end - start + 1, end };
}

// serveObject — extraCache ဖြင့် share / private cache ခွဲ
async function serveObject(request, env, f, { inlineDefault = false, cacheControl = "private, max-age=3600" } = {}) {
  const head = await env.R2.head(f.key);
  if (!head) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
  const size = head.size;
  const ctype = f.type || head.httpMetadata?.contentType || "application/octet-stream";
  const inline = inlineDefault && /^(image|video|audio|text)\//.test(ctype);
  const disposition = `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(f.name)}`;
  const etag = head.httpEtag || `"${f.key}-${size}"`;

  const rangeHeader = request.headers.get("Range");
  const range = parseRange(rangeHeader, size);

  if (range === "invalid") {
    return new Response("Range Not Satisfiable", {
      status: 416,
      headers: { "Content-Range": `bytes */${size}`, "Accept-Ranges": "bytes" },
    });
  }

  if (range) {
    const obj = await env.R2.get(f.key, { range: { offset: range.offset, length: range.length } });
    if (!obj) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
    return new Response(obj.body, {
      status: 206,
      headers: {
        "Content-Type": ctype,
        "Content-Length": String(range.length),
        "Content-Range": `bytes ${range.offset}-${range.end}/${size}`,
        "Accept-Ranges": "bytes",
        "Content-Disposition": disposition,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": cacheControl,
        "ETag": etag,
        "Vary": "Range",
      },
    });
  }

  const obj = await env.R2.get(f.key);
  if (!obj) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": ctype,
      "Content-Length": String(size),
      "Accept-Ranges": "bytes",
      "Content-Disposition": disposition,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": cacheControl,
      "ETag": etag,
    },
  });
}

// ======================= Main Router =======================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  try {
    // ---------- PUBLIC share download (no auth) ----------
    if (path.startsWith("/s/")) {
      const rest = path.slice(3);
      const segs = rest.split("/");
      const token = segs[0];
      const nameSeg = segs[1] ? decodeURIComponent(segs.slice(1).join("/")) : null;
      return await handleShare(request, env, token, nameSeg);
    }

    // ---------- Auth APIs (no session needed) ----------
    if (path === "/api/register" && request.method === "POST") {
      if (!sameOrigin(request, url)) return json({ error: "bad origin" }, 403);
      return await handleRegister(request, env);
    }
    if (path === "/api/login" && request.method === "POST") {
      if (!sameOrigin(request, url)) return json({ error: "bad origin" }, 403);
      return await handleLogin(request, env);
    }
    if (path === "/api/logout" && request.method === "POST") {
      return json({ ok: true }, 200, {
        "Set-Cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
      });
    }

    // ---------- Admin: invite code generate (protected by ADMIN_KEY) ----------
    if (path === "/api/admin/invite" && request.method === "POST") {
      return await handleAdminInvite(request, env);
    }

    // ---------- Auth pages ----------
    if (path === "/login") return html(LOGIN_HTML);
    if (path === "/register") return html(REGISTER_HTML);

    // ---------- Everything below needs auth ----------
    const auth = await getAuthUser(request, env);
    if (path.startsWith("/api/")) {
      if (!auth) return json({ error: "unauthorized" }, 401);
      const acct = await loadUser(env, auth.user);
      if (!acct) return json({ error: "unauthorized" }, 401);
      // password version check — password ပြောင်းရင် old session invalid
      if ((acct.ver || 0) !== auth.ver) return json({ error: "session expired" }, 401);
      if (request.method === "POST" && !sameOrigin(request, url)) {
        return json({ error: "bad origin" }, 403);
      }
      // generic rate-limit (mutating + heavy reads)
      if (request.method === "POST") {
        const okRate = await checkApiRate(env, "u:" + acct.username);
        if (!okRate) return json({ error: "လုပ်ဆောင်မှု အရမ်းများနေပါသည်။ ခဏစောင့်ပါ။" }, 429);
      }
      context.user = acct;
    } else {
      if (!auth) {
        return Response.redirect(url.origin + "/login", 302);
      }
      const acct = await loadUser(env, auth.user);
      if (!acct || (acct.ver || 0) !== auth.ver) return Response.redirect(url.origin + "/login", 302);
      context.user = acct;
    }

    const username = context.user.username;

    // ---------- API routes (authed, per-user) ----------
    if (path === "/api/me" && request.method === "GET") return json({ username, quota: PER_USER_BYTES });
    if (path === "/api/list" && request.method === "GET") return await apiList(request, env, username);
    if (path === "/api/folders/all" && request.method === "GET") return await apiFoldersAll(request, env, username);
    if (path === "/api/upload" && request.method === "POST") return await apiUpload(request, env, username);
    if (path === "/api/presign" && request.method === "POST") return await apiPresign(request, env, username);
    if (path === "/api/finalize" && request.method === "POST") return await apiFinalize(request, env, username);
    if (path === "/api/remote" && request.method === "POST") return await apiRemote(request, env, username);
    if (path === "/api/delete" && request.method === "POST") return await apiDelete(request, env, username);
    if (path === "/api/bulkdelete" && request.method === "POST") return await apiBulkDelete(request, env, username);
    if (path === "/api/rename" && request.method === "POST") return await apiRename(request, env, username);
    if (path === "/api/share" && request.method === "POST") return await apiShare(request, env, username);
    if (path === "/api/changepass" && request.method === "POST") return await apiChangePass(request, env, context.user);
    if (path === "/api/download" && request.method === "GET") return await apiDownload(request, env, username);
    if (path === "/api/view" && request.method === "GET") return await apiView(request, env, username);
    if (path === "/api/folder/create" && request.method === "POST") return await apiFolderCreate(request, env, username);
    if (path === "/api/folder/delete" && request.method === "POST") return await apiFolderDelete(request, env, username);
    if (path === "/api/folder/rename" && request.method === "POST") return await apiFolderRename(request, env, username);
    if (path === "/api/move" && request.method === "POST") return await apiMove(request, env, username);
    if (path === "/api/bulkmove" && request.method === "POST") return await apiBulkMove(request, env, username);

    // ---------- Main page ----------
    if (path === "/" || path === "/index.html") return html(APP_HTML);

    return new Response("Not Found", { status: 404 });
  } catch (err) {
    return json({ error: "server error" }, 500);
  }
}

// ======================= Auth Handlers =======================

async function handleRegister(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const body = await request.json().catch(() => ({}));
  let { username, password, invite } = body;
  username = String(username || "").trim();
  password = String(password || "");
  invite = String(invite || "").trim();

  if (!USERNAME_RE.test(username)) {
    return json({ error: "Username က စာလုံး ၃-၂၀ လုံး (a-z, 0-9, _) သာ ဖြစ်ရပါမည်။" }, 400);
  }
  if (password.length < 6) {
    return json({ error: "Password အနည်းဆုံး ၆ လုံး ထားပါ။" }, 400);
  }

  // --- total user cap ---
  if (MAX_TOTAL_USERS > 0) {
    const count = await loadUserCount(env);
    if (count >= MAX_TOTAL_USERS) {
      return json({ error: "အကောင့်အရေအတွက် ပြည့်သွားပါပြီ။ နောက်မှ ပြန်ကြိုးစားပါ။" }, 403);
    }
  }

  // --- IP per-day registration limit ---
  const regLock = await loadRegLock(env);
  const dayKey = todayKeyMM();
  const ipRec = regLock[ip] || { day: dayKey, count: 0 };
  if (ipRec.day !== dayKey) { ipRec.day = dayKey; ipRec.count = 0; }
  if (ipRec.count >= MAX_REG_PER_IP_PER_DAY) {
    return json({ error: "ဤ IP မှ ယနေ့ အကောင့်ဖွင့်ခွင့် ပြည့်သွားပါပြီ။ မနက်ဖြန် ပြန်ကြိုးစားပါ။" }, 429);
  }

  // --- invite code check ---
  let invites = null;
  if (REQUIRE_INVITE) {
    if (!invite) return json({ error: "Invite code လိုအပ်ပါသည်။" }, 400);
    invites = await loadInvites(env);
    const rec = invites[invite];
    if (!rec) return json({ error: "Invite code မှားနေပါသည်။" }, 400);
    if (rec.used) return json({ error: "ဤ invite code ကို သုံးပြီးသားဖြစ်ပါသည်။" }, 400);
  }

  const existing = await loadUser(env, username);
  if (existing) {
    return json({ error: "ဤ Username ကို သုံးပြီးသားဖြစ်ပါသည်။" }, 409);
  }

  const { salt, hash } = await hashPassword(password);
  const account = {
    username: username.toLowerCase(),
    displayName: username,
    salt, hash,
    ver: 0,                 // password version (session invalidation အတွက်)
    createdAt: nowMM(),
    regIp: ip,
  };
  await saveUser(env, account);

  // empty meta ဖန်တီး
  await saveMetaPlain(env, account.username, emptyMeta());

  // --- invite ကို used မှတ် ---
  if (REQUIRE_INVITE && invites) {
    invites[invite].used = true;
    invites[invite].usedBy = account.username;
    invites[invite].usedAt = nowMM();
    await saveInvites(env, invites);
  }

  // --- counters bump ---
  ipRec.count += 1;
  regLock[ip] = ipRec;
  await saveRegLock(env, regLock);
  await bumpUserCount(env);

  const tok = await makeToken(env, account.username, account.ver);
  return json({ ok: true }, 200, {
    "Set-Cookie": `session=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_MS / 1000)}`,
  });
}

// Admin invite generate — header  x-admin-key: <ADMIN_KEY>
async function handleAdminInvite(request, env) {
  const key = request.headers.get("x-admin-key") || "";
  if (!env.ADMIN_KEY || !safeEqual(key, env.ADMIN_KEY)) {
    return json({ error: "forbidden" }, 403);
  }
  const body = await request.json().catch(() => ({}));
  const n = Math.min(50, Math.max(1, Number(body.count) || 1));
  const invites = await loadInvites(env);
  const created = [];
  for (let i = 0; i < n; i++) {
    const code = randId().slice(0, 10).toUpperCase();
    invites[code] = { used: false, usedBy: null, createdAt: nowMM() };
    created.push(code);
  }
  await saveInvites(env, invites);
  return json({ ok: true, codes: created });
}

async function handleLogin(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const lock = await loadLock(env);
  const rec = lock[ip] || { fails: 0, until: 0 };

  if (rec.until && Date.now() < rec.until) {
    const sec = Math.ceil((rec.until - Date.now()) / 1000);
    return json({ error: `အကြိမ်များစွာ မှားနေပါသည်။ ${sec} စက္ကန့်ကြာမှ ပြန်ကြိုးစားပါ။` }, 429);
  }

  const body = await request.json().catch(() => ({}));
  let { username, password } = body;
  username = String(username || "").trim().toLowerCase();
  password = String(password || "");

  const account = await loadUser(env, username);
  let ok = false;
  if (account) {
    ok = await verifyPassword(password, account.salt, account.hash);
  } else {
    await hashPassword(password, "00000000000000000000000000000000");
  }

  if (ok) {
    delete lock[ip];
    await saveLock(env, lock);
    const tok = await makeToken(env, account.username, account.ver || 0);
    return json({ ok: true }, 200, {
      "Set-Cookie": `session=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_MS / 1000)}`,
    });
  }

  rec.fails = (rec.fails || 0) + 1;
  if (rec.fails >= 5) {
    rec.until = Date.now() + 5 * 60 * 1000;
    rec.fails = 0;
  }
  lock[ip] = rec;
  await saveLock(env, lock);
  const left = rec.until ? 0 : 5 - rec.fails;
  return json({
    error: rec.until
      ? "အကြိမ် ၅ ကြိမ် မှားသွားပါပြီ။ ၅ မိနစ် စောင့်ပါ။"
      : `Username သို့မဟုတ် Password မှားနေပါသည်။ (ကျန် ${left} ကြိမ်)`,
  }, 401);
}

// ======================= File Handlers (per-user) =======================

async function apiList(request, env, username) {
  const meta = await loadMetaPlain(env, username);
  const url = new URL(request.url);
  const folder = url.searchParams.get("folder") || "";

  const files = Object.entries(meta.files || {})
    .filter(([, f]) => (f.folder || "") === folder)
    .map(([id, f]) => ({
      id, name: f.name, size: f.size, type: f.type,
      uploadedAt: f.uploadedAt, folder: f.folder || "",
      share: f.share ? { token: f.share.token, expiresAt: f.share.expiresAt } : null,
    }))
    .sort((a, b) => (b.uploadedAt || "").localeCompare(a.uploadedAt || ""));

  const folders = Object.entries(meta.folders || {})
    .filter(([, fd]) => (fd.parent || "") === folder)
    .map(([id, fd]) => {
      const fileCount = Object.values(meta.files || {}).filter(f => (f.folder || "") === id).length;
      const subCount = Object.values(meta.folders || {}).filter(s => (s.parent || "") === id).length;
      return { id, name: fd.name, parent: fd.parent || "", count: fileCount + subCount };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const breadcrumb = [];
  let cur = folder;
  const guard = new Set();
  while (cur && meta.folders[cur] && !guard.has(cur)) {
    guard.add(cur);
    breadcrumb.unshift({ id: cur, name: meta.folders[cur].name });
    cur = meta.folders[cur].parent || "";
  }

  return json({
    files, folders, breadcrumb, currentFolder: folder,
    totalBytes: meta.totalBytes || 0, maxBytes: PER_USER_BYTES,
  });
}

// ဖိုင်ရွှေ့ရန် folder tree အကုန် တစ်ခါတည်း (N+1 fetch ဖြေရှင်း)
async function apiFoldersAll(request, env, username) {
  const meta = await loadMetaPlain(env, username);
  const folders = meta.folders || {};
  const out = [];
  function pathOf(id) {
    const names = [];
    let cur = id; const guard = new Set();
    while (cur && folders[cur] && !guard.has(cur)) {
      guard.add(cur);
      names.unshift(folders[cur].name);
      cur = folders[cur].parent || "";
    }
    return names.join(" / ");
  }
  for (const id of Object.keys(folders)) out.push({ id, path: pathOf(id) });
  out.sort((a, b) => a.path.localeCompare(b.path));
  return json({ folders: out });
}

async function apiUpload(request, env, username) {
  const form = await request.formData();
  const file = form.get("file");
  const folder = (form.get("folder") || "").toString();
  const customName = (form.get("name") || "").toString();
  if (!file || typeof file === "string") return json({ error: "ဖိုင်မပါပါ" }, 400);

  const size = file.size;
  const id = randId();
  const key = `users/${username}/files/${id}`;

  // အရင်ဆုံး quota/folder ကို snapshot နဲ့ စစ် (race လျော့ဖို့ နောက် CAS မှာ ထပ်စစ်)
  {
    const snap = await loadMetaPlain(env, username);
    if (folder && !snap.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
    if ((snap.totalBytes || 0) + size > PER_USER_BYTES) {
      return json({ error: "သိုလှောင်ခန့် ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413);
    }
  }

  // R2 object ကို အရင်တင် (ဒါက index မဟုတ်လို့ concurrent OK)
  await env.R2.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
  });

  let fname = cleanName(customName || file.name, id);
  if (customName && !/\.[a-z0-9]{1,8}$/i.test(fname)) {
    const origExt = (file.name.match(/\.[a-z0-9]{1,8}$/i) || [""])[0];
    if (origExt) fname += origExt;
  }

  // index.json ကို atomic CAS နဲ့ update → concurrent upload အတွက် ပြဿနာ မရှိ
  try {
    const result = await mutateMeta(env, username, (meta) => {
      if (folder && !meta.folders[folder]) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 400) };
      if ((meta.totalBytes || 0) + size > PER_USER_BYTES) {
        return { __abort: json({ error: "သိုလှောင်ခန့် ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413) };
      }
      meta.files = meta.files || {};
      meta.files[id] = {
        name: fname, size,
        type: file.type || "application/octet-stream",
        uploadedAt: nowMM(), folder, key,
      };
      meta.totalBytes = (meta.totalBytes || 0) + size;
      return { ok: true, id };
    });
    if (result instanceof Response) { await env.R2.delete(key); return result; }
    return json(result);
  } catch (e) {
    await env.R2.delete(key);
    return json({ error: "သိမ်းဆည်းရာတွင် ပြဿနာရှိ၍ ပြန်ကြိုးစားပါ။" }, 503);
  }
}

// ⚠️ presign — မူရင်းအတိုင်း (concurrent OK ဖြစ်အောင် snapshot စစ်ရုံသာ)
async function apiPresign(request, env, username) {
  const meta = await loadMetaPlain(env, username);
  const body = await request.json().catch(() => ({}));
  const { name, size, type, folder } = body;
  if (!name || !size) return json({ error: "name/size မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  if ((meta.totalBytes || 0) + Number(size) > PER_USER_BYTES) {
    return json({ error: "သိုလှောင်ခန့် ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413);
  }

  const id = randId();
  const key = `users/${username}/files/${id}`;
  const uploadUrl = await presignPut(env, key, 3600);
  return json({ ok: true, id, key, uploadUrl });
}

async function apiFinalize(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { id, key, name, type, folder } = body;
  if (!id || !key) return json({ error: "id/key မပါပါ" }, 400);
  if (key !== `users/${username}/files/${id}` || !/^[a-f0-9]{32}$/.test(id)) {
    return json({ error: "invalid key" }, 400);
  }

  const head = await env.R2.head(key);
  if (!head) return json({ error: "ဖိုင်မတွေ့ပါ" }, 400);
  const realSize = head.size;

  try {
    const result = await mutateMeta(env, username, (meta) => {
      if (folder && !meta.folders[folder]) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 400) };
      if ((meta.totalBytes || 0) + realSize > PER_USER_BYTES) {
        return { __abort: json({ error: "သိုလှောင်ခန့် ကျော်သွားသဖြင့် ဖျက်လိုက်ပါပြီ။", __overflow: true }, 413) };
      }
      meta.files = meta.files || {};
      meta.files[id] = {
        name: cleanName(name, id), size: realSize,
        type: type || head.httpMetadata?.contentType || "application/octet-stream",
        uploadedAt: nowMM(), folder: folder || "", key,
      };
      meta.totalBytes = (meta.totalBytes || 0) + realSize;
      return { ok: true, id };
    });
    if (result instanceof Response) {
      await env.R2.delete(key); // quota ကျော် / folder ပျောက် → orphan object ဖျက်
      return result;
    }
    return json(result);
  } catch (e) {
    await env.R2.delete(key);
    return json({ error: "သိမ်းဆည်းရာတွင် ပြဿနာရှိ၍ ပြန်ကြိုးစားပါ။" }, 503);
  }
}

// ============================================================
// ⚠️⚠️⚠️ apiRemote — Remote URL upload ⚠️⚠️⚠️
// မူရင်း logic အတိအကျ မထိ — index update အပိုင်းကိုသာ atomic CAS ပြောင်း
// ============================================================
async function apiRemote(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { url: remoteUrl, name, folder } = body;
  if (!remoteUrl) return json({ error: "URL မပါပါ" }, 400);

  // folder snapshot စစ်
  {
    const snap = await loadMetaPlain(env, username);
    if (folder && !snap.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  }

  let parsed;
  try { parsed = new URL(remoteUrl); } catch { return json({ error: "URL မှားနေပါသည်" }, 400); }
  if (!/^https?:$/.test(parsed.protocol)) return json({ error: "http/https သာ ခွင့်ပြုသည်" }, 400);
  const hn = parsed.hostname;
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|\[?::1\]?|metadata\.)/i.test(hn) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(hn) || hn.endsWith(".internal") || hn.endsWith(".local")) {
    return json({ error: "ဤ URL ကို ခွင့်မပြုပါ" }, 400);
  }

  const resp = await fetch(remoteUrl, { redirect: "follow" });
  if (!resp.ok) return json({ error: "URL မှ ဖိုင်ဆွဲ၍မရပါ (" + resp.status + ")" }, 400);

  const lenHeader = resp.headers.get("Content-Length");
  const declared = lenHeader ? Number(lenHeader) : 0;
  if (declared && declared > MAX_REMOTE_BYTES) {
    return json({ error: "Remote ဖိုင်သည် 1.5GB ထက်ကြီးနေပါသည်။" }, 413);
  }
  {
    const snap = await loadMetaPlain(env, username);
    if (declared && (snap.totalBytes || 0) + declared > PER_USER_BYTES) {
      return json({ error: "သိုလှောင်ခန့် ပြည့်သွားပါပြီ။" }, 413);
    }
  }

  const id = randId();
  const key = `users/${username}/files/${id}`;
  const ctype = resp.headers.get("Content-Type") || "application/octet-stream";
  await env.R2.put(key, resp.body, { httpMetadata: { contentType: ctype } });

  const head = await env.R2.head(key);
  const realSize = head ? head.size : declared;
  if (realSize > MAX_REMOTE_BYTES) {
    await env.R2.delete(key);
    return json({ error: "Remote ဖိုင်သည် 1.5GB ထက်ကြီးသဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
  }

  let fname = name;
  if (!fname) {
    try {
      let raw = decodeURIComponent(new URL(remoteUrl).pathname.split("/").pop() || "");
      raw = raw.split("?")[0].split("#")[0];
      const cd = resp.headers.get("Content-Disposition") || "";
      const mStar = /filename\*=(?:UTF-8'')?([^;]+)/i.exec(cd);
      const mPlain = /filename="?([^";]+)"?/i.exec(cd);
      if (mStar) raw = decodeURIComponent(mStar[1].trim());
      else if (mPlain) raw = mPlain[1].trim();
      fname = raw && raw.trim() ? raw.trim() : id;
    } catch { fname = id; }
  }
  if (!/\.[a-z0-9]{1,8}$/i.test(fname)) {
    const ext = extFromType(ctype);
    if (ext) fname = fname + "." + ext;
  }
  fname = cleanName(fname, id);

  // index update — atomic CAS (quota ကျော်ရင် object ဖျက်)
  try {
    const result = await mutateMeta(env, username, (meta) => {
      if (folder && !meta.folders[folder]) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 400) };
      if ((meta.totalBytes || 0) + realSize > PER_USER_BYTES) {
        return { __abort: json({ error: "သိုလှောင်ခန့် ကျော်သဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413) };
      }
      meta.files = meta.files || {};
      meta.files[id] = { name: fname, size: realSize, type: ctype, uploadedAt: nowMM(), folder: folder || "", key };
      meta.totalBytes = (meta.totalBytes || 0) + realSize;
      return { ok: true, id };
    });
    if (result instanceof Response) { await env.R2.delete(key); return result; }
    return json(result);
  } catch (e) {
    await env.R2.delete(key);
    return json({ error: "သိမ်းဆည်းရာတွင် ပြဿနာရှိ၍ ပြန်ကြိုးစားပါ။" }, 503);
  }
}

function extFromType(ctype) {
  const map = {
    "image/jpeg": "jpg", "image/jpg": "jpg", "image/png": "png", "image/gif": "gif",
    "image/webp": "webp", "image/bmp": "bmp", "image/svg+xml": "svg",
    "video/mp4": "mp4", "video/webm": "webm", "video/x-matroska": "mkv",
    "video/quicktime": "mov", "video/x-msvideo": "avi", "video/mpeg": "mpeg",
    "audio/mpeg": "mp3", "audio/wav": "wav", "audio/ogg": "ogg", "audio/aac": "aac",
    "audio/flac": "flac", "audio/x-m4a": "m4a",
    "application/pdf": "pdf", "application/zip": "zip",
    "application/x-rar-compressed": "rar", "text/plain": "txt",
  };
  return map[(ctype || "").split(";")[0].trim().toLowerCase()] || "";
}

async function apiDelete(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  // အရင် key/share token ကို snapshot က ရှာ → R2 object ဖျက် → index ကို CAS
  const snap = await loadMetaPlain(env, username);
  const f0 = snap.files?.[id];
  if (!f0) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);
  await env.R2.delete(f0.key);
  if (f0.share?.token) await env.R2.delete(shareKey(f0.share.token));
  const result = await mutateMeta(env, username, (meta) => {
    const f = meta.files?.[id];
    if (!f) return { __abort: json({ ok: true }) };
    meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
    delete meta.files[id];
    return { ok: true };
  });
  return result instanceof Response ? result : json(result);
}

async function apiBulkDelete(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const ids = Array.isArray(body.ids) ? body.ids.slice(0, 200) : [];
  if (!ids.length) return json({ error: "ဖိုင်မရွေးထားပါ" }, 400);
  const snap = await loadMetaPlain(env, username);
  let deleted = 0;
  for (const id of ids) {
    const f = snap.files?.[id];
    if (!f) continue;
    await env.R2.delete(f.key);
    if (f.share?.token) await env.R2.delete(shareKey(f.share.token));
  }
  const result = await mutateMeta(env, username, (meta) => {
    for (const id of ids) {
      const f = meta.files?.[id];
      if (!f) continue;
      meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
      delete meta.files[id];
      deleted++;
    }
    return { ok: true, deleted };
  });
  return result instanceof Response ? result : json(result);
}

async function apiRename(request, env, username) {
  const body = await request.json().catch(() => ({}));
  let { id, name } = body;
  const result = await mutateMeta(env, username, (meta) => {
    const f = meta.files?.[id];
    if (!f) return { __abort: json({ error: "ဖိုင်မတွေ့ပါ" }, 404) };
    let nm = cleanName(name, "");
    if (!nm) return { __abort: json({ error: "နာမည် ထည့်ပါ" }, 400) };
    if (!/\.[a-z0-9]{1,8}$/i.test(nm)) {
      const oldExt = (f.name.match(/\.[a-z0-9]{1,8}$/i) || [""])[0];
      if (oldExt) nm += oldExt;
    }
    f.name = nm;
    return { ok: true, name: nm };
  });
  return result instanceof Response ? result : json(result);
}

async function apiShare(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { id, duration } = body;

  // share token မှာ R2 side-effect ရှိလို့ token ကို အရင် ပြင်ဆင်
  const snap = await loadMetaPlain(env, username);
  const f0 = snap.files?.[id];
  if (!f0) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);

  if (duration === "off") {
    if (f0.share?.token) await env.R2.delete(shareKey(f0.share.token));
    const result = await mutateMeta(env, username, (meta) => {
      const f = meta.files?.[id];
      if (f) delete f.share;
      return { ok: true, share: null };
    });
    return result instanceof Response ? result : json(result);
  }
  const map = { "2d": 2 * 86400e3, "1w": 7 * 86400e3, "1m": 30 * 86400e3, "1y": 365 * 86400e3 };
  let expiresAt = null;
  if (duration !== "lifetime") {
    const ms = map[duration];
    if (!ms) return json({ error: "သက်တမ်းမှားနေပါသည်" }, 400);
    expiresAt = Date.now() + ms;
  }
  const token = f0.share?.token || randId();
  await saveShareIndex(env, token, username, id);

  const result = await mutateMeta(env, username, (meta) => {
    const f = meta.files?.[id];
    if (!f) return { __abort: json({ error: "ဖိုင်မတွေ့ပါ" }, 404) };
    f.share = { token, expiresAt };
    return { ok: true, share: { token, expiresAt, name: f.name } };
  });
  return result instanceof Response ? result : json(result);
}

// share token → {username, fileId} mapping
function shareKey(token) { return `__shares__/${token}.json`; }
async function saveShareIndex(env, token, username, fileId) {
  await env.R2.put(shareKey(token), JSON.stringify({ username, fileId }), {
    httpMetadata: { contentType: "application/json" },
  });
}
async function loadShareIndex(env, token) {
  if (!/^[a-f0-9]{32}$/.test(token)) return null;
  const obj = await env.R2.get(shareKey(token));
  if (!obj) return null;
  try { return JSON.parse(await obj.text()); } catch { return null; }
}

async function apiChangePass(request, env, account) {
  const body = await request.json().catch(() => ({}));
  const { oldPass, newPass } = body;
  const ok = await verifyPassword(String(oldPass || ""), account.salt, account.hash);
  if (!ok) return json({ error: "လက်ရှိ password မှားနေပါသည်" }, 400);
  if (!newPass || String(newPass).length < 6) return json({ error: "password အနည်းဆုံး ၆ လုံးထားပါ" }, 400);
  const { salt, hash } = await hashPassword(String(newPass));
  account.salt = salt;
  account.hash = hash;
  account.ver = (account.ver || 0) + 1; // session version ++ → တခြား device တွေ logout
  await saveUser(env, account);
  // လက်ရှိ device ကို session အသစ်ပေး
  const tok = await makeToken(env, account.username, account.ver);
  return json({ ok: true }, 200, {
    "Set-Cookie": `session=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_MS / 1000)}`,
  });
}

async function apiDownload(request, env, username) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const meta = await loadMetaPlain(env, username);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });
  return await serveObject(request, env, f, { inlineDefault: false });
}

async function apiView(request, env, username) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const meta = await loadMetaPlain(env, username);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });
  return await serveObject(request, env, f, { inlineDefault: true });
}

async function handleShare(request, env, token, nameSeg) {
  const idx = await loadShareIndex(env, token);
  if (!idx) return new Response("Link မတွေ့ပါ", { status: 404 });
  const meta = await loadMetaPlain(env, idx.username);
  const target = meta.files?.[idx.fileId];
  if (!target || !target.share || target.share.token !== token) {
    return new Response("Link မတွေ့ပါ", { status: 404 });
  }
  if (target.share.expiresAt && Date.now() > target.share.expiresAt) {
    return new Response("ဤ link သက်တမ်းကုန်သွားပါပြီ။ (မူရင်းဖိုင်မပျက်ပါ)", { status: 410 });
  }
  if (STRICT_SHARE_FILENAME && nameSeg) {
    const want = target.name;
    if (decodeURIComponent(nameSeg) !== want && nameSeg !== encodeURIComponent(want)) {
      return new Response("Link မတွေ့ပါ", { status: 404 });
    }
  }
  return await serveObject(request, env, target, {
    inlineDefault: true,
    cacheControl: "public, max-age=300, must-revalidate",
  });
}

// ======================= Folder Handlers (per-user) =======================
async function apiFolderCreate(request, env, username) {
  const body = await request.json().catch(() => ({}));
  let { name, parent } = body;
  name = (name || "").toString().trim();
  parent = (parent || "").toString();
  if (!name) return json({ error: "Folder နာမည် ထည့်ပါ" }, 400);
  if (name.length > 80) return json({ error: "နာမည် ရှည်လွန်းနေပါသည်" }, 400);
  const id = randId();
  const result = await mutateMeta(env, username, (meta) => {
    if (parent && !meta.folders[parent]) return { __abort: json({ error: "Parent folder မတွေ့ပါ" }, 400) };
    const dup = Object.values(meta.folders).some(
      fd => (fd.parent || "") === parent && fd.name.toLowerCase() === name.toLowerCase()
    );
    if (dup) return { __abort: json({ error: "ဤနာမည်ဖြင့် folder ရှိပြီးသားပါ" }, 400) };
    meta.folders[id] = { name, parent, createdAt: nowMM() };
    return { ok: true, id };
  });
  return result instanceof Response ? result : json(result);
}

async function apiFolderRename(request, env, username) {
  const body = await request.json().catch(() => ({}));
  let { id, name } = body;
  name = (name || "").toString().trim();
  const result = await mutateMeta(env, username, (meta) => {
    const fd = meta.folders?.[id];
    if (!fd) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 404) };
    if (!name) return { __abort: json({ error: "နာမည် ထည့်ပါ" }, 400) };
    fd.name = name;
    return { ok: true };
  });
  return result instanceof Response ? result : json(result);
}

async function apiFolderDelete(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  // ဖျက်ရမယ့် key တွေကို snapshot က ရှာ → R2 ဖျက် → index CAS
  const snap = await loadMetaPlain(env, username);
  if (!snap.folders?.[id]) return json({ error: "Folder မတွေ့ပါ" }, 404);
  const toDelete = new Set([id]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [fid, fd] of Object.entries(snap.folders)) {
      if (!toDelete.has(fid) && toDelete.has(fd.parent || "")) { toDelete.add(fid); changed = true; }
    }
  }
  for (const [fileId, f] of Object.entries(snap.files)) {
    if (toDelete.has(f.folder || "")) {
      await env.R2.delete(f.key);
      if (f.share?.token) await env.R2.delete(shareKey(f.share.token));
    }
  }
  const result = await mutateMeta(env, username, (meta) => {
    for (const [fileId, f] of Object.entries(meta.files)) {
      if (toDelete.has(f.folder || "")) {
        meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
        delete meta.files[fileId];
      }
    }
    for (const fid of toDelete) delete meta.folders[fid];
    return { ok: true };
  });
  return result instanceof Response ? result : json(result);
}

async function apiMove(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const { id, folder } = body;
  const result = await mutateMeta(env, username, (meta) => {
    const f = meta.files?.[id];
    if (!f) return { __abort: json({ error: "ဖိုင်မတွေ့ပါ" }, 404) };
    if (folder && !meta.folders[folder]) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 400) };
    f.folder = folder || "";
    return { ok: true };
  });
  return result instanceof Response ? result : json(result);
}

async function apiBulkMove(request, env, username) {
  const body = await request.json().catch(() => ({}));
  const ids = Array.isArray(body.ids) ? body.ids.slice(0, 200) : [];
  const folder = (body.folder || "").toString();
  if (!ids.length) return json({ error: "ဖိုင်မရွေးထားပါ" }, 400);
  const result = await mutateMeta(env, username, (meta) => {
    if (folder && !meta.folders[folder]) return { __abort: json({ error: "Folder မတွေ့ပါ" }, 400) };
    let moved = 0;
    for (const id of ids) {
      const f = meta.files?.[id];
      if (f) { f.folder = folder || ""; moved++; }
    }
    return { ok: true, moved };
  });
  return result instanceof Response ? result : json(result);
}

// ======================= HTML Pages =======================

const AUTH_CSS = `
:root{--brand:#4f46e5;--brand2:#7c3aed;--accent:#06b6d4;--bg1:#f8fafc;--ink:#0f172a;--muted:#64748b}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',-apple-system,sans-serif}
html,body{height:100%}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#eef2ff 0%,#faf5ff 50%,#ecfeff 100%);padding:20px;position:relative;overflow-x:hidden}
.blob{position:fixed;border-radius:50%;filter:blur(80px);opacity:.4;z-index:0;pointer-events:none}
.blob.a{width:380px;height:380px;background:#a5b4fc;top:-120px;left:-80px}
.blob.b{width:340px;height:340px;background:#67e8f9;bottom:-100px;right:-70px}
.card{position:relative;z-index:1;background:#fff;border:1px solid #eef0f5;
padding:40px 32px;border-radius:24px;box-shadow:0 20px 60px rgba(15,23,42,.12);width:100%;max-width:410px;color:var(--ink)}
.logo{width:60px;height:60px;margin:0 auto 18px;border-radius:18px;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,var(--brand),var(--accent));box-shadow:0 10px 26px rgba(79,70,229,.4);font-size:30px}
h1{margin:0 0 4px;font-size:23px;text-align:center;font-weight:800;color:var(--ink)}
.sub{text-align:center;color:var(--muted);font-size:13px;margin-bottom:26px}
.field{position:relative;margin:13px 0}
.field label{display:block;font-size:12px;font-weight:700;color:#475569;margin-bottom:5px}
.field input{width:100%;padding:13px 14px;border:1px solid #e2e8f0;border-radius:13px;font-size:15px;
background:#f8fafc;color:var(--ink);outline:none;transition:.2s}
.field input:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(79,70,229,.14);background:#fff}
.hint{font-size:11px;color:var(--muted);margin-top:4px}
button.main{width:100%;padding:14px;margin-top:16px;border:0;border-radius:13px;font-size:16px;font-weight:700;cursor:pointer;color:#fff;
background:linear-gradient(135deg,var(--brand),var(--brand2));box-shadow:0 10px 24px rgba(79,70,229,.35);transition:.2s;
display:flex;align-items:center;justify-content:center;gap:8px}
button.main:hover{transform:translateY(-2px);box-shadow:0 14px 30px rgba(79,70,229,.5)}
button.main:disabled{opacity:.7;cursor:not-allowed;transform:none}
.spin{width:18px;height:18px;border:2.5px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;
animation:spin .7s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.err{color:#dc2626;font-size:13px;margin-top:12px;text-align:center;min-height:18px}
.swap{text-align:center;margin-top:20px;font-size:13.5px;color:var(--muted)}
.swap a{color:var(--brand);font-weight:700;text-decoration:none}
.swap a:hover{text-decoration:underline}
`;

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lugyi Cloud • ဝင်ရန်</title>
<style>${AUTH_CSS}</style></head><body>
<div class="blob a"></div><div class="blob b"></div>
<div class="card">
<div class="logo">☁️</div>
<h1>Lugyi Cloud</h1>
<div class="sub">အကောင့်ဝင်၍ သင့်ဖိုင်များ စီမံပါ</div>
<div class="field"><label>အသုံးပြုသူအမည်</label><input id="u" placeholder="username" autocomplete="username"></div>
<div class="field"><label>စကားဝှက်</label><input id="p" type="password" placeholder="••••••" autocomplete="current-password"></div>
<button class="main" id="btn" onclick="login()"><span class="spin" id="spin"></span><span id="btnTxt">ဝင်မည်</span></button>
<div class="err" id="err"></div>
<div class="swap">အကောင့်မရှိသေးဘူးလား? <a href="/register">အကောင့်ဖွင့်ရန်</a></div>
</div>
<script>
async function login(){
  const btn=document.getElementById('btn'),spin=document.getElementById('spin'),btnTxt=document.getElementById('btnTxt');
  btn.disabled=true;spin.style.display='block';btnTxt.textContent='ဝင်နေသည်...';
  document.getElementById('err').textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.value,password:p.value})});
    const d=await r.json();
    if(r.ok){location.href='/';return;}
    document.getElementById('err').textContent=d.error||'ဝင်၍မရပါ';
  }catch(e){document.getElementById('err').textContent='ကွန်ရက် ပြဿနာ';}
  btn.disabled=false;spin.style.display='none';btnTxt.textContent='ဝင်မည်';
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
document.getElementById('u').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('p').focus();});
</script>
</body></html>`;

const REGISTER_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lugyi Cloud • အကောင့်ဖွင့်ရန်</title>
<style>${AUTH_CSS}</style></head><body>
<div class="blob a"></div><div class="blob b"></div>
<div class="card">
<div class="logo">✨</div>
<h1>အကောင့်အသစ်ဖွင့်ရန်</h1>
<div class="sub">Invite code ဖြင့် အကောင့်ဖွင့်ပါ</div>
<div class="field"><label>အသုံးပြုသူအမည်</label><input id="u" placeholder="username" autocomplete="username">
<div class="hint">စာလုံး ၃-၂၀ လုံး (a-z, A-Z, 0-9, _)</div></div>
<div class="field"><label>Invite Code</label><input id="inv" placeholder="INVITE CODE">
<div class="hint">Admin ထံမှ ရရှိသော code</div></div>
<div class="field"><label>စကားဝှက်</label><input id="p" type="password" placeholder="••••••" autocomplete="new-password">
<div class="hint">အနည်းဆုံး ၆ လုံး</div></div>
<div class="field"><label>စကားဝှက် အတည်ပြုရန်</label><input id="p2" type="password" placeholder="••••••" autocomplete="new-password"></div>
<button class="main" id="btn" onclick="reg()"><span class="spin" id="spin"></span><span id="btnTxt">အကောင့်ဖွင့်မည်</span></button>
<div class="err" id="err"></div>
<div class="swap">အကောင့်ရှိပြီးသားလား? <a href="/login">ဝင်ရန်</a></div>
</div>
<script>
async function reg(){
  const err=document.getElementById('err');err.textContent='';
  if(p.value!==p2.value){err.textContent='စကားဝှက် နှစ်ခု မတူပါ';return;}
  const btn=document.getElementById('btn'),spin=document.getElementById('spin'),btnTxt=document.getElementById('btnTxt');
  btn.disabled=true;spin.style.display='block';btnTxt.textContent='ဖွင့်နေသည်...';
  try{
    const r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.value,password:p.value,invite:document.getElementById('inv').value})});
    const d=await r.json();
    if(r.ok){location.href='/';return;}
    err.textContent=d.error||'အကောင့်မဖွင့်နိုင်ပါ';
  }catch(e){err.textContent='ကွန်ရက် ပြဿနာ';}
  btn.disabled=false;spin.style.display='none';btnTxt.textContent='အကောင့်ဖွင့်မည်';
}
['u','inv','p','p2'].forEach((id,i,a)=>document.getElementById(id).addEventListener('keydown',e=>{
  if(e.key==='Enter'){if(i<a.length-1)document.getElementById(a[i+1]).focus();else reg();}}));
</script>
</body></html>`;

const APP_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lugyi Cloud</title>
<style>
:root{--brand:#4f46e5;--brand2:#7c3aed;--acc:#06b6d4;--ink:#0f172a;--muted:#64748b;--line:#e8ecf3;
--card:#fff;--bg:#f1f5f9;--ok:#16a34a;--danger:#ef4444;--soft:#f8fafc;--softer:#eef2f7;--chip:#f1f5f9}
[data-theme="dark"]{--ink:#e5e9f0;--muted:#94a3b8;--line:#23304a;--card:#101827;--bg:#0a0f1c;
--soft:#131c2e;--softer:#1a2438;--chip:#1a2438}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',-apple-system,sans-serif}
body{margin:0;color:var(--ink);min-height:100vh;background:var(--bg);transition:background .3s}
header{position:sticky;top:0;z-index:30;background:var(--card);border-bottom:1px solid var(--line);
padding:12px 20px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px}
.brand .lg{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,var(--brand),var(--acc));
display:flex;align-items:center;justify-content:center;font-size:21px;color:#fff;box-shadow:0 6px 16px rgba(79,70,229,.3)}
.brand h1{margin:0;font-size:18px;font-weight:800;color:var(--ink)}
.brand .tagline{font-size:11px;color:var(--muted);margin-top:1px}
.topbtns{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.userchip{display:flex;align-items:center;gap:8px;background:var(--chip);border:1px solid var(--line);
padding:6px 12px;border-radius:30px;font-size:13px;font-weight:700;color:var(--ink)}
.userchip .av{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--brand),var(--brand2));
color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800}
button{padding:9px 14px;border:0;border-radius:11px;color:#fff;cursor:pointer;font-size:14px;font-weight:600;transition:.18s;
background:linear-gradient(135deg,var(--brand),var(--brand2));box-shadow:0 4px 12px rgba(79,70,229,.28)}
button:hover{transform:translateY(-1px);box-shadow:0 8px 18px rgba(79,70,229,.36)}
button:active{transform:translateY(0)}
button:disabled{opacity:.55;cursor:not-allowed;transform:none}
button.sec{background:var(--chip);color:var(--ink);box-shadow:none}
button.sec:hover{background:var(--softer)}
button.danger{background:linear-gradient(135deg,#f43f5e,#dc2626);box-shadow:0 4px 12px rgba(239,68,68,.26)}
button.ghost{background:var(--chip);color:var(--muted);box-shadow:none}
button.ghost:hover{background:var(--softer)}
input,select{padding:11px 12px;border:1px solid var(--line);border-radius:11px;font-size:14px;background:var(--card);outline:none;transition:.2s;color:var(--ink)}
input:focus,select:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(79,70,229,.13)}
.wrap{max-width:1080px;margin:0 auto;padding:20px 16px 70px}
.banner{background:linear-gradient(135deg,#fef3c7,#fde68a);color:#92400e;border-radius:14px;padding:12px 16px;
margin-bottom:16px;font-size:13.5px;font-weight:600;display:none;align-items:center;gap:9px}
.banner.show{display:flex}
.hero{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin-bottom:18px}
@media(max-width:760px){.hero{grid-template-columns:1fr}}
.glass{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;
box-shadow:0 2px 10px rgba(15,23,42,.04)}
.usage-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.usage-top .ic{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,#eef2ff,#e0f2fe);
display:flex;align-items:center;justify-content:center;font-size:24px}
.usage-num{font-size:22px;font-weight:800;line-height:1.1}
.usage-sub{font-size:12px;color:var(--muted)}
.prog{height:12px;background:var(--softer);border-radius:8px;overflow:hidden;margin-top:14px}
.prog>i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#06b6d4,#4f46e5);
transition:width .6s;border-radius:8px}
.prog.warn>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.mini{display:flex;gap:12px;margin-top:14px;flex-wrap:wrap}
.mini .m{flex:1;min-width:90px;text-align:center;background:var(--soft);border-radius:13px;padding:11px;border:1px solid var(--line)}
.mini .m b{font-size:18px;display:block;color:var(--ink)}
.mini .m span{font-size:11px;color:var(--muted)}
.dropzone{border:2px dashed var(--line);border-radius:16px;padding:22px;text-align:center;cursor:pointer;
transition:.2s;background:var(--soft)}
.dropzone:hover,.dropzone.drag{border-color:var(--brand);background:rgba(79,70,229,.06);transform:translateY(-2px)}
.dropzone .big{font-size:38px}
.dropzone .t{font-weight:700;margin-top:6px}
.dropzone .s{font-size:12px;color:var(--muted);margin-top:3px}
.section-h{display:flex;align-items:center;gap:9px;font-weight:800;font-size:15px;margin:6px 0 12px;color:var(--ink)}
.section-h .dot{width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,var(--brand),var(--acc))}
#upQueue{margin-top:12px;display:flex;flex-direction:column;gap:9px}
.uprow{background:var(--soft);border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.uprow .nm{font-size:13px;font-weight:600;word-break:break-all;display:flex;justify-content:space-between;gap:8px;align-items:center}
.uprow .pct{font-variant-numeric:tabular-nums;color:var(--brand);font-weight:700}
.upbar{height:8px;background:var(--softer);border-radius:6px;overflow:hidden;margin-top:7px}
.upbar>i{display:block;height:100%;width:0;border-radius:6px;background:linear-gradient(90deg,var(--brand),var(--acc));transition:width .25s}
.uprow.done .upbar>i{background:linear-gradient(90deg,#22c55e,#16a34a)}
.uprow.err .upbar>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.uprow .st{font-size:11px;color:var(--muted);margin-top:5px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.uprow .retry{background:#fee2e2;color:#b91c1c;border:0;border-radius:8px;padding:3px 10px;font-size:11px;box-shadow:none;display:none}
.uprow.err .retry{display:inline-block}
.remote-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.remote-row input{flex:1;min-width:160px}
.statusline{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--muted);min-height:20px}
.crumb{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:14px;margin:16px 0 12px;
background:var(--card);padding:11px 15px;border-radius:13px;border:1px solid var(--line)}
.crumb a{color:var(--brand);cursor:pointer;text-decoration:none;font-weight:700}
.crumb a:hover{text-decoration:underline}
.crumb span.sep{color:var(--muted)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.toolbar .search{flex:1;min-width:150px;position:relative}
.toolbar .search input{width:100%;padding-left:38px}
.toolbar .search .si{position:absolute;left:13px;top:50%;transform:translateY(-50%);opacity:.5}
.selbar{display:none;align-items:center;gap:8px;background:linear-gradient(135deg,#eef2ff,#e0f2fe);
border:1px solid #c7d2fe;border-radius:13px;padding:10px 14px;margin-bottom:12px;flex-wrap:wrap}
.selbar.show{display:flex}
.selbar .cnt{font-weight:800;color:#3730a3;font-size:14px}
[data-theme="dark"] .selbar{background:rgba(79,70,229,.15);border-color:#3730a3}
[data-theme="dark"] .selbar .cnt{color:#a5b4fc}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:12px;margin-bottom:18px}
.fold{background:var(--card);border:1px solid var(--line);border-radius:15px;padding:15px;cursor:pointer;
display:flex;flex-direction:column;gap:5px;transition:.2s;position:relative;overflow:hidden}
.fold:hover{transform:translateY(-3px);box-shadow:0 12px 26px rgba(79,70,229,.14);border-color:#c7d2fe}
.fold.dragover{border-color:var(--brand);background:rgba(79,70,229,.08);border-style:dashed}
.fold .ico{font-size:32px}
.fold .nm{font-weight:700;word-break:break-word;font-size:14px}
.fold .ct{font-size:11px;color:var(--muted)}
.fold .fbtns{position:absolute;top:8px;right:8px;display:none;gap:4px}
.fold:hover .fbtns{display:flex}
.fold .fbtns button{border:0;border-radius:8px;width:28px;height:28px;font-size:12px;padding:0;box-shadow:none}
.fold .fbtns .ren{background:#dbeafe;color:#1e40af}
.fold .fbtns .del{background:#fee2e2;color:#b91c1c}
/* file list view */
.file{background:var(--card);border-radius:15px;padding:14px;margin-bottom:11px;
box-shadow:0 2px 10px rgba(15,23,42,.04);border:1px solid var(--line);transition:.2s}
.file:hover{box-shadow:0 10px 24px rgba(15,23,42,.08);transform:translateY(-1px)}
.file.sel{border-color:var(--brand);background:rgba(79,70,229,.05)}
.file .top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.file .lft{display:flex;gap:11px;align-items:flex-start}
.chk{width:20px;height:20px;flex-shrink:0;margin-top:13px;cursor:pointer;accent-color:var(--brand)}
.ficon{font-size:24px;flex-shrink:0;width:46px;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#eef2ff,#e0f2fe);cursor:pointer;transition:.18s;overflow:hidden}
.ficon img{width:100%;height:100%;object-fit:cover}
.ficon:hover{transform:scale(1.06)}
.fname{font-weight:700;word-break:break-all;cursor:pointer;color:var(--ink);text-decoration:none;font-size:14.5px}
.fname:hover{color:var(--brand);text-decoration:underline}
.meta{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.6}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.acts button{font-size:12.5px;padding:7px 11px}
.tag{display:inline-block;font-size:11px;padding:2px 9px;border-radius:10px;background:#dbeafe;color:#1e40af;margin-left:6px;font-weight:700}
.tag.exp{background:#fee2e2;color:#991b1b}
.tag.life{background:#dcfce7;color:#166534}
/* file GRID view */
#list.gridview{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
#list.gridview .file{margin-bottom:0;display:flex;flex-direction:column}
#list.gridview .top{flex-direction:column;gap:8px}
#list.gridview .lft{flex-direction:column;align-items:center;text-align:center}
#list.gridview .chk{position:absolute;margin:0;top:10px;left:10px}
#list.gridview .file{position:relative}
#list.gridview .ficon{width:72px;height:72px;font-size:36px}
#list.gridview .fname{font-size:13px;text-align:center}
#list.gridview .meta{text-align:center;font-size:11px}
#list.gridview .acts{justify-content:center}
#list.gridview .acts button{font-size:11px;padding:6px 9px}
.pager{display:flex;gap:6px;justify-content:center;align-items:center;flex-wrap:wrap;margin:18px 0 6px}
.pager button{padding:8px 13px;min-width:40px}
.pager .pinfo{font-size:13px;color:var(--muted);font-weight:600;padding:0 6px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;
padding:13px 22px;border-radius:13px;z-index:99;opacity:0;transition:.3s;font-size:14px;max-width:90%;
box-shadow:0 12px 34px rgba(0,0,0,.4);pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%) translateY(-4px)}
.modal{position:fixed;inset:0;background:rgba(15,23,42,.5);backdrop-filter:blur(5px);display:none;
align-items:center;justify-content:center;z-index:50;padding:16px;animation:fadeIn .2s ease}
.modal.show{display:flex}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal .box{background:var(--card);border-radius:20px;padding:26px;max-width:430px;width:100%;color:var(--ink);
box-shadow:0 30px 70px rgba(0,0,0,.4);animation:pop .25s cubic-bezier(.2,.9,.3,1.2);border:1px solid var(--line)}
@keyframes pop{from{opacity:0;transform:scale(.9) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal h3{margin:0 0 16px;font-size:18px;display:flex;align-items:center;gap:9px;font-weight:800}
.modal input,.modal select{width:100%;margin:6px 0}
.modal .mico{width:56px;height:56px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 12px}
.modal .mico.ask{background:linear-gradient(135deg,#fef3c7,#fde68a)}
.modal .mico.del{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.modal .mtext{text-align:center;color:var(--muted);font-size:14px;line-height:1.6;margin-bottom:18px;word-break:break-word}
.modal .mbtns{display:flex;gap:10px}
.modal .mbtns button{flex:1}
.modal .pbox{background:#0f172a;border-radius:20px;padding:18px;max-width:880px;width:100%;
box-shadow:0 30px 70px rgba(0,0,0,.6);animation:pop .25s cubic-bezier(.2,.9,.3,1.2);border:1px solid #1e293b;color:#fff}
.modal .pbox .phead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.modal .pbox .ptitle{font-weight:700;font-size:15px;word-break:break-all}
.modal .pbox .pclose{background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.3);
border-radius:10px;width:36px;height:36px;padding:0;flex-shrink:0;box-shadow:none}
.modal .pbox .pbody{display:flex;align-items:center;justify-content:center;min-height:120px}
.modal .pbox img{max-width:100%;max-height:70vh;border-radius:12px;display:block}
.modal .pbox video{max-width:100%;max-height:70vh;border-radius:12px;background:#000;width:100%}
.modal .pbox audio{width:100%}
.modal .pbox .pna{padding:30px;text-align:center;color:#cbd5e1;font-size:14px}
small{color:var(--muted)}
.empty{text-align:center;color:var(--muted);padding:46px 0}
.empty .big{font-size:46px}
.spin{width:16px;height:16px;border:2.4px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;
animation:spin .7s linear infinite;display:inline-block;vertical-align:middle;margin-right:6px}
.spin.dark{border-color:rgba(79,70,229,.25);border-top-color:#4f46e5}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:560px){
  .brand .tagline{display:none}
  .acts button{flex:1;min-width:calc(50% - 4px)}
  .topbtns button{padding:8px 11px;font-size:13px}
}
</style></head><body>
<header>
<div class="brand"><div class="lg">☁️</div><div><h1>Lugyi Cloud</h1>
<div class="tagline">Secure Personal Drive</div></div></div>
<div class="topbtns">
<div class="userchip"><span class="av" id="avatar">U</span><span id="uname">...</span></div>
<button class="ghost" id="themeBtn" onclick="toggleTheme()" title="Theme">🌙</button>
<button class="ghost" onclick="openPass()">🔑</button>
<button class="ghost" onclick="logout()">🚪 ထွက်မည်</button>
</div>
</header>
<div class="wrap">

<div class="banner" id="storeBanner">⚠️ <span id="bannerTxt"></span></div>

<div class="hero">
  <div class="glass">
    <div class="usage-top">
      <div style="display:flex;gap:12px;align-items:center">
        <div class="ic">💾</div>
        <div><div class="usage-num" id="usageNum">—</div><div class="usage-sub" id="usagePct">တွက်နေသည်...</div></div>
      </div>
    </div>
    <div class="prog" id="progWrap"><i id="progBar" style="width:0%"></i></div>
    <div class="mini">
      <div class="m"><b id="statFiles">0</b><span>📁 ဖိုင်</span></div>
      <div class="m"><b id="statFolders">0</b><span>🗂️ Folder</span></div>
      <div class="m"><b id="statFree">—</b><span>✨ ကျန်</span></div>
    </div>
  </div>
  <div class="glass">
    <div class="section-h"><span class="dot"></span>🔗 Link မှ တင်ရန် <small>(1.5GB ထိ)</small></div>
    <div class="remote-row">
      <input type="text" id="remoteUrl" placeholder="https://...">
      <input type="text" id="remoteName" placeholder="ဖိုင်နာမည် (optional)">
    </div>
    <button id="remoteBtn" onclick="uploadRemote()" style="width:100%;margin-top:10px">⬆ Link မှ တင်မည်</button>
    <div class="statusline" id="remoteStatus"></div>
  </div>
</div>

<div class="glass" style="margin-bottom:18px">
  <div class="section-h"><span class="dot"></span>📤 ဖိုင်တင်ရန် <small>(တစ်ခါ အများဆုံး ၃ ဖိုင်)</small></div>
  <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
    <div class="big">☁️</div>
    <div class="t">ဖိုင်ရွေးရန် နှိပ်ပါ (သို့) ဆွဲချပါ</div>
    <div class="s">Photo • Video • Music • Txt • PDF ... — တစ်ခါ ၃ ဖိုင်အထိ</div>
  </div>
  <input type="file" id="fileInput" multiple style="display:none">
  <div id="upQueue"></div>
</div>

<div class="crumb" id="crumb"></div>

<div class="selbar" id="selbar">
  <span class="cnt" id="selCnt">0 ရွေးထား</span>
  <button class="sec" onclick="bulkMove()">📦 ရွှေ့</button>
  <button class="danger" onclick="bulkDelete()">🗑 ဖျက်</button>
  <button class="ghost" onclick="clearSel()">✖ ပယ်</button>
</div>

<div class="toolbar">
  <div class="search"><span class="si">🔍</span><input id="searchBox" placeholder="ဖိုင်ရှာရန်..." oninput="renderFiles()"></div>
  <select id="sortSel" onchange="renderFiles()">
    <option value="date">🕒 ရက်စွဲ (အသစ်)</option>
    <option value="dateAsc">🕒 ရက်စွဲ (အဟောင်း)</option>
    <option value="name">🔤 နာမည် (A→Z)</option>
    <option value="sizeDesc">📊 အရွယ် (ကြီး→သေး)</option>
    <option value="sizeAsc">📊 အရွယ် (သေး→ကြီး)</option>
  </select>
  <button class="sec" id="viewBtn" onclick="toggleView()" title="View">🔲</button>
  <button class="sec" onclick="openNewFolder()">📁 အသစ်</button>
</div>

<div class="section-h"><span class="dot"></span>🗂️ Folders</div>
<div class="grid" id="folders"></div>

<div class="section-h"><span class="dot"></span>📁 ဖိုင်များ</div>
<div id="list"></div>
<div class="pager" id="pager"></div>

</div>

<div class="modal" id="previewModal"><div class="pbox">
<div class="phead"><div class="ptitle" id="previewTitle"></div>
<button class="pclose" onclick="closePreview()">✖</button></div>
<div class="pbody" id="previewBody"></div>
</div></div>

<div class="modal" id="shareModal"><div class="box">
<h3>🔗 Share Link</h3>
<select id="shareDur">
<option value="2d">📅 ၂ ရက်</option><option value="1w">📅 ၁ ပတ်</option>
<option value="1m">📅 ၁ လ</option><option value="1y">📅 ၁ နှစ်</option>
<option value="lifetime">♾️ Lifetime</option><option value="off">🚫 Link ပိတ်မည်</option>
</select>
<button onclick="doShare()" style="width:100%;margin-top:12px">✅ အတည်ပြုမည်</button>
<div id="shareResult" style="margin-top:12px;word-break:break-all;font-size:13px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('shareModal')">ပိတ်မည်</button>
</div></div>

<div class="modal" id="folderModal"><div class="box">
<h3>📁 Folder အသစ်ဆောက်ရန်</h3>
<input type="text" id="folderName" placeholder="Folder နာမည်" maxlength="80">
<button onclick="doCreateFolder()" style="width:100%;margin-top:10px">✅ ဆောက်မည်</button>
<div id="folderErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('folderModal')">ပိတ်မည်</button>
</div></div>

<div class="modal" id="renameModal"><div class="box">
<h3>✏️ နာမည်ပြောင်းရန်</h3>
<input type="text" id="renameInput" placeholder="ဖိုင်နာမည် အသစ်" maxlength="200">
<button onclick="doRename()" style="width:100%;margin-top:10px">✅ ပြောင်းမည်</button>
<div id="renameErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('renameModal')">ပိတ်မည်</button>
</div></div>

<div class="modal" id="moveModal"><div class="box">
<h3>📦 ဖိုင်ရွှေ့ရန်</h3>
<select id="moveTarget"></select>
<button onclick="doMove()" style="width:100%;margin-top:12px">✅ ရွှေ့မည်</button>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('moveModal')">ပိတ်မည်</button>
</div></div>

<div class="modal" id="passModal"><div class="box">
<h3>🔑 Password ပြောင်းရန်</h3>
<input type="password" id="oldPass" placeholder="လက်ရှိ password">
<input type="password" id="newPass" placeholder="password အသစ် (၆ လုံးအထက်)">
<button onclick="doChangePass()" style="width:100%;margin-top:10px">✅ ပြောင်းမည်</button>
<div id="passErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<small style="display:block;margin-top:8px">ℹ️ Password ပြောင်းရင် အခြား device တွေက အလိုအလျောက် logout ဖြစ်ပါမယ်။</small>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('passModal')">ပိတ်မည်</button>
</div></div>

<div class="modal" id="confirmModal"><div class="box">
<div class="mico" id="confirmIco">❓</div>
<h3 id="confirmTitle" style="justify-content:center"></h3>
<div class="mtext" id="confirmText"></div>
<div class="mbtns">
<button class="sec" onclick="confirmResolve(false)">မလုပ်တော့ပါ</button>
<button class="danger" id="confirmOk" onclick="confirmResolve(true)">အတည်ပြုမည်</button>
</div></div></div>

<div class="toast" id="toast"></div>

<script>
let currentFolder="",currentShareId=null,currentMoveId=null,currentRenameId=null;
let allFolders=[],currentPage=1;const PAGE_SIZE=12;let lastFiles=[],_confirmCb=null;
const MAX_PARALLEL=3;
const DIRECT_LIMIT=25*1024*1024; // 25MB အထက် → presign (Worker memory ဘေးကင်း)
let viewMode=localStorage.getItem('lc_view')||'list';
let selected=new Set();
let lastUploadFiles=[];

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function openModal(id){document.getElementById(id).classList.add('show');}
function closeModal(id){document.getElementById(id).classList.remove('show');}
function fileIcon(t){t=t||'';if(t.startsWith('video/'))return'🎬';if(t.startsWith('image/'))return'🖼️';if(t.startsWith('audio/'))return'🎵';if(t.startsWith('text/'))return'📄';if(t.includes('pdf'))return'📕';if(t.includes('zip')||t.includes('rar'))return'🗜️';return'📦';}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function escapeJs(s){return String(s).replace(/['\\\\]/g,'\\\\$&').replace(/"/g,'&quot;');}

// ---- theme ----
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);
  document.getElementById('themeBtn').textContent=t==='dark'?'☀️':'🌙';}
function toggleTheme(){const cur=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  localStorage.setItem('lc_theme',cur);applyTheme(cur);}
applyTheme(localStorage.getItem('lc_theme')||'light');

function confirmBox({title,text,okText='အတည်ပြုမည်',danger=true}){
  return new Promise(res=>{_confirmCb=res;
    document.getElementById('confirmIco').textContent=danger?'🗑':'❓';
    document.getElementById('confirmIco').className='mico '+(danger?'del':'ask');
    document.getElementById('confirmTitle').textContent=title||'အတည်ပြုပါ';
    document.getElementById('confirmText').textContent=text||'';
    const ok=document.getElementById('confirmOk');ok.textContent=okText;ok.className=danger?'danger':'';
    openModal('confirmModal');});
}
function confirmResolve(v){closeModal('confirmModal');if(_confirmCb){_confirmCb(v);_confirmCb=null;}}

function clearMediaSession(){
  try{
    if('mediaSession' in navigator){
      navigator.mediaSession.metadata=null;
      navigator.mediaSession.playbackState='none';
      ['play','pause','seekto','seekforward','seekbackward','previoustrack','nexttrack','stop']
        .forEach(a=>{try{navigator.mediaSession.setActionHandler(a,null);}catch(e){}});
    }
  }catch(e){}
}
function openPreview(id,name,type){
  type=type||'';
  document.getElementById('previewTitle').textContent=name;
  const body=document.getElementById('previewBody');
  const src='/api/view?id='+encodeURIComponent(id);
  if(type.startsWith('image/'))body.innerHTML='<img src="'+src+'" alt="'+escapeHtml(name)+'">';
  else if(type.startsWith('video/'))body.innerHTML='<video id="pv" src="'+src+'" controls autoplay playsinline preload="metadata"></video>';
  else if(type.startsWith('audio/'))body.innerHTML='<audio id="pv" src="'+src+'" controls autoplay></audio>';
  else if(type.startsWith('text/'))body.innerHTML='<iframe src="'+src+'" style="width:100%;height:60vh;border:0;border-radius:12px;background:#fff"></iframe>';
  else body.innerHTML='<div class="pna">ဤဖိုင်အမျိုးအစားကို preview မပြနိုင်ပါ။<br>Download လုပ်ပြီး ကြည့်ပါ။</div>';
  openModal('previewModal');
}
function closePreview(){
  const body=document.getElementById('previewBody');
  const m=body.querySelector('video,audio');
  if(m){try{m.pause();m.removeAttribute('src');m.srcObject=null;m.load();}catch(e){}}
  body.innerHTML='';
  clearMediaSession();
  closeModal('previewModal');
}
document.addEventListener('play',function(e){
  if(e.target&&(e.target.tagName==='VIDEO'||e.target.tagName==='AUDIO')&&'mediaSession' in navigator){
    try{navigator.mediaSession.metadata=new MediaMetadata({title:document.getElementById('previewTitle').textContent||'Lugyi Cloud',artist:'Lugyi Cloud'});}catch(e){}
  }
},true);
// ESC = ပိတ်
document.addEventListener('keydown',e=>{if(e.key==='Escape'){
  ['previewModal','shareModal','folderModal','renameModal','moveModal','passModal','confirmModal'].forEach(id=>{
    const m=document.getElementById(id);if(m&&m.classList.contains('show')){if(id==='previewModal')closePreview();else closeModal(id);}});
}});

function setRoute(folder,push){currentFolder=folder;currentPage=1;clearSel();
  const url='#'+(folder?('f/'+folder):'');if(push)history.pushState({folder},'',url);load();}
window.addEventListener('popstate',e=>{const f=(e.state&&e.state.folder!==undefined)?e.state.folder:parseHash();currentFolder=f||"";currentPage=1;load();});
function parseHash(){const h=location.hash||'';const m=h.match(/^#f\\/(.+)$/);return m?decodeURIComponent(m[1]):"";}

async function loadMe(){
  try{const r=await fetch('/api/me');if(r.ok){const d=await r.json();
    document.getElementById('uname').textContent=d.username;
    document.getElementById('avatar').textContent=(d.username||'U').charAt(0).toUpperCase();}}catch(e){}
}

async function load(){
  const r=await fetch('/api/list?folder='+encodeURIComponent(currentFolder));
  if(r.status===401){location.href='/login';return;}
  const d=await r.json();
  const pct=Math.min(100,(d.totalBytes/d.maxBytes*100));
  document.getElementById('usageNum').innerHTML=fmtSize(d.totalBytes)+' <span style="font-size:13px;color:#94a3b8">/ '+fmtSize(d.maxBytes)+'</span>';
  document.getElementById('usagePct').textContent=pct.toFixed(1)+'% အသုံးပြုထား';
  document.getElementById('progBar').style.width=pct+'%';
  document.getElementById('progWrap').className='prog'+(pct>85?' warn':'');
  document.getElementById('statFiles').textContent=d.files.length;
  document.getElementById('statFolders').textContent=d.folders.length;
  document.getElementById('statFree').textContent=fmtSize(Math.max(0,d.maxBytes-d.totalBytes));

  // storage warning banner
  const banner=document.getElementById('storeBanner');
  if(pct>=90){banner.classList.add('show');document.getElementById('bannerTxt').textContent='သိုလှောင်ခန့် '+pct.toFixed(0)+'% ပြည့်နေပါပြီ။ မလိုတဲ့ဖိုင်တွေ ဖျက်ပါ။';}
  else banner.classList.remove('show');

  let cb='<a onclick="goFolder(\\'\\')">🏠 Home</a>';
  for(const b of d.breadcrumb)cb+='<span class="sep">›</span><a onclick="goFolder(\\''+b.id+'\\')">'+escapeHtml(b.name)+'</a>';
  document.getElementById('crumb').innerHTML=cb;

  const fg=document.getElementById('folders');
  if(!d.folders.length)fg.innerHTML='<div style="color:#94a3b8;font-size:13px;grid-column:1/-1">Folder မရှိသေးပါ။</div>';
  else fg.innerHTML=d.folders.map(fd=>
    '<div class="fold" data-fid="'+fd.id+'" onclick="goFolder(\\''+fd.id+'\\')" '+
    'ondragover="folderDragOver(event,this)" ondragleave="folderDragLeave(this)" ondrop="folderDrop(event,\\''+fd.id+'\\',this)">'+
    '<div class="fbtns">'+
    '<button class="ren" title="နာမည်ပြောင်း" onclick="event.stopPropagation();renameFolder(\\''+fd.id+'\\',\\''+escapeJs(fd.name)+'\\')">✏️</button>'+
    '<button class="del" title="ဖျက်" onclick="event.stopPropagation();delFolder(\\''+fd.id+'\\',\\''+escapeJs(fd.name)+'\\')">🗑</button></div>'+
    '<div class="ico">📁</div><div class="nm">'+escapeHtml(fd.name)+'</div><div class="ct">'+fd.count+' items</div></div>'
  ).join('');

  lastFiles=d.files;renderFiles();
}

function sortFiles(arr){
  const s=document.getElementById('sortSel').value;
  const a=arr.slice();
  if(s==='name')a.sort((x,y)=>x.name.localeCompare(y.name));
  else if(s==='sizeDesc')a.sort((x,y)=>(y.size||0)-(x.size||0));
  else if(s==='sizeAsc')a.sort((x,y)=>(x.size||0)-(y.size||0));
  else if(s==='dateAsc')a.sort((x,y)=>(x.uploadedAt||'').localeCompare(y.uploadedAt||''));
  else a.sort((x,y)=>(y.uploadedAt||'').localeCompare(x.uploadedAt||''));
  return a;
}

function renderFiles(){
  const list=document.getElementById('list'),pager=document.getElementById('pager');
  list.className=viewMode==='grid'?'gridview':'';
  const q=(document.getElementById('searchBox').value||'').toLowerCase().trim();
  let arr=lastFiles;
  if(q)arr=lastFiles.filter(f=>f.name.toLowerCase().includes(q));
  arr=sortFiles(arr);
  const total=arr.length;
  if(!total){list.innerHTML='<div class="empty"><div class="big">🗂️</div>'+(q?'ရှာဖွေမှု မတွေ့ပါ။':'ဤနေရာတွင် ဖိုင်မရှိသေးပါ။')+'</div>';pager.innerHTML='';updateSelBar();return;}
  const pages=Math.ceil(total/PAGE_SIZE);
  if(currentPage>pages)currentPage=pages;if(currentPage<1)currentPage=1;
  const start=(currentPage-1)*PAGE_SIZE,slice=arr.slice(start,start+PAGE_SIZE);
  list.innerHTML=slice.map(f=>{
    let shareTag='';
    if(f.share){const exp=f.share.expiresAt;
      if(exp&&Date.now()>exp)shareTag='<span class="tag exp">Link ကုန်</span>';
      else if(exp)shareTag='<span class="tag">'+new Date(exp).toLocaleDateString('my-MM')+' ထိ</span>';
      else shareTag='<span class="tag life">♾️ Lifetime</span>';}
    const tEsc=escapeJs(f.type||''),nEsc=escapeJs(f.name);
    const isImg=(f.type||'').startsWith('image/');
    const iconInner=isImg?'<img loading="lazy" src="/api/view?id='+f.id+'" alt="">':fileIcon(f.type);
    const isSel=selected.has(f.id);
    return '<div class="file'+(isSel?' sel':'')+'" draggable="true" ondragstart="fileDragStart(event,\\''+f.id+'\\')">'+
      '<div class="top"><div class="lft">'+
      '<input type="checkbox" class="chk" '+(isSel?'checked':'')+' onchange="toggleSel(\\''+f.id+'\\',this.checked)">'+
      '<div class="ficon" title="ကြည့်ရန်" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">'+iconInner+'</div><div>'+
      '<div class="fname" title="ကြည့်ရန်" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">'+escapeHtml(f.name)+'</div>'+shareTag+
      '<div class="meta">'+fmtSize(f.size)+' • '+escapeHtml(f.type||'')+'<br>🕒 '+escapeHtml(f.uploadedAt||'')+'</div>'+
      '</div></div></div><div class="acts">'+
      '<button class="sec" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">👁</button>'+
      '<button onclick="dl(\\''+f.id+'\\')">⬇</button>'+
      '<button class="sec" onclick="openRename(\\''+f.id+'\\',\\''+nEsc+'\\')">✏️</button>'+
      (f.share?'<button class="sec" onclick="copyShare(\\''+f.share.token+'\\',\\''+nEsc+'\\')">📋</button>':'')+
      '<button class="sec" onclick="openShare(\\''+f.id+'\\')">🔗</button>'+
      '<button class="sec" onclick="openMove(\\''+f.id+'\\')">📦</button>'+
      '<button class="danger" onclick="del(\\''+f.id+'\\',\\''+nEsc+'\\')">🗑</button>'+
      '</div></div>';
  }).join('');
  if(pages<=1){pager.innerHTML='';}
  else{
    let p='<button class="sec" '+(currentPage<=1?'disabled':'')+' onclick="gotoPage('+(currentPage-1)+')">‹</button>';
    p+='<span class="pinfo">'+currentPage+' / '+pages+'</span>';
    p+='<button class="sec" '+(currentPage>=pages?'disabled':'')+' onclick="gotoPage('+(currentPage+1)+')">›</button>';
    pager.innerHTML=p;
  }
  updateSelBar();
}
function gotoPage(p){currentPage=p;renderFiles();window.scrollTo({top:document.getElementById('list').offsetTop-80,behavior:'smooth'});}
function goFolder(id){setRoute(id,true);}
function dl(id){window.open('/api/download?id='+encodeURIComponent(id),'_blank');}
function toggleView(){viewMode=viewMode==='grid'?'list':'grid';localStorage.setItem('lc_view',viewMode);
  document.getElementById('viewBtn').textContent=viewMode==='grid'?'📋':'🔲';renderFiles();}
document.getElementById('viewBtn').textContent=viewMode==='grid'?'📋':'🔲';

// ---- selection / bulk ----
function toggleSel(id,on){if(on)selected.add(id);else selected.delete(id);
  const card=event.target.closest('.file');if(card)card.classList.toggle('sel',on);updateSelBar();}
function clearSel(){selected.clear();updateSelBar();
  document.querySelectorAll('.file.sel').forEach(c=>c.classList.remove('sel'));
  document.querySelectorAll('.chk:checked').forEach(c=>c.checked=false);}
function updateSelBar(){const bar=document.getElementById('selbar');
  if(selected.size>0){bar.classList.add('show');document.getElementById('selCnt').textContent=selected.size+' ရွေးထား';}
  else bar.classList.remove('show');}
async function bulkDelete(){
  const ids=[...selected];if(!ids.length)return;
  const ok=await confirmBox({title:'ဖိုင်များ ဖျက်မည်',text:ids.length+' ဖိုင်ကို အပြီးဖျက်မှာ သေချာလား?',okText:'🗑 ဖျက်မည်'});
  if(!ok)return;
  const r=await fetch('/api/bulkdelete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  const d=await r.json();if(r.ok){toast('🗑 '+(d.deleted||0)+' ဖိုင် ဖျက်ပြီး');clearSel();load();}else toast(d.error||'မရပါ');
}
async function bulkMove(){
  const ids=[...selected];if(!ids.length)return;
  currentMoveId='__bulk__';await buildAllFolders();
  const sel=document.getElementById('moveTarget');
  sel.innerHTML='<option value="">🏠 Home (root)</option>'+allFolders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.path)+'</option>').join('');
  openModal('moveModal');
}

// ---- drag file → folder ----
let dragFileId=null;
function fileDragStart(e,id){dragFileId=id;e.dataTransfer.effectAllowed='move';}
function folderDragOver(e,el){e.preventDefault();el.classList.add('dragover');}
function folderDragLeave(el){el.classList.remove('dragover');}
async function folderDrop(e,folderId,el){e.preventDefault();el.classList.remove('dragover');
  if(!dragFileId)return;const id=dragFileId;dragFileId=null;
  const r=await fetch('/api/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,folder:folderId})});
  const d=await r.json();if(r.ok){toast('📦 ရွှေ့ပြီး');load();}else toast(d.error||'မရပါ');}

async function del(id,name){
  const ok=await confirmBox({title:'ဖိုင်ဖျက်မည်',text:'"'+name+'" ကို အပြီးဖျက်မှာ သေချာလား?',okText:'🗑 ဖျက်မည်'});
  if(!ok)return;
  const r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();if(r.ok){toast('🗑 ဖျက်ပြီးပါပြီ');selected.delete(id);load();}else toast(d.error||'မဖျက်နိုင်ပါ');
}

function openRename(id,name){currentRenameId=id;document.getElementById('renameErr').textContent='';
  document.getElementById('renameInput').value=name;openModal('renameModal');
  setTimeout(()=>document.getElementById('renameInput').focus(),100);}
async function doRename(){
  const name=document.getElementById('renameInput').value.trim();
  if(!name){document.getElementById('renameErr').textContent='နာမည်ထည့်ပါ';return;}
  const r=await fetch('/api/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentRenameId,name})});
  const d=await r.json();
  if(r.ok){toast('✏️ နာမည်ပြောင်းပြီးပါပြီ');closeModal('renameModal');load();}
  else document.getElementById('renameErr').textContent=d.error||'မရပါ';
}

function openNewFolder(){document.getElementById('folderErr').textContent='';document.getElementById('folderName').value='';openModal('folderModal');
  setTimeout(()=>document.getElementById('folderName').focus(),100);}
async function doCreateFolder(){
  const name=document.getElementById('folderName').value.trim();
  if(!name){document.getElementById('folderErr').textContent='နာမည်ထည့်ပါ';return;}
  const r=await fetch('/api/folder/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,parent:currentFolder})});
  const d=await r.json();
  if(r.ok){toast('📁 Folder ဆောက်ပြီးပါပြီ');closeModal('folderModal');load();}
  else document.getElementById('folderErr').textContent=d.error||'မရပါ';
}
async function renameFolder(id,name){
  const nn=prompt('Folder နာမည် အသစ်:',name);if(nn==null)return;const t=nn.trim();if(!t)return;
  const r=await fetch('/api/folder/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,name:t})});
  const d=await r.json();if(r.ok){toast('✏️ Folder နာမည်ပြောင်းပြီး');load();}else toast(d.error||'မရပါ');
}
async function delFolder(id,name){
  const ok=await confirmBox({title:'Folder ဖျက်မည်',text:'"'+name+'" နှင့် အထဲက ဖိုင်အားလုံး ဖျက်မှာ သေချာလား?',okText:'🗑 ဖျက်မည်'});
  if(!ok)return;
  const r=await fetch('/api/folder/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();if(r.ok){toast('🗑 Folder ဖျက်ပြီးပါပြီ');load();}else toast(d.error||'မရပါ');
}

async function openMove(id){currentMoveId=id;await buildAllFolders();
  const sel=document.getElementById('moveTarget');
  sel.innerHTML='<option value="">🏠 Home (root)</option>'+allFolders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.path)+'</option>').join('');
  openModal('moveModal');}
// N+1 ဖြေရှင်း — folder tree တစ်ခါတည်း fetch
async function buildAllFolders(){
  try{const r=await fetch('/api/folders/all');const d=await r.json();allFolders=d.folders||[];}
  catch(e){allFolders=[];}
}
async function doMove(){
  const folder=document.getElementById('moveTarget').value;
  if(currentMoveId==='__bulk__'){
    const ids=[...selected];
    const r=await fetch('/api/bulkmove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,folder})});
    const d=await r.json();if(r.ok){toast('📦 '+(d.moved||0)+' ဖိုင် ရွှေ့ပြီး');closeModal('moveModal');clearSel();load();}else toast(d.error||'မရပါ');
    return;
  }
  const r=await fetch('/api/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentMoveId,folder})});
  const d=await r.json();if(r.ok){toast('📦 ရွှေ့ပြီးပါပြီ');closeModal('moveModal');load();}else toast(d.error||'မရပါ');
}

const dz=document.getElementById('dropzone');
['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag');}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag');}));
dz.addEventListener('drop',e=>{const fs=[...e.dataTransfer.files];if(fs.length)handleFiles(fs);});
document.getElementById('fileInput').addEventListener('change',e=>{const fs=[...e.target.files];if(fs.length)handleFiles(fs);e.target.value='';});

function handleFiles(files){
  if(files.length>MAX_PARALLEL){toast('⚠️ တစ်ခါ အများဆုံး ၃ ဖိုင်သာ တင်နိုင်ပါသည်။ ပထမ ၃ ဖိုင်ကိုသာ တင်ပါမည်။');files=files.slice(0,MAX_PARALLEL);}
  lastUploadFiles=files;
  const q=document.getElementById('upQueue');q.innerHTML='';
  files.map((f,i)=>{
    const row=document.createElement('div');row.className='uprow';row.id='up'+i;
    row.innerHTML='<div class="nm"><span>'+escapeHtml(f.name)+'</span><span class="pct" id="pct'+i+'">0%</span></div>'+
      '<div class="upbar"><i id="bar'+i+'"></i></div>'+
      '<div class="st"><span id="st'+i+'">စောင့်ဆိုင်းနေသည်...</span>'+
      '<button class="retry" onclick="retryUpload('+i+')">↻ ပြန်ကြိုးစား</button></div>';
    q.appendChild(row);return row;});
  Promise.all(files.map((f,i)=>uploadOne(f,i))).then(results=>{
    const okCount=results.filter(x=>x).length;
    if(okCount===files.length){toast('✅ အားလုံး တင်ပြီးပါပြီ');setTimeout(()=>{document.getElementById('upQueue').innerHTML='';},2500);}
    else toast('⚠️ '+okCount+'/'+files.length+' ဖိုင်သာ အောင်မြင်ပါသည်။');
    load();
  });
}
function retryUpload(i){
  const f=lastUploadFiles[i];if(!f)return;
  const row=document.getElementById('up'+i);if(row)row.classList.remove('err');
  uploadOne(f,i).then(ok=>{if(ok){toast('✅ ပြန်တင်အောင်မြင်ပါပြီ');load();}});
}
function setProg(i,pct,txt,cls){
  const bar=document.getElementById('bar'+i),p=document.getElementById('pct'+i),st=document.getElementById('st'+i),row=document.getElementById('up'+i);
  if(bar)bar.style.width=pct+'%';if(p)p.textContent=Math.round(pct)+'%';if(st&&txt)st.textContent=txt;
  if(cls&&row)row.classList.add(cls);
}
function xhrUpload(url,method,body,headers,onProg){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();xhr.open(method,url);
    if(headers)for(const k in headers)xhr.setRequestHeader(k,headers[k]);
    xhr.upload.onprogress=e=>{if(e.lengthComputable)onProg(e.loaded/e.total*100);};
    xhr.onload=()=>{let d={};try{d=JSON.parse(xhr.responseText);}catch(e){}
      if(xhr.status>=200&&xhr.status<300)resolve({ok:true,data:d,status:xhr.status});
      else resolve({ok:false,data:d,status:xhr.status});};
    xhr.onerror=()=>reject(new Error('network'));xhr.send(body);
  });
}
async function uploadOne(file,i){
  try{
    setProg(i,0,'တင်နေသည်...');
    if(file.size<=DIRECT_LIMIT){
      const fd=new FormData();fd.append('file',file);fd.append('folder',currentFolder);fd.append('name',file.name);
      const res=await xhrUpload('/api/upload','POST',fd,null,p=>setProg(i,p));
      if(!res.ok)throw new Error(res.data.error||'upload failed');
    }else{
      setProg(i,0,'ကြီးမားသောဖိုင် — ပြင်ဆင်နေသည်...');
      const pr=await fetch('/api/presign',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({name:file.name,size:file.size,type:file.type,folder:currentFolder})});
      const pd=await pr.json();if(!pr.ok)throw new Error(pd.error);
      const res=await xhrUpload(pd.uploadUrl,'PUT',file,{'Content-Type':file.type||'application/octet-stream'},p=>setProg(i,p,'သိုလှောင်ခန့်သို့ တင်နေသည်...'));
      if(!res.ok)throw new Error('Upload failed '+res.status);
      setProg(i,100,'အတည်ပြုနေသည်...');
      const fr=await fetch('/api/finalize',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({id:pd.id,key:pd.key,name:file.name,type:file.type,folder:currentFolder})});
      const fd2=await fr.json();if(!fr.ok)throw new Error(fd2.error);
    }
    setProg(i,100,'✅ ပြီးပါပြီ','done');
    return true;
  }catch(e){setProg(i,100,'❌ '+e.message,'err');return false;}
}

async function uploadRemote(){
  const url=document.getElementById('remoteUrl').value.trim();
  const name=document.getElementById('remoteName').value.trim();
  if(!url){toast('URL ထည့်ပါ');return;}
  const st=document.getElementById('remoteStatus'),btn=document.getElementById('remoteBtn');
  btn.disabled=true;st.innerHTML='<span class="spin dark"></span> ဖိုင်တင်နေသည်... (ခဏစောင့်ပါ)';
  try{
    const r=await fetch('/api/remote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,name,folder:currentFolder})});
    const d=await r.json();
    if(r.ok){toast('✅ ဖိုင်တင်ပြီးပါပြီ');document.getElementById('remoteUrl').value='';document.getElementById('remoteName').value='';load();}
    else toast('❌ '+(d.error||'မတင်နိုင်ပါ'));
  }catch(e){toast('❌ ကွန်ရက် ပြဿနာ');}
  st.innerHTML='';btn.disabled=false;
}

function openShare(id){currentShareId=id;document.getElementById('shareResult').textContent='';openModal('shareModal');}
async function doShare(){
  const dur=document.getElementById('shareDur').value;
  const r=await fetch('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentShareId,duration:dur})});
  const d=await r.json();if(!r.ok){toast(d.error||'မရပါ');return;}
  if(d.share){const link=buildShareLink(d.share.token,d.share.name);
    document.getElementById('shareResult').innerHTML='<b>🔗 Link:</b><br>'+escapeHtml(link)+'<br><button style="margin-top:8px" onclick="copyText(\\''+escapeJs(link)+'\\')">📋 Copy</button>';
    toast('✅ Share link ဖန်တီးပြီးပါပြီ');}
  else{document.getElementById('shareResult').textContent='🚫 Link ပိတ်လိုက်ပါပြီ။';toast('Link ပိတ်ပြီး');}
  load();
}
function buildShareLink(token,name){let base=location.origin+'/s/'+token;
  if(name){const safe=encodeURIComponent(name).replace(/%2F/g,'_');base+='/'+safe;}return base;}
function copyShare(token,name){copyText(buildShareLink(token,name));}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('📋 Copy ကူးပြီးပါပြီ'));}

function openPass(){document.getElementById('passErr').textContent='';document.getElementById('oldPass').value='';document.getElementById('newPass').value='';openModal('passModal');}
async function doChangePass(){
  const oldPass=document.getElementById('oldPass').value,newPass=document.getElementById('newPass').value;
  const r=await fetch('/api/changepass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldPass,newPass})});
  const d=await r.json();if(r.ok){toast('✅ Password ပြောင်းပြီးပါပြီ');closeModal('passModal');}else document.getElementById('passErr').textContent=d.error||'မရပါ';
}
async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/login';}

currentFolder=parseHash();
history.replaceState({folder:currentFolder},'',location.hash||'#');
loadMe();
load();
</script>
</body></html>`;
