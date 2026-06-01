// ======================= Fast Lugyi Storage =======================
// Cloudflare Pages Functions + R2  (single-file backend + HTML)
// Premium UI v2 • Folders • Video Seek (Range) • Rename • Multi-upload
// Security hardened • 5-day session • Upload progress
// ==================================================================

const MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024;        // 10 GB total storage
const MAX_REMOTE_BYTES = Math.floor(1.5 * 1024 * 1024 * 1024); // 1.5 GB remote url
const META_KEY = "__meta__/index.json";                 // file list + total size
const LOCK_KEY = "__meta__/loginlock.json";             // login attempt lock
const SESSION_DAYS = 5;                                  // auto logout after 5 days
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const MAX_PARALLEL_UPLOAD = 3;                           // phone multi-upload limit

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- Security headers (applied to HTML pages) ----
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

// ---- constant-time string compare (timing-attack safe for password) ----
function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  // length leak ကို လျှော့ချရန် hash ပြီး နှိုင်း
  if (a.length !== b.length) {
    // ဆက်တွက်စေပြီးမှ false ပြန် (timing flatten)
    let diff = 1;
    const max = Math.max(a.length, b.length, 1);
    for (let i = 0; i < max; i++) diff |= (a.charCodeAt(i % a.length || 0) ^ b.charCodeAt(i % b.length || 0));
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
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

async function makeToken(env, user) {
  const exp = Date.now() + SESSION_MS;               // 5 days
  const iat = Date.now();
  const payload = `${user}.${exp}.${iat}`;
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
  // constant-time signature compare
  if (!safeEqual(expected, parts[1])) return null;
  const seg = payload.split(".");
  const user = seg[0];
  const expStr = seg[1];
  const iatStr = seg[2];
  if (!expStr || Date.now() > Number(expStr)) return null;       // hard expiry (5 days)
  // absolute-age guard: token အသက် 5 ရက်ကျော်ရင် auto invalid
  if (iatStr && Date.now() - Number(iatStr) > SESSION_MS) return null;
  return user;
}

function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}

async function isAuthed(request, env) {
  const tok = getCookie(request, "session");
  const user = await verifyToken(env, tok);
  return !!user;
}

// ---- CSRF helper: same-origin enforcement for state-changing API ----
function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (origin) {
    try { if (new URL(origin).host !== url.host) return false; }
    catch { return false; }
    return true;
  }
  // Origin မပါရင် Referer နဲ့ စစ်
  const ref = request.headers.get("Referer");
  if (ref) {
    try { return new URL(ref).host === url.host; } catch { return false; }
  }
  // header နှစ်ခုလုံး မပါတဲ့ POST ကို ပယ်
  return false;
}

// ---- Metadata index (file list + folders + total bytes) ----
async function loadMeta(env) {
  const obj = await env.R2.get(META_KEY);
  if (!obj) return { totalBytes: 0, files: {}, folders: {} };
  try {
    const m = JSON.parse(await obj.text());
    m.files = m.files || {};
    m.folders = m.folders || {};
    m.totalBytes = m.totalBytes || 0;
    return m;
  } catch { return { totalBytes: 0, files: {}, folders: {} }; }
}
async function saveMeta(env, meta) {
  await env.R2.put(META_KEY, JSON.stringify(meta), {
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

function nowMM() {
  const d = new Date(Date.now() + (6 * 60 + 30) * 60 * 1000); // UTC+6:30
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function randId() {
  return crypto.randomUUID().replace(/-/g, "");
}

// ---- filename sanitize (path traversal / control char block) ----
function cleanName(name, fallback) {
  let n = String(name == null ? "" : name).trim();
  n = n.replace(/[\/\\]/g, "_");          // slash ဖယ်
  n = n.replace(/[\x00-\x1f\x7f]/g, "");  // control char ဖယ်
  n = n.replace(/^\.+/, "");              // ရှေ့ dot ဖယ် (.htaccess စသဖြင့်)
  if (n.length > 200) {
    const dot = n.lastIndexOf(".");
    const ext = dot > -1 ? n.slice(dot) : "";
    n = n.slice(0, 200 - ext.length) + ext;
  }
  return n || fallback || "file";
}

// ---- AWS Signature V4 for R2 presigned URL ----
async function sha256Hex(data) {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hmacRaw(key, msg) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
async function presignR2Put(env, objectKey, expiresSec = 3600) {
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

// ---- Range request parser ----
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

// ---- Stream an R2 object with Range support ----
async function serveObject(request, env, f, { inlineDefault = false } = {}) {
  const head = await env.R2.head(f.key);
  if (!head) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
  const size = head.size;
  const ctype = f.type || head.httpMetadata?.contentType || "application/octet-stream";
  const inline = inlineDefault && /^(image|video|audio|text)\//.test(ctype);
  const disposition = `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(f.name)}`;

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
        "Cache-Control": "private, max-age=3600",
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
      "Cache-Control": "private, max-age=3600",
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
      const token = rest.split("/")[0];
      return await handleShare(request, env, token);
    }

    // ---------- Login API ----------
    if (path === "/api/login" && request.method === "POST") {
      if (!sameOrigin(request, url)) return json({ error: "bad origin" }, 403);
      return await handleLogin(request, env);
    }
    if (path === "/api/logout" && request.method === "POST") {
      return json({ ok: true }, 200, {
        "Set-Cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
      });
    }

    // ---------- Login page (no auth needed) ----------
    if (path === "/login") return html(LOGIN_HTML);

    // ---------- Everything below needs auth ----------
    if (path.startsWith("/api/")) {
      if (!(await isAuthed(request, env))) return json({ error: "unauthorized" }, 401);
      // CSRF: state-changing POST တွေအတွက် same-origin စစ်
      if (request.method === "POST" && !sameOrigin(request, url)) {
        return json({ error: "bad origin" }, 403);
      }
    } else {
      if (!(await isAuthed(request, env))) {
        return Response.redirect(url.origin + "/login", 302);
      }
    }

    // ---------- API routes (authed) ----------
    if (path === "/api/list" && request.method === "GET") return await apiList(request, env);
    if (path === "/api/upload" && request.method === "POST") return await apiUpload(request, env);
    if (path === "/api/presign" && request.method === "POST") return await apiPresign(request, env);
    if (path === "/api/finalize" && request.method === "POST") return await apiFinalize(request, env);
    if (path === "/api/remote" && request.method === "POST") return await apiRemote(request, env);
    if (path === "/api/delete" && request.method === "POST") return await apiDelete(request, env);
    if (path === "/api/rename" && request.method === "POST") return await apiRename(request, env);
    if (path === "/api/share" && request.method === "POST") return await apiShare(request, env);
    if (path === "/api/changepass" && request.method === "POST") return await apiChangePass(request, env);
    if (path === "/api/download" && request.method === "GET") return await apiDownload(request, env);
    if (path === "/api/view" && request.method === "GET") return await apiView(request, env);
    if (path === "/api/folder/create" && request.method === "POST") return await apiFolderCreate(request, env);
    if (path === "/api/folder/delete" && request.method === "POST") return await apiFolderDelete(request, env);
    if (path === "/api/folder/rename" && request.method === "POST") return await apiFolderRename(request, env);
    if (path === "/api/move" && request.method === "POST") return await apiMove(request, env);

    // ---------- Main page ----------
    if (path === "/" || path === "/index.html") return html(APP_HTML);

    return new Response("Not Found", { status: 404 });
  } catch (err) {
    // internal error message ကို client ဆီ မပို့ (info leak ကာကွယ်)
    return json({ error: "server error" }, 500);
  }
}

// ======================= Handlers =======================

async function handleLogin(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const lock = await loadLock(env);
  const rec = lock[ip] || { fails: 0, until: 0 };

  if (rec.until && Date.now() < rec.until) {
    const sec = Math.ceil((rec.until - Date.now()) / 1000);
    return json({ error: `အကြိမ်များစွာ မှားနေပါသည်။ ${sec} စက္ကန့်ကြာမှ ပြန်ကြိုးစားပါ။` }, 429);
  }

  const body = await request.json().catch(() => ({}));
  const { username, password } = body;

  const meta = await loadMeta(env);
  const currentPass = meta.password || env.AUTH_PASS;

  // constant-time compare နှစ်ခုလုံး
  const okUser = safeEqual(username, env.AUTH_USER);
  const okPass = safeEqual(password, currentPass);

  if (okUser && okPass) {
    delete lock[ip];
    await saveLock(env, lock);
    const tok = await makeToken(env, username);
    return json({ ok: true }, 200, {
      "Set-Cookie": `session=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_MS / 1000)}`,
    });
  }

  rec.fails = (rec.fails || 0) + 1;
  if (rec.fails >= 3) {
    rec.until = Date.now() + 5 * 60 * 1000;
    rec.fails = 0;
  }
  lock[ip] = rec;
  await saveLock(env, lock);
  const left = rec.until ? 0 : 3 - rec.fails;
  return json({
    error: rec.until
      ? "အကြိမ် ၃ ကြိမ် မှားသွားပါပြီ။ ၅ မိနစ် စောင့်ပါ။"
      : `Username သို့မဟုတ် Password မှားနေပါသည်။ (ကျန် ${left} ကြိမ်)`,
  }, 401);
}

async function apiList(request, env) {
  const meta = await loadMeta(env);
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
    totalBytes: meta.totalBytes || 0, maxBytes: MAX_TOTAL_BYTES,
  });
}

// --- Small file direct upload (multipart/form-data) ---
async function apiUpload(request, env) {
  const meta = await loadMeta(env);
  const form = await request.formData();
  const file = form.get("file");
  const folder = (form.get("folder") || "").toString();
  const customName = (form.get("name") || "").toString(); // ✅ custom filename
  if (!file || typeof file === "string") return json({ error: "ဖိုင်မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  const size = file.size;
  if ((meta.totalBytes || 0) + size > MAX_TOTAL_BYTES) {
    return json({ error: "Storage 10GB ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413);
  }

  const id = randId();
  const key = `files/${id}`;
  await env.R2.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
  });

  // custom name ပါရင် အဲ့ဒါသုံး၊ extension မပါရင် မူရင်းကနေ ဖြည့်
  let fname = cleanName(customName || file.name, id);
  if (customName && !/\.[a-z0-9]{1,8}$/i.test(fname)) {
    const origExt = (file.name.match(/\.[a-z0-9]{1,8}$/i) || [""])[0];
    if (origExt) fname += origExt;
  }

  meta.files = meta.files || {};
  meta.files[id] = {
    name: fname, size,
    type: file.type || "application/octet-stream",
    uploadedAt: nowMM(), folder, key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + size;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Large file: get presigned PUT url ---
async function apiPresign(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { name, size, type, folder } = body;
  if (!name || !size) return json({ error: "name/size မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  if ((meta.totalBytes || 0) + Number(size) > MAX_TOTAL_BYTES) {
    return json({ error: "Storage 10GB ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413);
  }

  const id = randId();
  const key = `files/${id}`;
  const uploadUrl = await presignR2Put(env, key, 3600);
  return json({ ok: true, id, key, uploadUrl });
}

// --- finalize metadata after presigned PUT ---
async function apiFinalize(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, key, name, type, folder } = body;
  if (!id || !key) return json({ error: "id/key မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  // key spoof guard: server က သတ်မှတ်တဲ့ pattern မှ ခွင့်ပြု
  if (key !== `files/${id}` || !/^[a-f0-9]{32}$/.test(id)) {
    return json({ error: "invalid key" }, 400);
  }

  const head = await env.R2.head(key);
  if (!head) return json({ error: "R2 ထဲတွင် ဖိုင်မတွေ့ပါ" }, 400);
  const realSize = head.size;

  if ((meta.totalBytes || 0) + realSize > MAX_TOTAL_BYTES) {
    await env.R2.delete(key);
    return json({ error: "Storage 10GB ကျော်သွားသဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
  }

  meta.files = meta.files || {};
  meta.files[id] = {
    name: cleanName(name, id), size: realSize,
    type: type || head.httpMetadata?.contentType || "application/octet-stream",
    uploadedAt: nowMM(), folder: folder || "", key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Remote URL upload ---
async function apiRemote(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { url: remoteUrl, name, folder } = body;
  if (!remoteUrl) return json({ error: "URL မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  // SSRF guard
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
  if (declared && (meta.totalBytes || 0) + declared > MAX_TOTAL_BYTES) {
    return json({ error: "Storage 10GB ပြည့်သွားပါပြီ။" }, 413);
  }

  const id = randId();
  const key = `files/${id}`;
  const ctype = resp.headers.get("Content-Type") || "application/octet-stream";
  await env.R2.put(key, resp.body, { httpMetadata: { contentType: ctype } });

  const head = await env.R2.head(key);
  const realSize = head ? head.size : declared;
  if (realSize > MAX_REMOTE_BYTES) {
    await env.R2.delete(key);
    return json({ error: "Remote ဖိုင်သည် 1.5GB ထက်ကြီးသဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
  }
  if ((meta.totalBytes || 0) + realSize > MAX_TOTAL_BYTES) {
    await env.R2.delete(key);
    return json({ error: "Storage 10GB ကျော်သဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
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

  meta.files = meta.files || {};
  meta.files[id] = { name: fname, size: realSize, type: ctype, uploadedAt: nowMM(), folder: folder || "", key };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);
  return json({ ok: true, id });
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

async function apiDelete(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  const f = meta.files?.[id];
  if (!f) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);
  await env.R2.delete(f.key);
  meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
  delete meta.files[id];
  await saveMeta(env, meta);
  return json({ ok: true });
}

// ✅ NEW: Rename a file (keeps extension if new name has none)
async function apiRename(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  let { id, name } = body;
  const f = meta.files?.[id];
  if (!f) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);
  name = cleanName(name, "");
  if (!name) return json({ error: "နာမည် ထည့်ပါ" }, 400);
  // extension မပါရင် မူရင်းဖိုင်ရဲ့ extension ကို ဆက်ထား
  if (!/\.[a-z0-9]{1,8}$/i.test(name)) {
    const oldExt = (f.name.match(/\.[a-z0-9]{1,8}$/i) || [""])[0];
    if (oldExt) name += oldExt;
  }
  f.name = name;
  await saveMeta(env, meta);
  return json({ ok: true, name });
}

async function apiShare(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, duration } = body;
  const f = meta.files?.[id];
  if (!f) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);

  if (duration === "off") {
    delete f.share;
    await saveMeta(env, meta);
    return json({ ok: true, share: null });
  }
  const map = { "2d": 2 * 86400e3, "1w": 7 * 86400e3, "1m": 30 * 86400e3, "1y": 365 * 86400e3 };
  let expiresAt = null;
  if (duration !== "lifetime") {
    const ms = map[duration];
    if (!ms) return json({ error: "သက်တမ်းမှားနေပါသည်" }, 400);
    expiresAt = Date.now() + ms;
  }
  const token = f.share?.token || randId();
  f.share = { token, expiresAt };
  await saveMeta(env, meta);
  return json({ ok: true, share: { token, expiresAt, name: f.name } });
}

async function apiChangePass(request, env) {
  const body = await request.json().catch(() => ({}));
  const { oldPass, newPass } = body;
  const meta = await loadMeta(env);
  const currentPass = meta.password || env.AUTH_PASS;
  if (!safeEqual(oldPass, currentPass)) return json({ error: "လက်ရှိ password မှားနေပါသည်" }, 400);
  if (!newPass || newPass.length < 6) return json({ error: "password အနည်းဆုံး ၆ လုံးထားပါ" }, 400);
  meta.password = newPass;
  await saveMeta(env, meta);
  return json({ ok: true });
}

async function apiDownload(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const meta = await loadMeta(env);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });
  return await serveObject(request, env, f, { inlineDefault: false });
}

async function apiView(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const meta = await loadMeta(env);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });
  return await serveObject(request, env, f, { inlineDefault: true });
}

async function handleShare(request, env, token) {
  const meta = await loadMeta(env);
  let target = null;
  for (const [, f] of Object.entries(meta.files || {})) {
    if (f.share && f.share.token === token) { target = f; break; }
  }
  if (!target) return new Response("Link မတွေ့ပါ", { status: 404 });
  if (target.share.expiresAt && Date.now() > target.share.expiresAt) {
    return new Response("ဤ link သက်တမ်းကုန်သွားပါပြီ။ (မူရင်းဖိုင်မပျက်ပါ)", { status: 410 });
  }
  return await serveObject(request, env, target, { inlineDefault: true });
}

// ======================= Folder Handlers =======================
async function apiFolderCreate(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  let { name, parent } = body;
  name = (name || "").toString().trim();
  parent = (parent || "").toString();
  if (!name) return json({ error: "Folder နာမည် ထည့်ပါ" }, 400);
  if (name.length > 80) return json({ error: "နာမည် ရှည်လွန်းနေပါသည်" }, 400);
  if (parent && !meta.folders[parent]) return json({ error: "Parent folder မတွေ့ပါ" }, 400);
  const dup = Object.values(meta.folders).some(
    fd => (fd.parent || "") === parent && fd.name.toLowerCase() === name.toLowerCase()
  );
  if (dup) return json({ error: "ဤနာမည်ဖြင့် folder ရှိပြီးသားပါ" }, 400);
  const id = randId();
  meta.folders[id] = { name, parent, createdAt: nowMM() };
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

async function apiFolderRename(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  let { id, name } = body;
  name = (name || "").toString().trim();
  const fd = meta.folders?.[id];
  if (!fd) return json({ error: "Folder မတွေ့ပါ" }, 404);
  if (!name) return json({ error: "နာမည် ထည့်ပါ" }, 400);
  fd.name = name;
  await saveMeta(env, meta);
  return json({ ok: true });
}

async function apiFolderDelete(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  if (!meta.folders?.[id]) return json({ error: "Folder မတွေ့ပါ" }, 404);
  const toDelete = new Set([id]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [fid, fd] of Object.entries(meta.folders)) {
      if (!toDelete.has(fid) && toDelete.has(fd.parent || "")) { toDelete.add(fid); changed = true; }
    }
  }
  for (const [fileId, f] of Object.entries(meta.files)) {
    if (toDelete.has(f.folder || "")) {
      await env.R2.delete(f.key);
      meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
      delete meta.files[fileId];
    }
  }
  for (const fid of toDelete) delete meta.folders[fid];
  await saveMeta(env, meta);
  return json({ ok: true });
}

async function apiMove(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, folder } = body;
  const f = meta.files?.[id];
  if (!f) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  f.folder = folder || "";
  await saveMeta(env, meta);
  return json({ ok: true });
}
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast Lugyi Storage • ဝင်ရန်</title>
<style>
:root{--brand1:#6d28d9;--brand2:#2563eb;--accent:#06b6d4}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
html,body{height:100%}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(1200px 600px at 10% 0%,#1e1b4b,transparent),
radial-gradient(1000px 500px at 90% 100%,#0c4a6e,transparent),
linear-gradient(135deg,#0b1020,#111827 45%,#1e1b4b);
background-attachment:fixed;padding:16px;position:relative;overflow-x:hidden}
.orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.5;z-index:0;pointer-events:none;
animation:float 9s ease-in-out infinite;will-change:transform}
.orb.a{width:360px;height:360px;background:#7c3aed;top:-90px;left:-70px}
.orb.b{width:320px;height:320px;background:#06b6d4;bottom:-80px;right:-60px;animation-delay:-4s}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-26px)}}
.card{position:relative;z-index:1;background:rgba(255,255,255,.07);backdrop-filter:blur(22px);
border:1px solid rgba(255,255,255,.16);padding:38px 30px;border-radius:24px;
box-shadow:0 30px 70px rgba(0,0,0,.5);width:100%;max-width:400px;color:#fff}
.logo{width:66px;height:66px;margin:0 auto 16px;border-radius:20px;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,var(--brand1),var(--accent));box-shadow:0 10px 30px rgba(124,58,237,.55);font-size:32px}
h1{margin:0 0 4px;font-size:24px;text-align:center;font-weight:800;letter-spacing:.3px;
background:linear-gradient(90deg,#c4b5fd,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{text-align:center;color:rgba(255,255,255,.62);font-size:13px;margin-bottom:24px}
.field{position:relative;margin:13px 0}
.field input{width:100%;padding:14px 14px 14px 44px;border:1px solid rgba(255,255,255,.18);
border-radius:14px;font-size:15px;background:rgba(255,255,255,.06);color:#fff;outline:none;transition:.25s}
.field input::placeholder{color:rgba(255,255,255,.5)}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.25);background:rgba(255,255,255,.1)}
.field .ic{position:absolute;left:15px;top:50%;transform:translateY(-50%);opacity:.7}
button{width:100%;padding:14px;margin-top:12px;border:0;border-radius:14px;font-size:16px;font-weight:700;cursor:pointer;color:#fff;
background:linear-gradient(135deg,var(--brand1),var(--brand2));box-shadow:0 10px 26px rgba(37,99,235,.45);transition:.25s;
display:flex;align-items:center;justify-content:center;gap:8px}
button:hover{transform:translateY(-2px);box-shadow:0 16px 34px rgba(37,99,235,.6)}
button:disabled{opacity:.7;cursor:not-allowed;transform:none}
.spin{width:18px;height:18px;border:2.5px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;
animation:spin .7s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.err{color:#fca5a5;font-size:13px;margin-top:12px;text-align:center;min-height:18px}
.foot{text-align:center;margin-top:18px;font-size:11px;color:rgba(255,255,255,.45)}
</style></head><body>
<div class="orb a"></div><div class="orb b"></div>
<div class="card">
<div class="logo">⚡</div>
<h1>Fast Lugyi Storage</h1>
<div class="sub">🔒 လုံခြုံစိတ်ချရသော Cloud သိုလှောင်မှု</div>
<div class="field"><span class="ic">👤</span><input id="u" placeholder="Username" autocomplete="username"></div>
<div class="field"><span class="ic">🔑</span><input id="p" type="password" placeholder="Password" autocomplete="current-password"></div>
<button id="btn" onclick="login()"><span class="spin" id="spin"></span><span id="btnTxt">🚀 ဝင်မည်</span></button>
<div class="err" id="err"></div>
<div class="foot">Powered by Cloudflare R2 • Premium Edition</div>
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
  btn.disabled=false;spin.style.display='none';btnTxt.textContent='🚀 ဝင်မည်';
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
document.getElementById('u').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('p').focus();});
</script>
</body></html>`;
const APP_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast Lugyi Storage</title>
<style>
:root{--b1:#6d28d9;--b2:#2563eb;--acc:#06b6d4;--ink:#0f172a;--muted:#64748b;--line:#e6e9f2;
--card:rgba(255,255,255,.85);--ok:#16a34a;--danger:#ef4444}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
body{margin:0;color:var(--ink);min-height:100vh;
background:
radial-gradient(900px 500px at 100% -8%,#ede9fe,transparent),
radial-gradient(800px 500px at -10% 5%,#cffafe,transparent),
radial-gradient(600px 400px at 50% 110%,#fce7f3,transparent),
linear-gradient(180deg,#f6f8ff,#eef2fb)}
/* ===== Top bar ===== */
header{position:sticky;top:0;z-index:30;backdrop-filter:blur(16px);
background:linear-gradient(135deg,rgba(109,40,217,.96),rgba(37,99,235,.96));color:#fff;
padding:14px 18px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;
box-shadow:0 10px 34px rgba(37,99,235,.32)}
.brand{display:flex;align-items:center;gap:12px}
.brand .lg{width:44px;height:44px;border-radius:14px;background:rgba(255,255,255,.18);
display:flex;align-items:center;justify-content:center;font-size:24px;
box-shadow:inset 0 0 0 1px rgba(255,255,255,.3),0 6px 18px rgba(0,0,0,.18)}
.brand h1{margin:0;font-size:19px;font-weight:800;letter-spacing:.3px}
.brand .tagline{font-size:11px;opacity:.85;font-weight:500;margin-top:1px}
.topbtns{display:flex;gap:8px;flex-wrap:wrap}
button{padding:10px 15px;border:0;border-radius:12px;color:#fff;cursor:pointer;font-size:14px;font-weight:600;transition:.18s;
background:linear-gradient(135deg,var(--b1),var(--b2));box-shadow:0 5px 14px rgba(37,99,235,.3)}
button:hover{transform:translateY(-1px);box-shadow:0 9px 22px rgba(37,99,235,.4)}
button:active{transform:translateY(0)}
button:disabled{opacity:.55;cursor:not-allowed;transform:none}
button.sec{background:#eef2f8;color:#334155;box-shadow:none}
button.sec:hover{background:#e2e8f0}
button.danger{background:linear-gradient(135deg,#f43f5e,#dc2626);box-shadow:0 5px 14px rgba(239,68,68,.28)}
button.ghost{background:rgba(255,255,255,.14);color:#fff;border:1px solid rgba(255,255,255,.4);box-shadow:none}
button.ghost:hover{background:rgba(255,255,255,.26)}
input,select{padding:11px 12px;border:1px solid #d6dbe7;border-radius:12px;font-size:14px;background:#fff;outline:none;transition:.2s;color:var(--ink)}
input:focus,select:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(6,182,212,.18)}
.wrap{max-width:1040px;margin:0 auto;padding:18px 16px 60px}
/* ===== Stat / usage card ===== */
.hero{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin-bottom:16px}
@media(max-width:720px){.hero{grid-template-columns:1fr}}
.glass{background:var(--card);backdrop-filter:blur(14px);border:1px solid rgba(255,255,255,.7);
border-radius:20px;padding:18px;box-shadow:0 10px 34px rgba(15,23,42,.07)}
.usage-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.usage-top .ic{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,#ede9fe,#dbeafe);
display:flex;align-items:center;justify-content:center;font-size:24px}
.usage-num{font-size:22px;font-weight:800;line-height:1.1}
.usage-sub{font-size:12px;color:var(--muted)}
.prog{height:14px;background:#e9edf6;border-radius:10px;overflow:hidden;margin-top:14px;box-shadow:inset 0 1px 3px rgba(0,0,0,.08)}
.prog>i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#06b6d4,#2563eb);
background-size:200% 100%;transition:width .6s;border-radius:10px;animation:flow 3s linear infinite}
@keyframes flow{to{background-position:200% 0}}
.prog.warn>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.mini{display:flex;gap:14px;margin-top:8px;flex-wrap:wrap}
.mini .m{flex:1;min-width:90px;text-align:center;background:rgba(255,255,255,.6);border-radius:14px;padding:10px;border:1px solid var(--line)}
.mini .m b{font-size:18px;display:block}
.mini .m span{font-size:11px;color:var(--muted)}
/* ===== Upload zone ===== */
.dropzone{border:2px dashed #c3cde0;border-radius:18px;padding:22px;text-align:center;cursor:pointer;
transition:.2s;background:rgba(255,255,255,.5)}
.dropzone:hover,.dropzone.drag{border-color:var(--b2);background:rgba(219,234,254,.6);transform:translateY(-2px)}
.dropzone .big{font-size:40px}
.dropzone .t{font-weight:700;margin-top:6px}
.dropzone .s{font-size:12px;color:var(--muted);margin-top:3px}
.section-h{display:flex;align-items:center;gap:9px;font-weight:800;font-size:15px;margin:6px 0 12px}
.section-h .dot{width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,var(--b1),var(--acc))}
/* upload queue */
#upQueue{margin-top:12px;display:flex;flex-direction:column;gap:9px}
.uprow{background:rgba(255,255,255,.7);border:1px solid var(--line);border-radius:13px;padding:10px 12px}
.uprow .nm{font-size:13px;font-weight:600;word-break:break-all;display:flex;justify-content:space-between;gap:8px}
.uprow .pct{font-variant-numeric:tabular-nums;color:var(--b2);font-weight:700}
.upbar{height:9px;background:#e9edf6;border-radius:6px;overflow:hidden;margin-top:7px}
.upbar>i{display:block;height:100%;width:0;border-radius:6px;background:linear-gradient(90deg,var(--b1),var(--acc));transition:width .25s}
.uprow.done .upbar>i{background:linear-gradient(90deg,#22c55e,#16a34a)}
.uprow.err .upbar>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.uprow .st{font-size:11px;color:var(--muted);margin-top:5px}
/* remote row */
.remote-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.remote-row input{flex:1;min-width:160px}
.statusline{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:13px;color:var(--muted);min-height:20px}
/* ===== breadcrumb ===== */
.crumb{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:14px;margin:16px 0 12px;
background:var(--card);backdrop-filter:blur(12px);padding:11px 15px;border-radius:14px;
border:1px solid rgba(255,255,255,.7);box-shadow:0 5px 18px rgba(15,23,42,.05)}
.crumb a{color:var(--b2);cursor:pointer;text-decoration:none;font-weight:700}
.crumb a:hover{text-decoration:underline}
.crumb span.sep{color:#94a3b8}
/* toolbar */
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.toolbar .search{flex:1;min-width:160px;position:relative}
.toolbar .search input{width:100%;padding-left:38px}
.toolbar .search .si{position:absolute;left:13px;top:50%;transform:translateY(-50%);opacity:.5}
/* ===== folders grid ===== */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:12px;margin-bottom:18px}
.fold{background:linear-gradient(135deg,#fff,#eef2ff);border:1px solid #e1e7f7;border-radius:16px;padding:15px;cursor:pointer;
display:flex;flex-direction:column;gap:5px;transition:.2s;position:relative;overflow:hidden}
.fold:before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,transparent,rgba(109,40,217,.06));opacity:0;transition:.2s}
.fold:hover{transform:translateY(-3px);box-shadow:0 14px 30px rgba(37,99,235,.16);border-color:#c7d2fe}
.fold:hover:before{opacity:1}
.fold .ico{font-size:34px;filter:drop-shadow(0 4px 6px rgba(109,40,217,.25))}
.fold .nm{font-weight:700;word-break:break-word;font-size:14px}
.fold .ct{font-size:11px;color:var(--muted)}
.fold .fbtns{position:absolute;top:8px;right:8px;display:none;gap:4px}
.fold:hover .fbtns{display:flex}
.fold .fbtns button{border:0;border-radius:8px;width:28px;height:28px;font-size:12px;padding:0;box-shadow:none}
.fold .fbtns .ren{background:#dbeafe;color:#1e40af}
.fold .fbtns .del{background:#fee2e2;color:#b91c1c}
/* ===== file rows ===== */
.file{background:var(--card);backdrop-filter:blur(12px);border-radius:16px;padding:14px;margin-bottom:11px;
box-shadow:0 5px 18px rgba(15,23,42,.06);border:1px solid rgba(255,255,255,.7);transition:.2s}
.file:hover{box-shadow:0 14px 30px rgba(15,23,42,.1);transform:translateY(-1px)}
.file .top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.ficon{font-size:26px;flex-shrink:0;width:48px;height:48px;border-radius:13px;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#eef2ff,#e0f2fe);cursor:pointer;transition:.18s}
.ficon:hover{transform:scale(1.06)}
.fname{font-weight:700;word-break:break-all;cursor:pointer;color:var(--ink);text-decoration:none;font-size:14.5px}
.fname:hover{color:var(--b2);text-decoration:underline}
.meta{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.6}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.acts button{font-size:12.5px;padding:7px 11px}
.tag{display:inline-block;font-size:11px;padding:2px 9px;border-radius:10px;background:#dbeafe;color:#1e40af;margin-left:6px;font-weight:700}
.tag.exp{background:#fee2e2;color:#991b1b}
.tag.life{background:#dcfce7;color:#166534}
/* pager */
.pager{display:flex;gap:6px;justify-content:center;align-items:center;flex-wrap:wrap;margin:18px 0 6px}
.pager button{padding:8px 13px;min-width:40px}
.pager .pinfo{font-size:13px;color:var(--muted);font-weight:600;padding:0 6px}
/* toast */
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;
padding:13px 22px;border-radius:13px;z-index:99;opacity:0;transition:.3s;font-size:14px;max-width:90%;
box-shadow:0 12px 34px rgba(0,0,0,.45);pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%) translateY(-4px)}
/* modal */
.modal{position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(6px);display:none;
align-items:center;justify-content:center;z-index:50;padding:16px;animation:fadeIn .2s ease}
.modal.show{display:flex}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal .box{background:#fff;border-radius:22px;padding:26px;max-width:430px;width:100%;
box-shadow:0 30px 70px rgba(0,0,0,.45);animation:pop .25s cubic-bezier(.2,.9,.3,1.2);border:1px solid #eef0f5}
@keyframes pop{from{opacity:0;transform:scale(.9) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal h3{margin:0 0 16px;font-size:19px;display:flex;align-items:center;gap:9px;font-weight:800}
.modal input,.modal select{width:100%;margin:6px 0}
.modal .mico{width:56px;height:56px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 12px}
.modal .mico.ask{background:linear-gradient(135deg,#fef3c7,#fde68a)}
.modal .mico.del{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.modal .mtext{text-align:center;color:#475569;font-size:14px;line-height:1.6;margin-bottom:18px;word-break:break-word}
.modal .mbtns{display:flex;gap:10px}
.modal .mbtns button{flex:1}
.modal .pbox{background:#0f172a;border-radius:22px;padding:18px;max-width:880px;width:100%;
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
.empty .big{font-size:48px}
.spin{width:16px;height:16px;border:2.4px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;
animation:spin .7s linear infinite;display:inline-block;vertical-align:middle;margin-right:6px}
.spin.dark{border-color:rgba(109,40,217,.25);border-top-color:#6d28d9}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<header>
<div class="brand"><div class="lg">⚡</div><div><h1>Fast Lugyi Storage</h1>
<div class="tagline">Secure Cloud Drive • R2 Premium</div></div></div>
<div class="topbtns">
<button class="ghost" onclick="openPass()">🔑 Password</button>
<button class="ghost" onclick="logout()">🚪 ထွက်မည်</button>
</div>
</header>
<div class="wrap">

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
    <div class="section-h"><span class="dot"></span>🔗 Remote URL ဖြင့်တင်ရန် <small>(1.5GB ထိ)</small></div>
    <div class="remote-row">
      <input type="text" id="remoteUrl" placeholder="https://...">
      <input type="text" id="remoteName" placeholder="ဖိုင်နာမည် (optional)">
    </div>
    <button id="remoteBtn" onclick="uploadRemote()" style="width:100%;margin-top:10px">⬆ Remote တင်မည်</button>
    <div class="statusline" id="remoteStatus"></div>
  </div>
</div>

<div class="glass" style="margin-bottom:16px">
  <div class="section-h"><span class="dot"></span>📤 ဖုန်းထဲက ဖိုင်တင်ရန် <small>(တစ်ခါ အများဆုံး ၃ ဖိုင်)</small></div>
  <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
    <div class="big">☁️</div>
    <div class="t">ဖိုင်ရွေးရန် နှိပ်ပါ (သို့) ဆွဲချပါ</div>
    <div class="s">Photo • Video • Music • Txt • PDF ... — တစ်ခါ ၃ ဖိုင်အထိ</div>
  </div>
  <input type="file" id="fileInput" multiple style="display:none">
  <div id="upQueue"></div>
</div>

<div class="crumb" id="crumb"></div>

<div class="toolbar">
  <div class="search"><span class="si">🔍</span><input id="searchBox" placeholder="ဖိုင်နာမည် ရှာရန်..." oninput="renderFiles()"></div>
  <button class="sec" onclick="openNewFolder()">📁 Folder အသစ်</button>
</div>

<div class="section-h"><span class="dot"></span>🗂️ Folders</div>
<div class="grid" id="folders"></div>

<div class="section-h"><span class="dot"></span>📁 ဖိုင်များ</div>
<div id="list"></div>
<div class="pager" id="pager"></div>

</div>

<!-- Preview modal -->
<div class="modal" id="previewModal"><div class="pbox">
<div class="phead"><div class="ptitle" id="previewTitle"></div>
<button class="pclose" onclick="closePreview()">✖</button></div>
<div class="pbody" id="previewBody"></div>
</div></div>

<!-- Share modal -->
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

<!-- New folder modal -->
<div class="modal" id="folderModal"><div class="box">
<h3>📁 Folder အသစ်ဆောက်ရန်</h3>
<input type="text" id="folderName" placeholder="Folder နာမည်" maxlength="80">
<button onclick="doCreateFolder()" style="width:100%;margin-top:10px">✅ ဆောက်မည်</button>
<div id="folderErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('folderModal')">ပိတ်မည်</button>
</div></div>

<!-- Rename modal -->
<div class="modal" id="renameModal"><div class="box">
<h3>✏️ နာမည်ပြောင်းရန်</h3>
<input type="text" id="renameInput" placeholder="ဖိုင်နာမည် အသစ်" maxlength="200">
<button onclick="doRename()" style="width:100%;margin-top:10px">✅ ပြောင်းမည်</button>
<div id="renameErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('renameModal')">ပိတ်မည်</button>
</div></div>

<!-- Move modal -->
<div class="modal" id="moveModal"><div class="box">
<h3>📦 ဖိုင်ရွှေ့ရန်</h3>
<select id="moveTarget"></select>
<button onclick="doMove()" style="width:100%;margin-top:12px">✅ ရွှေ့မည်</button>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('moveModal')">ပိတ်မည်</button>
</div></div>

<!-- Password modal -->
<div class="modal" id="passModal"><div class="box">
<h3>🔑 Password ပြောင်းရန်</h3>
<input type="password" id="oldPass" placeholder="လက်ရှိ password">
<input type="password" id="newPass" placeholder="password အသစ် (၆ လုံးအထက်)">
<button onclick="doChangePass()" style="width:100%;margin-top:10px">✅ ပြောင်းမည်</button>
<div id="passErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('passModal')">ပိတ်မည်</button>
</div></div>

<!-- Confirm modal -->
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
const MAX_PARALLEL=3;            // ✅ တစ်ခါ ၃ ဖိုင်
const DIRECT_LIMIT=90*1024*1024;

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function openModal(id){document.getElementById(id).classList.add('show');}
function closeModal(id){document.getElementById(id).classList.remove('show');}
function fileIcon(t){t=t||'';if(t.startsWith('video/'))return'🎬';if(t.startsWith('image/'))return'🖼️';if(t.startsWith('audio/'))return'🎵';if(t.startsWith('text/'))return'📄';if(t.includes('pdf'))return'📕';if(t.includes('zip')||t.includes('rar'))return'🗜️';return'📦';}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function escapeJs(s){return String(s).replace(/['\\\\]/g,'\\\\$&').replace(/"/g,'&quot;');}

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

/* ===== Preview + MediaSession fix ===== */
function clearMediaSession(){
  // ✅ noti bar က video/audio metadata ပျောက်အောင် (refresh မလုပ်ဘဲ)
  try{
    if('mediaSession' in navigator){
      navigator.mediaSession.metadata=null;
      navigator.mediaSession.playbackState='none';
      // action handler တွေ ဖယ်
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
  // ✅ media ကို သေချာ ရပ်/ဖြုတ်ပြီးမှ ဖျက် — noti bar icon ချက်ချင်းပျောက်စေရန်
  const m=body.querySelector('video,audio');
  if(m){try{m.pause();m.removeAttribute('src');m.srcObject=null;m.load();}catch(e){}}
  body.innerHTML='';
  clearMediaSession();        // ✅ refresh မလုပ်ဘဲ noti ပျောက်
  closeModal('previewModal');
}
// video element တင်ပြီးတာနဲ့ mediaSession metadata ထည့်ပေး (close မှာ ပြန်ရှင်းမယ်)
document.addEventListener('play',function(e){
  if(e.target&&(e.target.tagName==='VIDEO'||e.target.tagName==='AUDIO')&&'mediaSession' in navigator){
    try{navigator.mediaSession.metadata=new MediaMetadata({title:document.getElementById('previewTitle').textContent||'Fast Lugyi Storage',artist:'Fast Lugyi Storage'});}catch(e){}
  }
},true);

/* ===== Routing ===== */
function setRoute(folder,push){currentFolder=folder;currentPage=1;
  const url='#'+(folder?('f/'+folder):'');if(push)history.pushState({folder},'',url);load();}
window.addEventListener('popstate',e=>{const f=(e.state&&e.state.folder!==undefined)?e.state.folder:parseHash();currentFolder=f||"";currentPage=1;load();});
function parseHash(){const h=location.hash||'';const m=h.match(/^#f\\/(.+)$/);return m?decodeURIComponent(m[1]):"";}

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

  let cb='<a onclick="goFolder(\\'\\')">🏠 Home</a>';
  for(const b of d.breadcrumb)cb+='<span class="sep">›</span><a onclick="goFolder(\\''+b.id+'\\')">'+escapeHtml(b.name)+'</a>';
  document.getElementById('crumb').innerHTML=cb;

  const fg=document.getElementById('folders');
  if(!d.folders.length)fg.innerHTML='<div style="color:#94a3b8;font-size:13px;grid-column:1/-1">Folder မရှိသေးပါ။</div>';
  else fg.innerHTML=d.folders.map(fd=>
    '<div class="fold" onclick="goFolder(\\''+fd.id+'\\')">'+
    '<div class="fbtns">'+
    '<button class="ren" title="နာမည်ပြောင်း" onclick="event.stopPropagation();renameFolder(\\''+fd.id+'\\',\\''+escapeJs(fd.name)+'\\')">✏️</button>'+
    '<button class="del" title="ဖျက်" onclick="event.stopPropagation();delFolder(\\''+fd.id+'\\',\\''+escapeJs(fd.name)+'\\')">🗑</button></div>'+
    '<div class="ico">📁</div><div class="nm">'+escapeHtml(fd.name)+'</div><div class="ct">'+fd.count+' items</div></div>'
  ).join('');

  lastFiles=d.files;renderFiles();
}

function renderFiles(){
  const list=document.getElementById('list'),pager=document.getElementById('pager');
  const q=(document.getElementById('searchBox').value||'').toLowerCase().trim();
  let arr=lastFiles;
  if(q)arr=lastFiles.filter(f=>f.name.toLowerCase().includes(q));
  const total=arr.length;
  if(!total){list.innerHTML='<div class="empty"><div class="big">🗂️</div>'+(q?'ရှာဖွေမှု မတွေ့ပါ။':'ဤနေရာတွင် ဖိုင်မရှိသေးပါ။')+'</div>';pager.innerHTML='';return;}
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
    return '<div class="file"><div class="top"><div style="display:flex;gap:11px">'+
      '<div class="ficon" title="ကြည့်ရန်" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">'+fileIcon(f.type)+'</div><div>'+
      '<div class="fname" title="ကြည့်ရန်" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">'+escapeHtml(f.name)+'</div>'+shareTag+
      '<div class="meta">'+fmtSize(f.size)+' • '+escapeHtml(f.type||'')+'<br>🕒 '+escapeHtml(f.uploadedAt||'')+' (မြန်မာစံတော်ချိန်)</div>'+
      '</div></div></div><div class="acts">'+
      '<button class="sec" onclick="openPreview(\\''+f.id+'\\',\\''+nEsc+'\\',\\''+tEsc+'\\')">👁 ကြည့်</button>'+
      '<button onclick="dl(\\''+f.id+'\\')">⬇ Download</button>'+
      '<button class="sec" onclick="openRename(\\''+f.id+'\\',\\''+nEsc+'\\')">✏️ Rename</button>'+
      (f.share?'<button class="sec" onclick="copyShare(\\''+f.share.token+'\\',\\''+nEsc+'\\')">📋 Link</button>':'')+
      '<button class="sec" onclick="openShare(\\''+f.id+'\\')">🔗 Share</button>'+
      '<button class="sec" onclick="openMove(\\''+f.id+'\\')">📦 ရွှေ့</button>'+
      '<button class="danger" onclick="del(\\''+f.id+'\\',\\''+nEsc+'\\')">🗑 ဖျက်</button>'+
      '</div></div>';
  }).join('');
  if(pages<=1){pager.innerHTML='';return;}
  let p='<button class="sec" '+(currentPage<=1?'disabled':'')+' onclick="gotoPage('+(currentPage-1)+')">‹ နောက်သို့</button>';
  p+='<span class="pinfo">စာမျက်နှာ '+currentPage+' / '+pages+'</span>';
  p+='<button class="sec" '+(currentPage>=pages?'disabled':'')+' onclick="gotoPage('+(currentPage+1)+')">ရှေ့သို့ ›</button>';
  pager.innerHTML=p;
}
function gotoPage(p){currentPage=p;renderFiles();window.scrollTo({top:document.getElementById('list').offsetTop-80,behavior:'smooth'});}
function goFolder(id){setRoute(id,true);}
function dl(id){window.open('/api/download?id='+encodeURIComponent(id),'_blank');}

async function del(id,name){
  const ok=await confirmBox({title:'ဖိုင်ဖျက်မည်',text:'"'+name+'" ကို အပြီးဖျက်မှာ သေချာလား?',okText:'🗑 ဖျက်မည်'});
  if(!ok)return;
  const r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();if(r.ok){toast('🗑 ဖျက်ပြီးပါပြီ');load();}else toast(d.error||'မဖျက်နိုင်ပါ');
}

/* ===== Rename ===== */
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

/* ===== Folder ops ===== */
function openNewFolder(){document.getElementById('folderErr').textContent='';document.getElementById('folderName').value='';openModal('folderModal');}
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

/* ===== Move ===== */
async function openMove(id){currentMoveId=id;await buildAllFolders();
  const sel=document.getElementById('moveTarget');
  sel.innerHTML='<option value="">🏠 Home (root)</option>'+allFolders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.path)+'</option>').join('');
  openModal('moveModal');}
async function buildAllFolders(){allFolders=[];const visited=new Set();
  async function walk(folderId,prefix){
    const r=await fetch('/api/list?folder='+encodeURIComponent(folderId));const d=await r.json();
    for(const fd of d.folders){const p=prefix?prefix+' / '+fd.name:fd.name;allFolders.push({id:fd.id,path:p});
      if(!visited.has(fd.id)){visited.add(fd.id);await walk(fd.id,p);}}}
  await walk("","");}
async function doMove(){
  const folder=document.getElementById('moveTarget').value;
  const r=await fetch('/api/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentMoveId,folder})});
  const d=await r.json();if(r.ok){toast('📦 ရွှေ့ပြီးပါပြီ');closeModal('moveModal');load();}else toast(d.error||'မရပါ');
}

/* ===== Upload (with % progress + 3-file limit) ===== */
const dz=document.getElementById('dropzone');
['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag');}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag');}));
dz.addEventListener('drop',e=>{const fs=[...e.dataTransfer.files];if(fs.length)handleFiles(fs);});
document.getElementById('fileInput').addEventListener('change',e=>{const fs=[...e.target.files];if(fs.length)handleFiles(fs);e.target.value='';});

function handleFiles(files){
  if(files.length>MAX_PARALLEL){toast('⚠️ တစ်ခါ အများဆုံး ၃ ဖိုင်သာ တင်နိုင်ပါသည်။ ပထမ ၃ ဖိုင်ကိုသာ တင်ပါမည်။');files=files.slice(0,MAX_PARALLEL);}
  const q=document.getElementById('upQueue');q.innerHTML='';
  const rows=files.map((f,i)=>{
    const row=document.createElement('div');row.className='uprow';row.id='up'+i;
    row.innerHTML='<div class="nm"><span>'+escapeHtml(f.name)+'</span><span class="pct" id="pct'+i+'">0%</span></div>'+
      '<div class="upbar"><i id="bar'+i+'"></i></div><div class="st" id="st'+i+'">စောင့်ဆိုင်းနေသည်...</div>';
    q.appendChild(row);return row;});
  // ✅ ၃ ဖိုင် တစ်ပြိုင်တည်း (parallel)
  Promise.all(files.map((f,i)=>uploadOne(f,i))).then(()=>{
    toast('✅ အားလုံး တင်ပြီးပါပြီ');setTimeout(()=>{document.getElementById('upQueue').innerHTML='';},2500);load();
  });
}
function setProg(i,pct,txt,cls){
  const bar=document.getElementById('bar'+i),p=document.getElementById('pct'+i),st=document.getElementById('st'+i),row=document.getElementById('up'+i);
  if(bar)bar.style.width=pct+'%';if(p)p.textContent=Math.round(pct)+'%';if(st&&txt)st.textContent=txt;
  if(cls&&row)row.classList.add(cls);
}
// XHR ဖြင့် upload progress % ရအောင်
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
      const res=await xhrUpload(pd.uploadUrl,'PUT',file,{'Content-Type':file.type||'application/octet-stream'},p=>setProg(i,p,'R2 သို့ တင်နေသည်...'));
      if(!res.ok)throw new Error('R2 PUT failed '+res.status);
      setProg(i,100,'အတည်ပြုနေသည်...');
      const fr=await fetch('/api/finalize',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({id:pd.id,key:pd.key,name:file.name,type:file.type,folder:currentFolder})});
      const fd2=await fr.json();if(!fr.ok)throw new Error(fd2.error);
    }
    setProg(i,100,'✅ ပြီးပါပြီ','done');
  }catch(e){setProg(i,100,'❌ '+e.message,'err');}
}

async function uploadRemote(){
  const url=document.getElementById('remoteUrl').value.trim();
  const name=document.getElementById('remoteName').value.trim();
  if(!url){toast('URL ထည့်ပါ');return;}
  const st=document.getElementById('remoteStatus'),btn=document.getElementById('remoteBtn');
  btn.disabled=true;st.innerHTML='<span class="spin dark"></span> Remote ဖိုင်တင်နေသည်... (ခဏစောင့်ပါ)';
  try{
    const r=await fetch('/api/remote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,name,folder:currentFolder})});
    const d=await r.json();
    if(r.ok){toast('✅ Remote ဖိုင်တင်ပြီးပါပြီ');document.getElementById('remoteUrl').value='';document.getElementById('remoteName').value='';load();}
    else toast('❌ '+(d.error||'မတင်နိုင်ပါ'));
  }catch(e){toast('❌ ကွန်ရက် ပြဿနာ');}
  st.innerHTML='';btn.disabled=false;
}

/* ===== Share / Pass ===== */
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

// init
currentFolder=parseHash();
history.replaceState({folder:currentFolder},'',location.hash||'#');
load();
</script>
</body></html>`;
