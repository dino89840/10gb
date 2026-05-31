// ======================= Fast Lugyi Storage =======================
// Cloudflare Pages Functions + R2  (single-file backend + HTML)
// Premium UI • Folders • Video Seek (Range) • Security hardened
// ==================================================================

const MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024;        // 10 GB total storage
const MAX_REMOTE_BYTES = Math.floor(1.5 * 1024 * 1024 * 1024); // 1.5 GB remote url
const META_KEY = "__meta__/index.json";                 // file list + total size
const LOCK_KEY = "__meta__/loginlock.json";             // login attempt lock

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- Security headers (applied to HTML pages) ----
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  "Content-Security-Policy":
    "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " +
    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; " +
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function html(body) {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS },
  });
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
  const exp = Date.now() + 1000 * 60 * 60 * 12; // 12 hours
  const payload = `${user}.${exp}`;
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
  if (expected !== parts[1]) return null;
  const [user, expStr] = payload.split(".");
  if (!expStr || Date.now() > Number(expStr)) return null;
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
  // Myanmar time = UTC+6:30
  const d = new Date(Date.now() + (6 * 60 + 30) * 60 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function randId() {
  return crypto.randomUUID().replace(/-/g, "");
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
  // returns {offset, length, end} or null
  if (!rangeHeader) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!m) return null;
  let start = m[1] === "" ? null : parseInt(m[1], 10);
  let end = m[2] === "" ? null : parseInt(m[2], 10);
  if (start === null && end === null) return null;
  if (start === null) {
    // suffix: last N bytes
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
    const obj = await env.R2.get(f.key, {
      range: { offset: range.offset, length: range.length },
    });
    if (!obj) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
    return new Response(obj.body, {
      status: 206,
      headers: {
        "Content-Type": ctype,
        "Content-Length": String(range.length),
        "Content-Range": `bytes ${range.offset}-${range.end}/${size}`,
        "Accept-Ranges": "bytes",
        "Content-Disposition": disposition,
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  // Full content
  const obj = await env.R2.get(f.key);
  if (!obj) return new Response("ဖိုင်မတွေ့ပါ", { status: 404 });
  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": ctype,
      "Content-Length": String(size),
      "Accept-Ranges": "bytes",
      "Content-Disposition": disposition,
      "Cache-Control": "public, max-age=3600",
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
      return await handleShare(request, env, path.slice(3));
    }

    // ---------- Login API ----------
    if (path === "/api/login" && request.method === "POST") {
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
    } else {
      // serving main app page
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
    if (path === "/api/share" && request.method === "POST") return await apiShare(request, env);
    if (path === "/api/changepass" && request.method === "POST") return await apiChangePass(request, env);
    if (path === "/api/download" && request.method === "GET") return await apiDownload(request, env);
    // folder routes
    if (path === "/api/folder/create" && request.method === "POST") return await apiFolderCreate(request, env);
    if (path === "/api/folder/delete" && request.method === "POST") return await apiFolderDelete(request, env);
    if (path === "/api/folder/rename" && request.method === "POST") return await apiFolderRename(request, env);
    if (path === "/api/move" && request.method === "POST") return await apiMove(request, env);

    // ---------- Main page ----------
    if (path === "/" || path === "/index.html") return html(APP_HTML);

    return new Response("Not Found", { status: 404 });
  } catch (err) {
    return json({ error: String(err && err.message || err) }, 500);
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

  if (username === env.AUTH_USER && password === currentPass) {
    delete lock[ip];
    await saveLock(env, lock);
    const tok = await makeToken(env, username);
    return json({ ok: true }, 200, {
      "Set-Cookie": `session=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`,
    });
  }

  rec.fails = (rec.fails || 0) + 1;
  if (rec.fails >= 3) {
    rec.until = Date.now() + 5 * 60 * 1000; // 5 minutes
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
  const folder = url.searchParams.get("folder") || ""; // "" = root

  const files = Object.entries(meta.files || {})
    .filter(([, f]) => (f.folder || "") === folder)
    .map(([id, f]) => ({
      id,
      name: f.name,
      size: f.size,
      type: f.type,
      uploadedAt: f.uploadedAt,
      folder: f.folder || "",
      share: f.share ? {
        token: f.share.token,
        expiresAt: f.share.expiresAt,
      } : null,
    }))
    .sort((a, b) => (b.uploadedAt || "").localeCompare(a.uploadedAt || ""));

  // folders living under current folder
  const folders = Object.entries(meta.folders || {})
    .filter(([, fd]) => (fd.parent || "") === folder)
    .map(([id, fd]) => {
      const fileCount = Object.values(meta.files || {}).filter(f => (f.folder || "") === id).length;
      const subCount = Object.values(meta.folders || {}).filter(s => (s.parent || "") === id).length;
      return { id, name: fd.name, parent: fd.parent || "", count: fileCount + subCount };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  // breadcrumb path
  const breadcrumb = [];
  let cur = folder;
  const guard = new Set();
  while (cur && meta.folders[cur] && !guard.has(cur)) {
    guard.add(cur);
    breadcrumb.unshift({ id: cur, name: meta.folders[cur].name });
    cur = meta.folders[cur].parent || "";
  }

  return json({
    files,
    folders,
    breadcrumb,
    currentFolder: folder,
    totalBytes: meta.totalBytes || 0,
    maxBytes: MAX_TOTAL_BYTES,
  });
}

// --- Small file direct upload (multipart/form-data) ---
async function apiUpload(request, env) {
  const meta = await loadMeta(env);
  const form = await request.formData();
  const file = form.get("file");
  const folder = (form.get("folder") || "").toString();
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

  meta.files = meta.files || {};
  meta.files[id] = {
    name: file.name,
    size,
    type: file.type || "application/octet-stream",
    uploadedAt: nowMM(),
    folder,
    key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + size;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Large file: get presigned PUT url (server enforces 10GB) ---
async function apiPresign(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { name, size, type, folder } = body;
  if (!name || !size) return json({ error: "name/size မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  // server-side enforcement: cannot upload past 10GB even via direct R2 PUT
  if ((meta.totalBytes || 0) + Number(size) > MAX_TOTAL_BYTES) {
    return json({ error: "Storage 10GB ပြည့်သွားပါပြီ။ တင်၍မရပါ။" }, 413);
  }

  const id = randId();
  const key = `files/${id}`;
  const uploadUrl = await presignR2Put(env, key, 3600);
  return json({ ok: true, id, key, uploadUrl });
}

// --- After browser uploaded to R2 via presigned url, record metadata ---
async function apiFinalize(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, key, name, size, type, folder } = body;
  if (!id || !key) return json({ error: "id/key မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  // verify object exists & get real size (cannot be spoofed by client)
  const head = await env.R2.head(key);
  if (!head) return json({ error: "R2 ထဲတွင် ဖိုင်မတွေ့ပါ" }, 400);
  const realSize = head.size;

  // server-side enforcement against fake size / over-limit smuggling
  if ((meta.totalBytes || 0) + realSize > MAX_TOTAL_BYTES) {
    await env.R2.delete(key); // rollback
    return json({ error: "Storage 10GB ကျော်သွားသဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
  }

  meta.files = meta.files || {};
  meta.files[id] = {
    name: name || id,
    size: realSize,
    type: type || head.httpMetadata?.contentType || "application/octet-stream",
    uploadedAt: nowMM(),
    folder: folder || "",
    key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Remote URL upload (stream into R2), max 1.5GB + 10GB total ---
async function apiRemote(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { url: remoteUrl, name, folder } = body;
  if (!remoteUrl) return json({ error: "URL မပါပါ" }, 400);
  if (folder && !meta.folders[folder]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  // basic SSRF guard: only http/https, block internal hosts
  let parsed;
  try { parsed = new URL(remoteUrl); } catch { return json({ error: "URL မှားနေပါသည်" }, 400); }
  if (!/^https?:$/.test(parsed.protocol)) return json({ error: "http/https သာ ခွင့်ပြုသည်" }, 400);
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/.test(parsed.hostname)) {
    return json({ error: "ဤ URL ကို ခွင့်မပြုပါ" }, 400);
  }

  const resp = await fetch(remoteUrl);
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
    try { fname = decodeURIComponent(new URL(remoteUrl).pathname.split("/").pop()) || id; }
    catch { fname = id; }
  }

  meta.files = meta.files || {};
  meta.files[id] = { name: fname, size: realSize, type: ctype, uploadedAt: nowMM(), folder: folder || "", key };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);
  return json({ ok: true, id });
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

// --- Create / update share link with duration ---
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

  const map = {
    "2d": 2 * 86400e3,
    "1w": 7 * 86400e3,
    "1m": 30 * 86400e3,
    "1y": 365 * 86400e3,
  };
  let expiresAt = null;
  if (duration !== "lifetime") {
    const ms = map[duration];
    if (!ms) return json({ error: "သက်တမ်းမှားနေပါသည်" }, 400);
    expiresAt = Date.now() + ms;
  }

  const token = f.share?.token || randId();
  f.share = { token, expiresAt };
  await saveMeta(env, meta);
  return json({ ok: true, share: { token, expiresAt } });
}

async function apiChangePass(request, env) {
  const body = await request.json().catch(() => ({}));
  const { oldPass, newPass } = body;
  const meta = await loadMeta(env);
  const currentPass = meta.password || env.AUTH_PASS;
  if (oldPass !== currentPass) return json({ error: "လက်ရှိ password မှားနေပါသည်" }, 400);
  if (!newPass || newPass.length < 4) return json({ error: "password အနည်းဆုံး ၄ လုံးထားပါ" }, 400);
  meta.password = newPass;
  await saveMeta(env, meta);
  return json({ ok: true });
}

// --- Authed download (original file) — WITH RANGE/SEEK SUPPORT ---
async function apiDownload(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const meta = await loadMeta(env);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });
  // inlineDefault=false -> download as attachment, but range still supported
  return await serveObject(request, env, f, { inlineDefault: false });
}

// --- Public share download (no auth, checks expiry) — WITH RANGE/SEEK SUPPORT ---
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

  // inlineDefault=true -> video/audio/image plays inline & supports seeking
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

  // duplicate name in same parent?
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

// Delete folder (and everything inside it recursively)
async function apiFolderDelete(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  if (!meta.folders?.[id]) return json({ error: "Folder မတွေ့ပါ" }, 404);

  // collect this folder + all descendants
  const toDelete = new Set([id]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [fid, fd] of Object.entries(meta.folders)) {
      if (!toDelete.has(fid) && toDelete.has(fd.parent || "")) {
        toDelete.add(fid);
        changed = true;
      }
    }
  }

  // delete files inside those folders
  for (const [fileId, f] of Object.entries(meta.files)) {
    if (toDelete.has(f.folder || "")) {
      await env.R2.delete(f.key);
      meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
      delete meta.files[fileId];
    }
  }
  // delete folder entries
  for (const fid of toDelete) delete meta.folders[fid];

  await saveMeta(env, meta);
  return json({ ok: true });
}

// Move a file into another folder ("" = root)
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

// ======================= HTML PAGES =======================

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast Lugyi Storage • ဝင်ရန်</title>
<style>
:root{--brand1:#6d28d9;--brand2:#2563eb;--accent:#06b6d4}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#0f172a,#1e1b4b 45%,#312e81);padding:16px;overflow:hidden;position:relative}
body::before,body::after{content:"";position:absolute;border-radius:50%;filter:blur(80px);opacity:.55;z-index:0}
body::before{width:340px;height:340px;background:#7c3aed;top:-80px;left:-60px}
body::after{width:300px;height:300px;background:#06b6d4;bottom:-70px;right:-50px}
.card{position:relative;z-index:1;background:rgba(255,255,255,.08);backdrop-filter:blur(18px);
border:1px solid rgba(255,255,255,.18);padding:36px 30px;border-radius:22px;
box-shadow:0 20px 60px rgba(0,0,0,.45);width:100%;max-width:390px;color:#fff}
.logo{width:64px;height:64px;margin:0 auto 14px;border-radius:18px;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,var(--brand1),var(--accent));box-shadow:0 8px 24px rgba(109,40,217,.5);font-size:30px}
h1{margin:0 0 4px;font-size:23px;text-align:center;font-weight:700;
background:linear-gradient(90deg,#c4b5fd,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{text-align:center;color:rgba(255,255,255,.65);font-size:13px;margin-bottom:22px}
.field{position:relative;margin:12px 0}
.field input{width:100%;padding:13px 14px 13px 42px;border:1px solid rgba(255,255,255,.2);
border-radius:12px;font-size:15px;background:rgba(255,255,255,.07);color:#fff;outline:none;transition:.2s}
.field input::placeholder{color:rgba(255,255,255,.5)}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.25)}
.field .ic{position:absolute;left:14px;top:50%;transform:translateY(-50%);opacity:.7}
button{width:100%;padding:13px;margin-top:10px;border:0;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer;color:#fff;
background:linear-gradient(135deg,var(--brand1),var(--brand2));box-shadow:0 8px 22px rgba(37,99,235,.45);transition:.2s}
button:hover{transform:translateY(-1px);box-shadow:0 12px 28px rgba(37,99,235,.55)}
button:disabled{opacity:.6;cursor:not-allowed}
.err{color:#fca5a5;font-size:13px;margin-top:10px;text-align:center;min-height:18px}
.foot{text-align:center;margin-top:16px;font-size:11px;color:rgba(255,255,255,.45)}
</style></head><body>
<div class="card">
<div class="logo">⚡</div>
<h1>Fast Lugyi Storage</h1>
<div class="sub">🔒 လုံခြုံစိတ်ချရသော Cloud သိုလှောင်မှု</div>
<div class="field"><span class="ic">👤</span><input id="u" placeholder="Username" autocomplete="username"></div>
<div class="field"><span class="ic">🔑</span><input id="p" type="password" placeholder="Password" autocomplete="current-password"></div>
<button id="btn" onclick="login()">🚀 ဝင်မည်</button>
<div class="err" id="err"></div>
<div class="foot">Powered by Cloudflare R2 • Premium Edition</div>
</div>
<script>
async function login(){
  const btn=document.getElementById('btn');btn.disabled=true;btn.textContent='⏳ ဝင်နေသည်...';
  document.getElementById('err').textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u.value,password:p.value})});
    const d=await r.json();
    if(r.ok){location.href='/';return;}
    document.getElementById('err').textContent=d.error||'ဝင်၍မရပါ';
  }catch(e){document.getElementById('err').textContent='ကွန်ရက် ပြဿနာ';}
  btn.disabled=false;btn.textContent='🚀 ဝင်မည်';
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
:root{--brand1:#6d28d9;--brand2:#2563eb;--accent:#06b6d4;--bg:#0f172a;--card:#ffffff;--ink:#1e293b;--muted:#64748b}
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
body{margin:0;background:linear-gradient(180deg,#eef2ff,#f8fafc);color:var(--ink);min-height:100vh}
header{background:linear-gradient(135deg,var(--brand1),var(--brand2));color:#fff;padding:16px 18px;
display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;
box-shadow:0 6px 24px rgba(37,99,235,.35);position:sticky;top:0;z-index:20}
.brand{display:flex;align-items:center;gap:10px}
.brand .lg{width:40px;height:40px;border-radius:12px;background:rgba(255,255,255,.18);
display:flex;align-items:center;justify-content:center;font-size:22px;backdrop-filter:blur(8px)}
header h1{margin:0;font-size:19px;font-weight:700}
.wrap{max-width:960px;margin:0 auto;padding:18px}
.bar{background:var(--card);border-radius:16px;padding:18px;margin-bottom:16px;
box-shadow:0 4px 18px rgba(15,23,42,.07);border:1px solid #eef0f5}
.bar b{font-size:15px}
.prog{height:12px;background:#e5e7eb;border-radius:8px;overflow:hidden;margin-top:10px}
.prog>i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#06b6d4);transition:width .5s}
.prog.warn>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
button{padding:10px 15px;border:0;border-radius:10px;color:#fff;cursor:pointer;font-size:14px;font-weight:600;transition:.18s;
background:linear-gradient(135deg,var(--brand1),var(--brand2));box-shadow:0 4px 12px rgba(37,99,235,.3)}
button:hover{transform:translateY(-1px)}
button.sec{background:#eef2f7;color:#334155;box-shadow:none}
button.sec:hover{background:#e2e8f0}
button.danger{background:linear-gradient(135deg,#ef4444,#dc2626)}
button.ghost{background:transparent;color:#fff;border:1px solid rgba(255,255,255,.4);box-shadow:none}
input,select{padding:10px;border:1px solid #d8dde6;border-radius:10px;font-size:14px;background:#fff;outline:none}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.18)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.sec-title{display:flex;align-items:center;gap:8px;font-weight:700;font-size:15px}
.crumb{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:14px;margin-bottom:12px}
.crumb a{color:var(--brand2);cursor:pointer;text-decoration:none;font-weight:600}
.crumb span.sep{color:#94a3b8}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.fold{background:linear-gradient(135deg,#fff,#f5f7ff);border:1px solid #e4e8f5;border-radius:14px;padding:14px;cursor:pointer;
display:flex;flex-direction:column;gap:6px;transition:.18s;position:relative}
.fold:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(37,99,235,.15);border-color:#c7d2fe}
.fold .ico{font-size:30px}
.fold .nm{font-weight:600;word-break:break-word}
.fold .ct{font-size:12px;color:var(--muted)}
.fold .x{position:absolute;top:8px;right:8px;border:0;background:#fee2e2;color:#b91c1c;border-radius:8px;
width:26px;height:26px;font-size:13px;padding:0;box-shadow:none;display:none}
.fold:hover .x{display:block}
.file{background:var(--card);border-radius:14px;padding:14px;margin-bottom:10px;
box-shadow:0 3px 14px rgba(15,23,42,.06);border:1px solid #eef0f5;transition:.18s}
.file:hover{box-shadow:0 8px 22px rgba(15,23,42,.1)}
.file .top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.ficon{font-size:26px;flex-shrink:0}
.fname{font-weight:600;word-break:break-all}
.meta{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.5}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.acts button{font-size:13px;padding:7px 11px}
.tag{display:inline-block;font-size:11px;padding:2px 9px;border-radius:10px;background:#dbeafe;color:#1e40af;margin-left:6px;font-weight:600}
.tag.exp{background:#fee2e2;color:#991b1b}
.tag.life{background:#dcfce7;color:#166534}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;
padding:13px 22px;border-radius:12px;z-index:99;opacity:0;transition:.3s;font-size:14px;max-width:90%;box-shadow:0 8px 26px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(-4px)}
.modal{position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(4px);display:none;
align-items:center;justify-content:center;z-index:50;padding:16px}
.modal.show{display:flex}
.modal .box{background:#fff;border-radius:18px;padding:24px;max-width:400px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.modal h3{margin:0 0 14px;font-size:18px}
.modal input,.modal select{width:100%;margin:6px 0}
small{color:var(--muted)}
.empty{text-align:center;color:var(--muted);padding:40px 0}
.empty .big{font-size:46px}
</style></head><body>
<header>
<div class="brand"><div class="lg">⚡</div><h1>Fast Lugyi Storage</h1></div>
<div class="row" style="margin:0">
<button class="ghost" onclick="openPass()">🔑 Password</button>
<button class="ghost" onclick="logout()">🚪 ထွက်မည်</button>
</div>
</header>
<div class="wrap">

<div class="bar">
<b>💾 Storage အသုံးပြုမှု</b>
<div id="usage" style="margin-top:6px;font-size:14px">တွက်နေသည်...</div>
<div class="prog" id="progWrap"><i id="progBar" style="width:0%"></i></div>
</div>

<div class="bar">
<div class="sec-title">📤 ဖိုင်တင်ရန် (Photo / Video / Txt / Music ...)</div>
<div class="row" style="margin-top:10px">
<input type="file" id="fileInput" multiple style="flex:1;min-width:200px">
<button onclick="uploadLocal()">⬆ တင်မည်</button>
<button class="sec" onclick="openNewFolder()">📁 Folder အသစ်</button>
</div>
<div id="upStatus"><small></small></div>
</div>

<div class="bar">
<div class="sec-title">🔗 Remote URL ဖြင့်တင်ရန် <small>(1.5GB ထိ)</small></div>
<div class="row" style="margin-top:10px">
<input type="text" id="remoteUrl" placeholder="https://..." style="flex:1;min-width:180px">
<input type="text" id="remoteName" placeholder="ဖိုင်နာမည် (optional)">
<button onclick="uploadRemote()">⬆ တင်မည်</button>
</div>
<div id="remoteStatus"><small></small></div>
</div>

<div class="crumb" id="crumb"></div>

<div class="sec-title" style="margin-bottom:10px">📂 Folders</div>
<div class="grid" id="folders"></div>

<div class="sec-title" style="margin-bottom:10px">📁 ဖိုင်များ</div>
<div id="list"></div>

</div>

<!-- Share modal -->
<div class="modal" id="shareModal"><div class="box">
<h3>🔗 Share Link</h3>
<select id="shareDur">
<option value="2d">📅 ၂ ရက်</option>
<option value="1w">📅 ၁ ပတ်</option>
<option value="1m">📅 ၁ လ</option>
<option value="1y">📅 ၁ နှစ်</option>
<option value="lifetime">♾️ Lifetime (သက်တမ်းမကုန်)</option>
<option value="off">🚫 Link ပိတ်မည်</option>
</select>
<button onclick="doShare()" style="width:100%;margin-top:10px">✅ အတည်ပြုမည်</button>
<div id="shareResult" style="margin-top:12px;word-break:break-all;font-size:13px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('shareModal')">ပိတ်မည်</button>
</div></div>

<!-- New folder modal -->
<div class="modal" id="folderModal"><div class="box">
<h3>📁 Folder အသစ်ဆောက်ရန်</h3>
<input type="text" id="folderName" placeholder="Folder နာမည်" maxlength="80">
<button onclick="doCreateFolder()" style="width:100%;margin-top:8px">✅ ဆောက်မည်</button>
<div id="folderErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('folderModal')">ပိတ်မည်</button>
</div></div>

<!-- Move modal -->
<div class="modal" id="moveModal"><div class="box">
<h3>📦 ဖိုင်ရွှေ့ရန်</h3>
<select id="moveTarget"></select>
<button onclick="doMove()" style="width:100%;margin-top:10px">✅ ရွှေ့မည်</button>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('moveModal')">ပိတ်မည်</button>
</div></div>

<!-- Password modal -->
<div class="modal" id="passModal"><div class="box">
<h3>🔑 Password ပြောင်းရန်</h3>
<input type="password" id="oldPass" placeholder="လက်ရှိ password">
<input type="password" id="newPass" placeholder="password အသစ်">
<button onclick="doChangePass()" style="width:100%;margin-top:8px">✅ ပြောင်းမည်</button>
<div id="passErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('passModal')">ပိတ်မည်</button>
</div></div>

<div class="toast" id="toast"></div>

<script>
let currentFolder="";          // "" = root
let currentShareId=null;
let currentMoveId=null;
let allFolders=[];             // for move dropdown

function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
setTimeout(()=>t.classList.remove('show'),3000);}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';
if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function openModal(id){document.getElementById(id).classList.add('show');}
function closeModal(id){document.getElementById(id).classList.remove('show');}
function fileIcon(t){t=t||'';if(t.startsWith('video/'))return'🎬';if(t.startsWith('image/'))return'🖼️';
if(t.startsWith('audio/'))return'🎵';if(t.startsWith('text/'))return'📄';
if(t.includes('pdf'))return'📕';if(t.includes('zip')||t.includes('rar'))return'🗜️';return'📦';}

async function load(){
  const r=await fetch('/api/list?folder='+encodeURIComponent(currentFolder));
  if(r.status===401){location.href='/login';return;}
  const d=await r.json();

  // usage
  const pct=Math.min(100,(d.totalBytes/d.maxBytes*100)).toFixed(1);
  document.getElementById('usage').innerHTML=
    '<b>'+fmtSize(d.totalBytes)+'</b> / '+fmtSize(d.maxBytes)+' &nbsp;<span style="color:#64748b">('+pct+'%)</span>';
  document.getElementById('progBar').style.width=pct+'%';
  document.getElementById('progWrap').className='prog'+(pct>85?' warn':'');

  // breadcrumb
  let cb='<a onclick="goFolder(\\'\\')">🏠 Home</a>';
  for(const b of d.breadcrumb){
    cb+='<span class="sep">›</span><a onclick="goFolder(\\''+b.id+'\\')">'+escapeHtml(b.name)+'</a>';
  }
  document.getElementById('crumb').innerHTML=cb;

  // folders grid
  const fg=document.getElementById('folders');
  if(!d.folders.length){fg.innerHTML='<div style="color:#94a3b8;font-size:13px">Folder မရှိသေးပါ။</div>';}
  else{
    fg.innerHTML=d.folders.map(fd=>
      '<div class="fold" onclick="goFolder(\\''+fd.id+'\\')">'+
      '<button class="x" title="ဖျက်မည်" onclick="event.stopPropagation();delFolder(\\''+fd.id+'\\',\\''+escapeJs(fd.name)+'\\')">🗑</button>'+
      '<div class="ico">📁</div><div class="nm">'+escapeHtml(fd.name)+'</div>'+
      '<div class="ct">'+fd.count+' items</div></div>'
    ).join('');
  }

  // files
  const list=document.getElementById('list');
  if(!d.files.length){
    list.innerHTML='<div class="empty"><div class="big">🗂️</div>ဤနေရာတွင် ဖိုင်မရှိသေးပါ။</div>';
  }else{
    list.innerHTML=d.files.map(f=>{
      let shareTag='';
      if(f.share){
        const exp=f.share.expiresAt;
        if(exp&&Date.now()>exp) shareTag='<span class="tag exp">Link ကုန်</span>';
        else if(exp) shareTag='<span class="tag">'+new Date(exp).toLocaleDateString('my-MM')+' ထိ</span>';
        else shareTag='<span class="tag life">♾️ Lifetime</span>';
      }
      return '<div class="file"><div class="top">'+
        '<div style="display:flex;gap:10px"><div class="ficon">'+fileIcon(f.type)+'</div><div>'+
        '<div class="fname">'+escapeHtml(f.name)+shareTag+'</div>'+
        '<div class="meta">'+fmtSize(f.size)+' • '+escapeHtml(f.type)+'<br>🕒 '+f.uploadedAt+' (မြန်မာစံတော်ချိန်)</div>'+
        '</div></div></div><div class="acts">'+
        '<button onclick="dl(\\''+f.id+'\\')">⬇ Download</button>'+
        (f.share?'<button class="sec" onclick="copyShare(\\''+f.share.token+'\\')">📋 Link</button>':'')+
        '<button class="sec" onclick="openShare(\\''+f.id+'\\')">🔗 Share</button>'+
        '<button class="sec" onclick="openMove(\\''+f.id+'\\')">📦 ရွှေ့</button>'+
        '<button class="danger" onclick="del(\\''+f.id+'\\',\\''+escapeJs(f.name)+'\\')">🗑 ဖျက်</button>'+
        '</div></div>';
    }).join('');
  }
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function escapeJs(s){return String(s).replace(/['\\\\]/g,'\\\\$&').replace(/"/g,'&quot;');}

function goFolder(id){currentFolder=id;load();}

function dl(id){window.open('/api/download?id='+encodeURIComponent(id),'_blank');}

async function del(id,name){
  if(!confirm('"'+name+'" ကို အပြီးဖျက်မှာ သေချာလား?'))return;
  const r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();
  if(r.ok){toast('🗑 ဖျက်ပြီးပါပြီ');load();}else toast(d.error||'မဖျက်နိုင်ပါ');
}

// ---- Folders ----
function openNewFolder(){document.getElementById('folderErr').textContent='';
  document.getElementById('folderName').value='';openModal('folderModal');}
async function doCreateFolder(){
  const name=document.getElementById('folderName').value.trim();
  if(!name){document.getElementById('folderErr').textContent='နာမည်ထည့်ပါ';return;}
  const r=await fetch('/api/folder/create',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,parent:currentFolder})});
  const d=await r.json();
  if(r.ok){toast('📁 Folder ဆောက်ပြီးပါပြီ');closeModal('folderModal');load();}
  else document.getElementById('folderErr').textContent=d.error||'မရပါ';
}
async function delFolder(id,name){
  if(!confirm('"'+name+'" folder နှင့် အထဲက ဖိုင်အားလုံးကို ဖျက်မှာ သေချာလား?'))return;
  const r=await fetch('/api/folder/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();
  if(r.ok){toast('🗑 Folder ဖျက်ပြီးပါပြီ');load();}else toast(d.error||'မရပါ');
}

// ---- Move ----
async function openMove(id){
  currentMoveId=id;
  // fetch full folder list (all)
  const r=await fetch('/api/list?folder=');
  // gather all folders by walking — simpler: use a dedicated traversal via repeated calls is heavy,
  // so we just offer root + folders visible from list endpoint recursively isn't available;
  // we request a flat list through breadcrumb-less approach:
  await buildAllFolders();
  const sel=document.getElementById('moveTarget');
  sel.innerHTML='<option value="">🏠 Home (root)</option>'+
    allFolders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.path)+'</option>').join('');
  openModal('moveModal');
}
async function buildAllFolders(){
  // BFS through folders using list endpoint
  allFolders=[];
  const visited=new Set();
  async function walk(folderId,prefix){
    const r=await fetch('/api/list?folder='+encodeURIComponent(folderId));
    const d=await r.json();
    for(const fd of d.folders){
      const p=prefix?prefix+' / '+fd.name:fd.name;
      allFolders.push({id:fd.id,path:p});
      if(!visited.has(fd.id)){visited.add(fd.id);await walk(fd.id,p);}
    }
  }
  await walk("","");
}
async function doMove(){
  const folder=document.getElementById('moveTarget').value;
  const r=await fetch('/api/move',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:currentMoveId,folder})});
  const d=await r.json();
  if(r.ok){toast('📦 ရွှေ့ပြီးပါပြီ');closeModal('moveModal');load();}
  else toast(d.error||'မရပါ');
}

// ---- Local upload: small files (<90MB) direct; large via presign ----
const DIRECT_LIMIT=90*1024*1024;
async function uploadLocal(){
  const inp=document.getElementById('fileInput');
  const files=[...inp.files];
  if(!files.length){toast('ဖိုင်ရွေးပါ');return;}
  const st=document.getElementById('upStatus').querySelector('small');
  for(const file of files){
    st.textContent='⏳ '+file.name+' တင်နေသည်...';
    try{
      if(file.size<=DIRECT_LIMIT){
        const fd=new FormData();fd.append('file',file);fd.append('folder',currentFolder);
        const r=await fetch('/api/upload',{method:'POST',body:fd});
        const d=await r.json();
        if(!r.ok)throw new Error(d.error);
      }else{
        const pr=await fetch('/api/presign',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({name:file.name,size:file.size,type:file.type,folder:currentFolder})});
        const pd=await pr.json();
        if(!pr.ok)throw new Error(pd.error);
        st.textContent='⏳ '+file.name+' (ကြီးမားသောဖိုင်) R2 သို့ တိုက်ရိုက်တင်နေသည်...';
        const put=await fetch(pd.uploadUrl,{method:'PUT',body:file,headers:{'Content-Type':file.type||'application/octet-stream'}});
        if(!put.ok)throw new Error('R2 PUT failed '+put.status);
        const fr=await fetch('/api/finalize',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({id:pd.id,key:pd.key,name:file.name,size:file.size,type:file.type,folder:currentFolder})});
        const fd2=await fr.json();
        if(!fr.ok)throw new Error(fd2.error);
      }
      toast('✅ '+file.name+' တင်ပြီးပါပြီ');
    }catch(e){toast('❌ '+file.name+': '+e.message);st.textContent='';return;}
  }
  st.textContent='';inp.value='';load();
}

async function uploadRemote(){
  const url=document.getElementById('remoteUrl').value.trim();
  const name=document.getElementById('remoteName').value.trim();
  if(!url){toast('URL ထည့်ပါ');return;}
  const st=document.getElementById('remoteStatus').querySelector('small');
  st.textContent='⏳ Remote ဖိုင်တင်နေသည်... (ခဏစောင့်ပါ)';
  const r=await fetch('/api/remote',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url,name,folder:currentFolder})});
  const d=await r.json();
  st.textContent='';
  if(r.ok){toast('✅ Remote ဖိုင်တင်ပြီးပါပြီ');document.getElementById('remoteUrl').value='';
    document.getElementById('remoteName').value='';load();}
  else toast('❌ '+(d.error||'မတင်နိုင်ပါ'));
}

function openShare(id){currentShareId=id;document.getElementById('shareResult').textContent='';openModal('shareModal');}
async function doShare(){
  const dur=document.getElementById('shareDur').value;
  const r=await fetch('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:currentShareId,duration:dur})});
  const d=await r.json();
  if(!r.ok){toast(d.error||'မရပါ');return;}
  if(d.share){
    const link=location.origin+'/s/'+d.share.token;
    document.getElementById('shareResult').innerHTML='<b>🔗 Link:</b><br>'+link+
      '<br><button style="margin-top:8px" onclick="copyText(\\''+link+'\\')">📋 Copy</button>';
    toast('✅ Share link ဖန်တီးပြီးပါပြီ');
  }else{document.getElementById('shareResult').textContent='🚫 Link ပိတ်လိုက်ပါပြီ။';toast('Link ပိတ်ပြီး');}
  load();
}
function copyShare(token){copyText(location.origin+'/s/'+token);}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('📋 Copy ကူးပြီးပါပြီ'));}

function openPass(){document.getElementById('passErr').textContent='';
  document.getElementById('oldPass').value='';document.getElementById('newPass').value='';openModal('passModal');}
async function doChangePass(){
  const oldPass=document.getElementById('oldPass').value;
  const newPass=document.getElementById('newPass').value;
  const r=await fetch('/api/changepass',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({oldPass,newPass})});
  const d=await r.json();
  if(r.ok){toast('✅ Password ပြောင်းပြီးပါပြီ');closeModal('passModal');}
  else document.getElementById('passErr').textContent=d.error||'မရပါ';
}

async function logout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

load();
</script>
</body></html>`;
