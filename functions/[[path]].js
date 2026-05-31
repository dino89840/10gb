// ======================= Fast Lugyi Storage =======================
// Cloudflare Pages Functions + R2  (single-file backend + HTML)
// ==================================================================

const MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024;        // 10 GB total storage
const MAX_REMOTE_BYTES = Math.floor(1.5 * 1024 * 1024 * 1024); // 1.5 GB remote url
const META_KEY = "__meta__/index.json";                 // file list + total size
const LOCK_KEY = "__meta__/loginlock.json";             // login attempt lock
const PROG_PREFIX = "__meta__/progress/";               // remote upload progress

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function html(body) {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
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

// ---- Metadata index (file list + total bytes + folders) ----
async function loadMeta(env) {
  const obj = await env.R2.get(META_KEY);
  if (!obj) return { totalBytes: 0, files: {}, folders: {} };
  try {
    const m = JSON.parse(await obj.text());
    if (!m.folders) m.folders = {};
    if (!m.files) m.files = {};
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

// ---- Remote upload progress (separate small objects so polling is cheap) ----
async function saveProgress(env, pid, data) {
  await env.R2.put(PROG_PREFIX + pid, JSON.stringify(data), {
    httpMetadata: { contentType: "application/json" },
  });
}
async function loadProgress(env, pid) {
  const obj = await env.R2.get(PROG_PREFIX + pid);
  if (!obj) return null;
  try { return JSON.parse(await obj.text()); } catch { return null; }
}
async function deleteProgress(env, pid) {
  try { await env.R2.delete(PROG_PREFIX + pid); } catch {}
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
  const canonicalHeaders = `host:${host}\n`;
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

// ---- Parse HTTP Range header: "bytes=START-END" ----
function parseRange(rangeHeader, size) {
  if (!rangeHeader) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!m) return null;
  let start = m[1] === "" ? null : Number(m[1]);
  let end = m[2] === "" ? null : Number(m[2]);

  if (start === null && end === null) return null;

  if (start === null) {
    // suffix: last N bytes
    start = Math.max(0, size - end);
    end = size - 1;
  } else if (end === null) {
    end = size - 1;
  }
  if (isNaN(start) || isNaN(end) || start > end || start >= size) return null;
  end = Math.min(end, size - 1);
  return { start, end };
}

// ---- Serve an R2 object with Range support (for video seek, etc.) ----
async function serveR2Object(request, env, fileMeta, disposition /* "inline"|"attachment" */) {
  const key = fileMeta.key;
  const fullSize = fileMeta.size;
  const ctype = fileMeta.type || "application/octet-stream";
  const dispName = `${disposition}; filename*=UTF-8''${encodeURIComponent(fileMeta.name)}`;

  const rangeHeader = request.headers.get("Range");
  const range = parseRange(rangeHeader, fullSize);

  if (range) {
    const len = range.end - range.start + 1;
    const obj = await env.R2.get(key, { range: { offset: range.start, length: len } });
    if (!obj) return new Response("Not Found", { status: 404 });
    const headers = {
      "Content-Type": ctype,
      "Content-Disposition": dispName,
      "Accept-Ranges": "bytes",
      "Content-Range": `bytes ${range.start}-${range.end}/${fullSize}`,
      "Content-Length": String(len),
      "Cache-Control": "public, max-age=3600",
    };
    if (obj.httpEtag) headers["ETag"] = obj.httpEtag;
    return new Response(obj.body, { status: 206, headers });
  }

  // Full object
  const obj = await env.R2.get(key);
  if (!obj) return new Response("Not Found", { status: 404 });
  const headers = {
    "Content-Type": ctype,
    "Content-Disposition": dispName,
    "Accept-Ranges": "bytes",
    "Content-Length": String(fullSize),
    "Cache-Control": "public, max-age=3600",
  };
  if (obj.httpEtag) headers["ETag"] = obj.httpEtag;
  return new Response(obj.body, { status: 200, headers });
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
    if (path === "/api/list" && request.method === "GET") return await apiList(env);
    if (path === "/api/upload" && request.method === "POST") return await apiUpload(request, env);
    if (path === "/api/presign" && request.method === "POST") return await apiPresign(request, env);
    if (path === "/api/finalize" && request.method === "POST") return await apiFinalize(request, env);
    if (path === "/api/remote" && request.method === "POST") return await apiRemote(request, env);
    if (path === "/api/remote-progress" && request.method === "GET") return await apiRemoteProgress(request, env);
    if (path === "/api/delete" && request.method === "POST") return await apiDelete(request, env);
    if (path === "/api/share" && request.method === "POST") return await apiShare(request, env);
    if (path === "/api/changepass" && request.method === "POST") return await apiChangePass(request, env);
    if (path === "/api/download" && request.method === "GET") return await apiDownload(request, env);
    // ---- Folder routes ----
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

async function apiList(env) {
  const meta = await loadMeta(env);
  const files = Object.entries(meta.files || {}).map(([id, f]) => ({
    id,
    name: f.name,
    size: f.size,
    type: f.type,
    uploadedAt: f.uploadedAt,
    folderId: f.folderId || null,
    share: f.share ? {
      token: f.share.token,
      expiresAt: f.share.expiresAt,
    } : null,
  })).sort((a, b) => (b.uploadedAt || "").localeCompare(a.uploadedAt || ""));

  const folders = Object.entries(meta.folders || {}).map(([id, fo]) => ({
    id,
    name: fo.name,
    createdAt: fo.createdAt,
  })).sort((a, b) => (a.name || "").localeCompare(b.name || ""));

  return json({
    files,
    folders,
    totalBytes: meta.totalBytes || 0,
    maxBytes: MAX_TOTAL_BYTES,
  });
}

// --- Small file direct upload (multipart/form-data) ---
async function apiUpload(request, env) {
  const meta = await loadMeta(env);
  const form = await request.formData();
  const file = form.get("file");
  const folderId = form.get("folderId") || null;
  if (!file || typeof file === "string") return json({ error: "ဖိုင်မပါပါ" }, 400);

  if (folderId && !meta.folders[folderId]) return json({ error: "Folder မတွေ့ပါ" }, 400);

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
    folderId: folderId || null,
    key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + size;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Large file: get presigned PUT url for direct browser->R2 upload ---
async function apiPresign(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { name, size, type } = body;
  if (!name || !size) return json({ error: "name/size မပါပါ" }, 400);

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
  const { id, key, name, size, type, folderId } = body;
  if (!id || !key) return json({ error: "id/key မပါပါ" }, 400);
  if (folderId && !meta.folders[folderId]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  const head = await env.R2.head(key);
  if (!head) return json({ error: "R2 ထဲတွင် ဖိုင်မတွေ့ပါ" }, 400);
  const realSize = head.size;

  if ((meta.totalBytes || 0) + realSize > MAX_TOTAL_BYTES) {
    await env.R2.delete(key);
    return json({ error: "Storage 10GB ကျော်သွားသဖြင့် ဖျက်လိုက်ပါပြီ။" }, 413);
  }

  meta.files = meta.files || {};
  meta.files[id] = {
    name: name || id,
    size: realSize,
    type: type || head.httpMetadata?.contentType || "application/octet-stream",
    uploadedAt: nowMM(),
    folderId: folderId || null,
    key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// --- Remote URL upload (stream into R2 with progress), max 1.5GB ---
async function apiRemote(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { url: remoteUrl, name, folderId } = body;
  if (!remoteUrl) return json({ error: "URL မပါပါ" }, 400);
  if (folderId && !meta.folders[folderId]) return json({ error: "Folder မတွေ့ပါ" }, 400);

  const resp = await fetch(remoteUrl);
  if (!resp.ok || !resp.body) return json({ error: "URL မှ ဖိုင်ဆွဲ၍မရပါ (" + resp.status + ")" }, 400);

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

  // progress id (returned to client so it can poll)
  const pid = randId();
  await saveProgress(env, pid, { total: declared, loaded: 0, done: false, error: null, ts: Date.now() });

  // Wrap the remote stream to count bytes + abort if exceeds limits.
  let loaded = 0;
  let lastWrite = 0;
  let aborted = false;
  const reader = resp.body.getReader();
  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) { controller.close(); return; }
        loaded += value.byteLength;

        if (loaded > MAX_REMOTE_BYTES) {
          aborted = true;
          controller.error(new Error("REMOTE_TOO_BIG"));
          try { await reader.cancel(); } catch {}
          return;
        }
        if ((meta.totalBytes || 0) + loaded > MAX_TOTAL_BYTES) {
          aborted = true;
          controller.error(new Error("STORAGE_FULL"));
          try { await reader.cancel(); } catch {}
          return;
        }

        controller.enqueue(value);

        // update progress at most ~every 1MB to avoid too many R2 writes
        const now = Date.now();
        if (loaded - lastWrite >= 1024 * 1024 || now - 0 === 0) {
          lastWrite = loaded;
          // fire and forget
          saveProgress(env, pid, {
            total: declared, loaded, done: false, error: null, ts: now,
          }).catch(() => {});
        }
      } catch (e) {
        controller.error(e);
      }
    },
    cancel() { try { reader.cancel(); } catch {} },
  });

  try {
    await env.R2.put(key, stream, { httpMetadata: { contentType: ctype } });
  } catch (e) {
    await env.R2.delete(key).catch(() => {});
    const msg = aborted
      ? (String(e.message).includes("STORAGE_FULL")
          ? "Storage 10GB ကျော်သဖြင့် ဖျက်လိုက်ပါပြီ။"
          : "Remote ဖိုင်သည် 1.5GB ထက်ကြီးသဖြင့် ဖျက်လိုက်ပါပြီ။")
      : "Remote ဖိုင်တင်ရာတွင် အမှားဖြစ်ပါသည်။";
    await saveProgress(env, pid, { total: declared, loaded, done: true, error: msg, ts: Date.now() });
    return json({ error: msg, pid }, 413);
  }

  const head = await env.R2.head(key);
  const realSize = head ? head.size : loaded;

  if (realSize > MAX_REMOTE_BYTES) {
    await env.R2.delete(key);
    const msg = "Remote ဖိုင်သည် 1.5GB ထက်ကြီးသဖြင့် ဖျက်လိုက်ပါပြီ။";
    await saveProgress(env, pid, { total: declared, loaded, done: true, error: msg, ts: Date.now() });
    return json({ error: msg, pid }, 413);
  }
  if ((meta.totalBytes || 0) + realSize > MAX_TOTAL_BYTES) {
    await env.R2.delete(key);
    const msg = "Storage 10GB ကျော်သဖြင့် ဖျက်လိုက်ပါပြီ။";
    await saveProgress(env, pid, { total: declared, loaded, done: true, error: msg, ts: Date.now() });
    return json({ error: msg, pid }, 413);
  }

  let fname = name;
  if (!fname) {
    try { fname = decodeURIComponent(new URL(remoteUrl).pathname.split("/").pop()) || id; }
    catch { fname = id; }
  }

  meta.files = meta.files || {};
  meta.files[id] = {
    name: fname, size: realSize, type: ctype,
    uploadedAt: nowMM(), folderId: folderId || null, key,
  };
  meta.totalBytes = (meta.totalBytes || 0) + realSize;
  await saveMeta(env, meta);

  await saveProgress(env, pid, { total: realSize, loaded: realSize, done: true, error: null, ts: Date.now() });
  return json({ ok: true, id, pid });
}

// --- Poll remote upload progress ---
async function apiRemoteProgress(request, env) {
  const url = new URL(request.url);
  const pid = url.searchParams.get("pid");
  if (!pid) return json({ error: "pid မပါပါ" }, 400);
  const prog = await loadProgress(env, pid);
  if (!prog) return json({ loaded: 0, total: 0, done: false, error: null });
  if (prog.done) deleteProgress(env, pid).catch(() => {}); // cleanup once read after done
  return json(prog);
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

// ---- Folder: create ----
async function apiFolderCreate(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const name = (body.name || "").trim();
  if (!name) return json({ error: "Folder နာမည် ထည့်ပါ" }, 400);
  // prevent duplicate names
  const dup = Object.values(meta.folders).some(f => f.name === name);
  if (dup) return json({ error: "ဒီနာမည်နဲ့ folder ရှိပြီးသားပါ" }, 400);

  const id = randId();
  meta.folders[id] = { name, createdAt: nowMM() };
  await saveMeta(env, meta);
  return json({ ok: true, id });
}

// ---- Folder: rename ----
async function apiFolderRename(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id } = body;
  const name = (body.name || "").trim();
  if (!meta.folders[id]) return json({ error: "Folder မတွေ့ပါ" }, 404);
  if (!name) return json({ error: "Folder နာမည် ထည့်ပါ" }, 400);
  meta.folders[id].name = name;
  await saveMeta(env, meta);
  return json({ ok: true });
}

// ---- Folder: delete (files inside move back to root, not deleted) ----
async function apiFolderDelete(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, deleteFiles } = body;
  if (!meta.folders[id]) return json({ error: "Folder မတွေ့ပါ" }, 404);

  for (const [fid, f] of Object.entries(meta.files)) {
    if (f.folderId === id) {
      if (deleteFiles) {
        await env.R2.delete(f.key);
        meta.totalBytes = Math.max(0, (meta.totalBytes || 0) - (f.size || 0));
        delete meta.files[fid];
      } else {
        f.folderId = null; // move to root
      }
    }
  }
  delete meta.folders[id];
  await saveMeta(env, meta);
  return json({ ok: true });
}

// ---- Move a file into a folder (or root) ----
async function apiMove(request, env) {
  const meta = await loadMeta(env);
  const body = await request.json().catch(() => ({}));
  const { id, folderId } = body;
  const f = meta.files?.[id];
  if (!f) return json({ error: "ဖိုင်မတွေ့ပါ" }, 404);
  if (folderId && !meta.folders[folderId]) return json({ error: "Folder မတွေ့ပါ" }, 400);
  f.folderId = folderId || null;
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

// --- Authed download (with Range support so in-browser seek works) ---
async function apiDownload(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const forceDl = url.searchParams.get("dl") === "1";
  const meta = await loadMeta(env);
  const f = meta.files?.[id];
  if (!f) return new Response("Not Found", { status: 404 });

  // If it's media and not forced download, serve inline so it can play & seek.
  const isMedia = /^(image|video|audio|text)\//.test(f.type || "");
  const disposition = (forceDl || !isMedia) ? "attachment" : "inline";
  return await serveR2Object(request, env, f, disposition);
}

// --- Public share download (no auth, checks expiry, Range support) ---
async function handleShare(request, env, token) {
  const meta = await loadMeta(env);
  let target = null;
  for (const [id, f] of Object.entries(meta.files || {})) {
    if (f.share && f.share.token === token) { target = f; break; }
  }
  if (!target) return new Response("Link မတွေ့ပါ", { status: 404 });

  if (target.share.expiresAt && Date.now() > target.share.expiresAt) {
    return new Response("ဤ link သက်တမ်းကုန်သွားပါပြီ။ (မူရင်းဖိုင်မပျက်ပါ)", { status: 410 });
  }

  const inline = /^(image|video|audio|text)\//.test(target.type || "");
  return await serveR2Object(request, env, target, inline ? "inline" : "attachment");
}

// ======================= HTML PAGES =======================

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast Lugyi Storage - ဝင်ရန်</title>
<style>
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#1e3c72,#2a5298);padding:16px}
.card{background:#fff;padding:32px;border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.3);width:100%;max-width:380px}
h1{margin:0 0 4px;font-size:22px;color:#1e3c72;text-align:center}
.sub{text-align:center;color:#888;font-size:13px;margin-bottom:20px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:8px;font-size:15px}
button{width:100%;padding:12px;margin-top:8px;background:#1e3c72;color:#fff;border:0;border-radius:8px;font-size:16px;cursor:pointer}
button:hover{background:#2a5298}
.err{color:#d33;font-size:13px;margin-top:8px;text-align:center;min-height:18px}
</style></head><body>
<div class="card">
<h1>⚡ Fast Lugyi Storage</h1>
<div class="sub">အကောင့်ဝင်ရန်</div>
<input id="u" placeholder="Username" autocomplete="username">
<input id="p" type="password" placeholder="Password" autocomplete="current-password">
<button id="btn" onclick="login()">ဝင်မည်</button>
<div class="err" id="err"></div>
</div>
<script>
async function login(){
  const btn=document.getElementById('btn');btn.disabled=true;btn.textContent='ဝင်နေသည်...';
  document.getElementById('err').textContent='';
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u.value,password:p.value})});
  const d=await r.json();
  if(r.ok){location.href='/';}
  else{document.getElementById('err').textContent=d.error||'ဝင်၍မရပါ';btn.disabled=false;btn.textContent='ဝင်မည်';}
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script>
</body></html>`;

const APP_HTML = `<!DOCTYPE html>
<html lang="my"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast Lugyi Storage</title>
<style>
*{box-sizing:border-box;font-family:system-ui,'Padauk','Myanmar3',sans-serif}
body{margin:0;background:#f0f2f5;color:#222}
header{background:linear-gradient(135deg,#1e3c72,#2a5298);color:#fff;padding:16px;display:flex;
align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
header h1{margin:0;font-size:20px}
.wrap{max-width:900px;margin:0 auto;padding:16px}
.bar{background:#fff;border-radius:12px;padding:16px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.prog{height:10px;background:#e5e7eb;border-radius:6px;overflow:hidden;margin-top:8px}
.prog>i{display:block;height:100%;background:linear-gradient(90deg,#16a34a,#22c55e);transition:width .3s}
.prog.warn>i{background:linear-gradient(90deg,#f59e0b,#ef4444)}
button{padding:9px 14px;border:0;border-radius:8px;background:#1e3c72;color:#fff;cursor:pointer;font-size:14px}
button:hover{opacity:.9}
button.sec{background:#e5e7eb;color:#333}
button.danger{background:#ef4444}
input,select{padding:9px;border:1px solid #ddd;border-radius:8px;font-size:14px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.file{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.file .top{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}
.fname{font-weight:600;word-break:break-all}
.meta{font-size:12px;color:#888;margin-top:4px}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.acts button{font-size:13px;padding:6px 10px}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:10px;background:#dbeafe;color:#1e40af;margin-left:6px}
.tag.exp{background:#fee2e2;color:#991b1b}
.folderbox{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);
display:flex;justify-content:space-between;align-items:center;gap:8px;cursor:pointer}
.folderbox:hover{background:#f8fafc}
.fbleft{display:flex;align-items:center;gap:8px;font-weight:600}
.crumb{font-size:14px;color:#1e3c72;margin-bottom:10px;cursor:pointer}
.crumb b{color:#111}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#222;color:#fff;
padding:12px 20px;border-radius:8px;z-index:99;opacity:0;transition:.3s;font-size:14px;max-width:90%}
.toast.show{opacity:1}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:50;padding:16px}
.modal.show{display:flex}
.modal .box{background:#fff;border-radius:12px;padding:20px;max-width:420px;width:100%}
.modal h3{margin:0 0 12px}
.modal input,.modal select{width:100%;margin:6px 0}
small{color:#888}
.player{margin-top:10px}
.player video,.player audio{width:100%;border-radius:8px;background:#000}
.player img{max-width:100%;border-radius:8px}
</style></head><body>
<header>
<h1>⚡ Fast Lugyi Storage</h1>
<div class="row" style="margin:0">
<button class="sec" onclick="openPass()">Password ပြောင်း</button>
<button class="sec" onclick="logout()">ထွက်မည်</button>
</div>
</header>
<div class="wrap">

<div class="bar">
<b>Storage အသုံးပြုမှု</b>
<div id="usage">တွက်နေသည်...</div>
<div class="prog" id="progWrap"><i id="progBar" style="width:0%"></i></div>
</div>

<div class="bar">
<b>📂 Folder</b>
<div class="row">
<input type="text" id="newFolderName" placeholder="Folder အသစ်နာမည်" style="flex:1;min-width:160px">
<button onclick="createFolder()">+ Folder ဆောက်မည်</button>
</div>
<small id="folderHint">ဖိုင်တင်ရင် အောက်က folder ထဲကို တင်ပါမယ်။</small>
</div>

<div class="bar">
<b>📤 ဖုန်းထဲကဖိုင်တင်ရန် (Photo / Video / Txt / Music ...)</b>
<div class="row">
<select id="uploadFolder" style="min-width:160px"><option value="">📁 Root (folder မရွေး)</option></select>
</div>
<div class="row">
<input type="file" id="fileInput" multiple>
<button onclick="uploadLocal()">တင်မည်</button>
</div>
<div id="upStatus"><small></small></div>
</div>

<div class="bar">
<b>🔗 Remote URL ဖြင့်တင်ရန် (1.5GB ထိ)</b>
<div class="row">
<select id="remoteFolder" style="min-width:160px"><option value="">📁 Root (folder မရွေး)</option></select>
</div>
<div class="row">
<input type="text" id="remoteUrl" placeholder="https://..." style="flex:1;min-width:180px">
<input type="text" id="remoteName" placeholder="ဖိုင်နာမည် (optional)">
<button id="remoteBtn" onclick="uploadRemote()">တင်မည်</button>
</div>
<div id="remoteStatus"><small></small></div>
<div class="prog" id="remoteProgWrap" style="display:none"><i id="remoteProgBar" style="width:0%"></i></div>
</div>

<div id="crumb" class="crumb"></div>
<h3 id="listTitle">📁 ဖိုင်များ</h3>
<div id="folderList"></div>
<div id="list"></div>

</div>

<!-- Share modal -->
<div class="modal" id="shareModal"><div class="box">
<h3>🔗 Share Link</h3>
<select id="shareDur">
<option value="2d">၂ ရက်</option>
<option value="1w">၁ ပတ်</option>
<option value="1m">၁ လ</option>
<option value="1y">၁ နှစ်</option>
<option value="lifetime">Lifetime (သက်တမ်းမကုန်)</option>
<option value="off">Link ပိတ်မည်</option>
</select>
<button onclick="doShare()" style="width:100%;margin-top:6px">အတည်ပြုမည်</button>
<div id="shareResult" style="margin-top:12px;word-break:break-all;font-size:13px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('shareModal')">ပိတ်မည်</button>
</div></div>

<!-- Move modal -->
<div class="modal" id="moveModal"><div class="box">
<h3>📁 Folder ထဲ ရွှေ့ရန်</h3>
<select id="moveFolder"></select>
<button onclick="doMove()" style="width:100%;margin-top:6px">ရွှေ့မည်</button>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('moveModal')">ပိတ်မည်</button>
</div></div>

<!-- Password modal -->
<div class="modal" id="passModal"><div class="box">
<h3>🔑 Password ပြောင်းရန်</h3>
<input type="password" id="oldPass" placeholder="လက်ရှိ password">
<input type="password" id="newPass" placeholder="password အသစ်">
<button onclick="doChangePass()" style="width:100%;margin-top:8px">ပြောင်းမည်</button>
<div id="passErr" style="color:#d33;font-size:13px;margin-top:8px"></div>
<button class="sec" style="width:100%;margin-top:10px" onclick="closeModal('passModal')">ပိတ်မည်</button>
</div></div>

<div class="toast" id="toast"></div>

<script>
let currentShareId=null;
let currentMoveId=null;
let state={files:[],folders:[],totalBytes:0,maxBytes:0};
let currentFolder=null; // null = root

function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
setTimeout(()=>t.classList.remove('show'),3000);}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';
if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function openModal(id){document.getElementById(id).classList.add('show');}
function closeModal(id){document.getElementById(id).classList.remove('show');}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function escapeJs(s){return String(s).replace(/['\\\\]/g,'\\\\$&').replace(/"/g,'&quot;');}

async function load(){
  const r=await fetch('/api/list');
  if(r.status===401){location.href='/login';return;}
  const d=await r.json();
  state=d;

  // usage
  const pct=Math.min(100,(d.totalBytes/d.maxBytes*100)).toFixed(1);
  document.getElementById('usage').innerHTML=
    fmtSize(d.totalBytes)+' / '+fmtSize(d.maxBytes)+' ('+pct+'%)';
  const bar=document.getElementById('progBar');bar.style.width=pct+'%';
  document.getElementById('progWrap').className='prog'+(pct>85?' warn':'');

  // folder selects (upload + remote)
  const optHtml='<option value="">📁 Root (folder မရွေး)</option>'+
    d.folders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.name)+'</option>').join('');
  document.getElementById('uploadFolder').innerHTML=optHtml;
  document.getElementById('remoteFolder').innerHTML=optHtml;

  // if current folder was deleted, go to root
  if(currentFolder && !d.folders.find(f=>f.id===currentFolder)) currentFolder=null;

  render();
}

function render(){
  const d=state;
  const crumb=document.getElementById('crumb');
  const folderList=document.getElementById('folderList');
  const list=document.getElementById('list');
  const title=document.getElementById('listTitle');

  if(currentFolder){
    const fo=d.folders.find(f=>f.id===currentFolder);
    crumb.innerHTML='<span onclick="goRoot()">📁 Root</span> / <b>'+escapeHtml(fo?fo.name:'?')+'</b>';
    title.textContent='📂 '+(fo?fo.name:'');
    folderList.innerHTML=''; // no nested folders
  }else{
    crumb.innerHTML='<b>📁 Root</b>';
    title.textContent='📁 ဖိုင်များ';
    // show folders
    folderList.innerHTML=d.folders.map(fo=>{
      const cnt=d.files.filter(f=>f.folderId===fo.id).length;
      return '<div class="folderbox"><div class="fbleft" onclick="openFolder(\\''+fo.id+'\\')">'+
        '📁 '+escapeHtml(fo.name)+' <small>('+cnt+' ဖိုင်)</small></div>'+
        '<div><button class="sec" onclick="event.stopPropagation();renameFolder(\\''+fo.id+'\\',\\''+escapeJs(fo.name)+'\\')">✏️</button> '+
        '<button class="danger" onclick="event.stopPropagation();deleteFolder(\\''+fo.id+'\\',\\''+escapeJs(fo.name)+'\\')">🗑</button></div></div>';
    }).join('');
  }

  // files in current view
  const files=d.files.filter(f=>(f.folderId||null)===(currentFolder||null));
  if(!files.length){
    list.innerHTML='<p style="color:#888">ဤနေရာတွင် ဖိုင်မရှိသေးပါ။</p>';
    return;
  }
  list.innerHTML=files.map(f=>{
    let shareTag='';
    if(f.share){
      const exp=f.share.expiresAt;
      if(exp&&Date.now()>exp) shareTag='<span class="tag exp">Link ကုန်</span>';
      else if(exp) shareTag='<span class="tag">'+new Date(exp).toLocaleDateString('my-MM')+' ထိ</span>';
      else shareTag='<span class="tag">Lifetime</span>';
    }
    const isVideo=/^video\\//.test(f.type||'');
    const isAudio=/^audio\\//.test(f.type||'');
    const isImage=/^image\\//.test(f.type||'');
    let player='';
    if(isVideo) player='<div class="player"><video controls preload="metadata" src="/api/download?id='+f.id+'"></video></div>';
    else if(isAudio) player='<div class="player"><audio controls preload="metadata" src="/api/download?id='+f.id+'"></audio></div>';
    else if(isImage) player='<div class="player"><img loading="lazy" src="/api/download?id='+f.id+'"></div>';

    return '<div class="file"><div class="top"><div>'+
      '<div class="fname">'+escapeHtml(f.name)+shareTag+'</div>'+
      '<div class="meta">'+fmtSize(f.size)+' • '+escapeHtml(f.type)+'<br>📅 '+f.uploadedAt+' (မြန်မာစံတော်ချိန်)</div>'+
      '</div></div>'+player+'<div class="acts">'+
      '<button onclick="dl(\\''+f.id+'\\')">⬇ Download</button>'+
      (f.share?'<button class="sec" onclick="copyShare(\\''+f.share.token+'\\')">📋 Link Copy</button>':'')+
      '<button class="sec" onclick="openShare(\\''+f.id+'\\')">🔗 Share</button>'+
      '<button class="sec" onclick="openMove(\\''+f.id+'\\')">📁 ရွှေ့</button>'+
      '<button class="danger" onclick="del(\\''+f.id+'\\',\\''+escapeJs(f.name)+'\\')">🗑 ဖျက်</button>'+
      '</div></div>';
  }).join('');
}

function openFolder(id){currentFolder=id;render();}
function goRoot(){currentFolder=null;render();}

async function createFolder(){
  const name=document.getElementById('newFolderName').value.trim();
  if(!name){toast('Folder နာမည် ထည့်ပါ');return;}
  const r=await fetch('/api/folder/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  const d=await r.json();
  if(r.ok){toast('Folder ဆောက်ပြီးပါပြီ');document.getElementById('newFolderName').value='';load();}
  else toast(d.error||'မဆောက်နိုင်ပါ');
}
async function renameFolder(id,old){
  const name=prompt('Folder နာမည်အသစ်:',old);
  if(name===null)return;
  const r=await fetch('/api/folder/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,name:name.trim()})});
  const d=await r.json();
  if(r.ok){toast('ပြောင်းပြီးပါပြီ');load();}else toast(d.error||'မရပါ');
}
async function deleteFolder(id,name){
  const inside=state.files.filter(f=>f.folderId===id).length;
  let deleteFiles=false;
  if(inside>0){
    const ch=confirm('"'+name+'" ထဲမှာ ဖိုင် '+inside+' ဖိုင်ရှိပါတယ်။\\n\\nOK = ဖိုင်တွေပါ အကုန်ဖျက်မည်\\nCancel = Folder ပဲဖျက်ပြီး ဖိုင်တွေကို Root သို့ ရွှေ့မည်');
    deleteFiles=ch;
  }else{
    if(!confirm('"'+name+'" ကို ဖျက်မှာ သေချာလား?'))return;
  }
  const r=await fetch('/api/folder/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,deleteFiles})});
  const d=await r.json();
  if(r.ok){toast('Folder ဖျက်ပြီးပါပြီ');if(currentFolder===id)currentFolder=null;load();}
  else toast(d.error||'မရပါ');
}

function dl(id){window.open('/api/download?id='+encodeURIComponent(id)+'&dl=1','_blank');}

async function del(id,name){
  if(!confirm('"'+name+'" ကို အပြီးဖျက်မှာ သေချာလား?'))return;
  const r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  const d=await r.json();
  if(r.ok){toast('ဖျက်ပြီးပါပြီ');load();}else toast(d.error||'မဖျက်နိုင်ပါ');
}

// ---- Local upload ----
const DIRECT_LIMIT=90*1024*1024;
async function uploadLocal(){
  const inp=document.getElementById('fileInput');
  const folderId=document.getElementById('uploadFolder').value;
  const files=[...inp.files];
  if(!files.length){toast('ဖိုင်ရွေးပါ');return;}
  const st=document.getElementById('upStatus').querySelector('small');
  for(const file of files){
    st.textContent=file.name+' တင်နေသည်...';
    try{
      if(file.size<=DIRECT_LIMIT){
        const fd=new FormData();fd.append('file',file);if(folderId)fd.append('folderId',folderId);
        const r=await fetch('/api/upload',{method:'POST',body:fd});
        const d=await r.json();
        if(!r.ok)throw new Error(d.error);
      }else{
        const pr=await fetch('/api/presign',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({name:file.name,size:file.size,type:file.type})});
        const pd=await pr.json();
        if(!pr.ok)throw new Error(pd.error);
        st.textContent=file.name+' (ကြီးမားသောဖိုင်) R2 သို့ တိုက်ရိုက်တင်နေသည်...';
        const put=await fetch(pd.uploadUrl,{method:'PUT',body:file,headers:{'Content-Type':file.type||'application/octet-stream'}});
        if(!put.ok)throw new Error('R2 PUT failed '+put.status);
        const fr=await fetch('/api/finalize',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({id:pd.id,key:pd.key,name:file.name,size:file.size,type:file.type,folderId})});
        const fd2=await fr.json();
        if(!fr.ok)throw new Error(fd2.error);
      }
      toast(file.name+' တင်ပြီးပါပြီ');
    }catch(e){toast('❌ '+file.name+': '+e.message);st.textContent='';return;}
  }
  st.textContent='';inp.value='';load();
}

// ---- Remote upload with progress polling ----
let remotePoll=null;
async function uploadRemote(){
  const url=document.getElementById('remoteUrl').value.trim();
  const name=document.getElementById('remoteName').value.trim();
  const folderId=document.getElementById('remoteFolder').value;
  if(!url){toast('URL ထည့်ပါ');return;}
  const st=document.getElementById('remoteStatus').querySelector('small');
  const btn=document.getElementById('remoteBtn');
  const pw=document.getElementById('remoteProgWrap');
  const pb=document.getElementById('remoteProgBar');
  btn.disabled=true;
  st.textContent='Remote ဖိုင်တင်နေသည်... (ခဏစောင့်ပါ)';
  pw.style.display='block';pb.style.width='0%';

  // We can't get pid until response returns, so poll after a short delay using a temp approach:
  // The server returns pid in the final response; but to show live %, we start the request and poll
  // using a pid we generate? -> Instead server controls pid. So we poll only after we know pid.
  // Trick: open the request; meanwhile poll a shared latest-progress is complex.
  // Simpler robust approach: send request, and the FIRST thing server does is create progress with a pid
  // we pass in. So we generate pid on client and send it.
  // (Handled below via clientPid.)

  const clientPid=(crypto.randomUUID?crypto.randomUUID():Date.now()+''+Math.random()).replace(/-/g,'');

  // start polling
  remotePoll=setInterval(async()=>{
    try{
      const r=await fetch('/api/remote-progress?pid='+clientPid);
      const p=await r.json();
      if(p.total>0){
        const pct=Math.min(100,(p.loaded/p.total*100)).toFixed(1);
        pb.style.width=pct+'%';
        st.textContent='တင်နေသည်... '+pct+'% ('+fmtSize(p.loaded)+' / '+fmtSize(p.total)+')';
      }else if(p.loaded>0){
        st.textContent='တင်နေသည်... '+fmtSize(p.loaded)+' (အရွယ်အစား မသိ)';
        pb.style.width='50%';
      }
    }catch{}
  },800);

  try{
    const r=await fetch('/api/remote',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url,name,folderId,pid:clientPid})});
    const d=await r.json();
    clearInterval(remotePoll);
    if(r.ok){
      pb.style.width='100%';
      st.textContent='✅ တင်ပြီးပါပြီ';
      document.getElementById('remoteUrl').value='';
      document.getElementById('remoteName').value='';
      toast('Remote ဖိုင်တင်ပြီးပါပြီ');
      setTimeout(()=>{pw.style.display='none';st.textContent='';},1500);
      load();
    }else{
      st.textContent='';pw.style.display='none';
      toast('❌ '+(d.error||'မတင်နိုင်ပါ'));
    }
  }catch(e){
    clearInterval(remotePoll);
    st.textContent='';pw.style.display='none';
    toast('❌ '+e.message);
  }
  btn.disabled=false;
}

// ---- Share ----
function openShare(id){currentShareId=id;document.getElementById('shareResult').textContent='';openModal('shareModal');}
async function doShare(){
  const dur=document.getElementById('shareDur').value;
  const r=await fetch('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:currentShareId,duration:dur})});
  const d=await r.json();
  if(!r.ok){toast(d.error||'မရပါ');return;}
  if(d.share){
    const link=location.origin+'/s/'+d.share.token;
    document.getElementById('shareResult').innerHTML='<b>Link:</b><br>'+link+
      '<br><button style="margin-top:8px" onclick="copyText(\\''+link+'\\')">📋 Copy</button>';
    toast('Share link ဖန်တီးပြီးပါပြီ');
  }else{document.getElementById('shareResult').textContent='Link ပိတ်လိုက်ပါပြီ။';toast('Link ပိတ်ပြီး');}
  load();
}
function copyShare(token){copyText(location.origin+'/s/'+token);}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('📋 Copy ကူးပြီးပါပြီ'));}

// ---- Move ----
function openMove(id){
  currentMoveId=id;
  const sel=document.getElementById('moveFolder');
  sel.innerHTML='<option value="">📁 Root</option>'+
    state.folders.map(f=>'<option value="'+f.id+'">📁 '+escapeHtml(f.name)+'</option>').join('');
  openModal('moveModal');
}
async function doMove(){
  const folderId=document.getElementById('moveFolder').value;
  const r=await fetch('/api/move',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:currentMoveId,folderId})});
  const d=await r.json();
  if(r.ok){toast('ရွှေ့ပြီးပါပြီ');closeModal('moveModal');load();}
  else toast(d.error||'မရပါ');
}

// ---- Password ----
function openPass(){document.getElementById('passErr').textContent='';
  document.getElementById('oldPass').value='';document.getElementById('newPass').value='';openModal('passModal');}
async function doChangePass(){
  const oldPass=document.getElementById('oldPass').value;
  const newPass=document.getElementById('newPass').value;
  const r=await fetch('/api/changepass',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({oldPass,newPass})});
  const d=await r.json();
  if(r.ok){toast('Password ပြောင်းပြီးပါပြီ');closeModal('passModal');}
  else document.getElementById('passErr').textContent=d.error||'မရပါ';
}

async function logout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

load();
</script>
</body></html>`;
