import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { WebSocketServer } from "ws";
import { Client } from "ssh2";
import { scanPorts } from "./scan.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const MAX_SESSIONS = 30;
const ATTEMPTS_PER_MIN = 8;
const ACCESS_KEY = process.env.ACCESS_KEY || "";
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === "1";
const MAX_SCAN_PORTS = 65535;

process.on("uncaughtException", (e) => { console.log("[uncaught]", e?.code || "", e?.message || e); });
process.on("unhandledRejection", (e) => { console.log("[unhandled]", e?.code || "", e?.message || e); });

class UserError extends Error {}

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const a = p[0], b = p[1];
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}
function isPrivateIP(ip) {
  const v = net.isIP(ip);
  if (v === 4) return isPrivateIPv4(ip);
  if (v === 6) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return true;
    if (l.indexOf("::ffff:") === 0) {
      const rest = l.slice(7);
      if (net.isIP(rest) === 4) return isPrivateIPv4(rest);
      return true;
    }
    return l.indexOf("fc") === 0 || l.indexOf("fd") === 0 || /^fe[89ab]/.test(l);
  }
  return true;
}

async function resolveHost(host) {
  if (net.isIP(host)) {
    if (!ALLOW_PRIVATE && isPrivateIP(host)) throw new UserError("اتصال به آدرس‌های داخلی/خصوصی مجاز نیست.");
    return host;
  }
  let timer;
  const addrs = await Promise.race([
    lookup(host, { all: true }),
    new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("dns timeout"), { code: "ETIMEDOUT" })), 8000); }),
  ]).finally(() => clearTimeout(timer));
  if (!addrs || !addrs.length) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const ok = addrs.filter((a) => ALLOW_PRIVATE || !isPrivateIP(a.address));
  if (!ok.length) throw new UserError("اتصال به آدرس‌های داخلی/خصوصی مجاز نیست.");
  const v4 = ok.find((a) => net.isIP(a.address) === 4);
  return (v4 || ok[0]).address;
}

function explainError(err) {
  const m = String(err?.message || "");
  const c = err?.code;
  if (err instanceof UserError) return m;
  if (err?.level === "client-authentication" || /All configured authentication methods failed/i.test(m))
    return "ورود ناموفق بود: نام کاربری، رمز عبور یا کلید اشتباه است.";
  if (/privateKey|passphrase|Unsupported key|key format|Cannot parse/i.test(m))
    return "کلید خصوصی نامعتبره یا رمز کلید (passphrase) اشتباهه.";
  if (/operation is not supported|Unsupported algorithm/i.test(m))
    return "الگوریتم رمزنگاری SSH پشتیبانی نشد؛ سرور مقصد الگوریتم ناسازگار دارد.";
  if (c === "ECONNREFUSED") return "سرور اتصال رو رد کرد؛ پورت اشتباهه یا سرویس SSH روشن نیست.";
  if (c === "ENOTFOUND" || c === "EAI_AGAIN") return "آدرس سرور پیدا نشد؛ Host رو دوباره چک کن.";
  if (c === "ETIMEDOUT" || /Timed out/i.test(m)) return "زمان اتصال تموم شد؛ سرور در دسترس نیست یا فایروال پورت رو بسته.";
  if (c === "EHOSTUNREACH" || c === "ENETUNREACH") return "مسیر شبکه تا سرور در دسترس نیست.";
  if (c === "ECONNRESET") return "اتصال توسط سرور قطع شد.";
  if (/handshake|Protocol|banner/i.test(m)) return "هندشیک SSH ناموفق بود.";
  return "خطا در اتصال: " + (m || "نامشخص");
}

const attempts = new Map();
function allowAttempt(ip) {
  const now = Date.now();
  if (attempts.size > 2000) {
    for (const [k, v] of attempts) if (!v.some((t) => now - t < 60000)) attempts.delete(k);
  }
  const arr = (attempts.get(ip) || []).filter((t) => now - t < 60000);
  if (arr.length >= ATTEMPTS_PER_MIN) { attempts.set(ip, arr); return false; }
  arr.push(now);
  attempts.set(ip, arr);
  return true;
}

function sendJson(ws, obj) { try { ws.send(JSON.stringify(obj)); } catch {} }
function clampInt(v, min, max, def) {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
}

function parsePortsPayload(body) {
  const set = new Set();
  if (Array.isArray(body.ports)) {
    for (const v of body.ports) {
      const n = Math.floor(Number(v));
      if (n >= 1 && n <= 65535) set.add(n);
    }
  }
  if (body.from != null && body.to != null) {
    let a = Math.floor(Number(body.from));
    let b = Math.floor(Number(body.to));
    if (Number.isFinite(a) && Number.isFinite(b)) {
      if (a > b) [a, b] = [b, a];
      a = Math.max(1, a);
      b = Math.min(65535, b);
      for (let p = a; p <= b; p++) set.add(p);
    }
  }
  const list = Array.from(set).sort((x, y) => x - y);
  if (list.length > MAX_SCAN_PORTS) throw new UserError(`حداکثر ${MAX_SCAN_PORTS} پورت در هر اسکن مجاز است.`);
  if (!list.length) throw new UserError("هیچ پورت معتبری انتخاب نشده.");
  return list;
}

let sessions = 0;

async function handleAuth(ws, msg) {
  const d = ws._d;
  if (d.state !== "idle") return;
  d.state = "connecting";

  let killTimer = null;
  const fail = (text, raw) => {
    if (d.state === "failed" || d.state === "closed") return;
    d.state = "failed";
    if (killTimer) clearTimeout(killTimer);
    d.killTimer = null;
    console.log("[ssh] fail:", raw?.code || raw?.level || "", String(raw?.message || text).slice(0, 200));
    sendJson(ws, { t: "error", m: text });
    try { d.conn?.end(); } catch {}
    setTimeout(() => { try { ws.close(); } catch {} }, 80);
  };

  try {
    if (!allowAttempt(d.ip)) return fail("تعداد تلاش‌ها زیاده؛ یک دقیقه صبر کن و دوباره امتحان کن.");
    if (ACCESS_KEY && msg.key !== ACCESS_KEY) return fail("کلید دسترسی اشتباهه.");

    const host = String(msg.host || "").trim().replace(/^\[|\]$/g, "");
    const username = String(msg.username || "").trim();
    const port = clampInt(msg.port, 1, 65535, 22);
    const password = typeof msg.password === "string" ? msg.password.slice(0, 1024) : "";
    const privateKey = typeof msg.privateKey === "string" ? msg.privateKey.slice(0, 20000) : "";
    const passphrase = typeof msg.passphrase === "string" ? msg.passphrase.slice(0, 1024) : "";
    d.cols = clampInt(msg.cols, 10, 500, 80);
    d.rows = clampInt(msg.rows, 4, 300, 24);

    if (!host || host.length > 253 || !/^[A-Za-z0-9.:_-]+$/.test(host)) return fail("آدرس سرور نامعتبره.");
    if (!username || username.length > 128) return fail("نام کاربری نامعتبره.");
    if (!password && !privateKey) return fail("رمز عبور یا کلید خصوصی لازمه.");

    sendJson(ws, { t: "stage", s: "dns" });
    const ip = await resolveHost(host);
    if (d.state !== "connecting") return;

    sendJson(ws, { t: "stage", s: "tcp" });
    console.log("[ssh] connect", host, "->", ip, "port", port);

    const conn = new Client();
    d.conn = conn;

    killTimer = setTimeout(() => { if (d.state === "connecting") fail("زمان اتصال تموم شد."); }, 40000);
    d.killTimer = killTimer;

    conn.on("handshake", () => { sendJson(ws, { t: "stage", s: "auth" }); });

    conn.on("keyboard-interactive", (_n, _i, _l, prompts, finish) => {
      finish((prompts || []).map(() => password));
    });

    conn.on("ready", () => {
      if (d.state !== "connecting") { try { conn.end(); } catch {} return; }
      sendJson(ws, { t: "stage", s: "shell" });
      conn.shell({ term: "xterm-256color", cols: d.cols, rows: d.rows }, (err, stream) => {
        if (err) return fail(explainError(err), err);
        if (d.state !== "connecting") { try { stream.close(); conn.end(); } catch {} return; }
        d.stream = stream;
        d.state = "ready";
        if (killTimer) clearTimeout(killTimer);
        d.killTimer = null;
        sendJson(ws, { t: "ready" });
        stream.on("data", (buf) => { try { ws.send(buf); } catch {} });
        if (stream.stderr) stream.stderr.on("data", (buf) => { try { ws.send(buf); } catch {} });
        stream.on("close", () => {
          if (d.state === "ready") {
            d.state = "closed";
            sendJson(ws, { t: "closed", m: "نشست SSH بسته شد." });
            try { conn.end(); } catch {}
            setTimeout(() => { try { ws.close(); } catch {} }, 80);
          }
        });
      });
    });

    conn.on("error", (err) => {
      if (d.state === "ready") {
        d.state = "closed";
        sendJson(ws, { t: "closed", m: explainError(err) });
        setTimeout(() => { try { ws.close(); } catch {} }, 80);
      } else {
        fail(explainError(err), err);
      }
    });

    conn.on("close", () => {
      if (d.state === "ready") {
        d.state = "closed";
        sendJson(ws, { t: "closed", m: "اتصال با سرور قطع شد." });
        setTimeout(() => { try { ws.close(); } catch {} }, 80);
      } else if (d.state === "connecting") {
        fail("اتصال بسته شد قبل از اینکه ورود کامل بشه.");
      }
    });

    // Full default algorithms on Node — no Bun crypto limits
    conn.connect({
      host: ip,
      port,
      username,
      password: password || undefined,
      privateKey: privateKey ? privateKey.split("\r\n").join("\n").trim() + "\n" : undefined,
      passphrase: passphrase || undefined,
      tryKeyboard: !!password,
      readyTimeout: 20000,
      keepaliveInterval: 15000,
      keepaliveCountMax: 4,
      algorithms: {
        cipher: { remove: ["chacha20-poly1305@openssh.com"] },
      },
    });
  } catch (e) {
    fail(explainError(e), e);
  }
}

const vendorMime = {
  "/vendor/xterm.js": "application/javascript; charset=utf-8",
  "/vendor/xterm.css": "text/css; charset=utf-8",
  "/vendor/fit.js": "application/javascript; charset=utf-8",
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const p = url.pathname;

  if (p === "/api/scan" && req.method === "POST") {
    try {
      const raw = await readBody(req);
      const body = JSON.parse(raw.toString("utf8") || "{}");
      const host = String(body.host || "").trim().replace(/^\[|\]$/g, "");
      if (!host || host.length > 253 || !/^[A-Za-z0-9.:_-]+$/.test(host)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "آدرس سرور نامعتبره." }));
        return;
      }
      const ports = parsePortsPayload(body);
      const ip = await resolveHost(host);
      console.log("[scan]", host, "->", ip, "ports", ports.length);
      const results = await scanPorts(ip, ports);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        ok: true,
        host,
        ip,
        results,
        open: results.filter((r) => r.open).map((r) => r.port),
      }));
    } catch (e) {
      const msg = e instanceof UserError ? e.message : explainError(e);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: msg }));
    }
    return;
  }

  if (p === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }
  if (p === "/favicon.ico") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (Object.prototype.hasOwnProperty.call(vendorMime, p)) {
    const filePath = path.join(__dirname, p.slice(1));
    try {
      const data = fs.readFileSync(filePath);
      res.writeHead(200, { "Content-Type": vendorMime[p], "Cache-Control": "public, max-age=86400" });
      res.end(data);
    } catch {
      res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("Library unavailable");
    }
    return;
  }

  if (p === "/" || p === "/index.html") {
    try {
      let html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
      html = html.replace('"false" === "true"', ACCESS_KEY ? '"true" === "true"' : '"false" === "true"');
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      });
      res.end(html);
    } catch {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("index.html missing");
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  if (sessions >= MAX_SESSIONS) {
    ws.close(1013, "Server busy");
    return;
  }
  sessions++;
  const ip =
    (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown";
  ws._d = { ip, state: "idle", conn: null, stream: null, killTimer: null, cols: 80, rows: 24 };

  ws.on("message", (message) => {
    const d = ws._d;
    let msg;
    try {
      msg = JSON.parse(typeof message === "string" ? message : Buffer.from(message).toString("utf8"));
    } catch { return; }
    if (!msg || typeof msg !== "object") return;
    switch (msg.t) {
      case "auth": handleAuth(ws, msg); break;
      case "in":
        if (d.state === "ready" && d.stream && typeof msg.d === "string") {
          try { d.stream.write(msg.d); } catch {}
        }
        break;
      case "resize":
        if (d.state === "ready" && d.stream) {
          const cols = clampInt(msg.cols, 10, 500, d.cols);
          const rows = clampInt(msg.rows, 4, 300, d.rows);
          d.cols = cols; d.rows = rows;
          try { d.stream.setWindow(rows, cols, 0, 0); } catch {}
        }
        break;
      case "ping": sendJson(ws, { t: "pong", ts: typeof msg.ts === "number" ? msg.ts : 0 }); break;
    }
  });

  ws.on("close", () => {
    sessions = Math.max(0, sessions - 1);
    const d = ws._d;
    if (!d) return;
    d.state = "closed";
    if (d.killTimer) { clearTimeout(d.killTimer); d.killTimer = null; }
    try { d.stream?.end(); } catch {}
    try { d.conn?.end(); } catch {}
  });
});

server.listen(PORT, HOST, () => {
  console.log("SSH web terminal running on port", PORT);
});
