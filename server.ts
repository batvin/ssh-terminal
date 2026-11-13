import { Client } from "ssh2";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { scanPorts } from "./scan";

const PORT = Number(Bun.env.PORT) || 8080;
const MAX_SESSIONS = 30;
const ATTEMPTS_PER_MIN = 8;
const ACCESS_KEY = Bun.env.ACCESS_KEY || "";
const ALLOW_PRIVATE = Bun.env.ALLOW_PRIVATE === "1";
const MAX_SCAN_PORTS = 65535;

process.on("uncaughtException", (e: any) => { console.log("[uncaught]", e?.code || "", e?.message || e); });
process.on("unhandledRejection", (e: any) => { console.log("[unhandled]", e?.code || "", e?.message || e); });

class UserError extends Error {}

function isPrivateIPv4(ip: string): boolean {
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
function isPrivateIP(ip: string): boolean {
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

async function resolveHost(host: string): Promise<string> {
  if (net.isIP(host)) {
    if (!ALLOW_PRIVATE && isPrivateIP(host)) throw new UserError("اتصال به آدرس‌های داخلی/خصوصی مجاز نیست.");
    return host;
  }
  let timer: any;
  const addrs: any = await Promise.race([
    lookup(host, { all: true }),
    new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("dns timeout"), { code: "ETIMEDOUT" })), 8000); }),
  ]).finally(() => clearTimeout(timer));
  if (!addrs || !addrs.length) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const ok = addrs.filter((a: any) => ALLOW_PRIVATE || !isPrivateIP(a.address));
  if (!ok.length) throw new UserError("اتصال به آدرس‌های داخلی/خصوصی مجاز نیست.");
  const v4 = ok.find((a: any) => net.isIP(a.address) === 4);
  return (v4 || ok[0]).address;
}

function explainError(err: any): string {
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

const attempts = new Map<string, number[]>();
function allowAttempt(ip: string): boolean {
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

function sendJson(ws: any, obj: any) { try { ws.send(JSON.stringify(obj)); } catch {} }
function clampInt(v: any, min: number, max: number, def: number): number {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
}

function parsePortsPayload(body: any): number[] {
  const set = new Set<number>();
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

// Safe algorithms for Bun crypto (no curve25519 / ed25519)
const SSH_ALGORITHMS = {
  kex: [
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha256",
  ],
  cipher: [
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm",
    "hannah.h@example.com",
    "aes256-gcm",
    "uma.s@example.org",
  ],
  serverHostKey: [
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
  ],
  hmac: [
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
  ],
};

async function handleAuth(ws: any, msg: any) {
  const d = ws.data;
  if (d.state !== "idle") return;
  d.state = "connecting";

  let killTimer: any = null;
  const fail = (text: string, raw?: any) => {
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

    conn.on("keyboard-interactive", (_n: any, _i: any, _l: any, prompts: any[], finish: any) => {
      finish((prompts || []).map(() => password));
    });

    conn.on("ready", () => {
      if (d.state !== "connecting") { try { conn.end(); } catch {} return; }
      sendJson(ws, { t: "stage", s: "shell" });
      conn.shell({ term: "xterm-256color", cols: d.cols, rows: d.rows }, (err: any, stream: any) => {
        if (err) return fail(explainError(err), err);
        if (d.state !== "connecting") { try { stream.close(); conn.end(); } catch {} return; }
        d.stream = stream;
        d.state = "ready";
        if (killTimer) clearTimeout(killTimer);
        d.killTimer = null;
        sendJson(ws, { t: "ready" });
        stream.on("data", (buf: Buffer) => { try { ws.send(buf); } catch {} });
        if (stream.stderr) stream.stderr.on("data", (buf: Buffer) => { try { ws.send(buf); } catch {} });
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

    conn.on("error", (err: any) => {
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
      algorithms: SSH_ALGORITHMS,
    });
  } catch (e: any) {
    fail(explainError(e), e);
  }
}

const vendorFiles: Record<string, [string, string]> = {
  "/vendor/xterm.js": ["./vendor/xterm.js", "application/javascript; charset=utf-8"],
  "/vendor/xterm.css": ["./vendor/xterm.css", "text/css; charset=utf-8"],
  "/vendor/fit.js": ["./vendor/fit.js", "application/javascript; charset=utf-8"],
};

const htmlHeaders = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

const server = Bun.serve({
  port: PORT,
  idleTimeout: 255,
  hostname: Bun.env.HOST || "0.0.0.0",
  async fetch(req: Request, server: any) {
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === "/ws") {
      if (sessions >= MAX_SESSIONS) return new Response("Server busy", { status: 503 });
      const ip =
        (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
        req.headers.get("x-real-ip") ||
        server.requestIP(req)?.address ||
        "unknown";
      const ok = server.upgrade(req, {
        data: { ip, state: "idle", conn: null, stream: null, killTimer: null, cols: 80, rows: 24 },
      });
      if (ok) return undefined as any;
      return new Response("WebSocket upgrade failed", { status: 400 });
    }

    if (p === "/api/scan" && req.method === "POST") {
      try {
        const body = await req.json();
        const host = String(body.host || "").trim().replace(/^\[|\]$/g, "");
        if (!host || host.length > 253 || !/^[A-Za-z0-9.:_-]+$/.test(host)) {
          return Response.json({ ok: false, error: "آدرس سرور نامعتبره." }, { status: 400 });
        }
        const ports = parsePortsPayload(body);
        const ip = await resolveHost(host);
        console.log("[scan]", host, "->", ip, "ports", ports.length);
        const results = await scanPorts(ip, ports);
        return Response.json({
          ok: true,
          host,
          ip,
          results,
          open: results.filter((r) => r.open).map((r) => r.port),
        });
      } catch (e: any) {
        const msg = e instanceof UserError ? e.message : explainError(e);
        return Response.json({ ok: false, error: msg }, { status: 400 });
      }
    }

    if (p === "/healthz") return new Response("ok");
    if (p === "/favicon.ico") return new Response(null, { status: 204 });

    if (Object.prototype.hasOwnProperty.call(vendorFiles, p)) {
      const f = Bun.file(vendorFiles[p][0]);
      if (!(await f.exists())) return new Response("Library unavailable", { status: 502 });
      return new Response(f, { headers: { "Content-Type": vendorFiles[p][1], "Cache-Control": "public, max-age=86400" } });
    }

    if (p === "/" || p === "/index.html") {
      let html = await Bun.file("./index.html").text();
      html = html.replace('"false" === "true"', ACCESS_KEY ? '"true" === "true"' : '"false" === "true"');
      return new Response(html, { headers: htmlHeaders });
    }
    return new Response("Not found", { status: 404 });
  },
  websocket: {
    idleTimeout: 120,
    maxPayloadLength: 1024 * 1024,
    open(_ws: any) { sessions++; },
    message(ws: any, message: any) {
      const d = ws.data;
      let msg: any;
      try { msg = JSON.parse(typeof message === "string" ? message : Buffer.from(message).toString("utf8")); }
      catch { return; }
      if (!msg || typeof msg !== "object") return;
      switch (msg.t) {
        case "auth": handleAuth(ws, msg); break;
        case "in":
          if (d.state === "ready" && d.stream && typeof msg.d === "string") { try { d.stream.write(msg.d); } catch {} }
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
    },
    close(ws: any) {
      sessions = Math.max(0, sessions - 1);
      const d = ws.data;
      if (!d) return;
      d.state = "closed";
      if (d.killTimer) { clearTimeout(d.killTimer); d.killTimer = null; }
      try { d.stream?.end(); } catch {}
      try { d.conn?.end(); } catch {}
    },
  },
});

console.log("SSH web terminal running on port", server.port);
