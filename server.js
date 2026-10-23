"use strict";
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = +process.env.PORT || 3000, TZ = process.env.TZ_NAME || "Europe/Warsaw";
const FILE = process.env.DATA_FILE || path.join(__dirname, "data", "db.json");
const DC = { id: process.env.DISCORD_CLIENT_ID, secret: process.env.DISCORD_CLIENT_SECRET, redirect: process.env.DISCORD_REDIRECT_URI };
const SECURE = process.env.COOKIE_SECURE === "1";
const POS = ["Разработчик", "Главный следящий", "Зам. главного следящего", "Следящий МЗ"], MGR = POS.slice(0, 3);
const COLS = ["users", "vac", "warn", "reports", "arch", "tasks"], DATE = /^\d{4}-\d\d-\d\d$/;

let db = { users: [], vac: [], warn: [], reports: [], arch: [], tasks: [], sessions: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, "utf8"))); } catch (e) {}
fs.mkdirSync(path.dirname(FILE), { recursive: true });
const persist = () => { const t = FILE + ".tmp"; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, FILE); };

const uid = () => crypto.randomBytes(5).toString("hex");
const str = (v, n = 500) => (typeof v === "string" ? v.slice(0, n) : "");
const today = () => new Date().toLocaleDateString("sv", { timeZone: TZ });
const hash = p => { const s = crypto.randomBytes(16).toString("hex"); return s + ":" + crypto.scryptSync(String(p), s, 64).toString("hex"); };
const check = (p, h) => { const [s, k] = String(h).split(":"); if (!k) return false; const a = crypto.scryptSync(String(p), s, 64), b = Buffer.from(k, "hex"); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const isDev = u => u.pos.includes("Разработчик"), isMgr = u => MGR.some(p => u.pos.includes(p));
const canTouch = (a, t) => isMgr(a) && (!isDev(t) || isDev(a));
const byId = (c, id) => db[c].find(x => x.id === id);

const cookies = r => Object.fromEntries((r.headers.cookie || "").split(";").map(c => c.trim().split("=")).filter(c => c[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join("="))]));
const setCookie = (res, k, v, age) => res.setHeader("Set-Cookie", [].concat(res.getHeader("Set-Cookie") || [], `${k}=${encodeURIComponent(v)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${SECURE ? "; Secure" : ""}`));
function startSession(res, u) { const t = crypto.randomBytes(32).toString("hex"); db.sessions[t] = { uid: u.id, exp: Date.now() + 30 * 864e5 }; persist(); setCookie(res, "sid", t, 30 * 86400); }
function authed(req) { const s = db.sessions[cookies(req).sid]; return s && s.exp > Date.now() ? db.users.find(u => u.id === s.uid) || null : null; }
const tries = {};
function limited(req) { const ip = (req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket.remoteAddress, n = Date.now(); const a = (tries[ip] = (tries[ip] || []).filter(t => n - t < 3e5)); a.push(n); return a.length > 10; }
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
const body = req => new Promise(r => { let d = ""; req.on("data", c => { d += c; if (d.length > 1e6) req.destroy(); }); req.on("end", () => { try { r(JSON.parse(d || "{}")); } catch (e) { r({}); } }); });

function stateFor(a) {
  const m = isMgr(a);
  return {
    me: a.id,
    users: db.users.map(({ hash, ...u }) => (m ? u : { ...u, note: "" })),
    vac: db.vac, warn: db.warn,
    reports: m ? db.reports : db.reports.filter(r => r.uid === a.id),
    arch: m ? db.arch : [],
    tasks: m ? db.tasks : db.tasks.filter(t => t.to === "all" || t.to === a.id).map(t => ({ ...t, subs: t.subs.filter(s => s.uid === a.id) }))
  };
}

function applyOp(a, op) {
  const { c, id, data } = op || {};
  if (!COLS.includes(c) || !/^[a-z0-9]{4,16}$/.test(id || "")) return "bad";
  const m = isMgr(a), cur = byId(c, id), now = Date.now();
  if (op.op === "delete") {
    if (!cur || !m) return "no";
    if (c === "users") { if (id === a.id || !canTouch(a, cur)) return "no"; db.users = db.users.filter(x => x.id !== id); return; }
    if (c === "tasks" || c === "vac" || c === "warn") { db[c] = db[c].filter(x => x.id !== id); return; }
    return "no";
  }
  if (!data || typeof data !== "object") return "bad";
  switch (c) {
    case "users": {
      if (!m) return "no";
      const nick = str(data.nick, 32).trim(); if (!nick) return "bad";
      if (db.users.some(x => x.id !== id && x.nick.toLowerCase() === nick.toLowerCase())) return "dup";
      const pos = (Array.isArray(data.pos) ? data.pos : []).filter(p => POS.includes(p));
      if (pos.includes("Разработчик") && !isDev(a) && !(cur && isDev(cur))) return "no";
      if (cur && !canTouch(a, cur)) return "no";
      const f = { nick, prefix: str(data.prefix, 64) || nick, forum: str(data.forum), date: str(data.date, 10), discord: str(data.discord, 32), note: str(data.note, 2000), pos };
      if (cur) Object.assign(cur, f); else db.users.push({ id, created: now, hash: hash(nick), ...f });
      return;
    }
    case "vac": case "warn": {
      if (!m) return "no";
      if (!cur) {
        const t = byId("users", str(data.uid, 20)); if (!t || !canTouch(a, t)) return "no";
        const b = { id, uid: t.id, nick: t.nick, date: now, by: a.id, byn: a.nick };
        if (c === "vac") { const f = str(data.from, 10), to = str(data.to, 10); if (!DATE.test(f) || !DATE.test(to) || to < f) return "bad"; Object.assign(b, { from: f, to, reason: str(data.reason, 300) }); }
        else { const r = str(data.reason, 300).trim(); if (!r) return "bad"; b.reason = r; }
        db[c].push(b); return;
      }
      if (c === "vac" && data.cancel && !cur.cancel) Object.assign(cur, { cancel: true, cby: a.id, cbyn: a.nick, cdate: now });
      else if (c === "warn" && data.removed && !cur.removed) Object.assign(cur, { removed: true, rby: a.id, rbyn: a.nick, rdate: now });
      return;
    }
    case "arch": {
      if (!m || cur) return "no";
      db.arch.push({ id, nick: str(data.nick, 32), vk: str(data.vk, 200), discord: str(data.discord, 32), forum: str(data.forum), reason: str(data.reason), period: str(data.period, 100), sl: str(data.sl, 100), date: str(data.date, 10), by: a.id, byn: a.nick });
      return;
    }
    case "reports": {
      if (!cur) { db.reports.push({ id, uid: a.id, rdate: str(data.rdate, 10), link: str(data.link), text: str(data.text, 2000), st: "new", date: now }); return; }
      if (!m || cur.st !== "new" || !["ok", "no"].includes(data.st)) return "no";
      Object.assign(cur, { st: data.st, by: a.id, byn: a.nick, ddate: now, reason: str(data.reason, 300) });
      return;
    }
    case "tasks": {
      if (cur && Array.isArray(data.subs) && data.subs.length === cur.subs.length + 1) {
        const l = data.subs[data.subs.length - 1];
        if (cur.closed || !(cur.to === "all" || cur.to === a.id) || String(cur.due).slice(0, 10) !== today() || cur.subs.some(x => x.uid === a.id)) return "no";
        cur.subs.push({ uid: a.id, nick: a.nick, text: str(l && l.text, 1000), date: now }); return;
      }
      if (!m) return "no";
      const due = str(data.due, 10), title = str(data.title, 120).trim(); if (!title || !DATE.test(due)) return "bad";
      const f = { title, desc: str(data.desc, 3000), due, to: data.to === "all" || byId("users", data.to) ? data.to : "all" };
      if (cur) Object.assign(cur, f, { closed: !!data.closed }); else db.tasks.push({ id, ...f, subs: [], by: a.id, byn: a.nick, created: now, closed: false });
      return;
    }
  }
  return "bad";
}

http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, "http://x").pathname, POST = req.method === "POST";
    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff" });
      return res.end(fs.readFileSync(path.join(__dirname, "public", "index.html")));
    }
    if (p === "/api/status") return send(res, 200, { users: db.users.length, discord: !!DC.id });
    if (p === "/api/setup" && POST) {
      if (db.users.length) return send(res, 403, { error: "Система уже настроена" });
      const b = await body(req), nick = str(b.nick, 32).trim();
      if (!nick || str(b.password, 200).length < 4) return send(res, 400, { error: "Укажите ник и пароль от 4 символов" });
      const u = { id: uid(), nick, prefix: nick, pos: ["Разработчик"], forum: "", date: today(), discord: str(b.discord, 32), note: "", created: Date.now(), hash: hash(b.password) };
      db.users.push(u); startSession(res, u); persist(); return send(res, 200, { ok: 1 });
    }
    if (p === "/api/login" && POST) {
      if (limited(req)) return send(res, 429, { error: "Слишком много попыток, подождите 5 минут" });
      const b = await body(req);
      const u = b.discord ? db.users.find(x => x.discord && x.discord === str(b.discord, 32)) : db.users.find(x => x.nick.toLowerCase() === str(b.nick, 32).trim().toLowerCase());
      if (!u || !check(b.password || "", u.hash)) return send(res, 401, { error: "Неверные данные для входа" });
      startSession(res, u); return send(res, 200, { ok: 1 });
    }
    if (p === "/api/logout" && POST) { delete db.sessions[cookies(req).sid]; persist(); setCookie(res, "sid", "", 0); return send(res, 200, { ok: 1 }); }
    if (p === "/auth/discord") {
      if (!DC.id) { res.writeHead(302, { Location: "/?err=" + encodeURIComponent("Вход через Discord не настроен") }); return res.end(); }
      const st = crypto.randomBytes(16).toString("hex"); setCookie(res, "dstate", st, 600);
      res.writeHead(302, { Location: "https://discord.com/oauth2/authorize?" + new URLSearchParams({ client_id: DC.id, redirect_uri: DC.redirect, response_type: "code", scope: "identify", state: st }) });
      return res.end();
    }
    if (p === "/auth/discord/callback") {
      const q = new URL(req.url, "http://x").searchParams, fail = m => { res.writeHead(302, { Location: "/?err=" + encodeURIComponent(m) }); res.end(); };
      if (!q.get("code") || q.get("state") !== cookies(req).dstate) return fail("Ошибка входа через Discord");
      const t = await (await fetch("https://discord.com/api/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: DC.id, client_secret: DC.secret, grant_type: "authorization_code", code: q.get("code"), redirect_uri: DC.redirect }) })).json();
      if (!t.access_token) return fail("Ошибка входа через Discord");
      const d = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + t.access_token } })).json();
      const u = db.users.find(x => x.discord && x.discord === d.id);
      if (!u) return fail("Ваш Discord ID не привязан ни к одному пользователю");
      startSession(res, u); res.writeHead(302, { Location: "/" }); return res.end();
    }
    if (p.startsWith("/api/")) {
      const a = authed(req); if (!a) return send(res, 401, { error: "auth" });
      if (p === "/api/state") return send(res, 200, stateFor(a));
      if (p === "/api/password" && POST) { const b = await body(req); if (str(b.password, 200).length < 4) return send(res, 400, { error: "Пароль от 4 символов" }); a.hash = hash(b.password); persist(); return send(res, 200, { ok: 1 }); }
      if (p === "/api/sync" && POST) {
        const b = await body(req), ops = Array.isArray(b.ops) ? b.ops.slice(0, 200) : []; let rejected = 0;
        for (const op of ops) { try { if (applyOp(a, op)) rejected++; } catch (e) { rejected++; } }
        persist(); return send(res, 200, { rejected });
      }
    }
    send(res, 404, { error: "not found" });
  } catch (e) { console.error(e); send(res, 500, { error: "Ошибка сервера" }); }
}).listen(PORT, () => console.log("Панель запущена: http://localhost:" + PORT));
