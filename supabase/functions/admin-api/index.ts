// QXNET 管理后台 BFF（Supabase Edge Function）
// 持有 service_role 调 Supabase Admin / REST；前端只持有签名会话 token，不接触 service_role。

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "https://gngcducutevgllbaejec.supabase.co";
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const ADMIN_USER = Deno.env.get("ADMIN_USER") || "admin";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") || "";
const SESSION_TTL = 100 * 365 * 24 * 60 * 60 * 1000; // 长期会话：同一设备登录后长期有效，不再定时掉线
const LOGIN_MAX_FAIL = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
};

const CARD_TYPES = ["day", "week", "month", "quarter", "lifetime"];
const RECORD_TABLES = ["messages", "chat_messages", "visits"];

// ===== 工具 =====
function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "content-type": "application/json" },
  });
}

function b64urlEncode(buf: ArrayBuffer | string): string {
  const bytes = typeof buf === "string" ? new TextEncoder().encode(buf) : new Uint8Array(buf);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): string {
  return atob(s.replace(/-/g, "+").replace(/_/g, "/"));
}

async function hmacSign(msg: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64urlEncode(sig);
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function verifyToken(token: string | null): Promise<boolean> {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [body, sig] = parts;
  const expected = await hmacSign(body, ADMIN_PASSWORD);
  if (!safeEqual(sig, expected)) return false;
  try {
    const payload = JSON.parse(b64urlDecode(body));
    return typeof payload.exp === "number" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

function timingEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for") || "";
  const first = xff.split(",")[0]?.trim();
  return first || req.headers.get("x-real-ip") || "unknown";
}

function ip4ToNum(ip: string): number {
  return ip.split(".").reduce((acc, p) => ((acc << 8) + Number(p)) >>> 0, 0);
}
function ip6Expand(ip: string): string {
  const parts = ip.split(":");
  const idx = parts.indexOf("");
  if (idx >= 0) {
    const fill = 8 - (parts.length - 1);
    parts.splice(idx, 1, ...Array(fill).fill("0"));
  }
  return parts.map((p) => p.padStart(4, "0")).join("");
}
// 白名单条目支持精确 IP 或 CIDR（如 113.12.105.122/32、240e:350:1784:a00::/64）
function ipInList(ip: string, list: string[]): boolean {
  const isV6 = ip.includes(":");
  for (const entry of list) {
    const [base, prefixStr] = entry.split("/");
    if (!prefixStr) { if (base === ip) return true; continue; }
    if (base.includes(":") !== isV6) continue;
    const prefix = Number(prefixStr);
    if (isV6) {
      const a = BigInt("0x" + ip6Expand(ip));
      const b = BigInt("0x" + ip6Expand(base));
      const bits = BigInt(prefix);
      const mask = bits >= 128n ? (1n << 128n) - 1n : (((1n << 128n) - 1n) << (128n - bits));
      if ((a & mask) === (b & mask)) return true;
    } else {
      const a = ip4ToNum(ip), b = ip4ToNum(base);
      const mask = prefix >= 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1)) >>> 0;
      if ((a & mask) === (b & mask)) return true;
    }
  }
  return false;
}

// ===== Supabase 服务端调用 =====
async function sbFetch(path: string, options: RequestInit = {}) {
  const headers: Record<string, string> = {
    apikey: SERVICE_ROLE,
    Authorization: `Bearer ${SERVICE_ROLE}`,
    "content-type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };
  const r = await fetch(SUPABASE_URL + path, { ...options, headers });
  const text = await r.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: r.status, body };
}

function normalizeUser(u: Record<string, unknown>) {
  const meta = (u.user_metadata || {}) as Record<string, unknown>;
  const expiresAt = meta.expires_at ? new Date(String(meta.expires_at)) : null;
  const now = new Date();
  let status = "active";
  if (u.banned_until) status = "banned";
  else if (expiresAt && expiresAt < now) status = "expired";
  return {
    id: u.id,
    email: u.email || "",
    created_at: u.created_at || "",
    last_sign_in_at: u.last_sign_in_at || "",
    email_confirmed: !!u.email_confirmed_at,
    banned_until: u.banned_until || null,
    deleted_at: u.deleted_at || null,
    card_key: meta.card_key || "",
    expires_at: meta.expires_at || "",
    device_id: meta.device_id || "",
    status,
  };
}

// ===== 路由处理 =====
async function handle(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  const url = new URL(req.url);
  // 网关两种前缀都剥离：/functions/v1/admin-api/... 或 /admin-api/...
  let path = url.pathname
    .replace(/^\/functions\/v1\/admin-api/, "")
    .replace(/^\/admin-api/, "");
  if (!path.startsWith("/")) path = "/" + path;
  if (path === "") path = "/";
  const method = req.method;

  const readBody = async (): Promise<Record<string, unknown>> => {
    const t = await req.text();
    return t ? JSON.parse(t) : {};
  };

  // 登录（无需鉴权）
  if (method === "POST" && path === "/login") {
    if (!ADMIN_PASSWORD) return json({ code: -1, msg: "后台未配置管理员密码" }, 503);
    const body = await readBody();
    const user = String(body.user || "");
    const password = String(body.password || "");
    if (!user || !password) return json({ code: -1, msg: "账号和密码不能为空" });

    const ip = clientIp(req);
    const nowIso = new Date().toISOString();

    // 可选 IP 白名单：Secret ADMIN_IP_ALLOWLIST 逗号分隔，留空不限制
    const allowList = (Deno.env.get("ADMIN_IP_ALLOWLIST") || "").split(",").map((s) => s.trim()).filter(Boolean);
    if (allowList.length > 0 && !ipInList(ip, allowList)) {
      return json({ code: -1, msg: "当前网络环境无权登录" });
    }

    // 读取该 IP 的登录记录（失败计数 / 锁定状态）
    const encIp = encodeURIComponent(ip);
    const { body: lb } = await sbFetch(`/rest/v1/admin_login_log?ip=eq.${encIp}&select=*`);
    const rec = Array.isArray(lb) && lb.length > 0 ? (lb[0] as Record<string, unknown>) : null;
    const lockedUntil = rec && rec.locked_until ? new Date(String(rec.locked_until)).getTime() : 0;
    if (lockedUntil > Date.now()) {
      const mins = Math.ceil((lockedUntil - Date.now()) / 60000);
      return json({ code: -1, msg: `失败次数过多，请 ${mins} 分钟后再试` });
    }

    const ok = timingEqual(user, ADMIN_USER) && timingEqual(password, ADMIN_PASSWORD);
    if (!ok) {
      const failCount = ((rec && Number(rec.fail_count)) || 0) + 1;
      const locked = failCount >= LOGIN_MAX_FAIL;
      const lockUntil = locked ? new Date(Date.now() + LOGIN_LOCK_MS).toISOString() : null;
      const row = {
        ip,
        fail_count: failCount,
        locked_until: lockUntil,
        last_user: user,
        last_fail_at: nowIso,
        last_success_at: rec?.last_success_at || null,
        updated_at: nowIso,
      };
      await sbFetch(`/rest/v1/admin_login_log?ip=eq.${encIp}`, {
        method: rec ? "PATCH" : "POST",
        body: JSON.stringify(rec ? row : [row]),
      });
      if (locked) return json({ code: -1, msg: `连续失败 ${LOGIN_MAX_FAIL} 次，账号已锁定 15 分钟` });
      const left = LOGIN_MAX_FAIL - failCount;
      return json({ code: -1, msg: `账号或密码错误（还可尝试 ${left} 次）` });
    }

    // 登录成功：清零失败计数与锁定时间，记录成功时间
    const successRow = {
      ip,
      fail_count: 0,
      locked_until: null,
      last_user: user,
      last_success_at: nowIso,
      last_fail_at: rec?.last_fail_at || null,
      updated_at: nowIso,
    };
    await sbFetch(`/rest/v1/admin_login_log?ip=eq.${encIp}`, {
      method: rec ? "PATCH" : "POST",
      body: JSON.stringify(rec ? successRow : [successRow]),
    });

    const token = await issueTokenAsync();
    return json({ code: 0, msg: "登录成功", data: { token } });
  }

  // 以下接口全部鉴权
  const auth = req.headers.get("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!(await verifyToken(token))) {
    return json({ code: -1, msg: "未登录或会话已过期" }, 401);
  }

  if (method === "GET" && path === "/me") {
    return json({ code: 0, data: { user: ADMIN_USER } });
  }

  // 登录审计记录
  if (method === "GET" && path === "/login-log") {
    const { status, body } = await sbFetch("/rest/v1/admin_login_log?select=*&order=updated_at.desc&limit=50");
    if (status !== 200) return json({ code: -1, msg: "获取登录记录失败" }, 500);
    return json({ code: 0, data: body || [] });
  }

  if (method === "POST" && path === "/logout") {
    return json({ code: 0, msg: "已退出" });
  }

  // 用户列表
  if (method === "GET" && path === "/users") {
    const { status, body } = await sbFetch("/auth/v1/admin/users?per_page=500");
    if (status !== 200) return json({ code: -1, msg: "获取用户失败" }, 500);
    let users = ((body as Record<string, { users: unknown[] }>).users || []).map(normalizeUser).filter((u) => !u.deleted_at);
    const search = (url.searchParams.get("search") || "").trim().toLowerCase();
    if (search) {
      users = users.filter(
        (u) =>
          u.email.toLowerCase().includes(search) ||
          String(u.card_key).toLowerCase().includes(search) ||
          String(u.device_id).toLowerCase().includes(search)
      );
    }
    users.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    return json({ code: 0, data: users });
  }

  // 重置密码
  const resetMatch = path.match(/^\/users\/([^/]+)\/reset-password$/);
  if (method === "POST" && resetMatch) {
    const body = await readBody();
    const password = String(body.password || "");
    if (password.length < 8) return json({ code: -1, msg: "新密码需 8 位及以上" });
    const { status, body: rb } = await sbFetch(`/auth/v1/admin/users/${resetMatch[1]}`, {
      method: "PUT",
      body: JSON.stringify({ password }),
    });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "重置失败" }, 500);
    return json({ code: 0, msg: "密码已重置" });
  }

  // 封禁 / 解封（GoTrue 用 ban_duration 时长；0s 解封；banned_until 由服务端计算）
  const banMatch = path.match(/^\/users\/([^/]+)\/ban$/);
  if (method === "POST" && banMatch) {
    const body = await readBody();
    const ban = !!body.ban;
    let banDuration = "0s";
    let banLabel = "已解封";
    if (ban) {
      const d = body.duration;
      if (d === undefined || d === null || d === "" || d === "permanent") {
        banDuration = "876000h";
        banLabel = "已永久封禁";
      } else {
        const hours = Number(d);
        if (!Number.isFinite(hours) || hours < 1 || hours > 876000) return json({ code: -1, msg: "封禁时长无效（1~876000 小时）" });
        const h = Math.floor(hours);
        banDuration = `${h}h`;
        banLabel = `已封禁 ${h} 小时`;
      }
    }
    const { status } = await sbFetch(`/auth/v1/admin/users/${banMatch[1]}`, {
      method: "PUT",
      body: JSON.stringify({ ban_duration: banDuration }),
    });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "操作失败" }, 500);
    return json({ code: 0, msg: banLabel });
  }

  // 删除用户
  const delMatch = path.match(/^\/users\/([^/]+)$/);
  if (method === "DELETE" && delMatch) {
    const { status } = await sbFetch(`/auth/v1/admin/users/${delMatch[1]}`, { method: "DELETE" });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "删除失败" }, 500);
    return json({ code: 0, msg: "用户已删除" });
  }

  // 卡密列表
  if (method === "GET" && path === "/cards") {
    const { status, body } = await sbFetch("/rest/v1/cards?select=*&order=id.desc");
    if (status !== 200) return json({ code: -1, msg: "获取卡密失败" }, 500);
    const cards = (body || []) as Record<string, unknown>[];
    // 建 card_key -> 邮箱 / 到期时间映射，回显已使用卡密绑定信息
    const { body: ub } = await sbFetch("/auth/v1/admin/users?per_page=500");
    const keyToEmail = new Map<string, string>();
    const keyToExpires = new Map<string, string>();
    const users = (((ub as Record<string, { users: unknown[] }>) || {}).users || []) as Record<string, unknown>[];
    for (const u of users) {
      const m = (u.user_metadata || {}) as Record<string, unknown>;
      const k = String(m.card_key || "");
      if (k && u.email) keyToEmail.set(k, String(u.email));
      if (k && m.expires_at) keyToExpires.set(k, String(m.expires_at));
    }
    const data = cards.map((c) => {
      const persisted = String(c.bound_email || "");
      const email = persisted || keyToEmail.get(String(c.card_key || "")) || "";
      const persistedExp = String(c.expires_at || "");
      const expiresAt = persistedExp || keyToExpires.get(String(c.card_key || "")) || "";
      return { ...c, bound_email: email, expires_at: expiresAt };
    });
    return json({ code: 0, data });
  }

  // 批量生成卡密
  if (method === "POST" && path === "/cards/batch") {
    const body = await readBody();
    const type = String(body.type || "");
    const n = Math.min(Math.max(parseInt(String(body.count), 10) || 0, 1), 500);
    if (!CARD_TYPES.includes(type)) return json({ code: -1, msg: "卡密类型无效" });
    const rows = Array.from({ length: n }, () => ({
      card_key: `QXNET-${randomCode(8)}`,
      type,
      used: false,
      created_at: new Date().toISOString(),
    }));
    const { status } = await sbFetch("/rest/v1/cards", { method: "POST", body: JSON.stringify(rows) });
    if (status !== 201 && status !== 200) return json({ code: -1, msg: "生成失败" }, 500);
    return json({ code: 0, msg: `已生成 ${rows.length} 张 ${type} 卡密`, data: rows.map((r) => r.card_key) });
  }

  // 自定义卡密：手动指定卡密 + 类型，查重后入库
  if (method === "POST" && path === "/cards/custom") {
    const body = await readBody();
    const type = String(body.type || "");
    const cardKey = String(body.card_key || "").trim();
    if (!CARD_TYPES.includes(type)) return json({ code: -1, msg: "卡密类型无效" });
    if (!cardKey) return json({ code: -1, msg: "卡密不能为空" });
    const { status: qs, body: qb } = await sbFetch(`/rest/v1/cards?card_key=eq.${encodeURIComponent(cardKey)}&select=id`);
    if (qs === 200 && Array.isArray(qb) && qb.length > 0) return json({ code: -1, msg: "该卡密已存在，不能重复添加" });
    const row = { card_key: cardKey, type, used: false, created_at: new Date().toISOString() };
    const { status } = await sbFetch("/rest/v1/cards", { method: "POST", body: JSON.stringify([row]) });
    if (status !== 201 && status !== 200) return json({ code: -1, msg: "添加失败" }, 500);
    return json({ code: 0, msg: "自定义卡密已添加", data: [cardKey] });
  }

  // 作废 / 吊销卡密：未使用仅标记；已使用连带封禁用该卡注册的账号
  const revokeMatch = path.match(/^\/cards\/([^/]+)\/revoke$/);
  if (method === "POST" && revokeMatch) {
    const cardId = revokeMatch[1];
    const { status: qs, body: qb } = await sbFetch(`/rest/v1/cards?id=eq.${cardId}&select=card_key,used`);
    if (qs !== 200) return json({ code: -1, msg: "作废失败" }, 500);
    const card = (qb as Record<string, unknown>[])[0];
    const wasUsed = !!(card && card.used);
    const cardKey = card ? String(card.card_key || "") : "";

    const { status } = await sbFetch(`/rest/v1/cards?id=eq.${cardId}`, {
      method: "PATCH",
      body: JSON.stringify({ used: true }),
    });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "作废失败" }, 500);

    // 已使用：连带封禁用这张卡注册的账号
    let bannedCount = 0;
    if (wasUsed && cardKey) {
      const { status: us, body: ub } = await sbFetch("/auth/v1/admin/users?per_page=500");
      if (us === 200) {
        const users = ((ub as Record<string, { users: unknown[] }>).users || []) as Record<string, unknown>[];
        const targets = users.filter((u) => {
          const m = (u.user_metadata || {}) as Record<string, unknown>;
          return String(m.card_key || "") === cardKey;
        });
        for (const t of targets) {
          const { status: bs } = await sbFetch(`/auth/v1/admin/users/${t.id}`, {
            method: "PUT",
            body: JSON.stringify({ ban_duration: "876000h" }),
          });
          if (bs === 200 || bs === 204) bannedCount++;
        }
      }
    }

    if (!wasUsed) return json({ code: 0, msg: "卡密已作废" });
    return json({ code: 0, msg: bannedCount > 0 ? `卡密已吊销，已封禁 ${bannedCount} 个对应账号` : "卡密已吊销（未找到对应账号）" });
  }

  // 删除卡密（未使用 / 已使用均可）
  const delCardMatch = path.match(/^\/cards\/([^/]+)$/);
  if (method === "DELETE" && delCardMatch) {
    const { status } = await sbFetch(`/rest/v1/cards?id=eq.${delCardMatch[1]}`, { method: "DELETE" });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "删除失败" }, 500);
    return json({ code: 0, msg: "卡密已删除" });
  }

  // 记录查看
  if (method === "GET" && path === "/records") {
    const type = url.searchParams.get("type") || "messages";
    const table = RECORD_TABLES.includes(type) ? type : "messages";
    const orderCol = table === "visits" ? "visited_at" : "created_at";
    const { status, body } = await sbFetch(`/rest/v1/${table}?select=*&order=${orderCol}.desc&limit=200`);
    if (status !== 200) return json({ code: -1, msg: "获取记录失败" }, 500);
    return json({ code: 0, data: body || [] });
  }

  return json({ code: -1, msg: "接口不存在" }, 404);
}

async function issueTokenAsync(): Promise<string> {
  const payload = { u: ADMIN_USER, exp: Date.now() + SESSION_TTL };
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacSign(body, ADMIN_PASSWORD);
  return `${body}.${sig}`;
}

function randomCode(len: number): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  let out = "";
  for (let i = 0; i < len; i++) out += chars[buf[i] % chars.length];
  return out;
}

Deno.serve((req: Request) => handle(req));
