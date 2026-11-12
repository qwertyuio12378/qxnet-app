// QXNET 管理后台 BFF（Supabase Edge Function）
// 持有 service_role 调 Supabase Admin / REST；前端只持有签名会话 token，不接触 service_role。

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "https://gngcducutevgllbaejec.supabase.co";
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const ADMIN_USER = Deno.env.get("ADMIN_USER") || "admin";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") || "";
const SESSION_TTL = 2 * 60 * 60 * 1000;

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
    if (!timingEqual(user, ADMIN_USER) || !timingEqual(password, ADMIN_PASSWORD)) {
      return json({ code: -1, msg: "管理员账号或密码错误" });
    }
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

  if (method === "POST" && path === "/logout") {
    return json({ code: 0, msg: "已退出" });
  }

  // 用户列表
  if (method === "GET" && path === "/users") {
    const { status, body } = await sbFetch("/auth/v1/admin/users?per_page=500");
    if (status !== 200) return json({ code: -1, msg: "获取用户失败" }, 500);
    let users = ((body as Record<string, { users: unknown[] }>).users || []).map(normalizeUser);
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

  // 封禁 / 解封（新版 GoTrue 用 ban_duration 时长：876000h 封 100 年，0s 解封；banned_until 由服务端计算）
  const banMatch = path.match(/^\/users\/([^/]+)\/ban$/);
  if (method === "POST" && banMatch) {
    const body = await readBody();
    const ban = !!body.ban;
    const banDuration = ban ? "876000h" : "0s";
    const { status } = await sbFetch(`/auth/v1/admin/users/${banMatch[1]}`, {
      method: "PUT",
      body: JSON.stringify({ ban_duration: banDuration }),
    });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "操作失败" }, 500);
    return json({ code: 0, msg: ban ? "已封禁" : "已解封" });
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
    return json({ code: 0, data: body || [] });
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

  // 作废卡密
  const revokeMatch = path.match(/^\/cards\/([^/]+)\/revoke$/);
  if (method === "POST" && revokeMatch) {
    const { status } = await sbFetch(`/rest/v1/cards?id=eq.${revokeMatch[1]}`, {
      method: "PATCH",
      body: JSON.stringify({ used: true }),
    });
    if (status !== 200 && status !== 204) return json({ code: -1, msg: "作废失败" }, 500);
    return json({ code: 0, msg: "卡密已作废" });
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
