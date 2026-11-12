const express = require('express');
const crypto = require('crypto');
const path = require('path');

const router = express.Router();

// ===== 环境配置（全部来自服务端环境变量，密钥不下发浏览器） =====
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://gngcducutevgllbaejec.supabase.co';
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_TTL = 2 * 60 * 60 * 1000; // 2 小时

let sbAdmin = null;
function getAdminClient() {
  if (sbAdmin) return sbAdmin;
  if (!SERVICE_ROLE_KEY) return null;
  const { createClient } = require('@supabase/supabase-js');
  sbAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  });
  return sbAdmin;
}

// ===== 内存会话表（token -> 过期时间戳） =====
const sessions = new Map();

function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  header.split(';').forEach(seg => {
    const idx = seg.indexOf('=');
    if (idx > -1) out[seg.slice(0, idx).trim()] = decodeURIComponent(seg.slice(idx + 1).trim());
  });
  return out;
}

function issueSession(res) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL);
  const maxAge = Math.floor(SESSION_TTL / 1000);
  res.setHeader('Set-Cookie',
    `admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
  return token;
}

function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.admin_session) sessions.delete(cookies.admin_session);
  res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

// 鉴权中间件：除登录外的 /admin/api 全部走这里
function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.admin_session;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ code: -1, msg: '未登录或会话已过期' });
  }
  if (sessions.get(token) < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ code: -1, msg: '未登录或会话已过期' });
  }
  next();
}

// ===== 登录 / 登出 =====
router.post('/api/login', (req, res) => {
  const { user, password } = req.body || {};
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ code: -1, msg: '后台未配置管理员密码（ADMIN_PASSWORD）' });
  }
  if (!user || !password) {
    return res.json({ code: -1, msg: '账号和密码不能为空' });
  }
  if (!timingSafeEqual(user, ADMIN_USER) || !timingSafeEqual(password, ADMIN_PASSWORD)) {
    return res.json({ code: -1, msg: '管理员账号或密码错误' });
  }
  issueSession(res);
  res.json({ code: 0, msg: '登录成功' });
});

router.post('/api/logout', requireAdmin, (req, res) => {
  destroySession(req, res);
  res.json({ code: 0, msg: '已退出' });
});

router.get('/api/me', requireAdmin, (req, res) => {
  res.json({ code: 0, data: { user: ADMIN_USER } });
});

// ===== 用户管理（Supabase Auth Admin） =====
function normalizeUser(u) {
  const meta = u.user_metadata || {};
  const expiresAt = meta.expires_at ? new Date(meta.expires_at) : null;
  const now = new Date();
  let status = 'active';
  if (u.banned_until) status = 'banned';
  else if (expiresAt && expiresAt < now) status = 'expired';
  return {
    id: u.id,
    email: u.email || '',
    created_at: u.created_at || '',
    last_sign_in_at: u.last_sign_in_at || '',
    email_confirmed: !!u.email_confirmed_at,
    banned_until: u.banned_until || null,
    card_key: meta.card_key || '',
    expires_at: meta.expires_at || '',
    device_id: meta.device_id || '',
    status
  };
}

router.get('/api/users', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const search = (req.query.search || '').trim().toLowerCase();
  try {
    const { data, error } = await sb.auth.admin.listUsers({ page: 1, perPage: 500 });
    if (error) throw error;
    let users = (data.users || []).map(normalizeUser);
    if (search) {
      users = users.filter(u =>
        u.email.toLowerCase().includes(search) ||
        u.card_key.toLowerCase().includes(search) ||
        u.device_id.toLowerCase().includes(search));
    }
    users.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    res.json({ code: 0, data: users });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '获取用户失败: ' + (e.message || e) });
  }
});

// 重置密码（管理员代设新密码，不读取也不返回旧密码）
router.post('/api/users/:id/reset-password', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const { id } = req.params;
  const { password } = req.body || {};
  if (!password || password.length < 8) {
    return res.json({ code: -1, msg: '新密码需 8 位及以上' });
  }
  try {
    const { error } = await sb.auth.admin.updateUserById(id, { password });
    if (error) throw error;
    res.json({ code: 0, msg: '密码已重置' });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '重置失败: ' + (e.message || e) });
  }
});

// 封禁 / 解封
router.post('/api/users/:id/ban', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const { id } = req.params;
  const { ban } = req.body || {};
  try {
    const banUntil = ban ? '2100-01-01T00:00:00.000Z' : 'none';
    const { error } = await sb.auth.admin.updateUserById(id, { ban_until: banUntil });
    if (error) throw error;
    res.json({ code: 0, msg: ban ? '已封禁' : '已解封' });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '操作失败: ' + (e.message || e) });
  }
});

// 删除用户
router.delete('/api/users/:id', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const { id } = req.params;
  try {
    const { error } = await sb.auth.admin.deleteUser(id);
    if (error) throw error;
    res.json({ code: 0, msg: '用户已删除' });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '删除失败: ' + (e.message || e) });
  }
});

// ===== 授权码（卡密）管理 =====
const CARD_TYPES = ['day', 'week', 'month', 'quarter', 'lifetime'];

function randomCode(len) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  const buf = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) out += chars[buf[i] % chars.length];
  return out;
}

router.get('/api/cards', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  try {
    const { data, error } = await sb.from('cards').select('*').order('id', { ascending: false });
    if (error) throw error;
    res.json({ code: 0, data: data || [] });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '获取卡密失败: ' + (e.message || e) });
  }
});

router.post('/api/cards/batch', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const { type, count } = req.body || {};
  const n = Math.min(Math.max(parseInt(count, 10) || 0, 1), 500);
  if (!CARD_TYPES.includes(type)) {
    return res.json({ code: -1, msg: '卡密类型无效' });
  }
  const rows = [];
  for (let i = 0; i < n; i++) {
    rows.push({
      card_key: `QXNET-${type.toUpperCase()}-${randomCode(8)}`,
      type,
      used: false,
      created_at: new Date().toISOString()
    });
  }
  try {
    const { error } = await sb.from('cards').insert(rows);
    if (error) throw error;
    res.json({ code: 0, msg: `已生成 ${rows.length} 张 ${type} 卡密`, data: rows.map(r => r.card_key) });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '生成失败: ' + (e.message || e) });
  }
});

// 作废卡密（标记已使用/不可用）
router.post('/api/cards/:id/revoke', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const { id } = req.params;
  try {
    const { error } = await sb.from('cards').update({ used: true }).eq('id', id);
    if (error) throw error;
    res.json({ code: 0, msg: '卡密已作废' });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '作废失败: ' + (e.message || e) });
  }
});

// ===== 记录查看 =====
router.get('/api/records', requireAdmin, async (req, res) => {
  const sb = getAdminClient();
  if (!sb) return res.status(503).json({ code: -1, msg: '未配置 service_role 密钥' });
  const type = req.query.type || 'messages';
  const table = ['messages', 'chat_messages', 'visits'].includes(type) ? type : 'messages';
  try {
    const { data, error } = await sb.from(table).select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    res.json({ code: 0, data: data || [] });
  } catch (e) {
    res.status(500).json({ code: -1, msg: '获取记录失败: ' + (e.message || e) });
  }
});

module.exports = router;
