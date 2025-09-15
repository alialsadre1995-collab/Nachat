// server.js — Backend only (no static/public).
// Features: fixed admin (Admin/1200@ by default), roles, bans (userId/deviceId/ip), JWT, Socket.IO.
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()),
    methods: ['GET','POST'],
    credentials: true
  }
});

const PORT = process.env.PORT || 10000;
if ((process.env.TRUST_PROXY || '').toLowerCase() === 'true') app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()), credentials: true }));
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// In-memory stores (MVP)
const users = new Map();        // userId -> { username, role, deviceId, passHash }
const usernameIndex = new Map(); // username -> userId
const deviceIndex = new Map();   // deviceId -> userId
const onlineSockets = new Map(); // socket.id -> { userId, username }
const bans = new Map();          // key -> { type, reason, by, createdAt, expiresAt }

const englishOnly = s => /^[A-Za-z0-9_.-]{3,20}$/.test(s || '');
function now(){ return Date.now(); }

// ===== Fixed admin (can override via env) =====
const FIXED_ADMIN_USER = process.env.FIXED_ADMIN_USER || 'Admin';
const FIXED_ADMIN_PASS = process.env.FIXED_ADMIN_PASS || '1200@';

async function ensureFixedAdmin(){
  if (usernameIndex.has(FIXED_ADMIN_USER)) return;
  const userId = nanoid(21);
  const passHash = await bcrypt.hash(FIXED_ADMIN_PASS, 10);
  const deviceId = 'fixed-admin-device';
  users.set(userId, { username: FIXED_ADMIN_USER, role: 'admin', deviceId, passHash });
  usernameIndex.set(FIXED_ADMIN_USER, userId);
  deviceIndex.set(deviceId, userId);
  console.log('Fixed admin created:', FIXED_ADMIN_USER);
}

// ===== Auth middleware =====
function authRequired(req,res,next){
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  }catch(e){
    return res.status(401).json({ error: 'unauthorized' });
  }
}
function adminOrMod(req,res,next){
  const u = users.get(req.user.userId);
  if (u && (u.role === 'admin' || u.role === 'mod')) return next();
  return res.status(403).json({ error: 'forbidden' });
}

// ===== REST API =====

// Password login (required for fixed admin)
app.post('/api/login-pass', async (req,res)=>{
  let { username, password, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username)) return res.status(400).json({ error: 'Bad username' });
  const userId = usernameIndex.get(username);
  if (!userId) return res.status(404).json({ error: 'No such user' });
  const u = users.get(userId);
  if (!u?.passHash) return res.status(400).json({ error: 'User has no password set' });
  const ok = await bcrypt.compare(password || '', u.passHash);
  if (!ok) return res.status(403).json({ error: 'Wrong password' });
  const devId = deviceId || u.deviceId || nanoid(16);
  u.deviceId = devId;
  deviceIndex.set(devId, userId);
  const token = jwt.sign({ userId, username: u.username, deviceId: devId }, JWT_SECRET, { expiresIn: '7d' });
  return res.json({ ok: true, token, userId, role: u.role, deviceId: devId, username: u.username });
});

// Quick login (no password) — fails if username exists and has password
app.post('/api/login', (req,res)=>{
  let { username, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username)) return res.status(400).json({ error: 'Username must be English (3-20)' });

  let userId = deviceIndex.get(deviceId || '');
  if (!userId){
    if (usernameIndex.has(username)) {
      const existing = users.get(usernameIndex.get(username));
      if (existing?.passHash) return res.status(400).json({ error: 'Password protected user. Use /api/login-pass' });
    }
    userId = nanoid(21);
    const devId = deviceId || nanoid(16);
    users.set(userId, { username, role: 'user', deviceId: devId });
    usernameIndex.set(username, userId);
    deviceIndex.set(devId, userId);
  }else{
    const u = users.get(userId);
    if (u?.passHash) return res.status(400).json({ error: 'Password protected user. Use /api/login-pass' });
    u.username = username;
  }
  const u = users.get(userId);
  const token = jwt.sign({ userId, username: u.username, deviceId: u.deviceId }, JWT_SECRET, { expiresIn: '7d' });
  return res.json({ ok: true, token, userId, role: u.role, deviceId: u.deviceId, username: u.username });
});

// Who am I
app.get('/api/me', authRequired, (req,res)=>{
  const u = users.get(req.user.userId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  return res.json({ userId: req.user.userId, username: u.username, role: u.role, deviceId: u.deviceId });
});

// Admin: bans
app.get('/api/admin/bans', authRequired, adminOrMod, (req,res)=>{
  const list = Array.from(bans.entries()).map(([key,val])=>({ key, ...val }));
  res.json(list);
});
app.post('/api/admin/ban', authRequired, adminOrMod, (req,res)=>{
  const { targetType, targetValue, reason, minutes } = req.body || {};
  if (!['userId','deviceId','ip'].includes(targetType)) return res.status(400).json({ error: 'invalid type' });
  const expiresAt = minutes ? now() + minutes*60*1000 : null;
  bans.set(targetValue, { type: targetType, reason: reason||'', by: req.user.userId, createdAt: now(), expiresAt });
  return res.json({ ok: true });
});
app.post('/api/admin/unban', authRequired, adminOrMod, (req,res)=>{
  const { key } = req.body || {};
  bans.delete(key);
  return res.json({ ok: true });
});
app.post('/api/admin/role', authRequired, (req,res)=>{
  const caller = users.get(req.user.userId);
  if (!caller || caller.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const { userId, role } = req.body || {};
  if (!['user','mod','admin'].includes(role)) return res.status(400).json({ error: 'bad role' });
  const u = users.get(userId);
  if (!u) return res.status(404).json({ error: 'no user' });
  u.role = role;
  return res.json({ ok: true });
});

// ===== Socket.IO =====
io.use((socket, next)=>{
  try{
    const token = socket.handshake.auth?.token;
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    next();
  }catch(e){
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket)=>{
  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
             socket.request.socket.remoteAddress || '0.0.0.0';
  const { userId, deviceId, username } = socket.user || {};

  // bans check
  const checks = [bans.get(deviceId), bans.get(userId), bans.get(ip)].filter(Boolean);
  const active = checks.find(b => !b.expiresAt || b.expiresAt > now());
  if (active){
    socket.emit('banned', { reason: active.reason || 'banned' });
    return socket.disconnect(true);
  }

  onlineSockets.set(socket.id, { userId, username });
  io.emit('presence', Array.from(onlineSockets.values()));

  socket.on('chat:msg', (payload)=>{
    if (typeof payload?.text !== 'string') return;
    const clean = (payload.text || '').slice(0, 500);
    io.emit('chat:new', { from: username, userId, text: clean, ts: now() });
  });

  socket.on('disconnect', ()=>{
    onlineSockets.delete(socket.id);
    io.emit('presence', Array.from(onlineSockets.values()));
  });
});

ensureFixedAdmin().then(()=>{
  server.listen(PORT, ()=> console.log('Server running on', PORT));
}).catch(err=>{
  console.error('Failed to init fixed admin:', err);
  process.exit(1);
});
