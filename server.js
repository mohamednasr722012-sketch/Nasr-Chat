'use strict';
/**
 * موقع مراسلة بالأكواد
 * - كل مستخدم يختار كود (رقم صحيح موجب بأي طول لحد 30 رقم) + اسم + كلمة سر
 * - الكود المحجوز مينفعش حد يسجل بيه تاني ومينفعش حد يدخله من غير كلمة السر
 * - إرسال نصوص + صور + فيديوهات
 */
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const multer = require('multer');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production'; // فعّلها لما تحط الموقع على HTTPS
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- مفتاح التوقيع (بيتولد مرة واحدة ويتحفظ) ---------- */
const SECRET_FILE = path.join(DATA_DIR, '.jwt_secret');
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (fs.existsSync(SECRET_FILE)) {
    JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8');
  } else {
    JWT_SECRET = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(SECRET_FILE, JWT_SECRET, { mode: 0o600 });
  }
}

/* ---------- قاعدة البيانات ---------- */
const db = new Database(path.join(DATA_DIR, 'chat.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_code TEXT NOT NULL REFERENCES users(code),
    to_code TEXT NOT NULL REFERENCES users(code),
    text TEXT NOT NULL DEFAULT '',
    media_file TEXT,
    media_type TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_msg_from ON messages(from_code, to_code, id);
  CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_code, from_code, id);
`);

const q = {
  getUser: db.prepare('SELECT * FROM users WHERE code = ?'),
  insertUser: db.prepare('INSERT INTO users (code, name, password_hash, created_at) VALUES (?, ?, ?, ?)'),
  failLogin: db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE code = ?'),
  resetFails: db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE code = ?'),
  bumpVersion: db.prepare('UPDATE users SET token_version = token_version + 1 WHERE code = ?'),
  setPassword: db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE code = ?'),
  setName: db.prepare('UPDATE users SET name = ? WHERE code = ?'),
  insertMsg: db.prepare(
    'INSERT INTO messages (from_code, to_code, text, media_file, media_type, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ),
  getMsg: db.prepare('SELECT * FROM messages WHERE id = ?'),
  peers: db.prepare(`
    SELECT peer, MAX(id) AS last_id FROM (
      SELECT to_code AS peer, id FROM messages WHERE from_code = ?
      UNION ALL
      SELECT from_code AS peer, id FROM messages WHERE to_code = ?
    ) GROUP BY peer ORDER BY last_id DESC LIMIT 200
  `),
  thread: db.prepare(`
    SELECT * FROM messages
    WHERE ((from_code = @me AND to_code = @peer) OR (from_code = @peer AND to_code = @me))
      AND (@before IS NULL OR id < @before)
    ORDER BY id DESC LIMIT 50
  `),
};

/* ---------- ثوابت وتحقق من المدخلات ---------- */
const CODE_RE = /^[1-9][0-9]{0,29}$/; // رقم موجب من غير أصفار في الأول، لحد 30 رقم
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const BCRYPT_ROUNDS = 12;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_ROUNDS);

const cleanName = (s) =>
  typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40) : '';
const validPassword = (p) => typeof p === 'string' && p.length >= 8 && p.length <= 128;
const validCode = (c) => typeof c === 'string' && CODE_RE.test(c);

/* ---------- الجلسات (JWT في كوكي httpOnly) ---------- */
const COOKIE = 'sid';
function issueSession(res, user) {
  const token = jwt.sign({ c: user.code, v: user.token_version }, JWT_SECRET, {
    expiresIn: '7d',
    algorithm: 'HS256',
  });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: IS_PROD,
    maxAge: 7 * 24 * 3600 * 1000,
    path: '/',
  });
}
function userFromToken(token) {
  if (!token) return null;
  try {
    const p = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    const u = q.getUser.get(p.c);
    if (!u || u.token_version !== p.v) return null;
    return u;
  } catch {
    return null;
  }
}
function requireAuth(req, res, next) {
  const u = userFromToken(req.cookies[COOKIE]);
  if (!u) return res.status(401).json({ error: 'لازم تسجل دخول' });
  req.user = u;
  next();
}

/* ---------- التطبيق ---------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'img-src': ["'self'", 'blob:', 'data:'],
        'media-src': ["'self'", 'blob:'],
        'connect-src': ["'self'", 'ws:', 'wss:'],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'frame-ancestors': ["'none'"],
      },
    },
  })
);
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));

// منع CSRF: أي طلب بيعدّل لازم يكون من نفس الموقع
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin) {
      try {
        if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'طلب مرفوض' });
      } catch {
        return res.status(403).json({ error: 'طلب مرفوض' });
      }
    }
  }
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'محاولات كتير، استنى شوية وجرب تاني' },
});
const lookupLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'بحث كتير، استنى دقيقة' },
});
const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  keyGenerator: (req) => req.user?.code || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false },
  message: { error: 'بتبعت بسرعة، استنى شوية' },
});

/* ---------- تسجيل حساب جديد ---------- */
app.post('/api/register', authLimiter, async (req, res) => {
  const { code, name, password } = req.body || {};
  if (!validCode(code))
    return res.status(400).json({ error: 'الكود لازم يكون رقم صحيح موجب (من غير أصفار في الأول) ومايزيدش عن 30 رقم' });
  const n = cleanName(name);
  if (!n) return res.status(400).json({ error: 'اكتب اسمك' });
  if (!validPassword(password)) return res.status(400).json({ error: 'كلمة السر لازم تكون من 8 لـ 128 حرف' });

  if (q.getUser.get(code)) return res.status(409).json({ error: 'الكود ده محجوز، اختار كود تاني' });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  try {
    q.insertUser.run(code, n, hash, Date.now()); // PRIMARY KEY بيمنع التكرار حتى لو اتبعت طلبين مع بعض
  } catch {
    return res.status(409).json({ error: 'الكود ده محجوز، اختار كود تاني' });
  }
  issueSession(res, q.getUser.get(code));
  res.json({ code, name: n });
});

/* ---------- تسجيل الدخول (مع قفل بعد محاولات فاشلة) ---------- */
app.post('/api/login', authLimiter, async (req, res) => {
  const { code, password } = req.body || {};
  const GENERIC = { error: 'الكود أو كلمة السر غلط' };
  if (!validCode(code) || typeof password !== 'string' || password.length > 128) return res.status(401).json(GENERIC);

  const user = q.getUser.get(code);
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH); // نفس التوقيت عشان محدش يعرف الكود موجود ولا لأ
    return res.status(401).json(GENERIC);
  }
  if (user.locked_until > Date.now()) {
    const mins = Math.ceil((user.locked_until - Date.now()) / 60000);
    return res.status(429).json({ error: `الحساب مقفول مؤقتاً بسبب محاولات غلط. جرب بعد ${mins} دقيقة` });
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    const fails = user.failed_attempts + 1;
    q.failLogin.run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0, code);
    return res.status(401).json(GENERIC);
  }
  q.resetFails.run(code);
  issueSession(res, user);
  res.json({ code: user.code, name: user.name });
});

/* ---------- خروج من كل الأجهزة ---------- */
app.post('/api/logout', (req, res) => {
  const u = userFromToken(req.cookies[COOKIE]);
  if (u && req.body && req.body.all === true) {
    q.bumpVersion.run(u.code);
    disconnectUser(u.code);
  }
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ code: req.user.code, name: req.user.name }));

/* ---------- تغيير كلمة السر / الاسم ---------- */
app.post('/api/change-password', authLimiter, requireAuth, async (req, res) => {
  const { current, next } = req.body || {};
  if (typeof current !== 'string' || !validPassword(next))
    return res.status(400).json({ error: 'كلمة السر الجديدة لازم تكون من 8 لـ 128 حرف' });
  if (!(await bcrypt.compare(current, req.user.password_hash)))
    return res.status(401).json({ error: 'كلمة السر الحالية غلط' });
  q.setPassword.run(await bcrypt.hash(next, BCRYPT_ROUNDS), req.user.code); // بيطرد كل الأجهزة التانية
  disconnectUser(req.user.code);
  issueSession(res, q.getUser.get(req.user.code));
  res.json({ ok: true });
});

app.post('/api/rename', requireAuth, (req, res) => {
  const n = cleanName(req.body && req.body.name);
  if (!n) return res.status(400).json({ error: 'اكتب اسم صحيح' });
  q.setName.run(n, req.user.code);
  res.json({ name: n });
});

/* ---------- البحث عن كود (عشان تبدأ محادثة) ---------- */
app.get('/api/users/:code', requireAuth, lookupLimiter, (req, res) => {
  if (!validCode(req.params.code)) return res.status(400).json({ error: 'كود غير صحيح' });
  const u = q.getUser.get(req.params.code);
  if (!u) return res.status(404).json({ error: 'الكود ده مش موجود' });
  res.json({ code: u.code, name: u.name }); // الاسم بس، مفيش أي بيانات تانية
});

/* ---------- المحادثات والرسائل ---------- */
const publicMsg = (m) => ({
  id: m.id,
  from: m.from_code,
  to: m.to_code,
  text: m.text,
  mediaType: m.media_type ? (m.media_type.startsWith('video/') ? 'video' : 'image') : null,
  mediaUrl: m.media_file ? `/api/media/${m.id}` : null,
  at: m.created_at,
});

app.get('/api/conversations', requireAuth, (req, res) => {
  const rows = q.peers.all(req.user.code, req.user.code);
  const out = rows.map((r) => {
    const peer = q.getUser.get(r.peer);
    const last = q.getMsg.get(r.last_id);
    return {
      code: r.peer,
      name: peer ? peer.name : r.peer,
      last: last ? publicMsg(last) : null,
    };
  });
  res.json(out);
});

app.get('/api/messages/:code', requireAuth, (req, res) => {
  if (!validCode(req.params.code)) return res.status(400).json({ error: 'كود غير صحيح' });
  const before = /^\d+$/.test(String(req.query.before || '')) ? Number(req.query.before) : null;
  const rows = q.thread.all({ me: req.user.code, peer: req.params.code, before });
  res.json(rows.reverse().map(publicMsg));
});

/* ---------- رفع الصور والفيديوهات ---------- */
const MAX_MB = 50;
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, crypto.randomBytes(24).toString('hex') + '.tmp'),
  }),
  limits: { fileSize: MAX_MB * 1024 * 1024, files: 1, fields: 5 },
});

// بنتحقق من محتوى الملف الحقيقي (مش بس الاسم أو النوع اللي المتصفح قاله)
function sniffType(file) {
  const fd = fs.openSync(file, 'r');
  const b = Buffer.alloc(16);
  fs.readSync(fd, b, 0, 16, 0);
  fs.closeSync(fd);
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { mime: 'image/jpeg', ext: 'jpg' };
  if (b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { mime: 'image/png', ext: 'png' };
  if (b.slice(0, 4).toString('latin1') === 'GIF8') return { mime: 'image/gif', ext: 'gif' };
  if (b.slice(0, 4).toString('latin1') === 'RIFF' && b.slice(8, 12).toString('latin1') === 'WEBP')
    return { mime: 'image/webp', ext: 'webp' };
  if (b.slice(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return { mime: 'video/webm', ext: 'webm' };
  if (b.slice(4, 8).toString('latin1') === 'ftyp') {
    return b.slice(8, 12).toString('latin1') === 'qt  '
      ? { mime: 'video/quicktime', ext: 'mov' }
      : { mime: 'video/mp4', ext: 'mp4' };
  }
  return null;
}

app.post('/api/messages/:code', requireAuth, sendLimiter, (req, res) => {
  upload.single('file')(req, res, (err) => {
    const tmp = req.file && req.file.path;
    const fail = (status, msg) => {
      if (tmp) fs.rm(tmp, { force: true }, () => {});
      return res.status(status).json({ error: msg });
    };
    if (err) {
      return fail(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400, err.code === 'LIMIT_FILE_SIZE' ? `الملف أكبر من ${MAX_MB} ميجا` : 'فشل رفع الملف');
    }
    const to = req.params.code;
    if (!validCode(to)) return fail(400, 'كود غير صحيح');
    if (to === req.user.code) return fail(400, 'مينفعش تبعت لنفسك');
    if (!q.getUser.get(to)) return fail(404, 'الكود ده مش موجود');

    const text = typeof req.body.text === 'string' ? req.body.text.replace(/\u0000/g, '').trim().slice(0, 4000) : '';
    let mediaFile = null;
    let mediaType = null;
    if (req.file) {
      const t = sniffType(req.file.path);
      if (!t) return fail(415, 'نوع الملف غير مسموح (صور JPG/PNG/GIF/WEBP وفيديو MP4/WEBM/MOV بس)');
      mediaFile = path.basename(req.file.path, '.tmp') + '.' + t.ext;
      fs.renameSync(req.file.path, path.join(UPLOAD_DIR, mediaFile));
      mediaType = t.mime;
    }
    if (!text && !mediaFile) return fail(400, 'الرسالة فاضية');

    const info = q.insertMsg.run(req.user.code, to, text, mediaFile, mediaType, Date.now());
    const msg = publicMsg(q.getMsg.get(info.lastInsertRowid));
    io.to('user:' + req.user.code).to('user:' + to).emit('message', msg);
    res.json(msg);
  });
});

/* ---------- تحميل الميديا: بس للمرسل والمستقبل ---------- */
app.get('/api/media/:id', requireAuth, (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
  const m = q.getMsg.get(Number(req.params.id));
  if (!m || !m.media_file || (m.from_code !== req.user.code && m.to_code !== req.user.code)) return res.sendStatus(404);
  res.set({
    'Content-Type': m.media_type,
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'private, max-age=86400',
    'Content-Disposition': 'inline',
    'Content-Security-Policy': "default-src 'none'; sandbox",
  });
  res.sendFile(path.join(UPLOAD_DIR, path.basename(m.media_file)), { headers: {} }); // بيدعم Range للفيديو
});

/* ---------- Socket.IO (رسائل لحظية) ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e4 });
io.use((socket, next) => {
  const cookies = Object.fromEntries(
    (socket.handshake.headers.cookie || '')
      .split(';')
      .map((c) => c.trim().split('='))
      .filter((p) => p.length === 2)
      .map(([k, v]) => [k, decodeURIComponent(v)])
  );
  const u = userFromToken(cookies[COOKIE]);
  if (!u) return next(new Error('unauthorized'));
  socket.data.code = u.code;
  next();
});
io.on('connection', (socket) => socket.join('user:' + socket.data.code));
function disconnectUser(code) {
  io.in('user:' + code).disconnectSockets(true);
}

server.listen(PORT, () => console.log(`شغال على http://localhost:${PORT}`));
