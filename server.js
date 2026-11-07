const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const HOURS = Number(process.env.RETENTION_HOURS) || 72; // сколько часов живут сообщения
const ROOM_KEY = process.env.ROOM_KEY || '';             // секретное слово в ссылке (после #)
const ADMIN = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('hex');
const HIDE_AT = 3;                                       // после стольких жалоб сообщение скрывается
if (!process.env.ADMIN_PASSWORD) console.log('ADMIN_PASSWORD не задан. Пароль админа на этот запуск:', ADMIN);

const UP = path.join(DATA, 'uploads');
const DB = path.join(DATA, 'messages.json');
fs.mkdirSync(UP, { recursive: true });

let msgs = [];
try { msgs = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch {}
let nextId = msgs.reduce((n, m) => Math.max(n, m.id), 0) + 1;

const save = () => { fs.writeFileSync(DB + '.tmp', JSON.stringify(msgs)); fs.renameSync(DB + '.tmp', DB); };
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const same = (a, b) => crypto.timingSafeEqual(Buffer.from(sha(a), 'hex'), Buffer.from(sha(b), 'hex'));
const isAdmin = req => same(req.get('x-admin') || '', ADMIN);
const dropFile = f => f && fs.rm(path.join(UP, f), { force: true }, () => {});

// Только в памяти, на диск не пишется: ограничение частоты и учёт жалоб
const hits = new Map();
const reporters = new Map();
function tooOften(req) {
  const k = sha(req.ip), now = Date.now();
  const a = (hits.get(k) || []).filter(t => now - t < 60000);
  a.push(now); hits.set(k, a);
  return a.length > 15;
}

const TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp',
                'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov' };
const upload = multer({
  storage: multer.diskStorage({
    destination: UP,
    filename: (req, f, cb) => cb(null, crypto.randomBytes(16).toString('hex') + '.' + TYPES[f.mimetype])
  }),
  limits: { fileSize: 30 * 1024 * 1024, files: 1 },
  fileFilter: (req, f, cb) => cb(null, !!TYPES[f.mimetype])
});

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  next();
});
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (ROOM_KEY && !same(req.get('x-room') || '', ROOM_KEY))
    return res.status(403).json({ error: 'Нет доступа. Проверь ссылку.' });
  next();
});

app.get('/api/messages', (req, res) => {
  const admin = isAdmin(req);
  const items = msgs.slice(-300).map(m => {
    const hidden = m.rep >= HIDE_AT, show = admin || !hidden;
    return { id: m.id, t: m.t, kind: m.kind, hidden, rep: admin ? m.rep : 0,
             text: show ? m.text : '', file: show ? m.file : null };
  });
  res.json({ hours: HOURS, admin, items });
});

app.post('/api/messages', upload.single('file'), (req, res) => {
  if (tooOften(req)) {
    if (req.file) dropFile(req.file.filename);
    return res.status(429).json({ error: 'Слишком часто. Подожди минуту.' });
  }
  const text = String(req.body.text || '').trim().slice(0, 2000);
  if (!text && !req.file)
    return res.status(400).json({ error: 'Напиши текст или выбери фото/видео (jpg, png, gif, webp, mp4, webm, mov до 30 МБ).' });
  const token = crypto.randomBytes(16).toString('hex');
  const m = { id: nextId++, t: Date.now(), text, rep: 0, tok: sha(token),
              file: req.file ? req.file.filename : null,
              kind: req.file ? req.file.mimetype.split('/')[0] : null };
  msgs.push(m); save();
  res.json({ id: m.id, token }); // токен нужен автору, чтобы удалить своё сообщение
});

app.post('/api/messages/:id/report', (req, res) => {
  const m = msgs.find(x => x.id == req.params.id);
  if (!m) return res.sendStatus(404);
  const s = reporters.get(m.id) || new Set(), k = sha(req.ip);
  if (!s.has(k)) { s.add(k); reporters.set(m.id, s); m.rep++; save(); }
  res.sendStatus(204);
});

app.delete('/api/messages/:id', (req, res) => {
  const i = msgs.findIndex(x => x.id == req.params.id);
  if (i < 0) return res.sendStatus(404);
  const m = msgs[i], tok = req.get('x-token');
  if (!isAdmin(req) && !(tok && same(sha(tok), m.tok))) return res.sendStatus(403);
  dropFile(m.file); msgs.splice(i, 1); save();
  res.sendStatus(204);
});

app.use('/uploads', express.static(UP, { maxAge: '1h' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) =>
  res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Файл больше 30 МБ.' : 'Не удалось загрузить файл.' }));

function cleanup() {
  const now = Date.now(), cut = now - HOURS * 3600e3;
  const old = msgs.filter(m => m.t <= cut);
  if (old.length) { old.forEach(m => dropFile(m.file)); msgs = msgs.filter(m => m.t > cut); save(); }
  const used = new Set(msgs.map(m => m.file));
  for (const f of fs.readdirSync(UP)) {
    const p = path.join(UP, f);
    if (!used.has(f) && now - fs.statSync(p).mtimeMs > 3600e3) fs.rmSync(p, { force: true });
  }
  for (const [k, a] of hits) if (now - a[a.length - 1] > 60000) hits.delete(k);
  const ids = new Set(msgs.map(m => m.id));
  for (const id of reporters.keys()) if (!ids.has(id)) reporters.delete(id);
}
cleanup();
setInterval(cleanup, 10 * 60e3);

app.listen(PORT, () => console.log('Чат запущен, порт ' + PORT));
