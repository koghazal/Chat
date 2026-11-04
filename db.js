const crypto = require('crypto'), path = require('path'), fs = require('fs'), { skeleton } = require('./security');
process.umask(0o077);
let Database; // better-sqlite3 لو متثبتة، وإلا sqlite المدمجة في Node 22+
try { Database = require('better-sqlite3'); } catch { ({ DatabaseSync: Database } = require('node:sqlite')); }
const DBP = process.env.DB_PATH || path.join(__dirname, require('fs').existsSync(path.join(__dirname, 'samar.db')) ? 'samar.db' : 'misk.db'); // samar.db = الاسم القديم، بيفضل مستخدم لو موجود
const db = new Database(DBP);
for (const f of [DBP, DBP + '-wal', DBP + '-shm']) try { fs.chmodSync(f, 0o600); } catch {}

db.exec(`
PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS roles(name TEXT PRIMARY KEY, level INTEGER NOT NULL, label TEXT NOT NULL, perms TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  pass_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member' REFERENCES roles(name),
  name_color TEXT DEFAULT '', style TEXT DEFAULT '{}', status_msg TEXT DEFAULT '', avatar TEXT DEFAULT '',
  points INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, created_at INTEGER NOT NULL, last_login INTEGER,
  muted_until INTEGER DEFAULT 0, banned_until INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rooms(name TEXT PRIMARY KEY, owner_id INTEGER, permanent INTEGER DEFAULT 0, description TEXT DEFAULT '', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL, user_id INTEGER, name TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room, id);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, reporter TEXT NOT NULL, target TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, left_ts INTEGER, user_id INTEGER, name TEXT NOT NULL, role TEXT NOT NULL, ip TEXT, country TEXT, device TEXT, browser TEXT, did TEXT);
CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts);
CREATE TABLE IF NOT EXISTS blocks(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL, by_name TEXT, ts INTEGER NOT NULL, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS likes(from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, PRIMARY KEY(from_id, to_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, details TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(url TEXT PRIMARY KEY, user_id INTEGER, kind TEXT NOT NULL, name TEXT, size INTEGER, mime TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS emojis(name TEXT PRIMARY KEY, url TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, text TEXT NOT NULL, img TEXT DEFAULT '', ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS post_likes(post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(post_id, user_id));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, name TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE TABLE IF NOT EXISTS notifs(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL, from_name TEXT, ts INTEGER NOT NULL, read INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_notifs_user ON notifs(user_id, id);
CREATE TABLE IF NOT EXISTS profile_visits(id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, visitor_id INTEGER NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pv_owner ON profile_visits(owner_id, ts);
CREATE TABLE IF NOT EXISTS activity(day TEXT NOT NULL, user_id INTEGER NOT NULL, msgs INTEGER DEFAULT 0, posts INTEGER DEFAULT 0, comments INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, PRIMARY KEY(day, user_id));
CREATE TABLE IF NOT EXISTS gallery(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, url TEXT NOT NULL, by_name TEXT, ts INTEGER NOT NULL);
`);

try { db.exec("ALTER TABLE users ADD COLUMN style TEXT DEFAULT '{}'"); } catch {} // لقواعد بيانات قديمة
try { db.exec('ALTER TABLE audit ADD COLUMN details TEXT'); } catch {}
try { db.exec('ALTER TABLE messages ADD COLUMN sys INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN vip INTEGER DEFAULT 0'); } catch {}
for (const c of ["reason TEXT DEFAULT ''", "ctx TEXT DEFAULT ''", "status TEXT DEFAULT 'open'", "room TEXT DEFAULT ''", "handled_by TEXT DEFAULT ''", 'handled_ts INTEGER DEFAULT 0']) { try { db.exec('ALTER TABLE reports ADD COLUMN ' + c); } catch {} }
db.exec(`CREATE TABLE IF NOT EXISTS pms(id INTEGER PRIMARY KEY AUTOINCREMENT, a INTEGER NOT NULL, b INTEGER NOT NULL, text TEXT NOT NULL, file TEXT DEFAULT '', ts INTEGER NOT NULL, read INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_pm_ab ON pms(a, b, id); CREATE INDEX IF NOT EXISTS idx_pm_b ON pms(b, read);
CREATE TABLE IF NOT EXISTS ignores(uid INTEGER NOT NULL, target INTEGER NOT NULL, PRIMARY KEY(uid, target));`);
try { db.exec('ALTER TABLE users ADD COLUMN role_until INTEGER DEFAULT 0'); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN role_prev TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE roles ADD COLUMN color TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE roles ADD COLUMN icon TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE roles ADD COLUMN ncolor TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE roles ADD COLUMN mbg TEXT DEFAULT ''"); } catch {}
db.exec("CREATE TABLE IF NOT EXISTS fakes(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT NOT NULL, role TEXT NOT NULL, room TEXT NOT NULL DEFAULT '', deco TEXT DEFAULT '', status TEXT DEFAULT '', color TEXT DEFAULT '', av TEXT DEFAULT '', rules TEXT DEFAULT '', likes INTEGER DEFAULT 0, active INTEGER DEFAULT 1, ts INTEGER NOT NULL)");
try { db.exec("ALTER TABLE messages ADD COLUMN file TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN frame TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN bg TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN skel TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN deco TEXT DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN deco_skel TEXT DEFAULT ''"); } catch {}
db.exec('CREATE INDEX IF NOT EXISTS idx_users_skel ON users(skel)');
for (const r of db.prepare("SELECT id, username FROM users WHERE skel IS NULL OR skel = ''").all()) db.prepare('UPDATE users SET skel = ? WHERE id = ?').run(skeleton(r.username), r.id);
db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)');
const PERMS = { kick: 'طرد', kickroom: 'طرد من الغرفة', mute: 'اسكات', ban: 'باند', tempban: 'باند مؤقت', setrole: 'تغيير الرتب', moverooms: 'نقل بين الغرف', editlikes: 'تعديل الإيكات', reveal: 'كشف النكات', viewlog: 'السجل', viewcases: 'الحالات', settings: 'إعدادات الموقع', roles: 'إدارة الصلاحيات', stats: 'الإحصائيات', filter: 'فلتر الكلمات', shortcuts: 'الاختصارات', welcome: 'رسائل الترحيب', assets: 'رفع البنرات والإيموجي', wallmod: 'إدارة الحائط', roomadmin: 'إدارة الغرف', members: 'العضويات', reports: 'البلاغات', delmsg: 'حذف الرسايل' };
const addRole = db.prepare('INSERT OR IGNORE INTO roles(name,level,label,perms) VALUES(?,?,?,?)');
const DEF_COLORS = { owner: '#f2c46b', admin: '#ff8a8a', mod: '#7fd1ff', member: '', bot: '#7be0c3' };
addRole.run('owner', 100, 'المالك', JSON.stringify(Object.keys(PERMS)));
addRole.run('admin', 80, 'مدير', JSON.stringify(['kick', 'kickroom', 'mute', 'ban', 'tempban', 'setrole', 'moverooms', 'reveal', 'viewlog', 'viewcases', 'stats', 'wallmod', 'roomadmin']));
addRole.run('mod', 50, 'مشرف', JSON.stringify(['kick', 'kickroom', 'mute']));
addRole.run('member', 10, 'عضو', '[]');
addRole.run('bot', 55, 'بوت', JSON.stringify(['mute']));
db.prepare("UPDATE roles SET perms = ? WHERE name = 'owner'").run(JSON.stringify(Object.keys(PERMS)));
if (!db.prepare("SELECT 1 x FROM settings WHERE key = 'roomadmin_perm'").get()) { // صلاحية جديدة للمدير في القواعد القديمة (مرة واحدة)
  const a = db.prepare("SELECT perms FROM roles WHERE name = 'admin'").get(); if (a) { const l = JSON.parse(a.perms); if (!l.includes('roomadmin')) db.prepare("UPDATE roles SET perms = ? WHERE name = 'admin'").run(JSON.stringify([...l, 'roomadmin'])); }
  db.prepare("INSERT INTO settings(key,value) VALUES('roomadmin_perm','1')").run();
}
if (!db.prepare("SELECT 1 x FROM settings WHERE key = 'members_perm'").get()) {
  const a = db.prepare("SELECT perms FROM roles WHERE name = 'admin'").get(); if (a) { const l = JSON.parse(a.perms); if (!l.includes('members')) db.prepare("UPDATE roles SET perms = ? WHERE name = 'admin'").run(JSON.stringify([...l, 'members'])); }
  db.prepare("INSERT INTO settings(key,value) VALUES('members_perm','1')").run();
}
if (!db.prepare("SELECT 1 x FROM settings WHERE key = 'msgtools_perm'").get()) {
  const add = (role, extra) => { const a = db.prepare('SELECT perms FROM roles WHERE name = ?').get(role); if (a) { const l = JSON.parse(a.perms); db.prepare('UPDATE roles SET perms = ? WHERE name = ?').run(JSON.stringify([...new Set([...l, ...extra])]), role); } };
  add('admin', ['reports', 'delmsg']); add('mod', ['delmsg']);
  db.prepare("INSERT INTO settings(key,value) VALUES('msgtools_perm','1')").run();
}
for (const [n, c] of Object.entries(DEF_COLORS)) db.prepare("UPDATE roles SET color = ? WHERE name = ? AND (color IS NULL OR color = '')").run(c, n);
const addSet = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)');
addSet.run('site_name', 'مسك');
db.prepare("UPDATE settings SET value = 'مسك' WHERE key = 'site_name' AND value = 'سمر'").run();
db.prepare("UPDATE settings SET value = REPLACE(value, 'في سمر', 'في مسك') WHERE key = 'welcome'").run();
addSet.run('welcome', 'أهلاً بكم في مسك، ادخل باسم مستعار وابدأ الكلام.');
addSet.run('rules', 'احترم الجميع. ممنوع السب والإساءة والروابط المشبوهة. تقدر تبلّغ عن أي عضو من قايمة المتواجدين.');
addSet.run('reg_open', '1');
addSet.run('guest_open', '1');
addSet.run('accent', '');
addSet.run('banner', '');
addSet.run('rooms_bar', '0');
addSet.run('bot_enabled', '1');
addSet.run('bot_mod', '1');
addSet.run('bot_rules', '');
addSet.run('bot_bad', '');
addSet.run('locked_rooms', '[]');
addSet.run('sess_hashed', '0');
addSet.run('filter_words', '');
addSet.run('shortcuts', JSON.stringify({ 'س1': 'السلام عليكم ورحمة الله وبركاته', 'س2': 'وعليكم السلام ورحمة الله وبركاته', 'س3': 'أهلاً وسهلاً بيك' }));
const addRoom = db.prepare('INSERT OR IGNORE INTO rooms(name,permanent,created_at) VALUES(?,1,?)');
['الصالة العامة', 'تعارف', 'ألعاب'].forEach(r => addRoom.run(r, Date.now()));

const roles = new Map(db.prepare('SELECT * FROM roles').all().map(r => [r.name, { level: r.level, label: r.label, perms: JSON.parse(r.perms), color: r.color || '', icon: r.icon || '', ncolor: r.ncolor || '', mbg: r.mbg || '' }]));
const hash = (p, salt) => crypto.scryptSync(p, salt, 64).toString('hex');
const scryptA = (p, salt) => new Promise((res, rej) => crypto.scrypt(p, salt, 64, (e, k) => e ? rej(e) : res(k.toString('hex'))));
const tokHash = t => crypto.createHash('sha256').update(String(t)).digest('hex');
const SESS_TTL = 30 * 864e5;
const eqHex = (h, row) => { const a = Buffer.from(h, 'hex'), b = Buffer.from(row.pass_hash, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
// الجلسات القديمة كانت مخزنة كنص صريح: نلغيها مرة واحدة ونعتمد التخزين المشفر
if (db.prepare("SELECT value v FROM settings WHERE key = 'sess_hashed'").get()?.v !== '1') { db.exec('DELETE FROM sessions'); db.prepare("UPDATE settings SET value = '1' WHERE key = 'sess_hashed'").run(); }
const now = () => Date.now();
const COLS = ['deco', 'deco_skel', 'likes', 'style', 'muted_until', 'banned_until', 'verified', 'vip', 'role_until', 'role_prev', 'role', 'name_color', 'status_msg', 'avatar', 'frame', 'bg'];

module.exports = {
  db,
  SETTING_KEYS: ['site_name', 'welcome', 'rules'],
  level: r => roles.get(r)?.level ?? 0,
  label: r => roles.get(r)?.label ?? '',
  color: r => roles.get(r)?.color ?? '',
  icon: r => roles.get(r)?.icon ?? '',
  rn: r => roles.get(r)?.ncolor ?? '',
  rb: r => roles.get(r)?.mbg ?? '',
  setRoleStyle(name, n, b) { db.prepare('UPDATE roles SET ncolor = ?, mbg = ? WHERE name = ?').run(n, b, name); Object.assign(roles.get(name), { ncolor: n, mbg: b }); },
  perms: r => roles.get(r)?.perms ?? [],
  can: (r, p) => (roles.get(r)?.perms ?? []).includes(p),
  roleExists: r => roles.has(r),
  userExists: n => skeleton(n) === skeleton('مسك بوت') || !!db.prepare('SELECT 1 x FROM users WHERE username = ? OR skel = ? OR deco_skel = ?').get(n, skeleton(n), skeleton(n)),
  decoTaken: (uid, sk) => !!db.prepare('SELECT 1 x FROM users WHERE id != ? AND (skel = ? OR deco_skel = ?) LIMIT 1').get(uid ?? -1, sk, sk),
  clearRoom: r => db.prepare('DELETE FROM messages WHERE room = ?').run(r),
  hasOwner: () => !!db.prepare("SELECT 1 x FROM users WHERE role = 'owner'").get(),
  hashA: scryptA,
  createUser(name, pass) {
    const salt = crypto.randomBytes(16).toString('hex');
    return this.createUserWith(name, hash(pass, salt), salt);
  },
  // نسخة غير حاجبة: الهاش محسوب مسبقًا
  createUserWith(name, passHash, salt) {
    const wantOwner = process.env.OWNER_NAME ? skeleton(process.env.OWNER_NAME) === skeleton(name) : true;
    const first = !db.prepare("SELECT 1 x FROM users WHERE role = 'owner'").get() && wantOwner;
    const r = db.prepare('INSERT INTO users(username,pass_hash,salt,role,created_at,last_login,skel) VALUES(?,?,?,?,?,?,?)')
      .run(name, passHash, salt, first ? 'owner' : 'member', now(), now(), skeleton(name));
    return db.prepare('SELECT * FROM users WHERE id = ?').get(Number(r.lastInsertRowid));
  },
  async newCred(pass) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, h: await scryptA(pass, salt) }; },
  async loginAsync(name, pass) {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(name);
    const h = await scryptA(pass, row ? row.salt : DUMMY_SALT);
    return row && eqHex(h, row) ? row : null;
  },
  async checkPass(uid, pass) {
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(uid); if (!row) return false;
    return eqHex(await scryptA(pass, row.salt), row);
  },
  login(name, pass) {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(name);
    const h = hash(pass, row ? row.salt : DUMMY_SALT);
    return row && eqHex(h, row) ? row : null;
  },
  visit: (u, i) => Number(db.prepare('INSERT INTO visits(ts,user_id,name,role,ip,country,device,browser,did) VALUES(?,?,?,?,?,?,?,?,?)').run(now(), u.uid, u.name, u.role, i.ip, i.country, i.device, i.browser, i.did).lastInsertRowid),
  leaveVisit: id => id && db.prepare('UPDATE visits SET left_ts = ? WHERE id = ?').run(now(), id),
  visits: () => db.prepare('SELECT ts,left_ts,name,role,ip,country,device,browser FROM visits ORDER BY id DESC LIMIT 100').all(),
  cases: () => db.prepare('SELECT ts,actor,action,target,details FROM audit ORDER BY id DESC LIMIT 100').all(),
  lastCountry: uid => db.prepare("SELECT country c FROM visits WHERE user_id = ? AND country != '' ORDER BY id DESC LIMIT 1").get(uid)?.c || '',
  sameDevice: (did, name) => did ? db.prepare('SELECT DISTINCT name FROM visits WHERE did = ? AND name != ? LIMIT 8').all(did, name).map(r => r.name) : [],
  addBlock: (kind, value, by, until) => value && db.prepare('INSERT INTO blocks(kind,value,by_name,ts,until) VALUES(?,?,?,?,?)').run(kind, value, by, now(), until),
  blockedBy(ip, ...dids) {
    const ids = dids.filter(Boolean);
    return db.prepare("SELECT 1 x FROM blocks WHERE until > ? AND ((kind = 'ip' AND value = ?)" + ids.map(() => " OR (kind = 'device' AND value = ?)").join('') + ') LIMIT 1').get(now(), ip || '-', ...ids);
  },
  blocks: () => db.prepare('SELECT id,kind,value,by_name,ts,until FROM blocks WHERE until > ? ORDER BY id DESC LIMIT 100').all(now()),
  members(q, off, lim) {
    const like = '%' + String(q || '').replace(/[%_\\]/g, c => '\\' + c) + '%';
    const w = "WHERE username LIKE ? ESCAPE '\\' OR IFNULL(deco,'') LIKE ? ESCAPE '\\'";
    return { total: db.prepare('SELECT COUNT(*) n FROM users ' + w).get(like, like).n, list: db.prepare('SELECT id,username,deco,role,avatar,frame,created_at,last_login,muted_until,banned_until,verified,vip,likes FROM users ' + w + ' ORDER BY IFNULL(last_login,created_at) DESC LIMIT ? OFFSET ?').all(like, like, lim, off) };
  },
  views: uid => db.prepare('SELECT COUNT(*) n FROM profile_visits WHERE owner_id = ?').get(uid).n,
  expireRoles() { const L = db.prepare("SELECT id, role_prev FROM users WHERE role_until > 0 AND role_until < ?").all(now()); L.forEach(x => { const r = roles.has(x.role_prev) ? x.role_prev : 'member'; db.prepare("UPDATE users SET role = ?, role_until = 0, role_prev = '' WHERE id = ?").run(r, x.id); x.role = r; }); return L; },
  memberRow: id => db.prepare('SELECT id,username,deco,role,banned_until,verified,vip,role_until,role_prev FROM users WHERE id = ?').get(id),
  unbanUser(uid) { db.prepare('UPDATE users SET banned_until = 0 WHERE id = ?').run(uid); db.prepare("DELETE FROM blocks WHERE kind = 'device' AND value IN (SELECT did FROM visits WHERE user_id = ? AND IFNULL(did,'') != '')").run(uid); db.prepare("DELETE FROM blocks WHERE kind = 'reg' AND value IN (SELECT ip FROM visits WHERE user_id = ?)").run(uid); },
  delBlock: id => db.prepare('DELETE FROM blocks WHERE id = ?').run(id),
  PERMS,
  rolesList: () => [...roles].map(([name, v]) => ({ name, ...v })),
  addRole(name, level, label, color, icon = '') {
    db.prepare('INSERT INTO roles(name,level,label,perms,color,icon) VALUES(?,?,?,?,?,?)').run(name, level, label, '[]', color, icon);
    roles.set(name, { level, label, perms: [], color, icon });
  },
  editRole(name, label, color, icon) {
    if (icon === undefined) icon = roles.get(name).icon || '';
    db.prepare('UPDATE roles SET label = ?, color = ?, icon = ? WHERE name = ?').run(label, color, icon, name);
    Object.assign(roles.get(name), { label, color, icon });
  },
  fakes: () => db.prepare('SELECT * FROM fakes ORDER BY id').all(),
  fakeAdd: o => db.prepare('INSERT INTO fakes(name,kind,role,room,deco,status,color,av,rules,likes,active,ts) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)').run(o.name, o.kind, o.role, o.room, o.deco, o.status, o.color, o.av, o.rules, o.likes, now()).lastInsertRowid,
  fakeSet(id, o) { const k = Object.keys(o).filter(x => ['name', 'kind', 'role', 'room', 'deco', 'status', 'color', 'av', 'rules', 'likes', 'active'].includes(x)); if (k.length) db.prepare('UPDATE fakes SET ' + k.map(x => x + ' = ?').join(', ') + ' WHERE id = ?').run(...k.map(x => o[x]), id); },
  fakeDel: id => db.prepare('DELETE FROM fakes WHERE id = ?').run(id),
  setRoleIcon(name, icon) { db.prepare('UPDATE roles SET icon = ? WHERE name = ?').run(icon, name); roles.get(name).icon = icon; },
  delRole(name) {
    db.prepare('DELETE FROM roles WHERE name = ?').run(name); roles.delete(name);
  },
  roleUsers: name => db.prepare('SELECT COUNT(*) c FROM users WHERE role = ?').get(name).c,
  roomWelcome: n => db.prepare('SELECT description d FROM rooms WHERE name = ?').get(n)?.d ?? '',
  setRoomWelcome: (n, t) => db.prepare('UPDATE rooms SET description = ? WHERE name = ?').run(t, n),
  roomWelcomes: () => Object.fromEntries(db.prepare('SELECT name, description FROM rooms').all().map(r => [r.name, r.description || ''])),
  counts: () => ({
    users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
    members7: db.prepare('SELECT COUNT(*) c FROM users WHERE last_login > ?').get(now() - 7 * 864e5).c,
    messages: db.prepare('SELECT COUNT(*) c FROM messages').get().c,
    today: db.prepare('SELECT COUNT(*) c FROM messages WHERE ts > ?').get(now() - 864e5).c,
    rooms: db.prepare('SELECT COUNT(*) c FROM rooms').get().c,
    posts: db.prepare('SELECT COUNT(*) c FROM posts').get().c,
    visits: db.prepare('SELECT COUNT(*) c FROM visits WHERE ts > ?').get(now() - 864e5).c,
    blocks: db.prepare('SELECT COUNT(*) c FROM blocks WHERE until > ?').get(now()).c,
  }),
  addUpload: (url, uid, kind, name, size, mime) => db.prepare('INSERT INTO uploads(url,user_id,kind,name,size,mime,ts) VALUES(?,?,?,?,?,?,?)').run(url, uid, kind, name, size, mime, now()),
  upload: url => db.prepare('SELECT * FROM uploads WHERE url = ?').get(url),
  delUpload: url => db.prepare('DELETE FROM uploads WHERE url = ?').run(url),
  emojis: () => db.prepare('SELECT name, url FROM emojis ORDER BY name').all(),
  addEmoji: (n, url) => db.prepare('INSERT INTO emojis(name,url) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET url = excluded.url').run(n, url),
  delEmoji: n => db.prepare('DELETE FROM emojis WHERE name = ?').run(n),
  // الإشعارات
  notify(uid, kind, text, from) {
    db.prepare('INSERT INTO notifs(user_id,kind,text,from_name,ts) VALUES(?,?,?,?,?)').run(uid, kind, text, from || '', now());
    db.prepare('DELETE FROM notifs WHERE user_id = ? AND id NOT IN (SELECT id FROM notifs WHERE user_id = ? ORDER BY id DESC LIMIT 100)').run(uid, uid);
    return db.prepare('SELECT id,kind,text,from_name,ts,read FROM notifs WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(uid);
  },
  notifs: uid => db.prepare('SELECT id,kind,text,from_name,ts,read FROM notifs WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(uid),
  unread: uid => db.prepare('SELECT COUNT(*) c FROM notifs WHERE user_id = ? AND read = 0').get(uid).c,
  readAll: uid => db.prepare('UPDATE notifs SET read = 1 WHERE user_id = ?').run(uid),
  clearNotifs: uid => db.prepare('DELETE FROM notifs WHERE user_id = ?').run(uid),
  // زائرين الملف الشخصي
  addVisit(owner, visitor) {
    if (owner === visitor) return;
    if (db.prepare('SELECT 1 x FROM profile_visits WHERE owner_id = ? AND visitor_id = ? AND ts > ?').get(owner, visitor, now() - 10 * 60e3)) return;
    db.prepare('INSERT INTO profile_visits(owner_id,visitor_id,ts) VALUES(?,?,?)').run(owner, visitor, now());
  },
  topVisited: since => db.prepare('SELECT u.id uid, u.username name, u.avatar av, u.frame fr, COUNT(*) n FROM profile_visits v JOIN users u ON u.id = v.owner_id WHERE v.ts > ? GROUP BY v.owner_id ORDER BY n DESC, MAX(v.ts) DESC LIMIT 10').all(since),
  myVisitors: uid => db.prepare('SELECT u.id uid, u.username name, u.avatar av, u.frame fr, MAX(v.ts) ts, COUNT(*) n FROM profile_visits v JOIN users u ON u.id = v.visitor_id WHERE v.owner_id = ? GROUP BY v.visitor_id ORDER BY ts DESC LIMIT 30').all(uid),
  // النشاط والترتيبات
  bump(uid, field, by = 1) {
    if (!['msgs', 'posts', 'comments', 'likes'].includes(field) || !uid) return;
    const day = new Date().toISOString().slice(0, 10);
    db.prepare(`INSERT INTO activity(day,user_id,${field}) VALUES(?,?,?) ON CONFLICT(day,user_id) DO UPDATE SET ${field} = ${field} + excluded.${field}`).run(day, uid, by);
  },
  rank(field, days) {
    if (!['msgs', 'posts', 'comments', 'likes'].includes(field)) return [];
    const since = new Date(now() - (days - 1) * 864e5).toISOString().slice(0, 10);
    return db.prepare(`SELECT u.id uid, u.username name, u.avatar av, u.frame fr, SUM(a.${field}) n FROM activity a JOIN users u ON u.id = a.user_id WHERE a.day >= ? GROUP BY a.user_id HAVING n > 0 ORDER BY n DESC LIMIT 10`).all(since);
  },
  // إطارات وخلفيات
  gallery: kind => db.prepare('SELECT id,url FROM gallery WHERE kind = ? ORDER BY id DESC LIMIT 200').all(kind),
  galItem: id => db.prepare('SELECT * FROM gallery WHERE id = ?').get(id),
  inGallery: (kind, url) => !!db.prepare('SELECT 1 x FROM gallery WHERE kind = ? AND url = ?').get(kind, url),
  addGallery: (kind, url, by) => db.prepare('INSERT INTO gallery(kind,url,by_name,ts) VALUES(?,?,?,?)').run(kind, url, by, now()),
  delGallery(id) {
    const g = db.prepare('SELECT * FROM gallery WHERE id = ?').get(id); if (!g) return null;
    db.prepare('DELETE FROM gallery WHERE id = ?').run(id);
    db.prepare(`UPDATE users SET ${g.kind === 'frame' ? 'frame' : 'bg'} = '' WHERE ${g.kind === 'frame' ? 'frame' : 'bg'} = ?`).run(g.url);
    return g;
  },
  // الحائط
  addPost: (uid, name, text, img) => Number(db.prepare('INSERT INTO posts(user_id,name,text,img,ts) VALUES(?,?,?,?,?)').run(uid, name, text, img || '', now()).lastInsertRowid),
  posts: uid => db.prepare(`SELECT p.id, p.user_id uid, p.name, p.text, p.img, p.ts, u.deco, u.avatar av, u.frame fr, u.role, u.style,
      (SELECT COUNT(*) FROM post_likes l WHERE l.post_id = p.id) likes, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) cc,
      EXISTS(SELECT 1 FROM post_likes l WHERE l.post_id = p.id AND l.user_id = ?) liked
      FROM posts p LEFT JOIN users u ON u.id = p.user_id ORDER BY p.id DESC LIMIT 40`).all(uid ?? -1),
  post: id => db.prepare('SELECT * FROM posts WHERE id = ?').get(id),
  delPost(id) { db.prepare('DELETE FROM post_likes WHERE post_id = ?').run(id); db.prepare('DELETE FROM comments WHERE post_id = ?').run(id); db.prepare('DELETE FROM posts WHERE id = ?').run(id); },
  postLike(pid, uid) {
    const had = db.prepare('SELECT 1 x FROM post_likes WHERE post_id = ? AND user_id = ?').get(pid, uid);
    if (had) db.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?').run(pid, uid);
    else db.prepare('INSERT INTO post_likes(post_id,user_id) VALUES(?,?)').run(pid, uid);
  },
  comments: pid => db.prepare('SELECT c.id, c.user_id uid, c.name, c.text, c.ts, u.deco dn, u.avatar av, u.frame fr FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id LIMIT 100').all(pid),
  addComment: (pid, uid, name, text) => db.prepare('INSERT INTO comments(post_id,user_id,name,text,ts) VALUES(?,?,?,?,?)').run(pid, uid, name, text, now()),
  comment: id => db.prepare('SELECT * FROM comments WHERE id = ?').get(id),
  delComment: id => db.prepare('DELETE FROM comments WHERE id = ?').run(id),
  setPerms(r, list) {
    const ok = [...new Set(list)].filter(k => PERMS[k] && (r === 'owner' || k !== 'roles'));
    db.prepare('UPDATE roles SET perms = ? WHERE name = ?').run(JSON.stringify(ok), r);
    roles.get(r).perms = ok;
  },
  userByName: n => db.prepare('SELECT id,username,deco,role,points,likes,status_msg,style,avatar,frame,bg FROM users WHERE username = ?').get(n),
  stats: uid => db.prepare('SELECT points, likes FROM users WHERE id = ?').get(uid) ?? { points: 0, likes: 0 },
  like(from, to) {
    const had = db.prepare('SELECT 1 x FROM likes WHERE from_id = ? AND to_id = ?').get(from, to);
    if (had) { db.prepare('DELETE FROM likes WHERE from_id = ? AND to_id = ?').run(from, to); db.prepare('UPDATE users SET likes = MAX(likes - 1, 0) WHERE id = ?').run(to); }
    else { db.prepare('INSERT INTO likes(from_id,to_id) VALUES(?,?)').run(from, to); db.prepare('UPDATE users SET likes = likes + 1 WHERE id = ?').run(to); }
  },
  setPassHash(uid, h, salt) {
    db.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').run(h, salt, uid);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(uid);
  },
  newSession(uid) {
    const t = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)').run(tokHash(t), uid, now());
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token NOT IN (SELECT token FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10)').run(uid, uid);
    return t;
  },
  delSession: t => db.prepare('DELETE FROM sessions WHERE token = ?').run(tokHash(t)),
  sessionUser: t => /^[a-f0-9]{64}$/.test(String(t)) ? db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.created_at > ?').get(tokHash(t), now() - SESS_TTL) : undefined,
  touch: uid => db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now(), uid),
  setCol(uid, col, val) { if (!COLS.includes(col)) throw new Error('bad column'); db.prepare(`UPDATE users SET ${col} = ? WHERE id = ?`).run(val, uid); },
  addPoint: uid => db.prepare('UPDATE users SET points = points + 1 WHERE id = ?').run(uid),
  setting: k => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? '',
  setSetting: (k, v) => db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v),
  addRoom: (n, uid) => db.prepare('INSERT INTO rooms(name,owner_id,permanent,created_at) VALUES(?,?,0,?)').run(n, uid, now()),
  delRoom: n => db.prepare('DELETE FROM rooms WHERE name = ?').run(n),
  logMsg: (room, uid, name, text, file) => Number(db.prepare('INSERT INTO messages(room,user_id,name,text,ts,file) VALUES(?,?,?,?,?,?)').run(room, uid, name, text, now(), file ? JSON.stringify(file) : '').lastInsertRowid),
  logSys: (room, text, uid, name, meta) => db.prepare('INSERT INTO messages(room,user_id,name,text,ts,sys,file) VALUES(?,?,?,?,?,1,?)').run(room, uid ?? null, name || '', text, now(), meta ? JSON.stringify(meta) : ''),
  history: room => db.prepare('SELECT m.id, m.sys, m.name, m.text, m.ts, m.file, u.role, u.deco, u.avatar av, u.frame fr, u.bg bgi FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.room = ? ORDER BY m.id DESC LIMIT 50').all(room).reverse()
    .map(r => ({ mid: r.id, sys: r.sys ? 1 : 0, name: r.name, dn: r.deco || '', text: r.text, ts: r.ts, av: r.av || '', fr: r.fr || '', bgi: r.bgi || '', file: r.file ? JSON.parse(r.file) : null })),
  report: (a, b, reason, ctx, room) => Number(db.prepare('INSERT INTO reports(reporter,target,ts,reason,ctx,room) VALUES(?,?,?,?,?,?)').run(a, b, now(), reason || '', ctx || '', room || '').lastInsertRowid),
  reportsList: (status, off) => db.prepare('SELECT id,reporter,target,ts,reason,ctx,room,status,handled_by,handled_ts FROM reports ' + (status === 'open' ? "WHERE status = 'open' " : '') + 'ORDER BY id DESC LIMIT 25 OFFSET ?').all(off),
  reportsOpen: () => db.prepare("SELECT COUNT(*) n FROM reports WHERE status = 'open'").get().n,
  reportGet: id => db.prepare('SELECT * FROM reports WHERE id = ?').get(id),
  reportSet: (id, status, by) => db.prepare('UPDATE reports SET status = ?, handled_by = ?, handled_ts = ? WHERE id = ?').run(status, by, now(), id),
  lastMsgsBy: (room, name, n) => db.prepare('SELECT text FROM messages WHERE room = ? AND name = ? AND sys = 0 ORDER BY id DESC LIMIT ?').all(room, name, n).map(r => r.text).reverse(),
  msgById: id => db.prepare('SELECT m.id, m.room, m.user_id, m.name, m.text, m.file, u.role FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.id = ? AND m.sys = 0').get(id),
  delMsg: id => db.prepare('DELETE FROM messages WHERE id = ?').run(id),
  // رسايل خاصة محفوظة بين الأعضاء
  pmAdd: (a, b, text, file) => Number(db.prepare('INSERT INTO pms(a,b,text,file,ts) VALUES(?,?,?,?,?)').run(a, b, text, file ? JSON.stringify(file) : '', now()).lastInsertRowid),
  pmThread: (me, other) => db.prepare('SELECT id,a,b,text,file,ts FROM (SELECT * FROM pms WHERE (a = ? AND b = ?) OR (a = ? AND b = ?) ORDER BY id DESC LIMIT 60) ORDER BY id').all(me, other, other, me).map(r => ({ id: r.id, mine: r.a === me, text: r.text, file: r.file ? JSON.parse(r.file) : null, ts: r.ts })),
  pmRead: (me, other) => db.prepare('UPDATE pms SET read = 1 WHERE b = ? AND a = ? AND read = 0').run(me, other),
  pmUnread: me => db.prepare('SELECT COUNT(*) n FROM pms WHERE b = ? AND read = 0').get(me).n,
  pmInbox: me => db.prepare('SELECT t.other, p.text, p.file, p.ts, p.a, (SELECT COUNT(*) FROM pms x WHERE x.b = ? AND x.a = t.other AND x.read = 0) unread, u.username name, u.deco, u.avatar av, u.frame fr FROM (SELECT CASE WHEN a = ? THEN b ELSE a END other, MAX(id) mid FROM pms WHERE a = ? OR b = ? GROUP BY other) t JOIN pms p ON p.id = t.mid JOIN users u ON u.id = t.other ORDER BY p.id DESC LIMIT 40').all(me, me, me, me),
  // قايمة التجاهل (على مستوى السيرفر)
  ignoreList: uid => db.prepare('SELECT i.target uid, u.username name FROM ignores i JOIN users u ON u.id = i.target WHERE i.uid = ?').all(uid),
  ignoreSet(uid, target, on) { if (on) { if (db.prepare('SELECT COUNT(*) n FROM ignores WHERE uid = ?').get(uid).n >= 200) return false; db.prepare('INSERT OR IGNORE INTO ignores(uid,target) VALUES(?,?)').run(uid, target); } else db.prepare('DELETE FROM ignores WHERE uid = ? AND target = ?').run(uid, target); return true; },
  isIgnoring: (uid, target) => !!db.prepare('SELECT 1 x FROM ignores WHERE uid = ? AND target = ?').get(uid, target),
  regBlocked: ip => !!ip && !!db.prepare("SELECT 1 x FROM blocks WHERE kind = 'reg' AND value = ? AND until > ?").get(ip, now()),
  audit: (actor, action, target, details) => db.prepare('INSERT INTO audit(actor,action,target,details,ts) VALUES(?,?,?,?,?)').run(actor, action, target ?? null, details ?? null, now()),
  prune() {
    db.prepare('DELETE FROM messages WHERE ts < ?').run(now() - 7 * 864e5);
    const old = db.prepare("SELECT url FROM uploads WHERE kind = 'msg' AND ts < ?").all(now() - 7 * 864e5).map(r => r.url);
    db.prepare("DELETE FROM uploads WHERE kind = 'msg' AND ts < ?").run(now() - 7 * 864e5);
    db.prepare('DELETE FROM sessions WHERE created_at < ?').run(now() - 30 * 864e5);
    db.prepare('DELETE FROM visits WHERE ts < ?').run(now() - 90 * 864e5);
    db.prepare('DELETE FROM profile_visits WHERE ts < ?').run(now() - 90 * 864e5);
    db.prepare('DELETE FROM activity WHERE day < ?').run(new Date(now() - 90 * 864e5).toISOString().slice(0, 10));
    db.prepare('DELETE FROM notifs WHERE ts < ?').run(now() - 60 * 864e5);
    db.prepare('DELETE FROM audit WHERE ts < ?').run(now() - 180 * 864e5);
    db.prepare('DELETE FROM blocks WHERE until < ?').run(now());
    db.prepare('DELETE FROM pms WHERE ts < ?').run(now() - 30 * 864e5);
    db.prepare('DELETE FROM reports WHERE status != \'open\' AND ts < ?').run(now() - 90 * 864e5);
    return old;
  },
  usedBytes: uid => db.prepare('SELECT COALESCE(SUM(size),0) s FROM uploads WHERE user_id = ? AND ts > ?').get(uid, now() - 864e5).s,
  totalBytes: () => db.prepare('SELECT COALESCE(SUM(size),0) s FROM uploads').get().s,
};
