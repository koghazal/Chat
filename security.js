// أدوات الأمان: حدود المعدل، تنظيف الأسماء، كلمات المرور، فحص الملفات، رؤوس الحماية
const crypto = require('crypto');
const env = (k, d) => { const v = Number(process.env[k]); return Number.isFinite(v) && v > 0 ? v : d; };

exports.CFG = {
  connPerIp: env('RL_CONN_PER_IP', 20),          // اتصالات متزامنة لكل ايبي
  connTotal: env('RL_CONN_TOTAL', 3000),        // اجمالي الاتصالات
  connRate: env('RL_CONN_RATE', 30),            // محاولات اتصال جديدة لكل ايبي كل دقيقة
  burst: env('RL_MSG_BURST', 30),               // حجم دفعة الرسائل لكل اتصال
  perSec: env('RL_MSG_PER_SEC', 10),            // معدل الرسائل في الثانية
  authFailIp: env('RL_AUTH_FAIL_IP', 10),       // محاولات دخول فاشلة لكل ايبي قبل القفل
  authFailAcct: env('RL_AUTH_FAIL_ACCT', 6),    // محاولات فاشلة لكل حساب+ايبي
  authFailAcctAll: env('RL_AUTH_FAIL_ACCT_ALL', 30), // محاولات فاشلة على حساب من كل الأيبيات في الساعة
  lockMin: env('RL_AUTH_LOCK_MIN', 10),
  regPerHour: env('RL_REG_PER_HOUR', 5),        // حسابات جديدة لكل ايبي في الساعة
  uploadsPerDayMember: env('UPLOAD_QUOTA_MB', 50) * 1e6,
  uploadsPerDayGuest: env('UPLOAD_QUOTA_GUEST_MB', 15) * 1e6,
  storageCap: env('STORAGE_CAP_MB', 2000) * 1e6,
  authTimeout: env('AUTH_TIMEOUT_MS', 60000),
};

// نافذة منزلقة: عدّاد أحداث لكل مفتاح
exports.Window = class {
  constructor(ms, max) { this.ms = ms; this.max = max; this.m = new Map(); }
  _p(k) { const n = Date.now(), a = (this.m.get(k) || []).filter(t => n - t < this.ms); if (a.length) this.m.set(k, a); else this.m.delete(k); return a; }
  hit(k) { const a = this._p(k); a.push(Date.now()); this.m.set(k, a); return a.length; }
  count(k) { return this._p(k).length; }
  full(k) { return this.count(k) >= this.max; }
  reset(k) { this.m.delete(k); }
  retry(k) { const a = this._p(k); return a.length ? Math.max(1, Math.ceil((a[0] + this.ms - Date.now()) / 1000)) : 0; }
  sweep() { for (const k of [...this.m.keys()]) this._p(k); }
};

// دلو رموز للرسائل لكل اتصال
exports.bucket = (burst, perSec) => { let tok = burst, last = Date.now(); return () => { const n = Date.now(); tok = Math.min(burst, tok + (n - last) / 1000 * perSec); last = n; if (tok < 1) return false; tok--; return true; }; };

// تنظيف النصوص: حذف محارف التحكم والتنسيق والحروف المخفية
const INVIS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}ᅟᅠㅤﾠ᠎⠀͏︎️]/gu;
exports.cleanName = s => String(s ?? '').normalize('NFC').replace(INVIS, '').replace(/\p{M}{3,}/gu, m => m.slice(0, 2)).replace(/\s+/g, ' ').trim();
exports.cleanText = s => String(s ?? '').normalize('NFC').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}ᅟᅠㅤﾠ᠎]/gu, c => c === '‍' || c === '‌' ? c : '').replace(/\p{M}{4,}/gu, m => m.slice(0, 3)).trim();

// بصمة الاسم: تمنع انتحال الأسماء بحروف متشابهة أو مسافات أو تشكيل
const CONF = { а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ɡ: 'g', ο: 'o', ν: 'v', ι: 'i', κ: 'k', α: 'a', ε: 'e', 'ı': 'i', '0': 'o', '1': 'l', 'ǀ': 'l' };
exports.skeleton = s => [...String(s ?? '').normalize('NFKC').toLowerCase()]
  .map(c => CONF[c] || c).join('')
  .replace(/[ً-ٰٟـ]/g, '')
  .replace(/[أإآٱ]/g, 'ا').replace(/[ىي]/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي')
  .replace(/[\s_\-.]+/g, '').replace(/\p{M}/gu, '');

const COMMON = new Set(['12345678', '123456789', '1234567890', 'password', 'password1', 'qwerty123', 'qwertyuiop', '11111111', '00000000', 'iloveyou', '12341234', 'abc12345', 'asdfghjkl', '987654321', '123123123', 'samar123', 'misk123', 'مرحبا123', '1q2w3e4r', 'zaq12wsx', 'password123', 'admin123', 'letmein1']);
exports.badPassword = (p, name = '') => {
  p = String(p ?? '');
  if (p.length < 8) return 'كلمة المرور لازم تكون 8 أحرف على الأقل';
  if (p.length > 72) return 'كلمة المرور طويلة (الحد 72 حرف)';
  if (COMMON.has(p.toLowerCase()) || /^(.)\1+$/.test(p)) return 'كلمة المرور ضعيفة ومعروفة، اختار غيرها';
  if (name && p.toLowerCase() === String(name).toLowerCase()) return 'كلمة المرور لا يجوز تكون نفس الاسم';
  if (!/\p{L}/u.test(p) && !/\d/.test(p)) return 'كلمة المرور لازم تحتوي على حروف أو أرقام';
  return '';
};

// فحص محتوى الملف الحقيقي (magic bytes) حسب الامتداد
const s4 = (b, o, n) => b.toString('latin1', o, o + n);
const V = {
  png: b => b[0] === 0x89 && s4(b, 1, 3) === 'PNG',
  jpg: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  gif: b => s4(b, 0, 4) === 'GIF8',
  webp: b => s4(b, 0, 4) === 'RIFF' && s4(b, 8, 4) === 'WEBP',
  pdf: b => s4(b, 0, 5) === '%PDF-',
  zip: b => s4(b, 0, 2) === 'PK' && (b[2] === 3 || b[2] === 5) ,
  mp3: b => s4(b, 0, 3) === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0),
  ogg: b => s4(b, 0, 4) === 'OggS',
  wav: b => s4(b, 0, 4) === 'RIFF' && s4(b, 8, 4) === 'WAVE',
  m4a: b => s4(b, 4, 4) === 'ftyp',
  mp4: b => s4(b, 4, 4) === 'ftyp',
  webm: b => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3,
  txt: b => { try { new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, 8192)); return !b.subarray(0, 8192).includes(0); } catch { return false; } },
};
V.docx = V.xlsx = V.zip;
exports.validFile = (ext, buf) => !!V[ext] && buf.length > 0 && V[ext](buf);
// توحيد الأرقام العربية والفارسية إلى 0-9 (س١ = س1)
exports.normDigits = s => String(s ?? '').replace(/[\u0660-\u0669]/g, c => c.charCodeAt(0) - 0x0660).replace(/[\u06f0-\u06f9]/g, c => c.charCodeAt(0) - 0x06f0);
// نوع الصورة الحقيقي
exports.imageType = buf => ['png', 'jpg', 'gif', 'webp'].find(k => buf.length > 12 && V[k](buf)) || '';

// رؤوس الحماية
exports.baseHeaders = https => ({
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
  ...(https ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
});
exports.csp = html => {
  const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`);
  return ["default-src 'none'", `script-src ${hashes.join(' ') || "'none'"}`, "style-src 'unsafe-inline' https://fonts.googleapis.com", 'font-src https://fonts.gstatic.com',
    "img-src 'self' data: blob:", "media-src 'self' blob:", "connect-src 'self' ws: wss:", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'", "object-src 'none'"].join('; ');
};

// فحص الأصل (Origin) للحماية من CSWSH و CSRF
exports.sameOrigin = req => {
  const o = req.headers.origin; if (!o) return true;
  try {
    const u = new URL(o), host = String(req.headers.host || '').toLowerCase();
    if (u.host.toLowerCase() === host) return true;
    return (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean).includes(u.origin.toLowerCase());
  } catch { return false; }
};
