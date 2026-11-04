// أدوات الشبكة: الايبي، الدولة، الجهاز، المتصفح
let geo = null; try { geo = require('geoip-lite'); } catch {}
const dn = (() => { try { return new Intl.DisplayNames(['ar'], { type: 'region' }); } catch { return null; } })();

exports.countryName = c => { if (c === 'PS' || c === 'IL') return 'فلسطين'; try { return c && dn ? dn.of(c) : c || ''; } catch { return c || ''; } };

// TRUST_PROXY: none (الافتراضي: عنوان الاتصال الفعلي فقط) | cloudflare | عدد (عدد البروكسيات الموثوقة قبل السيرفر)
const TP = String(process.env.TRUST_PROXY || 'none').toLowerCase();
const valid = ip => /^[0-9a-f:.]{2,45}$/i.test(ip);
exports.clientIp = req => {
  const h = req.headers, sock = String(req.socket.remoteAddress || '');
  let ip = sock;
  if (TP === 'cloudflare' && h['cf-connecting-ip']) ip = String(h['cf-connecting-ip']).trim();
  else if (/^\d+$/.test(TP) && Number(TP) > 0 && h['x-forwarded-for']) { const l = String(h['x-forwarded-for']).split(',').map(x => x.trim()); ip = l[Math.max(0, l.length - Number(TP))] || sock; }
  ip = ip.replace(/^::ffff:/, '').slice(0, 45);
  return valid(ip) ? ip : sock.replace(/^::ffff:/, '').slice(0, 45);
};
exports.isHttps = req => !!req.socket.encrypted || (TP !== 'none' && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');

const fixCC = c => (c === 'IL' ? 'PS' : c);
exports.clientCountry = (req, ip) => fixCC(rawCountry(req, ip));
const rawCountry = (req, ip) => {
  const c = TP === 'cloudflare' ? String(req.headers['cf-ipcountry'] || '').toUpperCase() : '';
  if (/^[A-Z]{2}$/.test(c) && c !== 'XX') return c;
  try { return geo?.lookup(ip)?.country || ''; } catch { return ''; }
};

exports.parseUA = (ua = '') => {
  ua = String(ua).slice(0, 400);
  let os = 'غير معروف', m;
  if ((m = /Android\s([\d.]+)/i.exec(ua))) os = 'Android ' + m[1];
  else if (/Android/i.test(ua)) os = 'Android';
  else if ((m = /(?:iPhone|CPU) OS (\d+)[_.](\d+)/i.exec(ua))) os = 'iOS ' + m[1] + '.' + m[2];
  else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
  else if ((m = /Windows NT ([\d.]+)/i.exec(ua))) os = 'Windows ' + ({ '10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7' }[m[1]] || m[1]);
  else if (/Mac OS X|Macintosh/i.test(ua)) os = 'macOS';
  else if (/CrOS/i.test(ua)) os = 'ChromeOS';
  else if (/Linux/i.test(ua)) os = 'Linux';
  const type = /iPad|Tablet/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua)) ? 'تابلت' : /Mobi|iPhone|Android/i.test(ua) ? 'موبايل' : 'كمبيوتر';
  const model = /iPhone/i.test(ua) ? 'iPhone' : /iPad/i.test(ua) ? 'iPad' : (/Android[\s\d.]*;\s*([^;)]+)/.exec(ua)?.[1] || '').replace(/\s*Build.*/i, '').trim().slice(0, 40);
  let bname = 'غير معروف', bver = '';
  for (const [re, n] of [[/SamsungBrowser\/([\d.]+)/, 'Samsung Browser'], [/Edg(?:e|A|iOS)?\/([\d.]+)/, 'Edge'], [/(?:OPR|Opera)\/([\d.]+)/, 'Opera'], [/(?:Firefox|FxiOS)\/([\d.]+)/, 'Firefox'], [/(?:Chrome|CriOS)\/([\d.]+)/, 'Chrome'], [/Version\/([\d.]+).*Safari/, 'Safari']]) {
    const x = re.exec(ua); if (x) { bname = n; bver = x[1].split('.')[0]; break; }
  }
  const webview = /; wv\)|FBAN|FBAV|Instagram|Line\//i.test(ua) ? ' (داخل تطبيق)' : '';
  return { device: `${type} - ${os}${model ? ` (${model})` : ''}`.slice(0, 80), browser: bname === 'غير معروف' ? bname : `${bname} ${bver}${webview}`, devType: type, os, model, bname, bver };
};
