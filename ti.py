# Threat-intel API clients: AbuseIPDB, AlienVault OTX, VirusTotal.
# Keys come from the environment only (ABUSEIPDB_API_KEY / OTX_API_KEY /
# VIRUSTOTAL_API_KEY). When a key is absent the provider is skipped
# silently and callers keep exactly their previous behaviour.
# Responses are cached in the existing SQLite DB, and each provider has
# a conservative self-imposed daily cap BELOW its published free limit:
#   AbuseIPDB  free 1000 checks/day      -> self cap 900/day,  cache 6h
#   VirusTotal free 500/day, 4/min      -> self cap 450/day,  cache 12h, min gap 16s
#   OTX        free account, generous   -> self cap 2000/day, cache 6h
# Only IPs, domains and file hashes are accepted (strict validation).
import json, os, re, time, urllib.parse, urllib.request, urllib.error

TTL = {'abuseipdb': 21600, 'otx': 21600, 'virustotal': 43200}
CAPS = {'abuseipdb': 900, 'otx': 2000, 'virustotal': 450}
VT_MIN_GAP = 16
IP_RE = r'(\d{1,3}\.){3}\d{1,3}'
DOM_RE = r'([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}'
HASH_RE = r'([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})'
ENV = {'abuseipdb': 'ABUSEIPDB_API_KEY', 'otx': 'OTX_API_KEY', 'virustotal': 'VIRUSTOTAL_API_KEY'}
LIMIT_AR = {'abuseipdb': 'الحد المجاني الرسمي: 1000 فحص/يوم',
            'otx': 'حساب مجاني بحدود سخية (البوت حاطط لنفسه حد محافظ 2000 طلب/يوم)',
            'virustotal': 'الحد المجاني الرسمي: 500 طلب/يوم و4 طلبات/دقيقة'}


def _fetch(url, headers, timeout=20):
    r = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(r, timeout=timeout).read()


def _db():
    from lib import db
    c = db()
    c.execute('create table if not exists ti_cache(provider text, query text, ts integer, payload text, primary key(provider,query))')
    c.execute('create table if not exists ti_usage(provider text, day text, count integer, last integer, primary key(provider,day))')
    return c


def _key(prov):
    return (os.environ.get(ENV[prov]) or '').strip()


def configured():
    return {p: bool(_key(p)) for p in ENV}


def not_configured(prov):
    names = {'abuseipdb': 'AbuseIPDB', 'otx': 'AlienVault OTX', 'virustotal': 'VirusTotal'}
    return ('⚠️ %s مش مفعّلة على البوت: مفيش مفتاح API مضاف (%s). '
            'المفتاح مجاني — %s. أول ما المفتاح يتضاف في إعدادات Render الأداة هتشتغل هنا على طول.'
            % (names[prov], ENV[prov], LIMIT_AR[prov]))


def kind_of(v):
    v = (v or '').strip().lower()
    if re.fullmatch(IP_RE, v):
        return 'ip'
    if re.fullmatch(HASH_RE, v):
        return 'hash'
    if re.fullmatch(DOM_RE, v):
        return 'domain'
    return None


def _call(prov, q, url, headers):
    c = _db()
    r = c.execute('select ts,payload from ti_cache where provider=? and query=?', (prov, q)).fetchone()
    if r and time.time() - r[0] < TTL[prov]:
        return json.loads(r[1])
    day = time.strftime('%Y-%m-%d', time.gmtime())
    u = c.execute('select count,last from ti_usage where provider=? and day=?', (prov, day)).fetchone()
    n, last = (u[0], u[1]) if u else (0, 0)
    if n >= CAPS[prov]:
        return {'_limited': True}
    if prov == 'virustotal' and time.time() - last < VT_MIN_GAP:
        return {'_limited': True}
    c.execute('insert or replace into ti_usage values(?,?,?,?)', (prov, day, n + 1, int(time.time())))
    c.commit()
    try:
        j = json.loads(_fetch(url, headers))
    except urllib.error.HTTPError as e:
        return {'_error': e.code}
    except Exception:
        return {'_error': 0}
    c.execute('insert or replace into ti_cache values(?,?,?,?)', (prov, q, int(time.time()), json.dumps(j)))
    c.commit()
    return j


def _err(prov, name, j):
    if j.get('_limited'):
        return '🛡 %s: وصلنا للحد المحافظ اللي البوت حاطه لنفسه النهاردة (%s). جرب بكرة.' % (name, LIMIT_AR[prov])
    return '🛡 %s: الخدمة مش بترد دلوقتي (كود %s). جرب بعد شوية.' % (name, j.get('_error'))


def abuseipdb(ip):
    if not _key('abuseipdb'):
        return None
    ip = (ip or '').strip()
    if not re.fullmatch(IP_RE, ip):
        return '⚠️ AbuseIPDB بيشتغل على عناوين IP بس — اكتب عنوان IPv4 صحيح.'
    j = _call('abuseipdb', ip,
              'https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90' % ip,
              {'Key': _key('abuseipdb'), 'Accept': 'application/json', 'User-Agent': 'osint-hub-bot'})
    if '_error' in j or '_limited' in j:
        return _err('abuseipdb', 'AbuseIPDB', j)
    d = j.get('data') or {}
    sc = d.get('abuseConfidenceScore')
    verdict = 'نضيف — مفيش بلاغات' if sc == 0 else 'مشتبه بقوة' if (sc or 0) >= 75 else 'فيه بلاغات إساءة' if (sc or 0) >= 25 else 'بلاغات قليلة'
    return '\n'.join([
        '🛡 سمعة %s على AbuseIPDB:' % ip,
        '• درجة الخطورة: %s/100 — %s' % (sc if sc is not None else 'غير متاح', verdict),
        '• بلاغات الإساءة: %s (من %s مستخدم مختلف)' % (d.get('totalReports', 'غير متاح'), d.get('numDistinctUsers', 'غير متاح')),
        '• آخر بلاغ: %s' % ((d.get('lastReportedAt') or 'لا يوجد')[:10]),
        '• الشركة/النوع: %s | %s' % (d.get('isp') or 'غير متاح', d.get('usageType') or 'غير متاح'),
        '• الدولة: %s | خروج Tor: %s' % (d.get('countryCode') or 'غير متاح', 'أيوه' if d.get('isTor') else 'لا')])


def _otx(kind, value):
    if not _key('otx'):
        return None
    j = _call('otx', kind + ':' + value,
              'https://otx.alienvault.com/api/v1/indicators/%s/%s/general' % (kind, urllib.parse.quote(value, safe='')),
              {'X-OTX-API-KEY': _key('otx'), 'User-Agent': 'osint-hub-bot'})
    if '_error' in j or '_limited' in j:
        return _err('otx', 'AlienVault OTX', j)
    pi = j.get('pulse_info') or {}
    cnt = pi.get('count', 0)
    L = ['🧬 AlienVault OTX عن %s:' % value,
         '• تقارير تهديد (Pulses) مرتبطة: %s' % cnt]
    for p in (pi.get('pulses') or [])[:3]:
        L.append('• %s (%s)' % (p.get('name', 'بدون اسم'), (p.get('created') or '')[:10]))
    if j.get('reputation'):
        L.append('• درجة السمعة عند OTX: %s (سالب = بلاغات ضده)' % j['reputation'])
    if j.get('country_name'):
        L.append('• الدولة: %s' % j['country_name'])
    if cnt == 0:
        L.append('مفيش تقارير مجتمعية مرتبطة بالمؤشر ده (مش معناه إنه آمن).')
    return '\n'.join(L)


def _vt(kind, value):
    if not _key('virustotal'):
        return None
    j = _call('virustotal', kind + ':' + value,
              'https://www.virustotal.com/api/v3/%s/%s' % (kind, value),
              {'x-apikey': _key('virustotal'), 'User-Agent': 'osint-hub-bot'})
    if '_error' in j:
        if j['_error'] == 404:
            return '🦠 VirusTotal: مفيش تقرير محفوظ عن المؤشر ده.'
        return _err('virustotal', 'VirusTotal', j)
    if '_limited' in j:
        return _err('virustotal', 'VirusTotal', j)
    a = (j.get('data') or {}).get('attributes') or {}
    s = a.get('last_analysis_stats') or {}
    mal = s.get('malicious', 0)
    L = ['🦠 VirusTotal عن %s:' % value,
         '• محركات شايفاه خبيث: %s | مشبوه: %s | نضيف: %s | مشافهوش: %s' % (mal, s.get('suspicious', 0), s.get('harmless', 0), s.get('undetected', 0)),
         '• الحكم: %s' % ('🔴 خبيث عند محركات كتير' if mal >= 5 else '🟡 فيه كشف محدود — راجع بنفسك' if mal > 0 else '🟢 مفيش كشف خبيث مسجل')]
    if a.get('reputation') is not None:
        L.append('• سمعة المجتمع: %s' % a['reputation'])
    if a.get('as_owner'):
        L.append('• مالك الـ AS: %s' % a['as_owner'])
    if a.get('registrar'):
        L.append('• المسجّل: %s' % a['registrar'])
    return '\n'.join(L)


def otx_auto(value):
    k = kind_of(value)
    if k == 'ip':
        return _otx('IPv4', value.strip().lower())
    if k == 'domain':
        return _otx('domain', value.strip().lower())
    if k == 'hash':
        return _otx('file', value.strip().lower())
    return '⚠️ اكتب IP أو دومين أو هاش ملف (MD5/SHA-1/SHA-256) صحيح.'


def vt_auto(value):
    k = kind_of(value)
    if k == 'ip':
        return _vt('ip_addresses', value.strip().lower())
    if k == 'domain':
        return _vt('domains', value.strip().lower())
    if k == 'hash':
        return _vt('files', value.strip().lower())
    return None


def ip_sections(ip):
    if kind_of(ip) != 'ip':
        return []
    out = []
    for fn in (abuseipdb, lambda x: _otx('IPv4', x), lambda x: _vt('ip_addresses', x)):
        try:
            s = fn((ip or '').strip())
        except Exception:
            s = None
        if s:
            out.append(s)
    return out


def ioc_sections(value):
    k = kind_of(value)
    if not k:
        return []
    v = (value or '').strip().lower()
    out = []
    fns = []
    if k == 'ip':
        return ip_sections(v)
    if k == 'domain':
        fns = [lambda: _otx('domain', v), lambda: _vt('domains', v)]
    if k == 'hash':
        fns = [lambda: _otx('file', v), lambda: _vt('files', v)]
    for fn in fns:
        try:
            s = fn()
        except Exception:
            s = None
        if s:
            out.append(s)
    return out
