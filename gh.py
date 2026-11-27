import json, re, urllib.request, urllib.error
SELF='xrsameh-wacs'
def api(path):
    r=urllib.request.Request('https://api.github.com'+path,headers={'User-Agent':'osint-hub-bot/1.0','Accept':'application/vnd.github+json'})
    try: return json.loads(urllib.request.urlopen(r,timeout=25).read())
    except urllib.error.HTTPError as e:
        if e.code==404: raise LookupError('مش موجود. اتأكد من الاسم.')
        if e.code in(403,429): raise RuntimeError('وصلنا لحد الطلبات المجاني من جيت هب (60 في الساعة). جرب بعد شوية.')
        raise RuntimeError('جيت هب مش بيرد دلوقتي، جرب بعد شوية.')
    except Exception: raise RuntimeError('تعذر الاتصال بجيت هب دلوقتي، جرب بعد شوية.')
OKN=re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')
OKR=re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$')
def d(s): return (s or 'غير متاح')[:10]
def user(n):
    if not OKN.match(n): return 'اسم مستخدم غير صالح.'
    u=api('/users/'+n)
    return '👤 %s (%s)\n• الاسم المعروض: %s\n• مستودعات عامة: %s\n• متابعين: %s | بيتابع: %s\n• تاريخ الإنشاء: %s\n• الرابط: %s\nالمصدر: GitHub API (بيانات عامة)'%(u['login'],u['type'],u.get('name') or 'غير متاح',u['public_repos'],u['followers'],u['following'],d(u['created_at']),u['html_url'])
def repos(n):
    if not OKN.match(n): return 'اسم مستخدم غير صالح.'
    l=api('/users/%s/repos?per_page=15&sort=pushed'%n)
    if not l: return 'مفيش مستودعات عامة.'
    return '📦 آخر مستودعات %s:\n\n'%n+'\n'.join('• %s | %s | ⭐%s | آخر دفع %s'%(r['name'],r.get('language') or 'غير متاح',r['stargazers_count'],d(r['pushed_at'])) for r in l)+'\nالمصدر: GitHub API (بيانات عامة)'
def repo(o):
    if not OKR.match(o): return 'اكتب المستودع بالشكل: صاحب/اسم مثال: torvalds/linux'
    r=api('/repos/'+o)
    return 'ℹ️ %s\n• الوصف: %s\n• اللغة: %s\n• ⭐ %s | 🍴 %s | مشاكل مفتوحة: %s\n• الرخصة: %s\n• إنشاء: %s | آخر دفع: %s\n• الفرع الأساسي: %s | مؤرشف: %s\n• الموضوعات: %s\n• %s\nالمصدر: GitHub API (بيانات عامة)'%(r['full_name'],r.get('description') or 'غير متاح',r.get('language') or 'غير متاح',r['stargazers_count'],r['forks_count'],r['open_issues_count'],(r.get('license') or {}).get('spdx_id') or 'غير متاح',d(r['created_at']),d(r['pushed_at']),r['default_branch'],'أيوه' if r['archived'] else 'لأ',', '.join(r.get('topics') or []) or 'غير متاح',r['html_url'])
def commits(o):
    if not OKR.match(o): return 'اكتب المستودع بالشكل: صاحب/اسم'
    l=api('/repos/%s/commits?per_page=10'%o)
    return '🕒 آخر commits في %s:\n\n'%o+'\n'.join('• %s | %s | %s'%(c['sha'][:7],d(c['commit']['author']['date']),c['commit']['message'].split('\n')[0][:70]) for c in l)+'\nالمصدر: GitHub API (بدون عرض إيميلات الأشخاص)'
RISK=re.compile(r'(^|/)(\.env(\..*)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.npmrc|\.pypirc|\.htpasswd|\.git-credentials|wp-config\.php|credentials(\.json)?|secrets?\.(json|ya?ml|txt)|\.aws/credentials|terraform\.tfstate)$|\.(pem|p12|pfx|key|kdbx|jks|keystore|sqlite3?|sql\.gz)$',re.I)
def files(o):
    if not OKR.match(o): return 'اكتب المستودع بالشكل: صاحب/اسم'
    r=api('/repos/'+o); t=api('/repos/%s/git/trees/%s?recursive=1'%(o,r['default_branch']))
    hit=[x['path'] for x in t.get('tree',[]) if x['type']=='blob' and RISK.search(x['path'])]
    s='🔑 فحص أسماء الملفات الحساسة في %s (أسماء فقط، بدون قراءة محتوى):\n'%o
    s+=('⚠️ ملفات تستحق المراجعة:\n'+'\n'.join('• '+h for h in hit[:25])) if hit else '✅ مفيش أسماء ملفات حساسة معروفة.'
    if t.get('truncated'): s+='\n(المستودع كبير، الفحص جزئي)'
    return s+'\nملاحظة: ده تلميح بالأسماء فقط، مش دليل على تسريب فعلي.'
def myemail():
    ev=api('/users/%s/events/public?per_page=30'%SELF); em={}
    for e in ev:
        if e.get('type')=='PushEvent':
            for c in e['payload'].get('commits',[]): em[c['author']['email']]=em.get(c['author']['email'],0)+1
    if not em: return '📧 مفيش commits حديثة في النشاط العام لحسابك.'
    bad=[k for k in em if 'noreply.github.com' not in k]
    s='📧 فحص ظهور إيميلك في commits حسابك (%s) آخر نشاط عام:\n'%SELF+'\n'.join('• %s (%d)'%(k,v) for k,v in em.items())
    return s+('\n⚠️ فيه إيميل حقيقي ظاهر للعامة. فعّل "Keep my email private" و"Block command line pushes that expose my email" من إعدادات جيت هب.' if bad else '\n✅ كله إيميلات noreply (مخفية).')
def run(cmd,arg):
    arg=arg.strip()
    f={'user':user,'repos':repos,'repo':repo,'commits':commits,'files':files}
    if cmd=='myemail': return myemail()
    if cmd in f:
        if not arg: return 'اكتب الاسم بعد الأمر.'
        return f[cmd](arg)
    return None
