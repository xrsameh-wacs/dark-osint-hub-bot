import hashlib,math,re,struct,zipfile,io,datetime
SUSP={'VirtualAlloc':'حجز ذاكرة (شائع في الحقن)','VirtualAllocEx':'حجز ذاكرة في عملية تانية','WriteProcessMemory':'كتابة في ذاكرة عملية تانية','CreateRemoteThread':'تشغيل كود داخل عملية تانية','SetWindowsHookExA':'تسجيل ضغطات/أحداث','SetWindowsHookExW':'تسجيل ضغطات/أحداث','GetAsyncKeyState':'مراقبة لوحة المفاتيح','URLDownloadToFileA':'تحميل ملف من النت','URLDownloadToFileW':'تحميل ملف من النت','WinExec':'تشغيل أوامر','ShellExecuteA':'تشغيل برنامج','ShellExecuteW':'تشغيل برنامج','IsDebuggerPresent':'كشف أدوات التحليل','CheckRemoteDebuggerPresent':'كشف أدوات التحليل','InternetOpenA':'اتصال بالإنترنت','InternetOpenW':'اتصال بالإنترنت','InternetOpenUrlA':'اتصال بالإنترنت','RegSetValueExA':'تعديل الريجستري','RegSetValueExW':'تعديل الريجستري','CryptEncrypt':'تشفير بيانات','AdjustTokenPrivileges':'رفع صلاحيات','OpenProcess':'فتح عملية تانية','NtUnmapViewOfSection':'تقنية process hollowing','ptrace':'تتبع عمليات','execve':'تشغيل برنامج','system':'تشغيل أوامر نظام','dlopen':'تحميل مكتبات وقت التشغيل'}
def ent(b):
    if not b: return 0.0
    n=len(b); c=[0]*256
    for x in b: c[x]+=1
    return -sum(v/n*math.log2(v/n) for v in c if v)
def hashes(d): return hashlib.md5(d).hexdigest(),hashlib.sha1(d).hexdigest(),hashlib.sha256(d).hexdigest()
def kind(d):
    if d[:2]==b'MZ': return 'pe'
    if d[:4]==b'\x7fELF': return 'elf'
    if d[:4]==b'%PDF': return 'pdf'
    if d[:2]==b'PK': return 'zip'
    if d[:2]==b'#!': return 'script'
    if d[:4] in(b'\xca\xfe\xba\xbe',b'\xcf\xfa\xed\xfe'): return 'macho'
    if d[:8]==b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': return 'ole'
    return 'other'
NAMES={'pe':'ملف تنفيذي ويندوز (PE)','elf':'ملف تنفيذي لينكس (ELF)','pdf':'مستند PDF','zip':'أرشيف ZIP أو مستند أوفيس حديث أو APK أو JAR','script':'سكربت نصي','macho':'ملف تنفيذي ماك','ole':'مستند أوفيس قديم (OLE)','other':'نوع غير معروف أو بيانات خام'}
def strings(d,n=6):
    return [m.group().decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{%d,}'%n,d[:8000000])]
def pe(d):
    out=[];sc=0;imps=[]
    try:
        o=struct.unpack_from('<I',d,0x3c)[0]
        if d[o:o+4]!=b'PE\0\0': return ['هيكل PE غير سليم'],1,[]
        mach,ns,ts,_,_,osz,ch=struct.unpack_from('<HHIIIHH',d,o+4)
        MM={0x14c:'x86 (32 بت)',0x8664:'x64 (64 بت)',0x1c0:'ARM',0xaa64:'ARM64'}
        opt=o+24; magic=struct.unpack_from('<H',d,opt)[0]; p32=magic==0x10b
        sub=struct.unpack_from('<H',d,opt+68)[0]
        dd=opt+(96 if p32 else 112)
        out.append('المعمارية: %s | %s | أقسام: %d'%(MM.get(mach,hex(mach)),'DLL' if ch&0x2000 else 'EXE',ns))
        try: out.append('تاريخ التجميع (في الترويسة، ممكن يتزور): '+datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d'))
        except Exception: pass
        out.append('الواجهة: '+{2:'نافذة رسومية',3:'سطر أوامر'}.get(sub,'غير محددة'))
        so=opt+osz; secs=[]
        for i in range(ns):
            nm,vs,va,rs,ro=struct.unpack_from('<8sIIII',d,so+40*i)
            nm=nm.rstrip(b'\0').decode('latin1','replace'); secs.append((nm,va,vs,ro,rs,ent(d[ro:ro+rs])))
        out.append('الأقسام:')
        for nm,va,vs,ro,rs,e in secs:
            tag=''
            if e>7.2: tag=' ⚠️ مضغوط أو مشفر غالبا'; sc+=2
            out.append('  • %s حجم %d إنتروبي %.2f%s'%(nm,rs,e,tag))
            if nm.lower().startswith(('upx','.aspack','.themida','.vmp')): out.append('  ⚠️ اسم قسم مرتبط بأداة تغليف (%s)'%nm); sc+=2
        def off(rva):
            for nm,va,vs,ro,rs,e in secs:
                if va<=rva<va+max(vs,rs): return rva-va+ro
            return None
        irva=struct.unpack_from('<I',d,dd+8)[0]; io_=off(irva) if irva else None
        if io_:
            k=io_
            while k+20<=len(d):
                oft,_,_,nrva,ft=struct.unpack_from('<IIIII',d,k)
                if not nrva: break
                t=off(oft or ft); step=4 if p32 else 8
                n=0
                while t and n<400:
                    v=int.from_bytes(d[t:t+step],'little')
                    if not v: break
                    if not v>>(step*8-1):
                        h=off(v&0x7fffffff)
                        if h: imps.append(d[h+2:h+80].split(b'\0')[0].decode('latin1'))
                    t+=step; n+=1
                k+=20
        out.append('الدوال المستوردة: %d'%len(imps))
        if len(imps)<10: out.append('⚠️ استيراد قليل جدا (علامة تغليف أو تحميل ديناميكي)'); sc+=1
        hit=[(a,SUSP[a]) for a in imps if a in SUSP]
        for a,w in hit[:12]: out.append('  ⚠️ %s: %s'%(a,w))
        sc+=min(len(hit),6)
    except Exception: out.append('تعذر قراءة جزء من الترويسة (الملف تالف أو مقطوع).'); sc+=1
    return out,sc,imps
def elf(d):
    out=[];sc=0;imps=[]
    try:
        c64=d[4]==2; le='<' if d[5]==1 else '>'
        t,m=struct.unpack_from(le+'HH',d,16)
        MA={3:'x86',62:'x86-64',40:'ARM',183:'ARM64',8:'MIPS',243:'RISC-V'}
        out.append('%s | %s | %s'%('64 بت' if c64 else '32 بت',MA.get(m,str(m)),{1:'ملف كائن',2:'تنفيذي',3:'مشترك أو PIE'}.get(t,'?')))
        if c64: ent_,_,shoff=struct.unpack_from(le+'QQQ',d,24); shent,shnum,shstr=struct.unpack_from(le+'HHH',d,58)
        else: ent_,_,shoff=struct.unpack_from(le+'III',d,24); shent,shnum,shstr=struct.unpack_from(le+'HHH',d,46)
        out.append('نقطة البداية: 0x%x'%ent_)
        secs=[]
        for i in range(min(shnum,100)):
            b=shoff+i*shent
            if c64: nm,ty,fl,ad,of,sz,ln=struct.unpack_from(le+'IIQQQQI',d,b)
            else: nm,ty,fl,ad,of,sz,ln=struct.unpack_from(le+'IIIIIII',d,b)
            secs.append((nm,ty,of,sz,ln))
        if shnum and shstr<len(secs):
            so=secs[shstr][2]; names=[d[so+s[0]:so+s[0]+40].split(b'\0')[0].decode('latin1') for s in secs]
            out.append('الأقسام: '+' '.join(names[:30]))
            for n,s in zip(names,secs):
                e=ent(d[s[2]:s[2]+s[3]]) if s[1]!=8 else 0
                if e>7.2 and s[3]>2000 and 'hash' not in n and 'eh_frame' not in n: out.append('⚠️ قسم %s إنتروبي %.2f (مضغوط أو مشفر غالبا)'%(n,e)); sc+=2
            if any(n.startswith('UPX') for n in names) or d.find(b'UPX!')>0: out.append('⚠️ علامة UPX (مضغوط)'); sc+=2
        for nm,ty,of,sz,ln in secs:
            if ty==11 and ln<len(secs):
                st=secs[ln][2]; esz=24 if c64 else 16
                for j in range(1,min(sz//esz,800)):
                    r=of+j*esz; sn=struct.unpack_from(le+'I',d,r)[0]; shn=struct.unpack_from(le+'H',d,r+(6 if c64 else 14))[0]
                    if shn==0: imps.append(d[st+sn:st+sn+60].split(b'\0')[0].decode('latin1'))
        out.append('دوال مستوردة: %d'%len(imps))
        hit=[(a,SUSP[a]) for a in imps if a in SUSP]
        for a,w in hit[:10]: out.append('  • %s: %s'%(a,w))
        sc+=min(len([1 for a,w in hit if a in('ptrace','execve','system')]),3)
    except Exception: out.append('تعذر قراءة جزء من الترويسة.'); sc+=1
    return out,sc,imps
def zipinfo(d):
    out=[];sc=0
    try:
        z=zipfile.ZipFile(io.BytesIO(d)); n=z.namelist(); out.append('عدد الملفات داخل الأرشيف: %d'%len(n))
        if 'AndroidManifest.xml' in n: out.append('📱 تطبيق أندرويد (APK)')
        if any(x.endswith('vbaProject.bin') for x in n): out.append('⚠️ فيه ماكرو (VBA) داخل مستند أوفيس'); sc+=3
        if any(x.lower().endswith(('.exe','.dll','.js','.vbs','.bat','.scr')) for x in n): out.append('⚠️ فيه ملفات تنفيذية أو سكربتات داخله'); sc+=2
        if 'word/document.xml' in n:
            try:
                core=z.read('docProps/core.xml').decode('utf8','replace')
                for tag,lab in(('dc:creator','المؤلف'),('cp:lastModifiedBy','آخر تعديل بواسطة'),('dcterms:created','تاريخ الإنشاء'),('dcterms:modified','تاريخ آخر تعديل')):
                    m=re.search('<%s[^>]*>([^<]*)</%s>'%(tag,tag),core)
                    if m and m.group(1): out.append('%s: %s'%(lab,m.group(1)))
            except Exception: pass
        out.append('أمثلة: '+' ، '.join(n[:8]))
    except Exception: out.append('تعذر فتح الأرشيف.')
    return out,sc
def pdfinfo(d):
    out=[];sc=0
    for k,w in((b'/JavaScript','فيه جافاسكربت'),(b'/OpenAction','بيشغل إجراء عند الفتح'),(b'/Launch','بيحاول يشغل برنامج'),(b'/EmbeddedFile','فيه ملفات مدمجة'),(b'/URI','فيه روابط')):
        if k in d: out.append('• '+w); sc+=2 if k in(b'/Launch',b'/JavaScript') else 0
    for k,lab in((b'/Author','المؤلف'),(b'/Creator','أداة الإنشاء'),(b'/Producer','المنتج'),(b'/CreationDate','تاريخ الإنشاء')):
        m=re.search(re.escape(k)+rb'\s*\(([^)]{1,80})\)',d)
        if m: out.append('%s: %s'%(lab,m.group(1).decode('latin1')))
    return out or ['مفيش مؤشرات واضحة داخل هيكل PDF.'],sc
def analyze(d,fname=''):
    k=kind(d); m5,s1,s2=hashes(d); e=ent(d)
    L=['🔬 تحليل ساكن للملف (من غير تشغيله)','الاسم: %s | الحجم: %d بايت'%(fname or 'غير متاح',len(d)),'النوع: '+NAMES[k],'SHA-256: '+s2,'MD5: '+m5,'الإنتروبي العام: %.2f من 8 %s'%(e,'(عالي: مضغوط أو مشفر)' if e>7.2 else '')]
    xe=k in('pe','elf','macho','script')
    sc=2 if xe and e>7.4 and len(d)>5000 else 0
    if k=='pe': o,s,_=pe(d); L+=o; sc+=s
    elif k=='elf': o,s,_=elf(d); L+=o; sc+=s
    elif k=='zip': o,s=zipinfo(d); L+=o; sc+=s
    elif k=='pdf': o,s=pdfinfo(d); L+=o; sc+=s
    elif k=='ole' and (b'VBA' in d or b'Macros' in d): L.append('⚠️ فيه ماكرو محتمل'); sc+=3
    st=strings(d); L.append('نصوص مقروءة: %d'%len(st)); blob='\n'.join(st)
    urls=sorted(set(re.findall(r'https?://[^\s"\'<>]{4,80}',blob)))[:8]; ips=sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',blob)))[:8]
    if urls: L.append('روابط داخل الملف:\n'+'\n'.join('  • '+u for u in urls)); sc+=1 if xe else 0
    if ips: L.append('عناوين IP: '+' ، '.join(ips))
    kw=[w for w in('powershell','cmd.exe','/bin/sh','wget ','curl ','keylog','ransom','bitcoin','schtasks','CurrentVersion\\Run') if w.lower() in blob.lower()]
    if kw: L.append('كلمات لافتة: '+' ، '.join(kw)); sc+=min(len(kw),3) if xe else 0
    L.append('')
    v='🟢 مفيش مؤشرات خطيرة واضحة' if sc<=2 else ('🟡 فيه علامات تستدعي الحذر' if sc<=6 else '🔴 مشبوه جدا')
    if not xe and sc==0: v='🟢 ملف عادي (وسائط أو بيانات)، الإنتروبي العالي طبيعي في الملفات المضغوطة ومش علامة خطر'
    L.append('الخلاصة: %s (درجة %d)'%(v,sc))
    L.append('ده تحليل ساكن مبسط بيعوّض Ghidra وradare2 بشكل خفيف: مفيش تفكيك كامل للكود، والملف ماتشغلش. الدرجة تقدير مش حكم نهائي.')
    L.append('للتأكد من السمعة: ابحث بالـ SHA-256 على https://www.virustotal.com (متترفعش ملفات خاصة).')
    return '\n'.join(L)
def meta(d,fname=''):
    k=kind(d); m5,s1,s2=hashes(d)
    L=['📋 بيانات الملف (زي ExifTool)','الاسم: %s | الحجم: %d بايت | النوع: %s'%(fname or 'غير متاح',len(d),NAMES[k]),'MD5: '+m5,'SHA-1: '+s1,'SHA-256: '+s2]
    if k=='zip': L+=zipinfo(d)[0]
    elif k=='pdf': L+=pdfinfo(d)[0]
    elif k=='pe': L+=pe(d)[0][:3]
    elif k=='elf': L+=elf(d)[0][:3]
    L.append('للصور استخدم 📷 افحص صورة (EXIF كامل).')
    return '\n'.join(L)
RUN={'Ghidra':(analyze,'ابعتلي الملف المشبوه كملف (📎 File، حتى 20 ميجا). هحلله ساكن من غير ما أشغله وأديك الخلاصة.'),
     'radare2':(analyze,'ابعتلي الملف التنفيذي كملف (📎 File، حتى 20 ميجا). هحلله ساكن من غير تشغيل وأديك الخلاصة.'),
     'ExifTool':(meta,'ابعتلي أي ملف (مستند أو PDF أو أرشيف) كملف (📎 File) وأطلعلك بياناته. للصور استخدم 📷 افحص صورة.')}
import urllib.request,json
def _get(u,t=20):
    return urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'osint-hub-bot'}),timeout=t).read()
def pwned(t):
    t=t.strip()
    h=t.upper() if re.fullmatch(r'[0-9a-fA-F]{40}',t) else hashlib.sha1(t.encode()).hexdigest().upper()
    try: body=_get('https://api.pwnedpasswords.com/range/'+h[:5]).decode()
    except Exception: return 'خدمة Pwned Passwords مش متاحة دلوقتي، جرب بعد شوية.'
    n=0
    for l in body.splitlines():
        a,_,c=l.partition(':')
        if a.strip()==h[5:]: n=int(c)
    src='\n(المصدر: api.pwnedpasswords.com. بيتبعت أول 5 حروف من الهاش بس، الباسورد نفسه مبيخرجش.)'
    if n: return '🔴 الباسورد ده ظهر %d مرة في تسريبات معروفة. متستخدموش أبدا وغيّره لو بتستعمله.%s'%(n,src)+'\nمهم: امسح رسالتك من الشات.'
    return '🟢 الباسورد ده مش ظاهر في التسريبات المعروفة (مش معناه إنه قوي: استخدم باسورد طويل وفريد).%s\nمهم: امسح رسالتك من الشات.'%src
PATS=[('AWS access key',r'AKIA[0-9A-Z]{16}'),('GitHub token',r'gh[pousr]_[A-Za-z0-9]{30,}'),('GitHub fine-grained token',r'github_pat_[A-Za-z0-9_]{40,}'),('Google API key',r'AIza[0-9A-Za-z_\-]{35}'),('Slack token',r'xox[baprs]-[A-Za-z0-9-]{10,}'),('Telegram bot token',r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'),('Groq key',r'gsk_[A-Za-z0-9]{40,}'),('Stripe key',r'sk_live_[0-9a-zA-Z]{20,}'),('Private key block',r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),('JWT',r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),('Hardcoded password',r'(?i)(password|passwd|secret)\s*[=:]\s*[\'"][^\'"\s]{6,}[\'"]')]
def secrets(d,fname=''):
    txt=d.decode('utf8','replace'); res=[]
    for i,l in enumerate(txt.splitlines(),1):
        for nm,p in PATS:
            if re.search(p,l): res.append('• سطر %d: %s'%(i,nm))
    head='🔑 فحص أسرار (زي TruffleHog/Semgrep، تعرّف أنماط شهيرة)\nالملف/النص: %s | %d حرف'%(fname or 'نص',len(txt))
    if not res: return head+'\n🟢 مفيش أنماط مفاتيح أو أسرار معروفة. (ده مش بديل لفحص كامل)'
    return head+'\n🔴 لقيت %d مؤشر (بعرض النوع ورقم السطر بس، مش القيمة):\n'%len(res)+'\n'.join(res[:40])+'\nلو دي مفاتيح حقيقية: لغيها وجدد غيرها فورا.'
def internetdb(ip):
    ip=ip.strip()
    if not re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}',ip): return 'اكتب عنوان IPv4 صحيح، مثال: 8.8.8.8'
    try: j=json.loads(_get('https://internetdb.shodan.io/'+ip))
    except urllib.error.HTTPError as e:
        return 'مفيش بيانات عن العنوان ده في Shodan InternetDB (غير متاح).' if e.code==404 else 'الخدمة مش متاحة دلوقتي.'
    except Exception: return 'الخدمة مش متاحة دلوقتي.'
    L=['🌍 بيانات عامة عن %s (من Shodan InternetDB، بيانات مفهرسة مسبقا، مفيش فحص مباشر مني)'%ip,'بورتات مفتوحة: '+(', '.join(map(str,j.get('ports',[]))) or 'غير متاح'),'أسماء مضيفين: '+(', '.join(j.get('hostnames',[])[:8]) or 'غير متاح'),'وسوم: '+(', '.join(j.get('tags',[])) or '-'),'ثغرات معروفة مرتبطة: '+(', '.join(j.get('vulns',[])[:10]) or 'غير متاح')]
    return '\n'.join(L)+'\nالمصدر: https://internetdb.shodan.io/'+ip
def crtsh(d):
    try: rows=json.loads(_get('https://crt.sh/?q=%25.'+d+'&output=json',40))
    except Exception: return 'crt.sh مش بيرد دلوقتي، جرب بعد شوية.'
    s=sorted({x.strip().lstrip('*.') for r in rows for x in r.get('name_value','').split('\n') if x.strip().endswith(d)})
    return '🧭 النطاقات الفرعية من شهادات SSL العلنية لـ %s (المصدر crt.sh، بدون أي فحص مباشر)\nالعدد: %d\n'%(d,len(s))+'\n'.join('• '+x for x in s[:60])+('\n... والباقي مقطوع' if len(s)>60 else '')
TXT={'Have I Been Pwned':('pwned','ابعتلي الباسورد (أو SHA-1 بتاعه) أفحصه في تسريبات معروفة. بيتبعت أول 5 حروف من الهاش بس. يفضل تجرب باسورد قديم، ومسح الرسالة بعدها.'),
 'CISA KEV Catalog':('ioc','اكتب رقم ثغرة CVE (مثال: CVE-2021-44228) أو IP أو دومين، وأدوّر في قاعدة الحوادث والمؤشرات المحلية.'),
 'MISP':('ioc','اكتب IP أو دومين أو رابط أو CVE وأدوّر في مؤشرات التهديد المحلية (Feodo وOpenPhish وKEV).'),
 'OpenCTI':('ioc','اكتب IP أو دومين أو رابط أو CVE وأدوّر في مؤشرات التهديد المحلية.'),
 'MITRE ATT&CK Navigator':('attack','اكتب اسم تقنية أو رقمها (مثال: T1059 أو phishing) وأجيبلك وصفها من MITRE ATT&CK.'),
 'VirusTotal':('ioc','اكتب IP أو دومين أو رابط أو CVE وأدوّر في المؤشرات المحلية. لسمعة ملف: ابعته كملف وأديك SHA-256 تبحث بيه.'),
 'Shodan':('idb','اكتب عنوان IP وأجيبلك بياناته العامة المفهرسة (بورتات وثغرات معروفة).'),
 'Censys':('idb','اكتب عنوان IP وأجيبلك بياناته العامة المفهرسة (بورتات وثغرات معروفة).'),
 'Nikto':('dom','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هعمل فحص سلبي لترويسات الأمان وأديك درجة ونصايح.'),
 'OWASP ZAP':('dom','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هعمل فحص سلبي لترويسات الأمان وأديك درجة ونصايح.'),
 'Nuclei':('dom','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هعمل فحص سلبي خفيف وأديك درجة ونصايح.'),
 'theHarvester':('subs','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هجيبلك النطاقات الفرعية من شهادات SSL العلنية.'),
 'Amass':('subs','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هجيبلك النطاقات الفرعية من شهادات SSL العلنية.'),
 'subfinder':('subs','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). هجيبلك النطاقات الفرعية من شهادات SSL العلنية.'),
 'TruffleHog':('sec','ابعت نص أو ملف كود وأفحصه عن مفاتيح وأسرار مكشوفة (بعرض النوع والسطر بس).'),
 'Semgrep':('sec','ابعت نص أو ملف كود وأفحصه عن مفاتيح وأسرار مكشوفة (بعرض النوع والسطر بس).')}
RUN['YARA']=(analyze,'ابعتلي الملف كملف (📎 File، حتى 20 ميجا). هفحصه ساكن بأنماط مشبوهة (زي قواعد YARA) من غير تشغيله.')
RUN['TruffleHog']=(secrets,TXT['TruffleHog'][1]); RUN['Semgrep']=(secrets,TXT['Semgrep'][1])
