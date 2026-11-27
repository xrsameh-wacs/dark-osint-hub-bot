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
import collections,socket as _s
def pcap(d,fname=''):
    if len(d)<24: return 'الملف مش PCAP صالح. ابعت ملف تسجيل شبكة بصيغة .pcap أو .pcapng.'
    pk=[]
    m=d[:4]
    if m in(b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
        e='<' if m in(b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'; nano=m in(b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d')
        lt=struct.unpack_from(e+'I',d,20)[0]; o=24
        while o+16<=len(d) and len(pk)<200000:
            s,us,cl,ol=struct.unpack_from(e+'IIII',d,o); o+=16
            pk.append((s+us/(1e9 if nano else 1e6),d[o:o+cl],lt)); o+=cl
    elif m==b'\x0a\x0d\x0d\x0a':
        o=0; lts=[]
        while o+12<=len(d) and len(pk)<200000:
            bt,bl=struct.unpack_from('<II',d,o)
            if bl<12: break
            if bt==1: lts.append(struct.unpack_from('<H',d,o+8)[0])
            if bt==6:
                ifid,th,tl,cl,ol=struct.unpack_from('<IIIII',d,o+8)
                pk.append(((th<<32|tl)/1e6,d[o+28:o+28+cl],lts[ifid] if ifid<len(lts) else 1))
            o+=bl
    else: return 'الملف مش PCAP صالح. ابعت ملف تسجيل شبكة بصيغة .pcap أو .pcapng.'
    if not pk: return 'مفيش حزم داخل الملف.'
    proto=collections.Counter(); src=collections.Counter(); dst=collections.Counter(); ports=collections.Counter(); dns=collections.Counter(); clear=set()
    for ts,b,lt in pk:
        try:
            if lt==1: et=struct.unpack('>H',b[12:14])[0]; b=b[14:]
            elif lt==101 or lt==12: et=0x800
            else: continue
            if et==0x8100: et=struct.unpack('>H',b[2:4])[0]; b=b[4:]
            if et==0x806: proto['ARP']+=1; continue
            if et==0x86dd: proto['IPv6']+=1; continue
            if et!=0x800: proto['أخرى']+=1; continue
            ihl=(b[0]&15)*4; p=b[9]; a=_s.inet_ntoa(b[12:16]); c=_s.inet_ntoa(b[16:20]); src[a]+=1; dst[c]+=1; t=b[ihl:]
            if p==6 and len(t)>=4:
                sp,dp=struct.unpack('>HH',t[:4]); proto['TCP']+=1; ports[dp]+=1
                if dp in(21,23,80,110,143,25,69): clear.add(dp)
            elif p==17 and len(t)>=8:
                sp,dp=struct.unpack('>HH',t[:4]); proto['UDP']+=1; ports[dp]+=1
                if dp==53 or sp==53:
                    q=t[8+12:]; n=[];i=0
                    while i<len(q) and q[i] and len(n)<10: n.append(q[i+1:i+1+q[i]].decode('latin1')); i+=1+q[i]
                    if n and dp==53: dns['.'.join(n)]+=1
            elif p==1: proto['ICMP']+=1
            else: proto['IP-%d'%p]+=1
        except Exception: continue
    dur=pk[-1][0]-pk[0][0]
    BAD={4444:'غالبا Metasploit/باب خلفي',1337:'منفذ شائع في الأدوات الخبيثة',31337:'منفذ باب خلفي قديم',6667:'IRC (قنوات تحكم قديمة)',3389:'RDP',5900:'VNC',23:'Telnet بدون تشفير',21:'FTP بدون تشفير'}
    L=['📡 ملخص تسجيل الشبكة (زي Wireshark/Zeek/Suricata خفيف)','الاسم: %s | الحزم: %d | المدة: %.1f ثانية'%(fname or 'غير متاح',len(pk),dur),'البروتوكولات: '+' ، '.join('%s %d'%x for x in proto.most_common(6)),'أكثر المصادر: '+' ، '.join('%s (%d)'%x for x in src.most_common(5)),'أكثر الوجهات: '+' ، '.join('%s (%d)'%x for x in dst.most_common(5)),'أكثر البورتات: '+' ، '.join('%d (%d)'%x for x in ports.most_common(8))]
    if dns: L.append('استعلامات DNS (%d مختلف): '%len(dns)+' ، '.join(k for k,_ in dns.most_common(15)))
    sus=[('⚠️ بورت %d: %s'%(p,BAD[p])) for p in ports if p in BAD]
    if clear: L.append('⚠️ بروتوكولات بدون تشفير: '+' ، '.join(str(x) for x in sorted(clear)))
    L+=sus[:6]
    L.append('\nالخلاصة: '+('🟡 فيه نقاط تستحق المراجعة (بورتات أو بروتوكولات مكشوفة)' if sus or clear else '🟢 مفيش بورتات أو بروتوكولات مريبة واضحة')+'\nده ملخص مبسط، مفيش تفكيك كامل للجلسات ولا قواعد Suricata.')
    return '\n'.join(L)
def trivy(d,fname=''):
    t=d.decode('utf8','replace'); pk=[];eco=None
    try:
        j=json.loads(t); eco='npm'
        for sec in('dependencies','devDependencies'):
            for n,v in (j.get(sec) or {}).items():
                v=re.sub(r'^[\^~>=<\s]+','',str(v)).split(' ')[0]
                if re.fullmatch(r'\d+(\.\d+)*',v): pk.append((n,v))
    except Exception:
        eco='PyPI'
        for l in t.splitlines():
            m=re.match(r'\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9.\-+]*)',l)
            if m: pk.append((m.group(1),m.group(2)))
    if not pk: return 'مش لاقي مكتبات بنسخ محددة. ابعت محتوى requirements.txt (مكتبة==نسخة) أو package.json.'
    pk=pk[:100]
    q={'queries':[{'package':{'name':n,'ecosystem':eco},'version':v} for n,v in pk]}
    try: r=json.loads(urllib.request.urlopen(urllib.request.Request('https://api.osv.dev/v1/querybatch',json.dumps(q).encode(),{'Content-Type':'application/json','User-Agent':'osint-hub-bot'}),timeout=30).read())
    except Exception: return 'خدمة OSV مش متاحة دلوقتي، جرب بعد شوية.'
    L=['🛡 فحص ثغرات المكتبات (زي Trivy، المصدر OSV.dev) | %s | %d مكتبة'%(eco,len(pk))]; bad=0
    for (n,v),res in zip(pk,r.get('results',[])):
        ids=[x['id'] for x in res.get('vulns',[])]
        if ids: bad+=1; L.append('🔴 %s %s: %d ثغرة (%s)'%(n,v,len(ids),' ، '.join(ids[:4])))
    L.append('\n'+('🔴 %d مكتبة فيها ثغرات معروفة. حدّثها. التفاصيل: https://osv.dev/<رقم الثغرة>'%bad if bad else '🟢 مفيش ثغرات معروفة في المكتبات دي حسب OSV (حسب النسخ المكتوبة فقط).'))
    return '\n'.join(L)
RULES=[('محاولات دخول SSH فاشلة',r'Failed password|authentication failure|Invalid user',5),('تشغيل PowerShell مشفر',r'(?i)powershell.*(-enc|-encodedcommand)',1),('تحميل ملف بـ certutil/bitsadmin',r'(?i)certutil.*-urlcache|bitsadmin.*/transfer',1),('إنشاء مستخدم جديد',r'(?i)useradd|net user .* /add|adduser',1),('مسح سجلات الأحداث',r'(?i)wevtutil\s+cl|Clear-EventLog|history -c|rm .*\.bash_history',1),('Reverse shell محتمل',r'/dev/tcp/|nc\s+-e|bash -i >&|mkfifo.*nc',1),('حقن SQL في طلب ويب',r"(?i)union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|information_schema",1),('Path traversal',r'\.\./\.\./|%2e%2e%2f',1),('ويب شل محتمل',r'(?i)cmd=|eval\(base64|c99|r57|shell_exec',1),('تصعيد صلاحيات sudo/su',r'(?i)sudo:.*COMMAND=|su: .*session opened for user root',3)]
def sigma(d,fname=''):
    ls=d.decode('utf8','replace').splitlines()[:50000]; L=['📋 فحص سجلات بقواعد شبيهة بـ Sigma | %d سطر'%len(ls)]; hit=0
    for nm,p,th in RULES:
        ms=[l for l in ls if re.search(p,l)]
        if len(ms)>=th: hit+=1; L.append('🔴 %s: %d سطر\n   مثال: %s'%(nm,len(ms),ms[0][:110]))
    L.append('\n'+('🟡 %d قاعدة اتطابقت، راجع الأسطر دي.'%hit if hit else '🟢 مفيش تطابق مع القواعد الأساسية (دي قواعد قليلة ومش بديل لـ SIEM كامل).'))
    return '\n'.join(L)
RUN['Wireshark']=(pcap,'ابعتلي ملف تسجيل شبكة (.pcap أو .pcapng) كملف (📎 File، حتى 20 ميجا) وأطلعلك ملخص: البروتوكولات وأكثر الأجهزة اتصالا وDNS وبورتات مريبة.')
RUN['Zeek']=RUN['Wireshark']; RUN['Suricata']=RUN['Wireshark']
RUN['Trivy']=(trivy,'ابعتلي محتوى requirements.txt (مكتبة==نسخة) أو package.json كنص أو ملف، وأفحص المكتبات في قاعدة ثغرات OSV.')
RUN['Sigma']=(sigma,'ابعتلي أسطر لوج كنص أو ملف (SSH أو ويندوز أو ويب)، وأطابقها على قواعد كشف شائعة.')
RUN['Wazuh']=(sigma,'ابعتلي أسطر لوج كنص أو ملف، وأعمل عليها مراقبة وكشف بقواعد أساسية (نسخة خفيفة من Wazuh).')
RUN['Volatility 3']=(analyze,'ابعتلي ملف (حتى 20 ميجا) وأعمل فرز جنائي خفيف: نوعه وهاشاته ونصوصه وروابطه. تحليل ذاكرة كامل مش ممكن على السيرفر المجاني.')
RUN['Autopsy']=RUN['Volatility 3']
TXT['OpenVAS / Greenbone']=('dom','اكتب الدومين (لازم يكون مضاف بـ /authdomain add). مفيش فحص ثغرات نشط، هعمل فحص سلبي لترويسات الأمان وأديك درجة ونصايح.')
INEXTRA={'EXIF.tools':'فحص EXIF من 📷 افحص صورة','InVID-WeVerify':None}
LAB={'Nmap','OpenVAS / Greenbone','Nuclei','Nikto','OWASP ZAP','Burp Suite','Wazuh','Suricata','Zeek','Volatility 3','Autopsy','CAPE Sandbox','BloodHound','sqlmap','Metasploit Framework','Hashcat','John the Ripper','Hydra','Trivy','MISP','OpenCTI','Ghidra','radare2','Wireshark'}
NEVER={'Sherlock','Maigret','Maltego','Recon-ng','SpiderFoot','GeoSpy'}
def status(n):
    if n in RUN or n in TXT or n in INEXTRA and INEXTRA[n]: return 'in'
    if n in NEVER: return 'never'
    if n in LAB: return 'lab'
    return 'link'
def inventory(rows):
    g={'in':[],'lab':[],'link':[],'never':[]}
    for n,c in rows: g[status(n)].append((n,c))
    out=['📋 جرد كل أدوات المكتبة (%d أداة)'%len(rows),'']
    out.append('✅ بتشتغل جوه البوت دلوقتي (نسخة خفيفة، %d):\n'%len(g['in'])+'، '.join(n for n,c in g['in']))
    out.append('\n🖥 النسخة الكاملة محتاجة سيرفر حقيقي (VPS) وبتشتغل على أجهزتك ودومينات تملكها بس. اللي لسه مش متاح خالص دلوقتي: '+'، '.join(n for n,c in g['lab'])+'\nوالنسخ الكاملة لأدوات ✅ زي Ghidra وWireshark وNmap-مشابهة محتاجة نفس السيرفر.')
    out.append('\n🔗 روابط فقط (مفيش API مجاني أو شروط الموقع تمنع، %d):\n'%len(g['link'])+'، '.join(n for n,c in g['link']))
    out.append('\n⛔ مش هتتبني (تتبع أشخاص أو هوية، %d):\n'%len(g['never'])+'، '.join(n for n,c in g['never']))
    out.append('\nكل الأدوات للأصول اللي تملكها أو معاك تصريح بيها بس.')
    return '\n'.join(out)
def _pe():
    d=bytearray(1024);d[0:2]=b'MZ';struct.pack_into('<I',d,0x3c,0x80);d[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',d,0x84,0x8664,1,0,0,0,0xf0,0x2022);d[0x98:0x9a]=struct.pack('<H',0x20b)
    struct.pack_into('<8sIIII',d,0x98+0xf0,b'UPX0',0x1000,0x1000,0x200,0x100); return bytes(d)
def _pcap():
    ip=bytes([0x45,0,0,0,0,0,0,0,64,17,0,0,10,0,0,1,8,8,8,8])
    q=b'\0\0\1\0\0\1\0\0\0\0\0\0\x07example\x03com\0\0\1\0\1'
    p=b'\0'*12+b'\x08\x00'+ip+struct.pack('>HHHH',5000,53,8+len(q),0)+q
    return struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',100,0,len(p),len(p))+p
def selftest(db,imgx=None,gh=None,domain_report=None):
    import concurrent.futures as cf
    ak='AKIA'+'ABCDEFGHIJKLMNOP'
    def zipb():
        b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('word/document.xml','x'); z.close(); return b.getvalue()
    def hexif():
        t=b'II*\x00\x08\x00\x00\x00'+struct.pack('<H',1)+struct.pack('<HHI4s',271,2,4,b'App\0')+b'\0\0\0\0'
        return imgx.exif(b'\0\0\0\x18ftypheic'+b'\0'*12+b'\0\0\0\x06Exif\0\0'+t)
    def dbq(q): return db().execute(q).fetchone()[0]
    T=[('Ghidra / radare2 / YARA / Volatility / Autopsy',lambda:'الخلاصة' in analyze(_pe(),'s.exe') and 'UPX' in analyze(_pe(),'s.exe')),
       ('ExifTool',lambda:'SHA-256' in meta(zipb(),'s.docx')),
       ('TruffleHog / Semgrep',lambda:'AWS' in secrets(('k="%s"'%ak).encode())),
       ('Wireshark / Zeek / Suricata',lambda:'example.com' in pcap(_pcap(),'s.pcap')),
       ('Sigma / Wazuh',lambda:'SSH' in sigma(b'Failed password for root\n'*6)),
       ('Trivy (OSV.dev)',lambda:'🔴' in trivy(b'requests==2.19.0\n')),
       ('Have I Been Pwned',lambda:'ظهر' in pwned(hashlib.sha1(b'password').hexdigest())),
       ('Shodan / Censys (InternetDB)',lambda:'بورتات' in internetdb('8.8.8.8')),
       ('theHarvester / Amass / subfinder (crt.sh)',lambda:'النطاقات' in crtsh('example.com')),
       ('CISA KEV / MISP / OpenCTI / VirusTotal (قاعدة محلية)',lambda:dbq('select count(*) from incidents')>0 and dbq('select count(*) from indicators')>0),
       ('MITRE ATT&CK',lambda:dbq("select count(*) from incidents where kind='technique'")>0),
       ('أدوات الصور (EXIF/HEIC)',lambda:hexif().get('الشركة المصنعة')=='App' if imgx else False),
       ('أدوات GitHub (API)',lambda:'octocat' in (gh.run('user','octocat') or '') if gh else False)]
    res=[]
    def run(t):
        try: return t[0],bool(t[1]())
        except Exception as e: return t[0],False
    with cf.ThreadPoolExecutor(6) as ex:
        futs=[ex.submit(run,t) for t in T]
        for f,t in zip(futs,T):
            try: res.append(f.result(timeout=100))
            except Exception: res.append((t[0],False))
    ok=sum(1 for _,r in res if r)
    L=['🧪 اختبار ذاتي للأدوات (على عينات آمنة مدمجة، من غير أي فحص لجهات تانية)']+['%s %s'%('✅' if r else '❌',n) for n,r in res]
    L.append('\nالنتيجة: %d من %d نجح'%(ok,len(res)))
    if ok<len(res): L.append('ملحوظة: الأدوات اللي بتعتمد على خدمة خارجية ممكن تفشل مؤقتا لو الخدمة مش بترد، أعد الاختبار بعد دقيقة.')
    return '\n'.join(L)
import hmac,os,urllib.error
def proof_code(domain):
    k=(os.environ.get('WEBHOOK_SECRET') or 'dev').encode()
    return hmac.new(k,('osint-hub-verify:'+domain).encode(),hashlib.sha256).hexdigest()[:32]
def txt_ok(domain):
    try: j=json.loads(_get('https://dns.google/resolve?name=_osint-hub.%s&type=TXT'%domain,15))
    except Exception: return None
    vals=[a.get('data','').strip('"') for a in j.get('Answer',[]) or []]
    return ('osint-hub-verify='+proof_code(domain)) in vals
SCAN_TOOLS={'nmap':'Nmap (أشهر 100 بورت + نسخ الخدمات)','nuclei':'Nuclei (قوالب كشف آمنة)','zap':'OWASP ZAP (فحص سلبي baseline)','nikto':'Nikto (ملفات وإعدادات وكشف معلومات)'}
def verify_text(domain):
    return ('🔐 إثبات ملكية %s (لازم قبل أي فحص نشط)\nأضف سجل DNS من نوع TXT:\nالاسم: _osint-hub.%s\nالقيمة: osint-hub-verify=%s\nبعد ما يتفعل (ممكن ياخد دقايق) اكتب: /verifydomain check %s'%(domain,domain,proof_code(domain),domain))
def dispatch(tool,domain):
    tok=os.environ.get('GH_ACTIONS_TOKEN','').strip()
    if not tok: return 'الفحص النشط لسه مش متفعل (مفتاح التشغيل مش مضاف).'
    body=json.dumps({'ref':'main','inputs':{'tool':tool,'domain':domain,'proof':proof_code(domain)}}).encode()
    r=urllib.request.Request('https://api.github.com/repos/xrsameh-wacs/osint-scanner/actions/workflows/scan.yml/dispatches',body,{'Authorization':'Bearer '+tok,'Accept':'application/vnd.github+json','User-Agent':'osint-hub-bot','Content-Type':'application/json'})
    try: urllib.request.urlopen(r,timeout=20); return None
    except urllib.error.HTTPError as e: return 'GitHub رفض تشغيل الفحص (كود %d).'%e.code
    except Exception: return 'تعذر الوصول لـ GitHub الآن.'
