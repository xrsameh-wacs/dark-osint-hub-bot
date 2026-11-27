import struct
def _rat(b,o,e,n=1):
    out=[]
    for i in range(n):
        a,d=struct.unpack(e+'II',b[o+8*i:o+8*i+8]); out.append(a/d if d else 0)
    return out
def _ifd(t,off,e,tags):
    res={}
    n=struct.unpack(e+'H',t[off:off+2])[0]
    for i in range(min(n,300)):
        p=off+2+12*i; tag,typ,cnt,val=struct.unpack(e+'HHI4s',t[p:p+12])
        sz={1:1,2:1,3:2,4:4,5:8,7:1}.get(typ,1)*cnt
        vo=struct.unpack(e+'I',val)[0] if sz>4 else None
        raw=val if sz<=4 else t[vo:vo+sz]
        if tag in tags or tag in (0x8769,0x8825):
            if typ==2: res[tag]=raw[:cnt].split(b'\0')[0].decode('utf-8','replace').strip()
            elif typ==3: res[tag]=struct.unpack(e+'H',raw[:2])[0]
            elif typ==4: res[tag]=struct.unpack(e+'I',raw[:4])[0]
            elif typ==5: res[tag]=_rat(t,vo,e,cnt) if vo is not None else None
    return res
def _exif_jpeg(data):
    """returns dict of readable fields or {} when no EXIF. stdlib only."""
    if data[:2]!=b'\xff\xd8': return {}
    i=2
    while i+4<=len(data):
        if data[i]!=0xFF: break
        mk=data[i+1]; ln=struct.unpack('>H',data[i+2:i+4])[0]
        if mk==0xE1 and data[i+4:i+10]==b'Exif\0\0':
            t=data[i+10:i+2+ln]; e='<' if t[:2]==b'II' else '>'
            f=struct.unpack(e+'I',t[4:8])[0]
            names={271:'الشركة المصنعة',272:'الموديل',305:'البرنامج',306:'تاريخ الملف',315:'المؤلف',33432:'حقوق النشر'}
            ifd0=_ifd(t,f,e,set(names))
            out={names[k]:v for k,v in ifd0.items() if k in names and v}
            if 0x8769 in ifd0:
                x=_ifd(t,ifd0[0x8769],e,{36867,42036,33434,33437,34855,40962,40963})
                m={36867:'تاريخ الالتقاط',42036:'العدسة',34855:'ISO'}
                for k,l in m.items():
                    if x.get(k): out[l]=x[k]
                if x.get(33434): out['زمن التعريض']='%.4g ثانية'%x[33434][0]
                if x.get(33437): out['فتحة العدسة']='f/%.2g'%x[33437][0]
                if x.get(40962) and x.get(40963): out['الأبعاد']='%sx%s'%(x[40962],x[40963])
            if 0x8825 in ifd0:
                g=_ifd(t,ifd0[0x8825],e,{1,2,3,4})
                try:
                    la=g[2]; lo=g[4]
                    lat=la[0]+la[1]/60+la[2]/3600; lon=lo[0]+lo[1]/60+lo[2]/3600
                    if g.get(1)=='S': lat=-lat
                    if g.get(3)=='W': lon=-lon
                    out['GPS']='%.6f,%.6f'%(lat,lon)
                except Exception: pass
            return out
        if mk in (0xDA,0xD9): break
        i+=2+ln
    return {}

def forensics(data):
    import hashlib, io
    out=['🔐 SHA-256: '+hashlib.sha256(data).hexdigest(),'🔐 MD5: '+hashlib.md5(data).hexdigest(),'📦 الحجم: %d بايت'%len(data)]
    hints=[]
    ex=exif(data) or {}
    sw=str(ex.get('Software','')).lower()
    if any(k in sw for k in('photoshop','gimp','lightroom','snapseed','canva','picsart','affinity','pixelmator')): hints.append('اسم برنامج تعديل في البيانات: '+str(ex.get('Software')))
    if data[:3]==b'\xff\xd8\xff' and not ex: hints.append('لا توجد بيانات EXIF (قد تكون حُذفت بالتعديل أو بالنشر على منصة)')
    try:
        from PIL import Image, ImageChops, ImageStat
        im=Image.open(io.BytesIO(data)); out.append('📐 الأبعاد: %dx%d'%im.size)
        g=im.convert('L').resize((8,8)); px=list(g.getdata()); av=sum(px)/64
        h=''.join('1' if p>av else '0' for p in px); out.append('🧬 بصمة بصرية (aHash): %016x'%int(h,2))
        if im.format=='JPEG':
            rgb=im.convert('RGB'); b=io.BytesIO(); rgb.save(b,'JPEG',quality=90); b.seek(0)
            d=ImageChops.difference(rgb,Image.open(b).convert('RGB'))
            mx=max(e[1] for e in d.getextrema()+[(0,0)]) if False else max(ch[1] for ch in d.getextrema())
            sd=sum(ImageStat.Stat(d).stddev)/3
            out.append('🧪 ELA (تحليل مستوى الخطأ): أعلى فرق %d وانحراف %.1f'%(mx,sd))
            if mx>=60 and sd>=6: hints.append('تفاوت واضح في مستوى الضغط بين مناطق الصورة (قد يدل على لصق أو تعديل)')
        else: out.append('🧪 ELA: متاح لصيغة JPEG فقط')
    except ImportError: out.append('🧪 ELA والبصمة البصرية: غير متاحة على هذا السيرفر حاليا')
    except Exception: out.append('🧪 ELA: تعذر التحليل لهذه الصورة')
    out.append('⚠️ مؤشرات التلاعب (تقدير فقط، مش دليل قاطع): '+('؛ '.join(hints) if hints else 'لا توجد مؤشرات واضحة'))
    return '\n'.join(out)

def vision(data,key,mime='image/jpeg'):
    import base64, json, urllib.request
    if len(data)>2800000: return None
    url='data:%s;base64,%s'%(mime,base64.b64encode(data).decode())
    p=('حلّل الصورة بالعربية المصرية المبسطة وبإيجاز في 3 أقسام: 1) وصف المشهد والمكان والمعالم الظاهرة (إن وُجدت). 2) كل نص ظاهر في الصورة بالحرف (OCR) أو اكتب "لا يوجد نص". 3) عناصر تفيد في التحقق من المصدر (لافتات، لغة، طقس، طراز). ممنوع تحديد هوية أي شخص أو ذكر اسمه أو التعرف عليه من وجهه؛ صف فقط الظاهر (عدد الأشخاص وما يلبسونه). لا تخمّن بلا دليل، وقل "غير واضح" عند الشك.')
    body=json.dumps({'model':'qwen/qwen3.8-27b','messages':[{'role':'user','content':[{'type':'text','text':p},{'type':'image_url','image_url':{'url':url}}]}],'max_tokens':900,'temperature':0.2}).encode()
    r=urllib.request.Request('https://api.groq.com/openai/v1/chat/completions',body,{'Authorization':'Bearer '+key,'Content-Type':'application/json','User-Agent':'osint-hub-bot/1.0'})
    return json.loads(urllib.request.urlopen(r,timeout=60).read())['choices'][0]['message']['content'].strip()

def kind(d):
    if d[:3]==b'\xff\xd8\xff': return 'jpeg'
    if d[:8]==b'\x89PNG\r\n\x1a\n': return 'png'
    if d[:4]==b'RIFF' and d[8:12]==b'WEBP': return 'webp'
    if d[:4] in(b'GIF8',): return 'gif'
    if d[4:8]==b'ftyp' and d[8:12] in(b'heic',b'heix',b'hevc',b'mif1',b'msf1',b'heim',b'heis',b'avif'): return 'heic'
    return None
def exif(data):
    if data[4:8]==b'ftyp':
        import re
        m=re.search(b'Exif\\x00\\x00(II\\*\\x00|MM\\x00\\*)',data[:3000000])
        if not m: return {}
        tiff=data[m.start()+6:m.start()+6+60000]
        return _exif_jpeg(b'\xff\xd8\xff\xe1'+struct.pack('>H',len(tiff)+8)+b'Exif\x00\x00'+tiff)
    return _exif_jpeg(data)
def to_jpeg(data):
    """HEIC/WEBP/etc to JPEG bytes for vision; None if no decoder."""
    import io
    try:
        try:
            import pillow_heif; pillow_heif.register_heif_opener()
        except ImportError: pass
        from PIL import Image
        im=Image.open(io.BytesIO(data)).convert('RGB'); im.thumbnail((1600,1600)); b=io.BytesIO(); im.save(b,'JPEG',quality=85); return b.getvalue()
    except Exception: return None
