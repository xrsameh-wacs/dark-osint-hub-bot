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
def exif(data):
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
