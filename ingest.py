import json, re, sys, time, urllib.parse, xml.etree.ElementTree as ET, datetime
from lib import *
def setsrc(c,name,url,desc,n,status):
    c.execute('insert or replace into sources values(?,?,?,?,?,?)',(name,url,desc,now(),n,status)); c.commit()
def hibp(c):
    u='https://haveibeenpwned.com/api/v3/breaches'; d=json.loads(get(u)); t=now()
    for b in d:
        det=json.dumps({'pwn_count':b.get('PwnCount'),'data_classes':b.get('DataClasses'),'verified':b.get('IsVerified'),'sensitive':b.get('IsSensitive'),'domain':b.get('Domain') or 'unavailable'})
        c.execute('insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?)',('hibp:'+b['Name'],'HIBP','data-breach',b.get('Title'),b.get('Title'),U(b.get('BreachDate')),'https://haveibeenpwned.com/PwnedWebsites#'+b['Name'],'unavailable',det,U((b.get('ModifiedDate') or '')[:10]),t))
    setsrc(c,'HIBP',u,'Have I Been Pwned breach list (metadata only)',len(d),'ok'); return len(d)
def kev(c):
    u='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'; d=json.loads(get(u)); t=now(); v=d['vulnerabilities']
    for x in v:
        det=json.dumps({'product':U(x.get('product')),'ransomware_use':U(x.get('knownRansomwareCampaignUse')),'due_date':U(x.get('dueDate')),'cwes':x.get('cwes')})
        c.execute('insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?)',('kev:'+x['cveID'],'CISA KEV','exploited-vulnerability',x.get('vulnerabilityName') or x['cveID'],U(x.get('vendorProject')),U(x.get('dateAdded')),'https://nvd.nist.gov/vuln/detail/'+x['cveID'],'unavailable',det,U(d.get('dateReleased','')[:10]),t))
    setsrc(c,'CISA KEV',u,'CISA Known Exploited Vulnerabilities catalog',len(v),'ok'); return len(v)
def nvd(c,days=30):
    end=datetime.datetime.utcnow(); st=end-datetime.timedelta(days=days); n=0; idx=0; t=now()
    base='https://services.nvd.nist.gov/rest/json/cves/2.0'
    while True:
        q=urllib.parse.urlencode({'pubStartDate':st.strftime('%Y-%m-%dT%H:%M:%S.000'),'pubEndDate':end.strftime('%Y-%m-%dT%H:%M:%S.000'),'resultsPerPage':2000,'startIndex':idx})
        d=None
        for a in range(4):
            try: d=json.loads(get(base+'?'+q,120)); break
            except Exception: time.sleep(10)
        if not d: break
        for w in d['vulnerabilities']:
            x=w['cve']; sev=sc='unavailable'
            for k in ('cvssMetricV31','cvssMetricV40','cvssMetricV30','cvssMetricV2'):
                m=x.get('metrics',{}).get(k)
                if m: sc=m[0]['cvssData'].get('baseScore'); sev=m[0]['cvssData'].get('baseSeverity') or m[0].get('baseSeverity') or 'unavailable'; break
            det=json.dumps({'cvss_score':sc,'status':x.get('vulnStatus')})
            c.execute('insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?)',('nvd:'+x['id'],'NVD','cve',x['id'],'unavailable',U(x.get('published','')[:10]),'https://nvd.nist.gov/vuln/detail/'+x['id'],str(sev),det,U(x.get('lastModified','')[:10]),t)); n+=1
        idx+=len(d['vulnerabilities'])
        if idx>=d['totalResults'] or not d['vulnerabilities']: break
        time.sleep(7)
    setsrc(c,'NVD',base,'NVD CVE API 2.0, CVEs published in last %d days'%days,n,'ok' if n else 'failed'); return n
def attack(c):
    u='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'; d=json.loads(get(u,300)); t=now(); n=0
    for o in d['objects']:
        if o.get('type')!='attack-pattern' or o.get('revoked') or o.get('x_mitre_deprecated'): continue
        ref=next((r for r in o.get('external_references',[]) if r.get('source_name')=='mitre-attack'),{})
        det=json.dumps({'tactics':[p['phase_name'] for p in o.get('kill_chain_phases',[])],'platforms':o.get('x_mitre_platforms'),'desc':(o.get('description') or '')[:1200]})
        c.execute('insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?)',('attack:'+ref.get('external_id',o['id']),'MITRE ATT&CK','technique',o['name'],'unavailable',U(o.get('created','')[:10]),U(ref.get('url')),'unavailable',det,U(o.get('modified','')[:10]),t)); n+=1
    setsrc(c,'MITRE ATT&CK',u,'MITRE ATT&CK Enterprise techniques (STIX)',n,'ok'); return n
def certfr(c):
    u='https://www.cert.ssi.gouv.fr/alerte/feed/'; r=ET.fromstring(get(u)); t=now(); n=0
    for it in r.iter('item'):
        link=(it.findtext('link') or '').strip(); title=(it.findtext('title') or '').strip()
        try: dt=datetime.datetime.strptime(it.findtext('pubDate').strip()[:25],'%a, %d %b %Y %H:%M:%S').strftime('%Y-%m-%d')
        except Exception: dt='unavailable'
        ref=re.search(r'(CERTFR-\d{4}-[A-Z]+-\d+)',link+title); ref=ref.group(1) if ref else link
        c.execute('insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?)',('certfr:'+ref,'CERT-FR','advisory',title,'unavailable',dt,U(link),'unavailable','{}',dt,t)); n+=1
    setsrc(c,'CERT-FR',u,'CERT-FR alert feed (recent items only)',n,'ok'); return n
def feodo(c):
    u='https://feodotracker.abuse.ch/downloads/ipblocklist.json'; d=json.loads(get(u)); t=now()
    for x in d:
        c.execute('insert or replace into indicators values(?,?,?,?,?,?,?,?)',(x['ip_address'],'ip','Feodo Tracker',U(x.get('malware')),U(x.get('first_seen')),U(x.get('status')),json.dumps({'port':x.get('port'),'as_name':x.get('as_name'),'country':x.get('country'),'last_online':x.get('last_online')}),t))
    setsrc(c,'Feodo Tracker',u,'abuse.ch Feodo botnet C2 IP blocklist',len(d),'ok'); return len(d)
def openphish(c):
    u='https://openphish.com/feed.txt'; L=[l.strip() for l in get(u).decode().splitlines() if l.strip()]; t=now()
    for x in L:
        c.execute('insert or replace into indicators values(?,?,?,?,?,?,?,?)',(x,'url','OpenPhish','phishing','unavailable','listed','{}',t))
    setsrc(c,'OpenPhish',u,'OpenPhish community feed (first-seen date not provided; fetched_at is the source date)',len(L),'ok'); return len(L)
ALL=[hibp,kev,nvd,attack,certfr,feodo,openphish]
def refresh_index(c):
    t=now()
    rows=[('incidents','table','osint.db','Security incident metadata from public sources',c.execute('select count(*) from incidents').fetchone()[0]),
      ('indicators','table','osint.db','Feodo/OpenPhish indicators',c.execute('select count(*) from indicators').fetchone()[0]),
      ('tools','table','osint.db','Security research tool catalog',c.execute('select count(*) from tools').fetchone()[0]),
      ('sources','table','osint.db','Source registry',c.execute('select count(*) from sources').fetchone()[0])]
    for r in rows: c.execute('insert or replace into library_index values(?,?,?,?,?,?)',(*r[:4],r[4],t))
    c.commit()
def run(names=None):
    c=db(); out={}
    for f in ALL:
        if names and f.__name__ not in names: continue
        try: out[f.__name__]=f(c)
        except Exception as e:
            out[f.__name__]='ERROR %s'%type(e).__name__
            c.execute('update sources set status=? where name=?',('error '+type(e).__name__,f.__name__))
    import tools_seed; tools_seed.seed(c); refresh_index(c); return out
if __name__=='__main__': print(run(sys.argv[1:] or None))
