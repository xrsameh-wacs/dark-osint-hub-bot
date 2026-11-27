import sqlite3, json, urllib.request, re, datetime, os, time
BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE,'osint.db')
UA='osint-lib/1.0 (metadata research)'
def now(): return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
def db():
    c=sqlite3.connect(DB,timeout=120); c.row_factory=sqlite3.Row
    c.execute('pragma busy_timeout=120000')
    try: c.execute('pragma journal_mode=WAL')
    except Exception: pass
    c.executescript('''
    create table if not exists incidents(id text primary key, source text, kind text, title text, company text, event_date text, url text, severity text, detail text, source_date text, fetched_at text);
    create index if not exists i_c on incidents(company); create index if not exists i_d on incidents(event_date); create index if not exists i_s on incidents(source);
    create table if not exists indicators(value text, type text, source text, malware text, first_seen text, status text, extra text, fetched_at text, primary key(value,source));
    create table if not exists tools(name text primary key, category text, url text, description text, license text, source text);
    create table if not exists sources(name text primary key, url text, description text, last_fetch text, records int, status text);
    create table if not exists authorized_domains(domain text primary key, added_at text);
    create table if not exists library_index(item text primary key, kind text, location text, description text, count int, updated_at text);
    ''')
    return c
def get(url,timeout=90):
    r=urllib.request.Request(url,headers={'User-Agent':UA})
    return urllib.request.urlopen(r,timeout=timeout).read()
def U(v): return v if v not in (None,'') else 'unavailable'
