"""Two local HTTP targets used to prove the pentest engine works.

vuln      — deliberately vulnerable (SQLi, XSS, IDOR, SSRF, traversal, weak
            session handling, exposed .env, open redirect, API data exposure).
hardened  — same routes implemented safely; the engine must report zero
            confirmed findings there. It is the false-positive control.

Run standalone:  python3 tests/target_app.py --mode vuln --port 8081
"""

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import sqlite3
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JWT_KEY = b'unit-test-key'
USERS = {
    'a@example.test': {'password': 'Passw0rdA!', 'role': 'user', 'orders': [1001, 1002]},
    'b@example.test': {'password': 'Passw0rdB!', 'role': 'user', 'orders': [2001, 2002]},
}
ORDERS = {
    1001: {'id': 1001, 'owner': 'a@example.test', 'total': 149.99, 'status': 'paid',
           'card': '4111111111111111', 'address': '12 Test Street, Cairo'},
    1002: {'id': 1002, 'owner': 'a@example.test', 'total': 35.00, 'status': 'shipped',
           'card': '4000000000000002', 'address': '12 Test Street, Cairo'},
    2001: {'id': 2001, 'owner': 'b@example.test', 'total': 89.50, 'status': 'paid',
           'card': '5555555555554444', 'address': '99 Sample Road, Giza'},
    2002: {'id': 2002, 'owner': 'b@example.test', 'total': 12.25, 'status': 'refunded',
           'card': '4012888888881881', 'address': '99 Sample Road, Giza'},
}
NOTES = {1: {'id': 1, 'owner': 'a@example.test', 'body': 'call customer about refund'},
         2: {'id': 2, 'owner': 'b@example.test', 'body': 'ship replacement unit'}}
PRODUCTS = [(1, 'Widget', 19.9), (2, 'Gadget', 29.5), (3, 'Doohickey', 5.0)]


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def make_jwt(email, role='user'):
    header = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    payload = b64(json.dumps({'sub': email, 'role': role, 'email': email}).encode())
    sig = b64(hmac.new(JWT_KEY, ('%s.%s' % (header, payload)).encode(), hashlib.sha256).digest())
    return '%s.%s.%s' % (header, payload, sig)


class State:
    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.sessions = {}
        self.failures = {}
        self.uploads = {}
        self.csrf = 'csrf-' + os.urandom(8).hex()
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    state = None
    vulnerable = True
    server_version = 'Werkzeug/2.0.1'
    sys_version = ''

    def log_message(self, *args):
        pass

    # -- plumbing ---------------------------------------------------------
    def _send(self, status, body=b'', ctype='text/html; charset=utf-8', extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if self.vulnerable:
            self.send_header('X-Powered-By', 'PHP/7.4.3')
        else:
            self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Permissions-Policy', 'geolocation=(), camera=()')
        items = extra.items() if isinstance(extra, dict) else (extra or [])
        for k, v in items:
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _json(self, status, obj, extra=None):
        self._send(status, json.dumps(obj, ensure_ascii=False),
                   'application/json; charset=utf-8', extra)

    def _cookie(self, email):
        if self._session_email():
            return []
        sid = os.urandom(8).hex()
        with self.state.lock:
            self.state.sessions[sid] = email
        if self.vulnerable:
            return [('Set-Cookie', 'sid=%s; Path=/' % sid),
                    ('Set-Cookie', 'auth=%s; Path=/' % make_jwt(email))]
        return [('Set-Cookie', 'sid=%s; Path=/; HttpOnly; SameSite=Lax' % sid)]

    def _session_email(self):
        cookie = self.headers.get('Cookie') or ''
        m = re.search(r'sid=([0-9a-f]+)', cookie)
        if not m:
            return None
        with self.state.lock:
            return self.state.sessions.get(m.group(1))

    def _bearer(self):
        auth = self.headers.get('Authorization') or ''
        if not auth.startswith('Bearer '):
            return None
        token = auth[7:].strip()
        try:
            header_b64, payload_b64, sig = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=' * (-len(header_b64) % 4)))
            if header.get('alg') == 'none' and self.vulnerable:
                payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)))
                return payload.get('email')
            if not self.vulnerable:
                if header.get('alg') != 'HS256':
                    return None
                expect = b64(hmac.new(JWT_KEY, ('%s.%s' % (header_b64, payload_b64)).encode(),
                                      hashlib.sha256).digest())
                if not hmac.compare_digest(expect, sig):
                    return None
                payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)))
                return payload.get('email')
        except Exception:
            return None
        return None

    def _body(self):
        length = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(length) if length else b''

    def _trusted(self):
        origin = self.headers.get('Origin')
        if self.vulnerable:
            return True
        if not origin:
            return True
        return origin.rstrip('/') == ('http://%s' % self.headers.get('Host', ''))

    # -- GET --------------------------------------------------------------
    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)

        if path == '/':
            return self._home()
        if path == '/search':
            return self._search(query)
        if path == '/product':
            return self._product(query)
        if path == '/page':
            return self._page(query)
        if path == '/redirect':
            return self._redirect(query)
        if path == '/fetch':
            return self._fetch(query)
        if path == '/orders':
            return self._orders()
        if path in ('/api/order', '/api/notes'):
            return self._api_object(path, query)
        if path == '/api/users':
            return self._api_users()
        if path == '/api/profile':
            return self._api_profile()
        if path == '/login':
            return self._login_page()
        if path == '/static/app.js':
            return self._send(200, "fetch('/api/users');\nfetch('/api/profile');\n"
                              "fetch('/api/order?id=1001');\nfetch('/api/notes?id=1');\n",
                              'application/javascript')
        if path == '/static/':
            return self._dir_listing()
        if path == '/.env':
            return self._env_file()
        if path.startswith('/uploads/'):
            return self._serve_upload(path)
        return self._not_found()

    def _home(self):
        csrf = '' if self.vulnerable else \
            '<input type="hidden" name="csrf_token" value="%s">' % self.state.csrf
        body = """<html><head><title>Dark OSINT Shop (test)</title>
<script src="/static/app.js"></script></head><body>
<h1>Shop</h1>
<a href="/search?q=widget">Search</a>
<a href="/product?id=1">Product 1</a>
<a href="/product?id=2">Product 2</a>
<a href="/page?file=about">About</a>
<a href="/redirect?next=/home">Continue</a>
<a href="/fetch?url=/static/app.js">Fetch</a>
<a href="/orders">My orders</a>
<a href="/login">Login</a>
<a href="/api/users">Users API</a>
<form method="post" action="/update-profile">%s
  <input name="name" value="Test User"><input name="email" value="a@example.test">
  <button type="submit">Save</button></form>
<form method="post" action="/login">
  <input name="username"><input name="password" type="password">
  <button type="submit">Sign in</button></form>
<form method="post" action="/upload" enctype="multipart/form-data">%s
  <input type="file" name="file"><button type="submit">Upload</button></form>
</body></html>""" % (csrf, csrf)
        return self._send(200, body, extra=self._cookie('guest@example.test'))

    def _search(self, query):
        term = (query.get('q') or [''])[0]
        shown = term if self.vulnerable else html.escape(term)
        return self._send(200, '<html><body><h2>Results for: %s</h2>'
                               '<p>No matches.</p></body></html>' % shown)

    def _product(self, query):
        raw = (query.get('id') or [''])[0]
        conn = sqlite3.connect(':memory:')
        conn.execute('create table products(id integer, name text, price real)')
        conn.executemany('insert into products values(?,?,?)', PRODUCTS)
        if self.vulnerable:
            try:
                rows = conn.execute('select id, name, price from products where id = %s' % raw).fetchall()
            except Exception as exc:
                return self._send(500, 'Traceback (most recent call last):\n'
                                       '  File "/app/shop.py", line 88, in product\n'
                                       'sqlite3.OperationalError: %s' % exc)
        else:
            try:
                rows = conn.execute('select id, name, price from products where id = ?',
                                    (raw,)).fetchall()
            except Exception:
                rows = []
        if not rows:
            return self._send(404, '<html><body>Product not found</body></html>')
        return self._send(200, ''.join('<div>%s — %.2f</div>' % (r[1], r[2]) for r in rows))

    def _page(self, query):
        name = (query.get('file') or ['about'])[0]
        if self.vulnerable:
            try:
                with open(os.path.normpath('/srv/app/pages/' + name), 'rb') as fh:
                    return self._send(200, fh.read(), 'text/plain; charset=utf-8')
            except Exception:
                return self._send(404, 'page not found')
        if name not in ('about', 'contact'):
            return self._send(404, 'page not found')
        return self._send(200, 'static page: %s' % name, 'text/plain; charset=utf-8')

    def _redirect(self, query):
        target = (query.get('next') or ['/'])[0]
        if not self.vulnerable and (not target.startswith('/') or target.startswith('//')):
            return self._send(400, 'invalid redirect target')
        return self._send(302, b'', 'text/plain', extra={'Location': target})

    def _fetch(self, query):
        target = (query.get('url') or [''])[0]
        if not self.vulnerable:
            if not target.startswith('/'):
                return self._send(400, 'only relative paths are allowed')
            return self._send(200, 'fetched local path')
        try:
            with urllib.request.urlopen(target, timeout=5) as r:
                return self._send(200, r.read(4096).decode('utf-8', 'replace'), 'text/plain')
        except Exception as exc:
            return self._send(502, 'fetch failed: %s' % exc, 'text/plain')

    def _orders(self):
        email = self._session_email()
        if not email:
            return self._send(401, '<html><body>login required</body></html>')
        items = ''.join('<a href="/api/order?id=%d&view=full">order %d</a>\n' % (oid, oid)
                        for oid in USERS.get(email, {}).get('orders', []))
        notes = ''.join('<a href="/api/notes?id=%d">note %d</a>\n'
                        % (nid, nid) for nid in NOTES)
        return self._send(200, '<html><body><h2>Orders of %s</h2>%s'
                               '<h3>Notes</h3>%s</body></html>' % (email, items, notes))

    def _api_object(self, path, query):
        raw = (query.get('id') or [''])[0]
        if not re.fullmatch(r'\d+', raw or ''):
            return self._send(400, 'bad id')
        oid = int(raw)
        email = self._session_email() or self._bearer()
        if path == '/api/order':
            order = ORDERS.get(oid)
            if not order:
                return self._send(404, 'not found')
            if not email:
                return self._send(401, 'login required')
            if not self.vulnerable and order['owner'] != email:
                return self._send(403, 'forbidden')
            return self._json(200, order)
        note = NOTES.get(oid)
        if not note:
            return self._send(404, 'not found')
        if not email and not self.vulnerable:
            return self._send(401, 'login required')
        if not self.vulnerable and note['owner'] != email:
            return self._send(403, 'forbidden')
        return self._json(200, note)

    def _api_users(self):
        if not self.vulnerable:
            return self._json(401, {'error': 'unauthorized'})
        rows = [{'email': e, 'role': u['role'], 'password_hash': hashlib.sha256(
            u['password'].encode()).hexdigest(), 'api_token': 'tok_' + os.urandom(6).hex()}
            for e, u in USERS.items()]
        return self._json(200, rows)

    def _api_profile(self):
        email = self._session_email() or self._bearer()
        if not email:
            return self._json(401, {'error': 'unauthorized'})
        if self.vulnerable:
            return self._json(200, {'email': email, 'role': USERS.get(email, {}).get('role', 'user'),
                                    'password_hash': hashlib.sha256(
                                        USERS.get(email, {}).get('password', '').encode()).hexdigest()})
        return self._json(200, {'email': email, 'role': USERS.get(email, {}).get('role', 'user')})

    def _login_page(self):
        body = ('<html><body><form method="post" action="/login">'
                '<input name="username"><input name="password" type="password">'
                '<button type="submit">Sign in</button></form></body></html>')
        return self._send(200, body, extra=self._cookie('guest@example.test'))

    def _dir_listing(self):
        if not self.vulnerable:
            return self._send(404, 'not found')
        body = ('<html><body><h1>Index of /static</h1><ul>'
                '<li><a href="app.js">app.js</a></li>'
                '<li><a href="list.txt">list.txt</a></li></ul></body></html>')
        return self._send(200, body)

    def _env_file(self):
        if not self.vulnerable:
            return self._send(404, 'not found')
        return self._send(200, 'APP_ENV=production\nDB_HOST=127.0.0.1\n'
                               'DB_PASSWORD=SuperSecretTest123\nJWT_KEY=abc123\n',
                          'text/plain; charset=utf-8')

    def _serve_upload(self, path):
        name = path.rsplit('/', 1)[-1]
        with self.state.lock:
            data = self.state.uploads.get(name)
        if data is None:
            return self._send(404, 'not found')
        return self._send(200, data, 'text/plain; charset=utf-8')

    def _not_found(self):
        if self.vulnerable:
            return self._send(404, 'Traceback (most recent call last):\n'
                                   '  File "/app/shop.py", line 12, in do_GET\n'
                                   'FileNotFoundError: no route for %s' % self.path)
        return self._send(404, 'Page not found')

    # -- POST -------------------------------------------------------------
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/login':
            return self._login()
        if path == '/logout':
            return self._logout()
        if path == '/update-profile':
            return self._update_profile()
        if path == '/upload':
            return self._upload()
        return self._not_found()

    def do_OPTIONS(self):
        allow = 'GET, POST, PUT, DELETE, OPTIONS' if self.vulnerable else 'GET, POST, HEAD, OPTIONS'
        self.send_response(200)
        self.send_header('Allow', allow)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _login(self):
        form = urllib.parse.parse_qs(self._body().decode(), keep_blank_values=True)
        username = (form.get('username') or [''])[0]
        password = (form.get('password') or [''])[0]
        with self.state.lock:
            fails = self.state.failures.get(username, 0)
        if not self.vulnerable and fails >= 3:
            return self._send(429, 'too many attempts, slow down')
        user = USERS.get(username)
        if not user or user['password'] != password:
            with self.state.lock:
                self.state.failures[username] = fails + 1
            if self.vulnerable:
                if not user:
                    return self._send(404, '<html><body>User not found</body></html>')
                return self._send(401, '<html><body>Wrong password for %s</body></html>' % username)
            return self._send(401, '<html><body>Invalid credentials</body></html>')
        with self.state.lock:
            self.state.failures[username] = 0
        if self.vulnerable:
            existing = re.search(r'sid=([0-9a-f]+)', self.headers.get('Cookie') or '')
        else:
            existing = None
        sid = existing.group(1) if existing else os.urandom(8).hex()
        with self.state.lock:
            if not self.vulnerable:
                for existing, owner in list(self.state.sessions.items()):
                    if owner == username:
                        self.state.sessions.pop(existing, None)
            self.state.sessions[sid] = username
        if self.vulnerable:
            cookies = [('Set-Cookie', 'sid=%s; Path=/' % sid),
                       ('Set-Cookie', 'auth=%s; Path=/' % make_jwt(username))]
        else:
            cookies = [('Set-Cookie', 'sid=%s; Path=/; HttpOnly; SameSite=Lax' % sid)]
        body = '<html><body>Welcome %s</body></html>' % html.escape(username)
        return self._send(200, body, extra=cookies)

    def _logout(self):
        cookie = self.headers.get('Cookie') or ''
        m = re.search(r'sid=([0-9a-f]+)', cookie)
        if m and not self.vulnerable:
            with self.state.lock:
                self.state.sessions.pop(m.group(1), None)
        return self._send(200, '<html><body>bye</body></html>')

    def _update_profile(self):
        form = urllib.parse.parse_qs(self._body().decode(), keep_blank_values=True)
        if not self.vulnerable:
            token = (form.get('csrf_token') or [''])[0]
            if token != self.state.csrf or not self._trusted():
                return self._send(403, 'csrf rejected')
        return self._send(200, '<html><body>saved %s</body></html>'
                          % html.escape((form.get('name') or [''])[0]))

    def _upload(self):
        body = self._body()
        ctype = self.headers.get('Content-Type') or ''
        if 'multipart/form-data' not in ctype:
            return self._send(400, 'no multipart')
        if not self.vulnerable:
            if not self._session_email():
                return self._send(401, 'login required')
            if b'text/plain' in body:
                return self._send(400, 'invalid file type')
        name = 'file_%s.txt' % os.urandom(4).hex()
        with self.state.lock:
            self.state.uploads[name] = body
        return self._send(200, '<html><body><a href="/uploads/%s">uploaded</a></body></html>' % name)


def build(mode='vuln', port=0):
    vulnerable = mode != 'hardened'
    handler = type('BoundHandler', (Handler,), {
        'state': State(vulnerable),
        'vulnerable': vulnerable,
        'server_version': 'Werkzeug/2.0.1' if vulnerable else '',
        'sys_version': '',
    })
    server = ThreadingHTTPServer(('127.0.0.1', port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, 'http://127.0.0.1:%d' % server.server_address[1]


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', default='vuln', choices=['vuln', 'hardened'])
    ap.add_argument('--port', type=int, default=8081)
    args = ap.parse_args()
    srv, url = build(args.mode, args.port)
    print('serving %s target on %s' % (args.mode, url))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
