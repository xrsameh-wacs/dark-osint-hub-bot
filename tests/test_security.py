"""Security regression tests for the twelve review findings.

Each test exercises real code: signed payloads, the real worker subprocess, the
real report builders, and the real socket layer with only DNS/socket primitives
stubbed where a live network call would otherwise be required.
"""

import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pentest          # noqa: E402
import target_app       # noqa: E402

KEY = 'security-test-key'
WORKER = os.path.join(ROOT, 'pentest_worker.py')
URL = 'https://shop.example.com/'
SCOPE = ['example.com']


def make_payload(**over):
    payload = {'url': URL, 'scope': list(SCOPE), 'options': {'rate': 0.3},
               'chat_id': 7, 'ts': str(int(time.time())),
               'nonce': pentest.secrets.token_hex(16), 'timeout': 3600}
    payload.update(over)
    payload['sig'] = pentest.sign_job(payload, KEY)
    return payload


def check(payload, key=KEY):
    with unittest.mock.patch.dict(os.environ, {'SCAN_KEY': key}):
        return pentest.verify_worker_job(payload)


# ------------------------------------------------------------------ payload


class PayloadSignatureTest(unittest.TestCase):
    def test_valid_payload_is_accepted(self):
        self.assertTrue(check(make_payload())['ok'])

    def test_every_actable_field_is_signed(self):
        """Tampering with anything the worker acts on must break the signature."""
        for field, value in (('url', 'https://other.example.net/'),
                             ('scope', ['example.com', 'third-party.test']),
                             ('options', {'rate': 0, 'allow_private': True}),
                             ('chat_id', 999),
                             ('timeout', 86400),
                             ('ts', str(int(time.time()) + 1)),
                             ('nonce', pentest.secrets.token_hex(16))):
            payload = make_payload()
            payload[field] = value
            result = check(payload)
            self.assertFalse(result['ok'], '%s was not covered by the signature' % field)

    def test_nonce_is_required_and_shaped(self):
        for bad in ('', 'short', 'z' * 32, None):
            payload = make_payload()
            payload['nonce'] = bad
            payload['sig'] = pentest.sign_job(payload, KEY)
            self.assertFalse(check(payload)['ok'], 'nonce %r accepted' % bad)

    def test_replay_window_is_five_minutes(self):
        now = int(time.time())
        self.assertFalse(check(make_payload(ts=str(now - pentest.JOB_TTL - 1)))['ok'])
        self.assertTrue(check(make_payload(ts=str(now - 60)))['ok'])
        self.assertFalse(check(make_payload(ts=str(now + 120)))['ok'])

    def test_wrong_key_is_refused(self):
        self.assertFalse(check(make_payload(), key='another-key')['ok'])

    def test_target_must_be_inside_the_signed_scope(self):
        payload = make_payload()
        payload['url'] = 'https://evil.example.net/'
        payload['sig'] = pentest.sign_job(payload, KEY)
        self.assertFalse(check(payload)['ok'])


class WorkerRefusesTamperedJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = target_app.build('hardened')
        cls.host = pentest.domain_of(cls.url)
        cls.tmp = tempfile.mkdtemp(prefix='sec-worker-')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_job(self, payload, allow_private=True, name='job'):
        path = os.path.join(self.tmp, name + '.json')
        with open(path, 'w') as fh:
            json.dump(payload, fh)
        out = os.path.join(self.tmp, name + '-result.json')
        env = dict(os.environ, SCAN_KEY=KEY, PENTEST_MIN_RATE='0')
        env.pop('TELEGRAM_TOKEN', None)
        env.pop('TELEGRAM_BOT_TOKEN', None)
        if allow_private:
            env['PENTEST_ALLOW_PRIVATE'] = '1'
        else:
            env.pop('PENTEST_ALLOW_PRIVATE', None)
        proc = subprocess.run([sys.executable, WORKER, '--job', path, '--out', out,
                               '--no-telegram'], capture_output=True, text=True,
                              env=env, timeout=300)
        return proc, out

    def job(self, **over):
        payload = {'url': self.url, 'scope': [self.host], 'options': {'rate': 0},
                   'chat_id': 1, 'ts': str(int(time.time())),
                   'nonce': pentest.secrets.token_hex(16), 'timeout': 3600}
        payload.update(over)
        payload['sig'] = pentest.sign_job(payload, KEY)
        return payload

    def test_scope_expansion_after_signing_is_refused(self):
        payload = self.job()
        payload['scope'] = [self.host, 'third-party.test']
        proc, out = self.run_job(payload, name='scope')
        self.assertEqual(proc.returncode, 2, proc.stderr[-400:])
        self.assertFalse(os.path.exists(out))

    def test_allow_private_in_payload_is_ignored(self):
        """The payload asks for private access; the worker's env does not grant it."""
        payload = self.job(options={'rate': 0, 'allow_private': True})
        proc, out = self.run_job(payload, allow_private=False, name='private')
        self.assertEqual(proc.returncode, 2, proc.stderr[-400:])
        self.assertIn('policy', proc.stderr.lower())
        self.assertFalse(os.path.exists(out))

    def test_same_job_runs_when_the_worker_env_allows_it(self):
        proc, out = self.run_job(self.job(), allow_private=True, name='allowed')
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertTrue(os.path.exists(out))


class WorkerOptionClampTest(unittest.TestCase):
    def test_payload_cannot_widen_limits(self):
        import importlib
        import pentest_worker
        # the environment here is deliberately hostile: the payload must still lose
        with unittest.mock.patch.dict(os.environ, {'PENTEST_MIN_RATE': '0.2',
                                                   'PENTEST_ALLOW_PRIVATE': '0',
                                                   'PENTEST_INSECURE_TLS': '0'}):
            importlib.reload(pentest_worker)
            options = pentest_worker._worker_options({'options': {
                'rate': 0, 'max_requests': 10 ** 7, 'max_pages': 5000, 'max_depth': 99,
                'allow_private': True, 'insecure_tls': True,
                'accounts': [{'username': 'x', 'password': 'y'}]}})
        self.assertGreaterEqual(options['rate'], 0.2)
        self.assertLessEqual(options['max_requests'], pentest_worker.MAX_REQUESTS)
        self.assertLessEqual(options['max_pages'], 60)
        self.assertLessEqual(options['max_depth'], 3)
        self.assertFalse(options['allow_private'])
        self.assertFalse(options['insecure_tls'])


# ------------------------------------------------------------------ redaction


class _Recon:
    def as_dict(self):
        return {'pages': ['https://shop.example.com/orders?token=ABCDEF123456'],
                'page_count': 1, 'forms': [], 'form_count': 0,
                'params': [('https://shop.example.com/', 'order_id', '149.99'),
                           ('https://shop.example.com/', 'token', 'ABCDEF123456')],
                'param_count': 2, 'api': ['https://shop.example.com/api/orders?api_key=SEKRET123'],
                'api_count': 1, 'js': [], 'subdomains': [], 'dns': {}, 'tech': ['nginx'],
                'robots': '', 'sitemap': [], 'notes': [], 'ports': []}


class _Client:
    requests = 1


class _Scope:
    domains = ['example.com']


class _Scanner:
    def __init__(self, findings, coverage):
        self.target = 'https://shop.example.com/'
        self.scope = _Scope()
        self.findings = findings
        self.coverage = coverage
        self.notes = ['رابط فيه token=ABCDEF123456 كان مكشوف']
        self.opts = {'rate': 0.2}
        self.started = time.time()
        self.client = _Client()
        self.recon = _Recon()


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self.finding = pentest.make_finding(
            'idor', url='https://shop.example.com/api/orders?token=ABCDEF123456&id=5',
            parameter='order_id', evidence='order 149.99 for a@example.test')
        self.report = pentest.build_report(
            _Scanner([self.finding], {'nmap': 'ok', 'nuclei': 'ok',
                                      'zap': 'ok', 'wpscan': 'skipped'}))

    def test_secret_is_gone_from_finding_and_url_kept_usable(self):
        self.assertNotIn('ABCDEF123456', self.finding['url'])
        self.assertIn('<redacted>', self.finding['url'])
        self.assertIn('/api/orders', self.finding['url'])

    def test_secret_is_gone_from_json_telegram_and_markdown(self):
        blob = json.dumps(self.report, ensure_ascii=False)
        telegram = pentest.render_telegram(self.report)
        markdown = pentest.render_markdown(self.report)
        for text in (blob, telegram, markdown):
            self.assertNotIn('ABCDEF123456', text)
            self.assertNotIn('SEKRET123', text)

    def test_non_sensitive_values_stay_readable(self):
        blob = json.dumps(self.report, ensure_ascii=False)
        for value in ('149.99', 'a@example.test', 'order_id', 'nginx'):
            self.assertIn(value, blob)

    def test_recon_params_and_notes_are_redacted(self):
        params = self.report['recon']['params']
        token_row = [p for p in params if p[1] == 'token'][0]
        self.assertEqual(token_row[2], '<redacted>')
        number_row = [p for p in params if p[1] == 'order_id'][0]
        self.assertEqual(number_row[2], '149.99')
        self.assertNotIn('ABCDEF123456', ' '.join(self.report['notes']))


class CoverageFlagsTest(unittest.TestCase):
    def report(self, coverage):
        return pentest.build_report(_Scanner([], coverage))

    def test_failed_tool_flips_coverage_ok(self):
        report = self.report({'nmap': 'failed', 'nuclei': 'ok',
                              'zap': 'missing', 'wpscan': 'skipped'})
        self.assertFalse(report['coverage_ok'])
        self.assertEqual(report['coverage_failed'], ['nmap', 'zap'])

    def test_clean_run_reports_full_coverage(self):
        report = self.report({'nmap': 'ok', 'nuclei': 'ok',
                              'zap': 'ok', 'wpscan': 'skipped'})
        self.assertTrue(report['coverage_ok'])
        self.assertEqual(report['coverage_failed'], [])


# ------------------------------------------------------------------ secrets


class ConsentTokenTest(unittest.TestCase):
    SECRET = 'consent-secret'

    def test_token_is_128_bit(self):
        token = pentest.consent_token(self.SECRET, URL, 7)
        self.assertEqual(len(token.split('.')[1]), 32)
        self.assertTrue(pentest.consent_valid(self.SECRET, URL, 7, token))

    def test_bound_to_target_and_chat(self):
        token = pentest.consent_token(self.SECRET, URL, 7)
        self.assertFalse(pentest.consent_valid(self.SECRET, 'https://other.example.com/', 7, token))
        self.assertFalse(pentest.consent_valid(self.SECRET, URL, 8, token))

    def test_expired_and_future_tokens_are_refused(self):
        now = int(time.time())
        for ts in (now - pentest.CONSENT_TTL - 5, now + 3600):
            sig = pentest.hmac.new(self.SECRET.encode(),
                                   ('pentest|%s|%s|%s' % (URL, 7, ts)).encode(),
                                   pentest.hashlib.sha256).hexdigest()[:32]
            self.assertFalse(pentest.consent_valid(self.SECRET, URL, 7, '%d.%s' % (ts, sig)),
                             'timestamp %d accepted' % ts)

    def test_short_legacy_token_is_refused(self):
        now = int(time.time())
        sig = pentest.hmac.new(self.SECRET.encode(),
                               ('pentest|%s|%s|%s' % (URL, 7, now)).encode(),
                               pentest.hashlib.sha256).hexdigest()[:20]
        self.assertFalse(pentest.consent_valid(self.SECRET, URL, 7, '%d.%s' % (now, sig)))


class SafeErrorTest(unittest.TestCase):
    def test_token_never_reaches_the_log_line(self):
        exc = RuntimeError('failed calling https://api.telegram.org/bot123456:AAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage')
        text = pentest.safe_error(exc)
        self.assertNotIn('AAAAAAAAAAAAAAAAAAAAAAAAA', text)
        self.assertIn('redacted', text)
        self.assertLessEqual(len(text), 200)

    def test_long_and_multiline_errors_are_flattened(self):
        text = pentest.safe_error(ValueError('a\nb\n' + 'x' * 500))
        self.assertNotIn('\n', text)
        self.assertLessEqual(len(text), 200)


# ------------------------------------------------------------------ dns pinning


class PinnedAddressTest(unittest.TestCase):
    def test_socket_uses_the_checked_address_not_a_second_lookup(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]
        seen = []

        def fake_connect(address, *a, **kw):
            seen.append(address)
            raise OSError('blocked in test')

        scope = pentest.Scope(['example.com'], allow_private=False, allow_ports=(80,))
        with unittest.mock.patch('socket.getaddrinfo', return_value=answers):
            client = pentest.Client(scope, safe_only=True)
            with unittest.mock.patch('socket.create_connection', side_effect=fake_connect):
                resp = client.get('http://example.com/')
        self.assertEqual(seen, [('93.184.216.34', 80)])
        self.assertIsNotNone(resp.error)

    def test_private_answer_is_refused_before_connecting(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        scope = pentest.Scope(['example.com'], allow_private=False, allow_ports=(80,))
        with unittest.mock.patch('socket.getaddrinfo', return_value=answers):
            with self.assertRaises(pentest.ScopeError):
                scope.check_url('http://example.com/')

    def test_metadata_answer_is_refused_even_with_private_allowed(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 0))]
        scope = pentest.Scope(['example.com'], allow_private=True, allow_ports=(80,))
        with unittest.mock.patch('socket.getaddrinfo', return_value=answers):
            with self.assertRaises(pentest.ScopeError):
                scope.check_url('http://example.com/')


# ------------------------------------------------------------------ workflow


# ------------------------------------------------------------ external tools


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            try:
                data = self.request.recv(1024)
            except OSError:
                return
            if not data:
                return
            self.request.sendall(b'echo:' + data)


def _fake_tools(tmp):
    for name in ('nmap', 'nuclei'):
        path = os.path.join(tmp, name)
        with open(path, 'w') as fh:
            fh.write('#!/bin/sh\nexit 1\n')
        os.chmod(path, 0o755)


class _FakeRecon:
    def __init__(self):
        self.ports = []
        self.tech = []
        self.pinned_ip = {}


class _FakeScanner:
    def __init__(self, target, scope, opts=None):
        self.target = target
        self.scope = scope
        self.opts = dict({'external_tools': True}, **(opts or {}))
        self.recon = _FakeRecon()
        self.coverage = {}
        self.notes = []
        self.added = []

    def note(self, text):
        self.notes.append(text)

    def add(self, finding):
        self.added.append(finding)


class ExternalToolPinningTest(unittest.TestCase):
    """nmap, nuclei and ZAP must never resolve the target name themselves."""

    TARGET = 'https://shop.example.com/'
    RESOLVED = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tools-')
        _fake_tools(self.tmp)
        self.calls = []

    def run_tools(self, scope, target=None):
        s = _FakeScanner(target or self.TARGET, scope)
        real = subprocess.run

        def record(argv, **kw):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, b'', b'')

        env = dict(os.environ, PATH=self.tmp + os.pathsep + os.environ.get('PATH', ''))
        env.pop('PENTEST_ZAP_JSON', None)
        with unittest.mock.patch.dict(os.environ, env, clear=False):
            with unittest.mock.patch('socket.getaddrinfo', return_value=self.RESOLVED):
                with unittest.mock.patch('subprocess.run', side_effect=record):
                    pentest.check_external(s)
        return s

    def test_nmap_scans_the_pinned_ip_not_the_name(self):
        scope = pentest.Scope(['example.com'])
        self.run_tools(scope)
        nmap = [c for c in self.calls if os.path.basename(c[0]) == 'nmap'][0]
        self.assertEqual(nmap[-1], '93.184.216.34')
        self.assertNotIn('shop.example.com', nmap)
        self.assertIn('-n', nmap)          # no reverse lookups either

    def test_nuclei_goes_through_the_allow_list_proxy(self):
        scope = pentest.Scope(['example.com'])
        self.run_tools(scope)
        nuclei = [c for c in self.calls if os.path.basename(c[0]) == 'nuclei'][0]
        proxy = nuclei[nuclei.index('-proxy') + 1]
        self.assertRegex(proxy, r'^http://127\.0\.0\.1:\d+$')
        self.assertEqual(nuclei[nuclei.index('-u') + 1], self.TARGET)

    def test_private_answer_stops_both_tools_before_they_run(self):
        scope = pentest.Scope(['example.com'], allow_private=False)
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        s = _FakeScanner(self.TARGET, scope)
        with unittest.mock.patch('socket.getaddrinfo', return_value=answers):
            with unittest.mock.patch('subprocess.run') as run:
                pentest.check_external(s)
        run.assert_not_called()
        self.assertEqual(s.coverage['nmap'], 'failed')
        self.assertEqual(s.coverage['nuclei'], 'failed')
        self.assertIn('تعذر تثبيت عنوان', ' '.join(s.notes))

    def test_pinned_address_is_recorded_in_the_report(self):
        scope = pentest.Scope(['example.com'])
        s = self.run_tools(scope)
        self.assertEqual(s.recon.pinned_ip, {'host': 'shop.example.com', 'ip': '93.184.216.34'})

    def test_rebound_answer_is_ignored_after_the_first_pin(self):
        """A second answer cannot move the scan: the first pin wins."""
        scope = pentest.Scope(['example.com'])
        other = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        with unittest.mock.patch('socket.getaddrinfo', return_value=self.RESOLVED):
            self.assertEqual(scope.pin('shop.example.com'), '93.184.216.34')
        with unittest.mock.patch('socket.getaddrinfo', return_value=other):
            self.assertEqual(scope.pin('shop.example.com'), '93.184.216.34')


class PinningProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _EchoHandler)
        cls.echo.daemon_threads = True
        cls.echo_port = cls.echo.server_address[1]
        threading.Thread(target=cls.echo.serve_forever, kwargs={'poll_interval': 0.05},
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.echo.shutdown()
        cls.echo.server_close()

    def exchange(self, proxy, request):
        with socket.create_connection(('127.0.0.1', proxy.server_address[1]), 5) as conn:
            conn.sendall(request)
            return conn.recv(1024)

    def test_tunnels_to_the_pinned_address(self):
        scope = pentest.Scope(['127.0.0.1'], allow_private=True, allow_ports=(self.echo_port,))
        with pentest.PinnedProxy(scope) as proxy:
            with socket.create_connection(('127.0.0.1', proxy.server_address[1]), 5) as conn:
                conn.sendall(b'CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n' % self.echo_port)
                head = conn.recv(1024)
                self.assertIn(b'200', head.split(b'\r\n')[0])
                conn.sendall(b'ping')
                self.assertEqual(conn.recv(1024), b'echo:ping')

    def test_refuses_a_host_outside_the_scope(self):
        scope = pentest.Scope(['example.com'], allow_private=True)
        with pentest.PinnedProxy(scope) as proxy:
            head = self.exchange(proxy, b'CONNECT evil.test:443 HTTP/1.1\r\n\r\n')
        self.assertIn(b'403', head.split(b'\r\n')[0])

    def test_refuses_the_metadata_address_even_when_private_is_allowed(self):
        scope = pentest.Scope(['169.254.169.254'], allow_private=True, allow_ports=(80,))
        with pentest.PinnedProxy(scope) as proxy:
            head = self.exchange(proxy, b'CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n')
        self.assertIn(b'403', head.split(b'\r\n')[0])

    def test_refuses_a_blocked_port(self):
        scope = pentest.Scope(['127.0.0.1'], allow_private=True, allow_ports=(self.echo_port,))
        with pentest.PinnedProxy(scope) as proxy:
            head = self.exchange(proxy, b'CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n')
        self.assertIn(b'403', head.split(b'\r\n')[0])


class FullProfileTest(unittest.TestCase):
    """Every opt-in extra must be off by default and switchable from the bot."""

    TARGET = 'https://shop.example.com/'
    RESOLVED = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tools-')
        _fake_tools(self.tmp)

    def scan(self, opts=None):
        s = _FakeScanner(self.TARGET, pentest.Scope(['example.com']), opts)
        calls = []

        def record(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, b'', b'')

        env = dict(os.environ, PATH=self.tmp + os.pathsep + os.environ.get('PATH', ''))
        with unittest.mock.patch.dict(os.environ, env, clear=False):
            with unittest.mock.patch('socket.getaddrinfo', return_value=self.RESOLVED):
                with unittest.mock.patch('subprocess.run', side_effect=record):
                    pentest.check_external(s)
        return s, calls

    def test_extras_are_off_by_default(self):
        for key in ('full_severities', 'wide_ports', 'zap_active', 'takeover_check'):
            self.assertFalse(pentest.DEFAULT_OPTIONS[key], key)

    def test_default_profile_keeps_the_short_port_list(self):
        _, calls = self.scan()
        nmap = [c for c in calls if os.path.basename(c[0]) == 'nmap'][0]
        ports = nmap[nmap.index('-p') + 1].split(',')
        self.assertEqual(len(ports), 7)
        self.assertEqual(nmap[nmap.index('--host-timeout') + 1], '45s')

    def test_wide_ports_expands_the_nmap_list(self):
        _, calls = self.scan({'wide_ports': True})
        nmap = [c for c in calls if os.path.basename(c[0]) == 'nmap'][0]
        ports = nmap[nmap.index('-p') + 1].split(',')
        self.assertGreater(len(ports), 90)
        self.assertIn('3306', ports)
        self.assertEqual(nmap[nmap.index('--host-timeout') + 1], '180s')
        self.assertEqual(nmap[-1], '93.184.216.34')      # still the pinned address

    def test_full_severities_widens_nuclei(self):
        _, calls = self.scan({'full_severities': True})
        nuclei = [c for c in calls if os.path.basename(c[0]) == 'nuclei'][0]
        self.assertEqual(nuclei[nuclei.index('-severity') + 1],
                         'critical,high,medium,low,info')

    def test_nuclei_stays_narrow_by_default(self):
        _, calls = self.scan()
        nuclei = [c for c in calls if os.path.basename(c[0]) == 'nuclei'][0]
        self.assertEqual(nuclei[nuclei.index('-severity') + 1], 'critical,high,medium')


class TakeoverTest(unittest.TestCase):
    def scanner(self, subs, opts=None):
        s = _FakeScanner('https://example.com/', pentest.Scope(['example.com']), opts)
        s.recon.subdomains = subs
        return s

    def test_dangling_cname_is_flagged_and_verified(self):
        s = self.scanner(['shop.example.com'], {'takeover_check': True})
        dns = {'shop.example.com': {'CNAME': ['old.github.io.']}, 'old.github.io': {}}
        with unittest.mock.patch.object(pentest, 'dns_lookup',
                                        side_effect=lambda h: dns.get(h, {})):
            pentest.check_takeover(s)
        self.assertEqual([f['kind'] for f in s.added], ['subdomain_takeover'])
        self.assertTrue(s.added[0]['verified'])
        self.assertIn('ساقط', s.added[0]['evidence'])

    def test_live_cname_is_reported_as_unverified(self):
        s = self.scanner(['shop.example.com'], {'takeover_check': True})
        dns = {'shop.example.com': {'CNAME': ['alive.github.io.']},
               'alive.github.io': {'A': ['185.199.108.153']}}
        with unittest.mock.patch.object(pentest, 'dns_lookup',
                                        side_effect=lambda h: dns.get(h, {})):
            pentest.check_takeover(s)
        self.assertFalse(s.added[0]['verified'])

    def test_out_of_domain_subdomains_are_ignored(self):
        s = self.scanner(['evil.test', 'other.example.com'], {'takeover_check': True})
        dns = {'other.example.com': {'CNAME': ['old.github.io.']}, 'old.github.io': {}}
        with unittest.mock.patch.object(pentest, 'dns_lookup',
                                        side_effect=lambda h: dns.get(h, {})):
            pentest.check_takeover(s)
        self.assertEqual([f['url'] for f in s.added], ['http://other.example.com/'])

    def test_disabled_by_default(self):
        s = self.scanner(['shop.example.com'])
        pentest.check_takeover(s)
        self.assertEqual(s.added, [])
        self.assertIn('غير مفعّل', ' '.join(s.notes))

    def test_non_provider_cname_is_ignored(self):
        s = self.scanner(['shop.example.com'], {'takeover_check': True})
        dns = {'shop.example.com': {'CNAME': ['internal.example.net.']}}
        with unittest.mock.patch.object(pentest, 'dns_lookup',
                                        side_effect=lambda h: dns.get(h, {})):
            pentest.check_takeover(s)
        self.assertEqual(s.added, [])


class ProfileSwitchTest(unittest.TestCase):
    def options(self, profile):
        import bot
        with unittest.mock.patch.dict(os.environ,
                                       {'PENTEST_PROFILE': profile, 'TELEGRAM_TOKEN': '0:ci'}):
            # the deployment other tests may set these; the profile test wants defaults
            os.environ.pop('PENTEST_MAX_REQUESTS', None)
            os.environ.pop('PENTEST_ALLOW_PRIVATE', None)
            return bot.pt_options()

    def test_safe_profile_keeps_every_extra_off(self):
        opts = self.options('')
        for key in ('allow_upload', 'rate_limit_probe', 'full_severities',
                    'wide_ports', 'zap_active', 'takeover_check'):
            self.assertFalse(opts[key], key)
        self.assertEqual(opts['max_requests'], 900)

    def test_full_profile_turns_them_all_on(self):
        opts = self.options('full')
        for key in ('allow_upload', 'rate_limit_probe', 'full_severities',
                    'wide_ports', 'zap_active', 'takeover_check'):
            self.assertTrue(opts[key], key)
        self.assertEqual(opts['max_requests'], 1500)
        self.assertFalse(opts['allow_private'])      # private ranges stay blocked


class FullWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = Path(os.path.join(ROOT, 'deploy', 'pentest.yml')).read_text()

    def test_zap_runs_full_scan_only_when_the_job_asks(self):
        self.assertIn('zap-full-scan.py', self.text)
        self.assertIn('zap-baseline.py', self.text)
        self.assertIn('zap_mode=%s', self.text)
        self.assertIn('ZAP_MODE: ${{ steps.job.outputs.zap_mode }}', self.text)

    def test_pinning_survives_the_active_mode(self):
        self.assertIn('--add-host "$TARGET_HOST:$PINNED_IP"', self.text)



class ExternalToolWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = Path(os.path.join(ROOT, 'deploy', 'pentest.yml')).read_text()

    def test_private_egress_is_blocked(self):
        self.assertIn('Block private-network egress', self.text)
        for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                    '169.254.0.0/16', '100.64.0.0/10'):
            self.assertIn(net, self.text)
        self.assertIn('iptables -F OUTPUT', self.text)   # cleared before upload

    def test_zap_container_resolves_to_the_pinned_ip(self):
        self.assertIn('--add-host "$TARGET_HOST:$PINNED_IP"', self.text)
        self.assertIn('pinned_ip=%s', self.text)

    def test_pin_failure_fails_the_run(self):
        self.assertIn('cannot pin the target address', self.text)



class WorkflowHardeningTest(unittest.TestCase):
    """Static checks on the workflow file, stdlib only (CI installs no packages)."""

    @classmethod
    def setUpClass(cls):
        cls.text = Path(os.path.join(ROOT, 'deploy', 'pentest.yml')).read_text()
        cls.lines = [ln.rstrip() for ln in cls.text.splitlines()]
        start = max(i for i, ln in enumerate(cls.lines) if ln.strip() == 'path: |')
        cls.artifact = []
        for line in cls.lines[start + 1:]:
            if not line.strip():
                continue
            if len(line) - len(line.lstrip()) != 12:
                break
            cls.artifact.append(line.strip())
        cls.verify_step = cls.text.split('id: job')[1].split('Install detection tools')[0]
        cls.checkout = cls.text.split('- name: Check out the engine')[1].split('- name:')[0]

    def test_no_repository_token_is_requested(self):
        self.assertNotIn('PENTEST_REPO_TOKEN', self.text)
        self.assertNotIn('token:', self.checkout)
        self.assertIn('persist-credentials: false', self.checkout)

    def test_runs_are_serialized(self):
        self.assertIn('concurrency:', self.text)
        self.assertIn('group: pentest-worker', self.text)
        self.assertIn('cancel-in-progress: false', self.text)

    def test_artifact_cannot_leak_the_raw_zap_report(self):
        self.assertIn('pentest_result.json', self.artifact)
        self.assertNotIn('zap.json', self.artifact)
        self.assertIn('rm -f zap.json', self.text)

    def test_signature_check_uses_the_engine_verifier(self):
        self.assertIn('import pentest', self.verify_step)
        self.assertIn('verify_worker_job', self.verify_step)
        self.assertIn('nonce', self.verify_step)

    def test_nuclei_rate_is_conservative(self):
        source = Path(os.path.join(ROOT, 'pentest.py')).read_text()
        self.assertIn("'-rl', '5'", source)
        self.assertIn("'-c', '5'", source)
        self.assertNotIn("'-rl', '20'", source)

    def test_no_state_changing_github_permissions(self):
        self.assertIn('permissions:\n  contents: read', self.text)
        self.assertNotIn('contents: write', self.text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
