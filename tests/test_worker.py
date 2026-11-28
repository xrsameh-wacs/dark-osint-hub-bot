"""Worker-level tests: signed jobs run, unsigned/expired/out-of-scope jobs are refused."""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pentest      # noqa: E402
import target_app   # noqa: E402

KEY = 'worker-test-key'
WORKER = os.path.join(ROOT, 'pentest_worker.py')


def build_job(url, scope, ts=None, key=KEY, options=None, nonce=None):
    payload = {'url': url, 'scope': scope, 'ts': str(ts or int(time.time())),
               'nonce': nonce if nonce is not None else pentest.secrets.token_hex(16),
               'options': dict({'rate': 0}, **(options or {})), 'chat_id': None,
               'timeout': 3600}
    payload['sig'] = pentest.sign_job(payload, key)
    return payload


def run_worker(job, out, allow_private=False):
    tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    json.dump(job, tmp)
    tmp.close()
    env = dict(os.environ, SCAN_KEY=KEY, PENTEST_MAX_REQUESTS='1600', PENTEST_MIN_RATE='0')
    env.pop('TELEGRAM_TOKEN', None)
    env.pop('TELEGRAM_BOT_TOKEN', None)
    if allow_private:
        env['PENTEST_ALLOW_PRIVATE'] = '1'
    else:
        env.pop('PENTEST_ALLOW_PRIVATE', None)
    proc = subprocess.run([sys.executable, WORKER, '--job', tmp.name, '--out', out,
                           '--no-telegram'], capture_output=True, text=True, env=env,
                          timeout=300)
    os.unlink(tmp.name)
    return proc


class WorkerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = target_app.build('vuln')
        cls.host = pentest.domain_of(cls.url)
        cls.tmp = tempfile.mkdtemp(prefix='pentest-worker-')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def out(self, name):
        return os.path.join(self.tmp, name)

    def test_signed_job_runs_and_writes_reports(self):
        out = self.out('ok.json')
        proc = run_worker(build_job(self.url, [self.host] + [], key=KEY),
                          out, allow_private=True)
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        report = json.load(open(out))
        self.assertEqual(report['status'], 'completed')
        self.assertIn('sqlite3.OperationalError', json.dumps(report))
        self.assertTrue(os.path.exists(self.out('ok.md')))
        self.assertIn('#', open(self.out('ok.md')).read())

    def test_private_target_refused_without_explicit_opt_in(self):
        proc = run_worker(build_job(self.url, [self.host]), self.out('private.json'))
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(os.path.exists(self.out('private.json')))

    def test_bad_signature_refused(self):
        job = build_job(self.url, [self.host])
        job['sig'] = '0' * 64
        proc = run_worker(job, self.out('bad.json'))
        self.assertEqual(proc.returncode, 2)
        self.assertIn('REFUSED', proc.stderr)
        self.assertFalse(os.path.exists(self.out('bad.json')))

    def test_expired_job_refused(self):
        proc = run_worker(build_job(self.url, [self.host], ts=int(time.time()) - 7200),
                          self.out('old.json'))
        self.assertEqual(proc.returncode, 2)
        self.assertIn('صلاحية', proc.stderr)

    def test_out_of_scope_target_refused(self):
        proc = run_worker(build_job(self.url, ['example.test']), self.out('scope.json'))
        self.assertEqual(proc.returncode, 2)
        self.assertIn('خارج النطاق', proc.stderr)

    def test_empty_scope_refused(self):
        proc = run_worker(build_job(self.url, []), self.out('empty.json'))
        self.assertEqual(proc.returncode, 2)

    def test_scope_matching_is_suffix_safe(self):
        """shop.example.com is in scope for example.com, but notexample.com is not."""
        self.assertTrue(pentest.host_in_scope('shop.example.com', ['example.com']))
        self.assertFalse(pentest.host_in_scope('notexample.com', ['example.com']))
        self.assertFalse(pentest.host_in_scope('example.com.evil.test', ['example.com']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
