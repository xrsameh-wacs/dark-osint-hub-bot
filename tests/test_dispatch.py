"""Proves the bot -> GitHub dispatch -> worker contract end to end.

The outbound call to GitHub is replaced by a recorder (a real call would start a
real workflow); everything after that - the signed payload, the worker's own
verification, the scan and the report file - runs as real code.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pentest      # noqa: E402
import target_app   # noqa: E402

KEY = 'dispatch-test-key'
WORKER = os.path.join(ROOT, 'pentest_worker.py')


class _Accepted:
    status = 204

    def read(self):
        return b''

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class DispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = target_app.build('vuln')
        cls.host = pentest.domain_of(cls.url)
        cls.tmp = tempfile.mkdtemp(prefix='pentest-dispatch-')
        cls._env = {k: os.environ.get(k) for k in ('GH_ACTIONS_TOKEN', 'SCAN_KEY')}
        os.environ['GH_ACTIONS_TOKEN'] = 'gh-actions-token-for-test'
        os.environ['SCAN_KEY'] = KEY
        cls.err, cls.sent = cls.dispatch()

    @classmethod
    def tearDownClass(cls):
        for key, value in cls._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        cls.server.shutdown()

    @classmethod
    def dispatch(cls):
        captured = {}
        real = urllib.request.urlopen

        def recorder(req, timeout=None):
            captured['url'] = req.full_url
            captured['method'] = req.get_method()
            captured['headers'] = {k.lower(): v for k, v in req.header_items()}
            captured['body'] = json.loads(req.data.decode())
            return _Accepted()

        urllib.request.urlopen = recorder
        try:
            err = pentest.dispatch_worker(cls.url, [cls.host], chat_id=4242,
                                          options={'rate': 0, 'allow_private': True})
        finally:
            urllib.request.urlopen = real
        return err, captured

    def test_dispatch_hits_the_pentest_workflow(self):
        self.assertIsNone(self.err)
        self.assertTrue(self.sent['url'].endswith('/actions/workflows/pentest.yml/dispatches'),
                        self.sent['url'])
        self.assertEqual(self.sent['method'], 'POST')
        self.assertTrue(self.sent['headers']['authorization'].startswith('Bearer '))
        self.assertEqual(sorted(self.sent['body']['inputs']), ['job', 'sig', 'ts'])
        self.assertTrue(self.sent['body']['ref'])

    def test_dispatched_payload_is_accepted_and_scanned_by_the_worker(self):
        job = base64.b64decode(self.sent['body']['inputs']['job'])
        payload = json.loads(job)
        self.assertEqual(payload['chat_id'], 4242)
        self.assertEqual(payload['scope'], [self.host])

        path = os.path.join(self.tmp, 'job.json')
        with open(path, 'wb') as fh:
            fh.write(job)
        out = os.path.join(self.tmp, 'result.json')
        env = dict(os.environ, SCAN_KEY=KEY)
        env.pop('TELEGRAM_TOKEN', None)
        env.pop('TELEGRAM_BOT_TOKEN', None)
        proc = subprocess.run([sys.executable, WORKER, '--job', path, '--out', out,
                               '--no-telegram'], capture_output=True, text=True,
                              env=env, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr[-600:])
        report = json.load(open(out))
        self.assertEqual(report['status'], 'completed')
        self.assertEqual(report['target'], pentest.canonical_target(self.url))
        self.assertIn('sqli', {f['kind'] for f in report['findings']})

    def test_worker_refuses_a_payload_tampered_after_signing(self):
        payload = json.loads(base64.b64decode(self.sent['body']['inputs']['job']))
        payload['url'] = 'https://attacker.example/'
        path = os.path.join(self.tmp, 'tampered.json')
        with open(path, 'w') as fh:
            json.dump(payload, fh)
        out = os.path.join(self.tmp, 'tampered-result.json')
        env = dict(os.environ, SCAN_KEY=KEY)
        env.pop('TELEGRAM_TOKEN', None)
        proc = subprocess.run([sys.executable, WORKER, '--job', path, '--out', out,
                               '--no-telegram'], capture_output=True, text=True,
                              env=env, timeout=120)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(os.path.exists(out))


if __name__ == '__main__':
    unittest.main(verbosity=2)
