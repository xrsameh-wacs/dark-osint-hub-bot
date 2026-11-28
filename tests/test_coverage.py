"""Coverage honesty: a tool that fails or is absent must never look like a pass.

Each test puts stub binaries on PATH so the real subprocess path runs, then
checks the per-tool coverage state, the notes, and both report renderings.
"""

import json
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pentest      # noqa: E402
import target_app   # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>
<port protocol="tcp" portid="3306"><state state="closed"/></port>
</ports></host></runstats><runstats><finished exit="success"/></runstats></nmaprun>"""

NUCLEI_OK = json.dumps({'template-id': 'git-config', 'info': {'name': 'Exposed .git',
                                                              'severity': 'high'},
                        'matched-at': 'http://target/.git/config',
                        'matcher-name': 'git'})

ZAP_OK = {'site': [{'@name': 'http://target',
                    'alerts': [{'alert': 'Missing X-Frame-Options', 'riskcode': '2',
                                'pluginid': '10020',
                                'instances': [{'uri': 'http://target/'}]}]}]}


def stub(directory, name, output='', code=0):
    """A real executable on PATH, so the engine's subprocess path is exercised."""
    path = os.path.join(directory, name)
    with open(path, 'w') as fh:
        fh.write('#!/usr/bin/env python3\nimport sys\nsys.stdout.write(%r)\nsys.exit(%d)\n'
                 % (output, code))
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


class CoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = target_app.build('hardened')

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def scan(self, bin_dir=None, zap_json='__unset__', external=True):
        saved_path = os.environ.get('PATH', '')
        saved_zap = os.environ.pop('PENTEST_ZAP_JSON', None)
        if zap_json != '__unset__':
            os.environ['PENTEST_ZAP_JSON'] = zap_json
        if bin_dir:
            os.environ['PATH'] = bin_dir + os.pathsep + saved_path
        options = {'rate': 0.0, 'timeout': 8, 'max_requests': 400, 'max_pages': 4,
                   'online_recon': False, 'external_tools': external,
                   'rate_limit_probe': False, 'allow_upload': False}
        try:
            port = int(self.url.rsplit(':', 1)[1])
            scope = pentest.Scope(['127.0.0.1'], allow_private=True, allow_ports=(port,))
            return pentest.run_scan(self.url, options, scope=scope)
        finally:
            os.environ['PATH'] = saved_path
            os.environ.pop('PENTEST_ZAP_JSON', None)
            if saved_zap is not None:
                os.environ['PENTEST_ZAP_JSON'] = saved_zap

    def tmpdir(self):
        path = tempfile.mkdtemp(prefix='cov-')
        self.addCleanup(lambda: __import__('shutil').rmtree(path, ignore_errors=True))
        return path

    # -- happy path ---------------------------------------------------------
    def test_healthy_tools_are_marked_ok_and_their_findings_unconfirmed(self):
        bin_dir = self.tmpdir()
        stub(bin_dir, 'nmap', NMAP_XML)
        stub(bin_dir, 'nuclei', NUCLEI_OK + '\n')
        zap_path = os.path.join(self.tmpdir(), 'zap.json')
        with open(zap_path, 'w') as fh:
            json.dump(ZAP_OK, fh)

        report = self.scan(bin_dir=bin_dir, zap_json=zap_path)

        self.assertEqual(report['coverage'],
                         {'nmap': 'ok', 'nuclei': 'ok', 'zap': 'ok', 'wpscan': 'skipped'})
        tool_findings = [f for f in report['findings'] if f['kind'] == 'tool_finding']
        self.assertEqual(len(tool_findings), 2, 'nuclei + ZAP rows expected')
        for f in tool_findings:
            self.assertFalse(f['verified'], '%s from a tool cannot be confirmed' % f['source'])
        self.assertEqual(report['confirmed'], 0)
        self.assertEqual(report['suspected'], len(tool_findings))

        telegram = pentest.render_telegram(report)
        markdown = pentest.render_markdown(report)
        self.assertIn('🧰 تغطية الأدوات', telegram)
        self.assertIn('✅ nmap', telegram)
        self.assertIn('⏭️ WPScan', telegram)
        self.assertNotIn('تغطية ناقصة', telegram)
        self.assertIn('## تغطية الأدوات', markdown)
        self.assertIn('✅ nuclei', markdown)
        self.assertNotIn('تغطية ناقصة', markdown)

    # -- failure path -------------------------------------------------------
    def test_failing_tools_are_explicit_and_coverage_is_incomplete(self):
        bin_dir = self.tmpdir()
        stub(bin_dir, 'nmap', '', code=1)
        stub(bin_dir, 'nuclei', '', code=1)
        missing_zap = os.path.join(self.tmpdir(), 'never-written.json')

        report = self.scan(bin_dir=bin_dir, zap_json=missing_zap)

        self.assertEqual(report['coverage'],
                         {'nmap': 'failed', 'nuclei': 'failed', 'zap': 'missing',
                          'wpscan': 'skipped'})
        self.assertEqual(sorted(pentest.coverage_problems(report)), ['nmap', 'nuclei', 'zap'])

        joined = ' | '.join(report['notes'])
        self.assertIn('nmap فشلت', joined)
        self.assertIn('nuclei فشلت', joined)
        self.assertIn('OWASP ZAP غير متاحة', joined)
        self.assertIn('exit 1', joined)

        telegram = pentest.render_telegram(report)
        markdown = pentest.render_markdown(report)
        for text in (telegram, markdown):
            self.assertIn('تغطية ناقصة', text)
            self.assertIn('❌ nmap', text)
            self.assertIn('❌ nuclei', text)
            self.assertIn('⚠️ OWASP ZAP', text)
            self.assertNotIn('فحص مكتمل التغطية', text)

    # -- explicitly disabled ------------------------------------------------
    def test_disabled_external_tools_are_skipped_not_failed(self):
        report = self.scan(external=False)
        self.assertEqual(set(report['coverage'].values()), {'skipped'})
        self.assertEqual(pentest.coverage_problems(report), [])
        self.assertNotIn('تغطية ناقصة', pentest.render_telegram(report))
        self.assertTrue(any('معطّلة' in n for n in report['notes']),
                        'the report must say external coverage was not attempted')

    # -- values vs secrets --------------------------------------------------
    def test_tool_evidence_keeps_values_and_masks_secrets(self):
        row = {'source': 'nuclei', 'name': 'Leak', 'severity': 'medium', 'url': 'http://t/',
               'evidence': 'order 149.99 for a@example.test api_key=SECRETVALUE123'}
        finding = pentest.tool_findings([row])[0]
        self.assertIn('149.99', finding['evidence'])
        self.assertIn('a@example.test', finding['evidence'])
        self.assertNotIn('SECRETVALUE123', finding['evidence'])
        self.assertIn('<redacted>', finding['evidence'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
