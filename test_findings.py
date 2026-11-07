import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from findings import finding, normalize, consolidate, policy_failed, sarif, render
from security_scan import SecurityScanner


class FindingsTests(unittest.TestCase):
    def vuln(self, **kw):
        args = dict(scanner='trivy', kind='vulnerability', rule='CVE-TEST', severity='HIGH', package='demo', version='1', ecosystem='pip')
        args.update(kw)
        return finding(**args)

    def test_merge_evidence_and_keep_highest_severity(self):
        rows = consolidate([self.vuln(), self.vuln(scanner='grype', severity='CRITICAL', fix='2')])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['scanners'], ['grype', 'trivy'])
        self.assertEqual(rows[0]['severity'], 'CRITICAL')
        self.assertEqual(rows[0]['fix'], '2')

    def test_advisory_aliases_merge_across_scanners(self):
        grype = normalize('grype', {'matches': [{'vulnerability': {'id': 'GHSA-demo', 'severity': 'High'},
            'relatedVulnerabilities': [{'id': 'CVE-TEST'}], 'artifact': {'name': 'demo', 'version': '1', 'type': 'python'}}]})
        rows = consolidate([self.vuln()] + grype)
        self.assertEqual(len(rows), 1)
        self.assertIn('GHSA-demo', rows[0]['aliases'])
        self.assertEqual(rows[0]['scanners'], ['grype', 'trivy'])

    def test_package_identity_prevents_false_merge(self):
        self.assertEqual(len(consolidate([self.vuln(), self.vuln(ecosystem='npm'), self.vuln(version='2'), self.vuln(package='other')])), 4)

    def test_baseline_and_new_only_policy(self):
        old = consolidate([self.vuln()])
        current = consolidate([self.vuln(), self.vuln(rule='CVE-NEW', severity='LOW')], {'findings': old})
        self.assertEqual(current[0]['status'], 'existing')
        self.assertFalse(policy_failed(current, 'HIGH', only_new=True))
        self.assertTrue(policy_failed(current, 'HIGH'))
        self.assertTrue(policy_failed(current, 'LOW', only_new=True))

    def test_fixable_policy(self):
        self.assertFalse(policy_failed(consolidate([self.vuln()]), 'HIGH', only_fixable=True))
        self.assertTrue(policy_failed(consolidate([self.vuln(fix='2')]), 'HIGH', only_fixable=True))

    def test_priority(self):
        rows = consolidate([self.vuln(rule='A', severity='LOW', fix='2'), self.vuln(rule='B', severity='HIGH'), self.vuln(rule='C', severity='HIGH', fix='2')])
        self.assertEqual([r['rule'] for r in rows], ['C', 'B', 'A'])

    def test_history_secret_values_never_exported(self):
        rows = normalize('trufflehog', [{'DetectorName': 'AWS', 'Raw': 'DO-NOT-EXPORT', 'Redacted': 'ALSO-SECRET', 'ExtraData': {'secret': 'OTHER'},
            'SourceMetadata': {'Data': {'Git': {'file': 'old.env', 'commit': 'abc', 'line': 3}}}}])
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(rows))
        self.assertNotIn('ALSO-SECRET', json.dumps(rows))
        self.assertIn('abc', rows[0]['fix'])
        self.assertEqual(rows[0]['kind'], 'secret-history')

    def test_changed_secret_at_same_location_is_new(self):
        def secret(value):
            return normalize('trivy', {'Results': [{'Target': 'demo.env', 'Secrets': [
                {'RuleID': 'token', 'Severity': 'HIGH', 'Match': value, 'StartLine': 1}]}]})
        before = consolidate(secret('disposable-value-one'))
        after = consolidate(secret('disposable-value-two'), {'findings': before})
        self.assertEqual(after[0]['status'], 'new')
        self.assertNotIn('disposable-value-two', json.dumps(after))

    def test_semgrep_source_is_not_exported(self):
        rows = normalize('semgrep', {'results': [{'check_id': 'shell', 'path': '/workspace/app.py', 'start': {'line': 4}, 'extra': {'severity': 'ERROR', 'message': 'Shell injection', 'lines': 'SECRET SOURCE'}}]})
        self.assertEqual(rows[0]['severity'], 'HIGH')
        self.assertEqual(rows[0]['location'], 'app.py')
        self.assertNotIn('SECRET SOURCE', json.dumps(rows))

    def test_zap_risk_codes_and_urls(self):
        rows = normalize('zap', {'site': [{'alerts': [{'pluginid': '123', 'riskcode': '3', 'name': 'Test', 'instances': [{'uri': 'https://example.invalid/'}]}]}]})
        self.assertEqual(rows[0]['severity'], 'HIGH')
        self.assertEqual(rows[0]['kind'], 'web')

    def test_license_output(self):
        rows = normalize('trivy', {'Results': [{'Licenses': [{'Name': 'MIT', 'PkgName': 'demo', 'Severity': 'LOW'}]}]})
        self.assertEqual(rows[0]['kind'], 'license')

    def test_html_escape_and_sarif(self):
        report = {'target': '<script>', 'created_at': 'now', 'scanners': {'test': {'status': 'completed'}},
            'findings': consolidate([self.vuln(title='<img src=x>', location='app.py', line=2)]), 'new_count': 0}
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'report.html'
            render(report, file)
            html = file.read_text(encoding='utf-8')
            self.assertIn('&lt;img', html)
            self.assertNotIn('<img', html)
        output = sarif(report)
        self.assertEqual(output['version'], '2.1.0')
        self.assertEqual(output['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'], 2)

    def scanner(self, directory):
        return SecurityScanner(argparse.Namespace(target=directory, output=directory, clair=False, no_browser=True, timeout=20))

    def test_malformed_scanner_output_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner = self.scanner(temp)
            with patch('security_scan.subprocess.run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = 'invalid'
                scanner.execute('semgrep', [], expected='results')
            self.assertEqual(scanner.status['semgrep']['status'], 'failed')

    def test_semgrep_partial_errors_are_not_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner = self.scanner(temp)
            with patch('security_scan.subprocess.run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = '{"results": [], "errors": [{"type":"parse error"}]}'
                scanner.execute('semgrep', [], expected='results')
            self.assertEqual(scanner.status['semgrep']['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
