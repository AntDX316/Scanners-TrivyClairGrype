import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from reporting import trivy_report, grype_report
from scan_docker import DockerVulnerabilityScanner


class ReportingTests(unittest.TestCase):
    def test_all_findings_and_escaping(self):
        data = {'Results': [{'Target': '<script>alert(1)</script>', 'Vulnerabilities': [
            {'PkgName': f'package-{i}', 'Description': '<img src=x onerror=alert(1)>'}
            for i in range(30)]}]}
        report = trivy_report(data)
        self.assertIn('package-29', report)
        self.assertNotIn('<script>', report)
        self.assertNotIn('<img', report)

    def test_secret_redaction_and_configuration(self):
        report = trivy_report({'Results': [{'Secrets': [{'RuleID': 'key', 'Match': 'SENSITIVE'}],
            'Misconfigurations': [{'ID': 'AVD-123', 'Resolution': 'Use nonroot'}]}]})
        self.assertNotIn('SENSITIVE', report)
        self.assertIn('Rotate credential', report)
        self.assertIn('Use nonroot', report)

    def test_fix_requires_versions(self):
        report = grype_report({'matches': [{'vulnerability': {'fix': {'state': 'not-fixed', 'versions': []}}}]})
        self.assertIn('No fix reported', report)
        self.assertIn('not-fixed', report)

    def test_empty_and_unavailable_differ(self):
        self.assertIn('No findings', grype_report({'matches': []}))
        self.assertIn('incomplete', grype_report({}))

    def test_grype_output_path_and_readonly_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner(directory, Path(directory) / 'nested' / 'results')
            with patch('scan_docker.subprocess.run') as run, patch.object(scanner, 'load_json_file', return_value={'matches': []}):
                result = scanner.run_grype_docker()
            self.assertEqual(result.parent, scanner.output_dir)
            self.assertIn(f'{Path(directory).resolve()}:/workspace:ro', run.call_args.args[0])

    def test_failure_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner(directory, directory, open_browser=False)
            with patch.object(scanner, 'check_docker', return_value=False):
                self.assertEqual(scanner.scan_all(), 2)

    def test_clair_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner(directory, directory)
            with patch('scan_docker.subprocess.run') as run:
                self.assertIsNone(scanner.run_clair_docker())
                run.assert_not_called()

    def test_invalid_json_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner(directory, directory)
            with patch('scan_docker.subprocess.run'), patch.object(scanner, 'load_json_file', return_value={}):
                self.assertIsNone(scanner.run_trivy_docker())
                self.assertIsNone(scanner.run_grype_docker())

    def test_partial_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner(directory, directory, open_browser=False)
            with patch.object(scanner, 'check_docker', return_value=True), \
                 patch.object(scanner, 'run_trivy_docker', return_value=Path(directory) / 'trivy.json'), \
                 patch.object(scanner, 'run_grype_docker', return_value=None), \
                 patch.object(scanner, 'generate_combined_report', return_value=Path(directory) / 'report.html'):
                self.assertEqual(scanner.scan_all(), 2)

    def test_custom_output_report(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = DockerVulnerabilityScanner('<script>', Path(directory) / 'nested')
            trivy = Path(directory) / 'trivy.json'
            trivy.write_text(json.dumps({'Results': []}))
            report = scanner.generate_combined_report(trivy, None)
            html = report.read_text(encoding='utf-8')
            self.assertNotIn('<script>', html)
            self.assertIn('incomplete coverage', html)


if __name__ == '__main__':
    unittest.main()
