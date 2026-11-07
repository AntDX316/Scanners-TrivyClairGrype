"""Extended Docker scan orchestration and CI policy."""
import argparse
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from findings import LEVELS, normalize, consolidate, policy_failed, sarif, render
from scan_docker import DockerVulnerabilityScanner

from scanner_images import IMAGES


class SecurityScanner(DockerVulnerabilityScanner):
    def __init__(self, args):
        super().__init__(args.target, args.output, clair=args.clair, open_browser=not args.no_browser)
        self.args = args
        self.status = {}
        self.rows = []

    def skip(self, name, reason):
        self.status[name] = {'status': 'skipped', 'detail': reason}

    def record(self, name, data, detail=''):
        self.rows.extend(normalize(name, data))
        self.status[name] = {'status': 'completed', 'detail': detail}

    def execute(self, name, command, *, jsonl=False, success=(0,), expected=None):
        container = f'{name}-scanner-{self.timestamp}'
        cmd = ['docker', 'run', '--rm', '--name', container] + command
        print(f'Running {name}... ', flush=True)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=self.args.timeout)
            if result.returncode not in success:
                # Scanner output may contain source or credentials; do not echo it to CI logs.
                raise ValueError(f'process exited {result.returncode}; rerun scanner locally to diagnose')
            data = [json.loads(line) for line in result.stdout.splitlines() if line.strip()] if jsonl else json.loads(result.stdout)
            if expected is not None and (not isinstance(data, dict) or expected not in data):
                raise ValueError('missing expected JSON schema field')
            if name == 'semgrep' and data.get('errors'):
                self.record(name, data)
                raise ValueError(f'{len(data["errors"])} analysis errors; coverage is incomplete')
            self.record(name, data)
            # Store only normalized fields for source/secret scanners, never raw credentials or source snippets.
            (self.output_dir / f'{name}_results_{self.timestamp}.json').write_text(
                json.dumps({'findings': normalize(name, data)}, indent=2), encoding='utf-8')
            print(f'{name}: completed', flush=True)
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError) as exc:
            self.status[name] = {'status': 'failed', 'detail': 'Timeout' if isinstance(exc, subprocess.TimeoutExpired) else str(exc)}
            if isinstance(exc, subprocess.TimeoutExpired):
                subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=30)
            print(f'{name}: failed (see coverage status)', flush=True)

    def scan_source(self, source):
        mount = ['-v', f'{source.resolve()}:/workspace:ro']
        if not self.args.skip_semgrep:
            config = self.args.semgrep_config
            if Path(config).is_file():
                mount += ['-v', f'{Path(config).resolve()}:/rules.yaml:ro']
                config = '/rules.yaml'
            self.execute('semgrep', mount + ['-w', '/workspace', IMAGES['semgrep'], 'semgrep', 'scan',
                '--config', config, '--metrics=off', '--disable-version-check', '--json', '--no-git-ignore',
                '--exclude', '.git', '--exclude', '.security-baseline', '--exclude', str(self.output_dir.name), '/workspace'], expected='results')
        else:
            self.skip('semgrep', 'Disabled by user')
        if not self.args.skip_trufflehog:
            if (source / '.git').exists():
                command = ['git', 'file:///workspace']
                detail = 'Git history'
            else:
                command = ['filesystem', '/workspace']
                detail = 'Working tree only; .git is absent'
            self.execute('trufflehog', ['-v', f'{source.resolve()}:/workspace:ro', IMAGES['trufflehog']] +
                command + ['--json', '--no-verification'], jsonl=True)
            if self.status['trufflehog']['status'] == 'completed':
                self.status['trufflehog']['detail'] = detail + '; credential verification disabled'
        else:
            self.skip('trufflehog', 'Disabled by user')

    def scan_zap(self):
        if not self.args.url:
            self.skip('zap', 'No web URL supplied; use --url')
            return
        name = f'zap-scanner-{self.timestamp}'
        output = self.output_dir / f'zap_results_{self.timestamp}.json'
        script = 'zap-full-scan.py' if self.args.zap_active else 'zap-baseline.py'
        command = ['docker', 'run', '--rm', '--name', name, '-v', f'{self.output_dir.resolve()}:/zap/wrk:rw',
            IMAGES['zap'], script, '-t', self.args.url, '-J', output.name, '-m', '1', '-T', '10', '-I']
        try:
            result = subprocess.run(command, capture_output=True, timeout=self.args.timeout)
            # ZAP uses 1/2 for detected alerts, 3 for execution errors.
            if result.returncode not in (0, 1, 2):
                raise ValueError(f'ZAP exited {result.returncode}')
            data = json.loads(output.read_text(encoding='utf-8'))
            if 'site' not in data:
                raise ValueError('Missing ZAP site report')
            self.record('zap', data, 'Active web scan' if self.args.zap_active else 'Passive baseline with one-minute spider')
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            self.status['zap'] = {'status': 'failed', 'detail': str(exc)}
            if isinstance(exc, subprocess.TimeoutExpired):
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)

    def run(self):
        baseline = None
        if self.args.baseline:
            baseline = json.loads(Path(self.args.baseline).read_text(encoding='utf-8-sig'))
            if baseline.get('target') != self.target:
                raise ValueError('Baseline target differs from this scan target')
            if baseline.get('schema_version') != 1 or not isinstance(baseline.get('findings'), list):
                raise ValueError('Baseline must be a combined JSON report with schema_version 1')
        if not self.check_docker():
            return 2
        remote = self.target.startswith(('https://', 'http://', 'git@'))
        # A single checkout lets all source scanners inspect the same Git revision/history.
        with tempfile.TemporaryDirectory(prefix='security-checkout-') as temp:
            source = Path(self.target)
            original = self.target
            try:
                if remote:
                    source = Path(temp) / 'repo'
                    subprocess.run(['git', 'clone', '--', self.target, str(source)], check=True,
                        capture_output=True, timeout=self.args.timeout)
                    self.target = str(source)
                for scanner, method in (('trivy', self.run_trivy_docker), ('grype', self.run_grype_docker)):
                    file = method()
                    if file:
                        self.record(scanner, self.load_json_file(file))
                    else:
                        self.status[scanner] = {'status': 'failed', 'detail': 'No validated scanner output'}
                if source.is_dir():
                    self.scan_source(source)
                else:
                    self.skip('semgrep', 'Code scan requires a directory or Git target')
                    self.skip('trufflehog', 'History scan requires a directory or Git target')
                if self.clair:
                    file = self.run_clair_docker()
                    self.status['clair'] = {'status': 'completed' if file else 'failed', 'detail': 'Legacy integration'}
                    if file:
                        self.rows.extend(self.normalize_clair(self.load_json_file(file)))
                else:
                    self.skip('clair', 'Legacy integration; opt in with --clair')
            except (subprocess.SubprocessError, OSError) as exc:
                self.status['checkout'] = {'status': 'failed', 'detail': type(exc).__name__}
            finally:
                self.target = original
        self.scan_zap()
        rows = consolidate(self.rows, baseline)
        previous = {f['fingerprint'] for f in (baseline or {}).get('findings', [])}
        current = {f['fingerprint'] for f in rows}
        report = {'schema_version': 1, 'target': self.target, 'created_at': datetime.now(timezone.utc).isoformat(),
            'scanners': self.status, 'findings': rows, 'new_count': sum(f['status'] == 'new' for f in rows),
            'resolved_count': len(previous - current) if baseline is not None else 0,
            'baseline_note': 'Absent findings are not proof of resolution when coverage differs or scanners failed.'}
        report['policy_failed'] = policy_failed(rows, self.args.fail_on, self.args.only_new, self.args.only_fixable)
        prefix = self.output_dir / f'combined_report_{self.timestamp}'
        prefix.with_suffix('.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        prefix.with_suffix('.sarif').write_text(json.dumps(sarif(report), indent=2), encoding='utf-8')
        render(report, prefix.with_suffix('.html'))
        print(f'Report: {prefix.with_suffix(".html")}\nUnique findings: {len(rows)}', flush=True)
        if self.open_browser:
            import webbrowser
            webbrowser.open(prefix.with_suffix('.html').resolve().as_uri())
        if any(s['status'] == 'failed' for s in self.status.values()):
            return 2
        return 1 if report['policy_failed'] else 0

    @staticmethod
    def normalize_clair(data):
        from findings import finding
        return [finding('clair', 'vulnerability', v.get('Name'), v.get('Severity'),
            package=v.get('FeatureName'), version=v.get('FeatureVersion'), fix=v.get('FixedBy'))
            for v in data.get('Vulnerabilities') or []]


def main():
    parser = argparse.ArgumentParser(description='Multi-layer Docker security scanner')
    parser.add_argument('target', help='Directory, Git repository URL, or registry image')
    parser.add_argument('-o', '--output', default='results')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--clair', action='store_true', help='Enable legacy Clair integration')
    parser.add_argument('--skip-semgrep', action='store_true')
    parser.add_argument('--skip-trufflehog', action='store_true')
    parser.add_argument('--semgrep-config', default='p/security-audit', help='Registry ruleset or local YAML file')
    parser.add_argument('--url', help='Explicit web target for ZAP baseline scanning')
    parser.add_argument('--zap-active', action='store_true', help='Use active full scan against the supplied staging URL')
    parser.add_argument('--baseline', help='Previous combined JSON report')
    parser.add_argument('--fail-on', choices=['NONE'] + list(LEVELS), default='NONE')
    parser.add_argument('--only-new', action='store_true', help='Apply policy only to new findings (requires baseline)')
    parser.add_argument('--only-fixable', action='store_true', help='Apply policy only where remediation is reported')
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    if args.only_new and not args.baseline:
        parser.error('--only-new requires --baseline')
    if args.zap_active and not args.url:
        parser.error('--zap-active requires --url')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    if args.url and (urlparse(args.url).scheme not in ('http', 'https') or not urlparse(args.url).netloc):
        parser.error('--url must be an HTTP(S) URL')
    try:
        return SecurityScanner(args).run()
    except (ValueError, OSError) as exc:
        print(f'Configuration error: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
