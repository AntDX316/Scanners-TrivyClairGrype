"""Shared, escaped HTML rendering for scanner output."""
from html import escape


def text(value):
    return escape(str(value if value is not None else ""), quote=True)


def table(headers, rows):
    rows = list(rows)
    if not rows:
        return '<p>No findings reported by this scanner.</p>'
    return ('<div style="overflow-x:auto"><table><tr>' +
            ''.join('<th>' + text(h) + '</th>' for h in headers) + '</tr>' +
            ''.join('<tr>' + ''.join('<td>' + text(v) + '</td>' for v in row) + '</tr>' for row in rows) +
            '</table></div>')


def trivy_report(data):
    if not data or 'Results' not in data:
        return '<p>Scanner results unavailable. Coverage is incomplete.</p>'
    rows = []
    for result in data.get('Results') or []:
        for v in result.get('Vulnerabilities') or []:
            rows.append(('Vulnerability', result.get('Target'), v.get('PkgName'),
                         v.get('VulnerabilityID'), v.get('Severity'), v.get('InstalledVersion'),
                         v.get('FixedVersion') or 'No fix reported', v.get('Title') or v.get('Description')))
        for v in result.get('Misconfigurations') or []:
            rows.append(('Configuration', result.get('Target'), '', v.get('ID'), v.get('Severity'),
                         '', v.get('Resolution'), v.get('Title')))
        for v in result.get('Secrets') or []:
            # Never copy secret matches or source snippets into the combined report.
            rows.append(('Secret', result.get('Target'), '', v.get('RuleID'), v.get('Severity'),
                         '', 'Rotate credential and remove from source', v.get('Title')))
    return table(('Type', 'Location', 'Package', 'Finding', 'Severity', 'Installed', 'Remediation', 'Details'), rows)


def grype_report(data):
    if not data or 'matches' not in data:
        return '<p>Scanner results unavailable. Coverage is incomplete.</p>'
    rows = []
    for match in data.get('matches') or []:
        v, a = match.get('vulnerability') or {}, match.get('artifact') or {}
        fix = v.get('fix') or {}
        rows.append((a.get('name'), a.get('version'), v.get('id'), v.get('severity'),
                     ', '.join(fix.get('versions') or []) or 'No fix reported',
                     fix.get('state') or 'unknown', v.get('description')))
    return table(('Package', 'Installed', 'Finding', 'Severity', 'Fixed versions', 'Fix status', 'Details'), rows)


def clair_report(data):
    if not data or 'Vulnerabilities' not in data:
        return '<p>Clair results unavailable or scan skipped. This is not a clean scan.</p>'
    return table(('Package', 'Finding', 'Severity', 'Fixed version', 'Details'),
                 ((v.get('FeatureName'), v.get('Name'), v.get('Severity'), v.get('FixedBy'),
                   v.get('Description')) for v in data.get('Vulnerabilities') or []))
