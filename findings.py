"""Normalize scanner output without copying source code or secret values."""
import hashlib
import json
from html import escape
from pathlib import Path

LEVELS = {'UNKNOWN': 0, 'INFO': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}


def finding(scanner, kind, rule, severity, location='', package='', version='', ecosystem='', fix='', title='', line=0):
    severity = str(severity).upper()
    severity = {'WARNING': 'MEDIUM', 'ERROR': 'HIGH', 'INFORMATIONAL': 'INFO', 'NEGLIGIBLE': 'INFO'}.get(severity, severity)
    location = str(location or '').replace('\\', '/').removeprefix('/workspace/').removeprefix('/src/').removeprefix('./')
    return dict(scanners=[scanner], kind=kind, rule=str(rule or 'unknown'), severity=severity if severity in LEVELS else 'UNKNOWN',
                location=location, package=str(package or ''), version=str(version or ''), ecosystem=str(ecosystem or ''),
                fix=str(fix or ''), title=str(title or ''), line=int(line or 0))


def normalize(scanner, data):
    rows = []
    if scanner == 'trivy':
        for r in data.get('Results') or []:
            for v in r.get('Vulnerabilities') or []:
                rows.append(finding(scanner, 'vulnerability', v.get('VulnerabilityID'), v.get('Severity'),
                    package=v.get('PkgName'), version=v.get('InstalledVersion'), ecosystem=r.get('Type'),
                    fix=v.get('FixedVersion'), title=v.get('Title')))
                rows[-1]['locations'] = [str(r.get('Target') or '')]
            for v in r.get('Misconfigurations') or []:
                rows.append(finding(scanner, 'configuration', v.get('ID'), v.get('Severity'), r.get('Target'),
                    fix=v.get('Resolution'), title=v.get('Title'), line=(v.get('CauseMetadata') or {}).get('StartLine')))
            for v in r.get('Secrets') or []:
                rows.append(finding(scanner, 'secret', v.get('RuleID'), v.get('Severity'), r.get('Target'),
                    fix='Rotate credential and remove from source/history', title=v.get('Title'), line=v.get('StartLine')))
            for v in r.get('Licenses') or []:
                rows.append(finding(scanner, 'license', v.get('Name'), v.get('Severity'), r.get('Target'),
                    package=v.get('PkgName'), title='License: ' + str(v.get('Name')), fix='Review license obligations'))
    elif scanner == 'grype':
        ecosystems = {'python': 'pip', 'java-archive': 'jar', 'deb': 'debian', 'gem': 'gemspec', 'rust-crate': 'cargo'}
        for m in data.get('matches') or []:
            v, a = m.get('vulnerability') or {}, m.get('artifact') or {}
            aliases = sorted({v.get('id') or ''} | {x.get('id') or '' for x in m.get('relatedVulnerabilities') or []})
            cves = [x for x in aliases if x.startswith('CVE-')]
            canonical = cves[0] if len(cves) == 1 else v.get('id')
            rows.append(finding(scanner, 'vulnerability', canonical, v.get('severity'),
                package=a.get('name'), version=a.get('version'), ecosystem=ecosystems.get(a.get('type'), a.get('type')),
                fix=', '.join((v.get('fix') or {}).get('versions') or []), title=v.get('description')))
            rows[-1]['aliases'] = aliases
            rows[-1]['locations'] = [str(x.get('path') or '') for x in a.get('locations') or []]
    elif scanner == 'semgrep':
        for v in data.get('results') or []:
            extra = v.get('extra') or {}
            rows.append(finding(scanner, 'code', v.get('check_id'), extra.get('severity'), v.get('path'),
                title=extra.get('message'), line=(v.get('start') or {}).get('line'),
                fix='Review code and apply rule guidance'))
    elif scanner == 'trufflehog':
        for v in data:
            meta = (v.get('SourceMetadata') or {}).get('Data') or {}
            git = meta.get('Git') or meta.get('Filesystem') or {}
            rows.append(finding(scanner, 'secret-history', v.get('DetectorName'), 'HIGH',
                git.get('file'), title='Potential credential in Git history' if 'Git' in meta else 'Potential credential in files',
                line=git.get('line'), fix='Rotate credential; review commit ' + str(git.get('commit') or 'working tree')))
    elif scanner == 'zap':
        for site in data.get('site') or []:
            for v in site.get('alerts') or []:
                for instance in v.get('instances') or [{}]:
                    rows.append(finding(scanner, 'web', v.get('pluginid'),
                        {'0': 'INFO', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH'}.get(str(v.get('riskcode')), 'UNKNOWN'),
                        instance.get('uri') or site.get('@name'), title=v.get('name'), fix=v.get('solution')))
    return rows


def consolidate(rows, baseline=None):
    merged = {}
    for row in rows:
        row = dict(row, locations=row.get('locations') or ([row['location']] if row['location'] else []), aliases=row.get('aliases') or [row['rule']])
        # Include ecosystem/version so unrelated packages are never merged merely by CVE.
        key = tuple(row[k] for k in ('kind', 'rule', 'package', 'version', 'ecosystem', 'location', 'line'))
        fingerprint = hashlib.sha256(json.dumps(key).encode()).hexdigest()
        if fingerprint in merged:
            current = merged[fingerprint]
            current['aliases'] = sorted(set(current['aliases'] + row['aliases']))
            current['locations'] = sorted(set(current['locations'] + row['locations']))
            current['scanners'] = sorted(set(current['scanners'] + row['scanners']))
            if LEVELS[row['severity']] > LEVELS[current['severity']]:
                current['severity'] = row['severity']
            current['fix'] = '; '.join(sorted(set(filter(None, (current['fix'], row['fix'])))))
        else:
            merged[fingerprint] = dict(row, fingerprint=fingerprint)
    previous = {f['fingerprint'] for f in (baseline or {}).get('findings', [])}
    for fp, row in merged.items():
        row['status'] = ('existing' if fp in previous else 'new') if baseline is not None else 'uncompared'
    return sorted(merged.values(), key=lambda r: (-LEVELS[r['severity']], not bool(r['fix']), r['rule'], r['package']))


def policy_failed(rows, threshold, only_new=False, only_fixable=False):
    return threshold != 'NONE' and any(LEVELS[r['severity']] >= LEVELS[threshold] and
        (not only_new or r['status'] == 'new') and (not only_fixable or bool(r['fix'])) for r in rows)


def sarif(report):
    results = []
    for f in report['findings']:
        result = {'ruleId': f['rule'], 'level': 'error' if LEVELS[f['severity']] >= 4 else 'warning' if LEVELS[f['severity']] >= 2 else 'note',
            'message': {'text': f['title'] or f['rule']}, 'partialFingerprints': {'primaryLocationLineHash': f['fingerprint']},
            'properties': {k: f[k] for k in ('kind', 'severity', 'scanners', 'status', 'package', 'version', 'fix')}}
        if f['location'] and not f['location'].startswith(('http:', 'https:')):
            loc = {'artifactLocation': {'uri': f['location'].replace(' ', '%20')}}
            if f['line'] > 0:
                loc['region'] = {'startLine': f['line']}
            result['locations'] = [{'physicalLocation': loc}]
        results.append(result)
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{'tool': {'driver': {'name': 'Scanners-TrivyClairGrype'}}, 'results': results}]}


def render(report, path):
    e = lambda v: escape(str(v or ''), quote=True)
    cards = ''.join(f'<article><b>{e(name)}</b><strong>{e(info["status"])}</strong><small>{e(info.get("detail"))}</small></article>' for name, info in report['scanners'].items())
    rows = ''.join('<tr>' + ''.join(f'<td>{e(value)}</td>' for value in (
        f['severity'], f['kind'], f['status'], f['rule'], f['package'] + ' ' + f['version'],
        (f['location'] or ', '.join(f.get('locations', []))) + (':' + str(f['line']) if f['line'] else ''), ', '.join(f['scanners']), f['fix'], f['title'])) + '</tr>' for f in report['findings'])
    html = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security scan report</title>
<style>*{box-sizing:border-box}body{margin:0;background:#0a1020;color:#dce7fa;font:15px system-ui}main{max-width:1600px;margin:auto;padding:36px}header{border-bottom:1px solid #28364b;padding-bottom:25px}.eyebrow{color:#57dbc1;letter-spacing:3px;font-size:12px}h1{font-size:42px;margin:12px 0}p,small{color:#9aabc4}section{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0}article{background:#121e32;padding:18px;border:1px solid #28364b;border-radius:12px}strong{display:block;font-size:24px;margin:10px 0;color:#57dbc1}input,select{background:#121e32;color:#e4edff;padding:12px;border:1px solid #3b506b;border-radius:8px;margin:0 10px 15px 0}input{width: min(420px,95%)}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;border-bottom:1px solid #253248;padding:12px;vertical-align:top}th{color:#57dbc1}td{max-width:300px;overflow-wrap:anywhere}footer{padding-top:24px;color:#9aabc4}a{color:#57dbc1}</style><main><header><div class="eyebrow">SECURITY / MULTI-LAYER ANALYSIS</div><h1>Security scan report</h1>'''
    html += f'<p>{e(report["target"])} · {e(report["created_at"])}</p></header><section>{cards}</section>'
    html += f'<h2>{len(report["findings"])} unique findings · {report["new_count"]} new</h2><p>Sorted by severity, then available remediation. Scanner agreement is evidence, not proof of exploitability. Missing coverage is shown above.</p>'
    html += '<input id="search" aria-label="Search findings" placeholder="Search package, rule, scanner or remediation"><select id="severity" aria-label="Filter severity"><option value="">All severities</option>'
    html += ''.join(f'<option>{v}</option>' for v in reversed(LEVELS)) + '</select><select id="status" aria-label="Filter baseline status"><option value="">All baseline statuses</option><option>new</option><option>existing</option><option>uncompared</option></select>'
    html += '<div class="scroll"><table><thead><tr>' + ''.join(f'<th>{h}</th>' for h in ('Severity','Category','Baseline','Rule','Package / installed','Location','Evidence','Remediation','Details')) + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
    html += '<footer>Secret values and source snippets are excluded from this report. Raw Trivy output remains sensitive. Made by <a href="https://github.com/AntDX316">@AntDX316</a>.</footer></main><script>function filter(){const q=document.querySelector("#search").value.toLowerCase(),s=document.querySelector("#severity").value,b=document.querySelector("#status").value;document.querySelectorAll("tbody tr").forEach(r=>r.hidden=!(r.textContent.toLowerCase().includes(q)&&(!s||r.cells[0].textContent===s)&&(!b||r.cells[2].textContent===b)))}document.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",filter));</script></html>'
    Path(path).write_text(html, encoding='utf-8')
