"""
core/reporter.py — Report Generator
Produces JSON and plain-text pentest reports from scan results.
"""

import json
import time


class ReportGenerator:
    def __init__(self, scan):
        self.scan = scan

    def as_json(self):
        return {
            'meta': {
                'tool': 'APIReaper v1.0',
                'target': self.scan['target'],
                'scan_id': self.scan['id'],
                'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.scan['started'])),
                'status': self.scan['status'],
            },
            'summary': {
                'endpoints_discovered': len(self.scan['endpoints']),
                'vulnerabilities_found': len(self.scan['vulns']),
                'critical': len([v for v in self.scan['vulns'] if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.scan['vulns'] if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.scan['vulns'] if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.scan['vulns'] if v['severity'] == 'LOW']),
            },
            'endpoints': self.scan['endpoints'],
            'vulnerabilities': self.scan['vulns'],
        }

    def as_text(self):
        s = self.scan
        sep = '=' * 65
        thin = '-' * 65
        vuln_counts = {sev: len([v for v in s['vulns'] if v['severity'] == sev])
                       for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}

        lines = [
            sep,
            ' APIReaper — Security Assessment Report',
            sep,
            f' Target  : {s["target"]}',
            f' Scan ID : {s["id"]}',
            f' Date    : {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(s["started"]))}',
            f' Status  : {s["status"].upper()}',
            sep,
            '',
            '[ EXECUTIVE SUMMARY ]',
            thin,
            f'  Endpoints Discovered : {len(s["endpoints"])}',
            f'  Vulnerabilities      : {len(s["vulns"])}',
            f'    CRITICAL : {vuln_counts["CRITICAL"]}',
            f'    HIGH     : {vuln_counts["HIGH"]}',
            f'    MEDIUM   : {vuln_counts["MEDIUM"]}',
            f'    LOW      : {vuln_counts["LOW"]}',
            '',
            '[ DISCOVERED ENDPOINTS ]',
            thin,
        ]

        for ep in s['endpoints']:
            lines.append(f'  {ep["method"]:<8} {ep["path"]:<50} [{ep.get("status","?")}] ({ep.get("source","")})')

        lines += ['', '[ VULNERABILITIES ]', thin]

        for v in sorted(s['vulns'], key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].index(x['severity'])):
            lines += [
                '',
                f'  [{v["severity"]}] {v["name"]}',
                f'  Endpoint    : {v["method"]} {v["endpoint"]}',
                f'  CWE         : {v["cwe"]}    CVSS: {v["cvss"]}',
                f'  Description : {v["description"]}',
                f'  Remediation : {v["remediation"]}',
                f'  PoC Request :',
            ]
            for line in v['poc_request'].split('\n'):
                lines.append(f'    {line}')
            if v.get('evidence'):
                lines.append(f'  Evidence    : {str(v["evidence"])[:200]}')
            lines.append(thin)

        lines += ['', sep, ' END OF REPORT — APIReaper', sep, '']
        return '\n'.join(lines)
