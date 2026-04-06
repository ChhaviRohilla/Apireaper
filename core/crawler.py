"""
core/crawler.py — Real API Endpoint Crawler

Crawls target website, parses HTML + JS to discover all API endpoints.
Uses BeautifulSoup for HTML parsing and regex for JS analysis.
"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


# ─── Patterns that reveal API calls in JavaScript ───────────────────────────
JS_PATTERNS = [
    # fetch('/api/users')  or  fetch("https://example.com/api/users")
    r'''fetch\s*\(\s*['"`]([^'"`\s]+)['"`]''',
    # axios.get('/api/users')
    r'''axios\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(\s*['"`]([^'"`\s]+)['"`]''',
    # axios({ url: '/api/users' })
    r'''url\s*:\s*['"`]([^'"`\s]*(?:/api|/v\d)[^'"`\s]*)['"`]''',
    # this.$http.get('/api') or Vue resource
    r'''\$http\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]''',
    # $.ajax({ url: '/api' })  or  $.get('/api')
    r'''\$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?['"`]([^'"`\s]+)['"`]''',
    # XMLHttpRequest .open('GET', '/api/...')
    r'''\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]+)['"`]''',
    # apiUrl = '/api/v1/users'  or  endpoint: '/api/...'
    r'''(?:apiUrl|endpoint|baseUrl|API_URL|api_url)\s*[=:]\s*['"`]([^'"`\s]+)['"`]''',
    # '/api/v1/...' or '/v2/...' string literals
    r'''['"`](/(?:api|v\d+|graphql|rest|service)[^'"`\s\)>]*)['"`]''',
]

# HTTP methods keywords near URLs in JS
METHOD_HINTS = {
    'post': 'POST', 'put': 'PUT', 'patch': 'PATCH',
    'delete': 'DELETE', 'get': 'GET'
}

COMMON_PROBE_PATHS = [
    # Auth
    ('/api/v1/auth/login', 'POST'), ('/api/v1/auth/register', 'POST'),
    ('/api/v1/auth/logout', 'POST'), ('/api/v1/auth/refresh', 'POST'),
    ('/api/v1/auth/me', 'GET'), ('/api/v2/auth/login', 'POST'),
    # Users
    ('/api/v1/users', 'GET'), ('/api/v1/users', 'POST'),
    ('/api/v1/users/1', 'GET'), ('/api/v2/users', 'GET'),
    ('/api/v1/profile', 'GET'), ('/api/v1/me', 'GET'),
    # Admin
    ('/api/admin', 'GET'), ('/api/admin/users', 'GET'),
    ('/api/admin/settings', 'GET'), ('/api/admin/dashboard', 'GET'),
    ('/api/admin/logs', 'GET'),
    # Products / data
    ('/api/v1/products', 'GET'), ('/api/v2/products', 'GET'),
    ('/api/v1/orders', 'GET'), ('/api/v1/cart', 'GET'),
    ('/api/v1/search', 'GET'), ('/api/search', 'GET'),
    # Meta / docs
    ('/swagger.json', 'GET'), ('/openapi.json', 'GET'),
    ('/api-docs', 'GET'), ('/api/docs', 'GET'),
    ('/graphql', 'POST'), ('/api/graphql', 'POST'),
    ('/api/health', 'GET'), ('/api/status', 'GET'),
    ('/api/v1/config', 'GET'), ('/api/v1/settings', 'GET'),
    ('/.well-known/openid-configuration', 'GET'),
    # Files / uploads
    ('/api/v1/upload', 'POST'), ('/api/v1/files', 'GET'),
    # Notifications / messages
    ('/api/v1/notifications', 'GET'), ('/api/v1/messages', 'GET'),
    # Payments
    ('/api/v1/payments', 'POST'), ('/api/v1/invoices', 'GET'),
    # Webhooks
    ('/api/v1/webhooks', 'GET'), ('/api/v1/reports', 'GET'),
]


class APICrawler:
    def __init__(self, target, options, log_fn, is_stopped_fn):
        self.target = target.rstrip('/')
        self.options = options
        self.log = log_fn
        self.is_stopped = is_stopped_fn
        self.depth = int(options.get('depth', 2))
        self.timeout = int(options.get('timeout', 8))
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; APIReaper/1.0; Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
        }
        # Custom auth header if provided
        if options.get('auth_token'):
            self.headers['Authorization'] = f"Bearer {options['auth_token']}"
        
        self.visited_pages = set()
        self.found_endpoints = {}  # key: (method, path) → endpoint dict
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def run(self):
        """Main entry point — crawl + probe + parse swagger/graphql"""
        self.log('info', f'Crawler starting on {self.target}')

        # 1. Crawl HTML pages and extract JS URLs
        self._crawl_page(self.target, current_depth=0)

        # 2. Active probe common paths
        if not self.is_stopped():
            self._probe_common_paths()

        # 3. Try to parse Swagger/OpenAPI if found
        if not self.is_stopped():
            self._try_swagger()

        # 4. Introspect GraphQL if found
        if not self.is_stopped():
            self._try_graphql()

        return list(self.found_endpoints.values())

    # ─── PAGE CRAWLER ────────────────────────────────────────────────────────

    def _crawl_page(self, url, current_depth):
        if self.is_stopped() or current_depth > self.depth:
            return
        if url in self.visited_pages:
            return
        self.visited_pages.add(url)

        self.log('info', f'Crawling {url}')
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            self.log('warn', f'Failed to fetch {url}: {e}')
            return

        content_type = resp.headers.get('Content-Type', '')

        # Parse HTML
        if 'html' in content_type:
            self._parse_html(resp.text, url, current_depth)

        # Parse JS directly
        if 'javascript' in content_type:
            self._extract_from_js(resp.text, url)

    def _parse_html(self, html, base_url, current_depth):
        """Extract JS file URLs, inline scripts, and links from HTML"""
        soup = BeautifulSoup(html, 'html.parser')  # using built-in parser, no lxml needed

        # 1. Find all <script src="..."> and fetch them
        for tag in soup.find_all('script', src=True):
            js_url = urljoin(base_url, tag['src'])
            if self._is_same_origin(js_url):
                if js_url not in self.visited_pages:
                    self.visited_pages.add(js_url)
                    self.log('info', f'Fetching JS: {js_url}')
                    try:
                        r = self.session.get(js_url, timeout=self.timeout)
                        self._extract_from_js(r.text, js_url)
                    except Exception as e:
                        self.log('warn', f'JS fetch failed: {e}')

        # 2. Inline scripts
        for tag in soup.find_all('script', src=False):
            if tag.string:
                self._extract_from_js(tag.string, base_url)

        # 3. Follow links for deeper crawl
        if current_depth < self.depth:
            for tag in soup.find_all('a', href=True):
                link = urljoin(base_url, tag['href'])
                if self._is_same_origin(link) and link not in self.visited_pages:
                    self._crawl_page(link, current_depth + 1)

        # 4. Look for data-* attributes with API paths
        for tag in soup.find_all(True):
            for attr_name, attr_val in tag.attrs.items():
                if isinstance(attr_val, str) and '/api/' in attr_val:
                    self._register_endpoint(attr_val, 'GET', 'HTML data-attr')

    def _extract_from_js(self, js_code, source_url):
        """Extract API endpoint references from JavaScript source"""
        found_count = 0
        for pattern in JS_PATTERNS:
            for match in re.finditer(pattern, js_code, re.IGNORECASE):
                path = match.group(1)
                if self._looks_like_api_path(path):
                    # Try to detect HTTP method from surrounding context
                    start = max(0, match.start() - 60)
                    ctx = js_code[start:match.start()].lower()
                    method = 'GET'
                    for keyword, m in METHOD_HINTS.items():
                        if keyword in ctx:
                            method = m
                            break
                    self._register_endpoint(path, method, 'JS analysis')
                    found_count += 1

        if found_count:
            self.log('info', f'Found {found_count} API refs in {source_url.split("/")[-1]}')

    # ─── ACTIVE PROBING ──────────────────────────────────────────────────────

    def _probe_common_paths(self):
        """Actively probe well-known API paths"""
        self.log('info', f'Probing {len(COMMON_PROBE_PATHS)} common API paths...')
        for path, method in COMMON_PROBE_PATHS:
            if self.is_stopped():
                break
            url = self.target + path
            try:
                if method == 'GET':
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.options(url, timeout=self.timeout)
                
                status = resp.status_code
                # Any non-404 response means the endpoint exists
                if status != 404:
                    level = 'success' if status < 300 else 'warn'
                    self.log(level, f'{method} {path} → {status}')
                    self._register_endpoint(path, method, 'path probe', status)
            except requests.exceptions.ConnectionError:
                self.log('error', f'Connection refused — is {self.target} reachable?')
                break
            except Exception:
                pass
            time.sleep(0.05)  # Polite delay

    # ─── SWAGGER / OPENAPI ───────────────────────────────────────────────────

    def _try_swagger(self):
        """Try to fetch and parse OpenAPI/Swagger spec"""
        spec_paths = ['/swagger.json', '/openapi.json', '/api/swagger.json',
                      '/api-docs', '/v2/api-docs', '/v3/api-docs']
        for path in spec_paths:
            if self.is_stopped():
                break
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and resp.headers.get('Content-Type','').find('json') != -1:
                    spec = resp.json()
                    count = self._parse_openapi_spec(spec)
                    if count > 0:
                        self.log('success', f'Parsed OpenAPI spec — {count} endpoints extracted from {path}')
                        return
            except Exception:
                pass

    def _parse_openapi_spec(self, spec):
        """Extract endpoints from OpenAPI 2.x / 3.x spec"""
        count = 0
        # OpenAPI 3.x
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method in ['get','post','put','patch','delete']:
                if method in methods:
                    self._register_endpoint(path, method.upper(), 'OpenAPI spec')
                    count += 1
        return count

    # ─── GRAPHQL ────────────────────────────────────────────────────────────

    def _try_graphql(self):
        """Try GraphQL introspection"""
        gql_paths = ['/graphql', '/api/graphql', '/gql']
        introspection_query = '{"query":"{__schema{types{name fields{name}}}}"}'
        
        for path in gql_paths:
            if self.is_stopped():
                break
            url = self.target + path
            try:
                resp = self.session.post(url, data=introspection_query,
                    headers={'Content-Type': 'application/json'}, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'data' in data and '__schema' in str(data):
                        types = data.get('data', {}).get('__schema', {}).get('types', [])
                        self.log('success', f'GraphQL introspection enabled at {path}! {len(types)} types exposed')
                        self._register_endpoint(path, 'POST', 'GraphQL introspection', 200, {
                            'note': 'GraphQL introspection is enabled — full schema exposed',
                            'types': [t['name'] for t in types if not t['name'].startswith('__')][:20]
                        })
            except Exception:
                pass

    # ─── HELPERS ────────────────────────────────────────────────────────────

    def _register_endpoint(self, path, method, source, status=None, extra=None):
        """Add endpoint to discovered list (deduplicated)"""
        # Normalize path — strip full domain if present
        if path.startswith('http'):
            parsed = urlparse(path)
            if not self._is_same_origin(path):
                return
            path = parsed.path + ('?' + parsed.query if parsed.query else '')

        if not path.startswith('/'):
            path = '/' + path

        key = f'{method}:{path}'
        if key not in self.found_endpoints:
            self.found_endpoints[key] = {
                'method': method,
                'path': path,
                'url': self.target + path,
                'source': source,
                'status': status,
                'extra': extra or {}
            }

    def _looks_like_api_path(self, path):
        """Filter out noise — only keep paths that look like API endpoints"""
        if len(path) < 3 or len(path) > 200:
            return False
        noise = ['.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff',
                 '.map', '.html', 'cdn.', 'fonts.', 'google', 'analytics',
                 'facebook', 'twitter', '#{', '${', '/*']
        return any(kw in path for kw in ['/api', '/v1', '/v2', '/v3', '/graphql',
                                          '/rest', '/service', '/auth', '/user',
                                          '/admin', '/data', '/endpoint']) \
               and not any(n in path.lower() for n in noise)

    def _is_same_origin(self, url):
        """Check if URL belongs to the same target domain"""
        try:
            target_host = urlparse(self.target).netloc
            url_host = urlparse(url).netloc
            return url_host == target_host or not url_host
        except Exception:
            return False
