"""
core/postman.py — Postman Collection + cURL Generator

Generates a full Postman Collection v2.1 JSON from discovered endpoints.
Each endpoint gets:
  - Realistic sample request body / params
  - Auth headers pre-filled
  - Description with security notes
  - cURL command
  - Pre-request and test scripts
"""

import json
import uuid
import time
import re


# ─── Sample data per endpoint type ──────────────────────────────────────────

SAMPLE_BODIES = {
    # AUTH
    'login':    {"email": "user@example.com", "password": "Password123!"},
    'register': {"name": "John Doe", "email": "user@example.com", "password": "Password123!", "role": "user"},
    'refresh':  {"refresh_token": "{{refresh_token}}"},
    'logout':   {"refresh_token": "{{refresh_token}}"},
    'forgot':   {"email": "user@example.com"},
    'reset':    {"token": "{{reset_token}}", "password": "NewPassword123!"},
    'verify':   {"otp": "123456", "email": "user@example.com"},

    # USERS
    'users_post':   {"name": "Jane Doe", "email": "jane@example.com", "role": "user", "phone": "+1234567890"},
    'users_put':    {"name": "Jane Doe Updated", "email": "jane@example.com", "phone": "+1234567890"},
    'profile_put':  {"name": "My Name", "bio": "Hello world", "avatar_url": "https://example.com/avatar.png"},
    'password':     {"current_password": "OldPass123!", "new_password": "NewPass123!"},

    # PRODUCTS / ITEMS
    'products_post': {"name": "Product Name", "description": "Product description", "price": 29.99, "stock": 100, "category": "electronics"},
    'products_put':  {"name": "Updated Product", "price": 34.99, "stock": 80},

    # ORDERS / CART
    'orders_post': {"items": [{"product_id": "{{product_id}}", "quantity": 2}], "shipping_address": "123 Main St, City, Country", "payment_method": "card"},
    'cart_post':   {"product_id": "{{product_id}}", "quantity": 1},
    'cart_put':    {"quantity": 3},

    # PAYMENTS
    'payments': {"amount": 99.99, "currency": "USD", "card_token": "tok_test_123", "order_id": "{{order_id}}"},
    'invoices': {"customer_id": "{{user_id}}", "items": [{"description": "Service fee", "amount": 49.99}], "due_date": "2025-12-31"},

    # MESSAGES / NOTIFICATIONS
    'messages_post': {"recipient_id": "{{user_id}}", "content": "Hello there!", "type": "text"},
    'notifications': {"title": "Test Notification", "body": "This is a test", "user_id": "{{user_id}}"},

    # WEBHOOKS
    'webhooks_post': {"url": "https://your-server.com/webhook", "events": ["order.created", "payment.received"], "secret": "webhook_secret_key"},
    'webhooks_put':  {"url": "https://your-server.com/webhook-updated", "active": True},

    # FILES / UPLOADS
    'upload': {"file": "<binary>", "type": "image", "filename": "photo.jpg"},

    # SEARCH
    'search': None,  # GET with params

    # ADMIN
    'admin_settings': {"maintenance_mode": False, "max_users": 1000, "feature_flags": {"new_ui": True}},
    'admin_users_put': {"role": "admin", "status": "active", "verified": True},

    # GRAPHQL
    'graphql': {"query": "{ users { id email name } }", "variables": {}},

    # GENERIC POST
    'generic_post': {"key": "value", "data": "sample"},
}

SAMPLE_QUERY_PARAMS = {
    'search':   [("q", "search term"), ("limit", "20"), ("offset", "0")],
    'users':    [("page", "1"), ("limit", "20"), ("sort", "created_at"), ("order", "desc")],
    'products': [("page", "1"), ("limit", "20"), ("category", "electronics"), ("min_price", "10"), ("max_price", "500")],
    'orders':   [("status", "pending"), ("page", "1"), ("limit", "10")],
    'logs':     [("level", "error"), ("from", "2025-01-01"), ("to", "2025-12-31"), ("limit", "50")],
    'analytics':[("period", "30d"), ("metric", "pageviews")],
    'reports':  [("format", "json"), ("from", "2025-01-01"), ("to", "2025-12-31")],
    'export':   [("format", "csv"), ("type", "users")],
    'default':  [("page", "1"), ("limit", "20")],
}

# Security test notes per vulnerability type
SECURITY_NOTES = {
    'auth':    '⚠️ PENTEST: Try no token, expired token, token of another user',
    'users':   '⚠️ PENTEST: Try BOLA — change ID to another user\'s ID. Try mass assignment — add "role":"admin"',
    'admin':   '🚨 PENTEST: Test with regular user token — should return 403. If 200, BFLA confirmed!',
    'search':  '⚠️ PENTEST: Inject SQLi payloads: ?q=\' OR \'1\'=\'1 or ?q=1; SELECT SLEEP(2)--',
    'upload':  '⚠️ PENTEST: Try uploading .php/.js files, path traversal in filename: ../../etc/passwd',
    'webhook': '⚠️ PENTEST: Try SSRF — set url to http://169.254.169.254/latest/meta-data/',
    'payment': '⚠️ PENTEST: Try negative amounts, currency manipulation, replay attacks',
    'graphql': '🚨 PENTEST: Run introspection query — if enabled, full schema is exposed',
    'default': 'ℹ️ Test with and without auth token. Check response for sensitive data leakage.',
}


class PostmanGenerator:
    def __init__(self, target, endpoints, scan_id, auth_token=None):
        self.target = target.rstrip('/')
        self.endpoints = endpoints
        self.scan_id = scan_id
        self.auth_token = auth_token or "{{auth_token}}"
        self.host = self._extract_host(target)

    def generate_collection(self):
        """Generate full Postman Collection v2.1"""
        collection = {
            "info": {
                "_postman_id": str(uuid.uuid4()),
                "name": f"APIReaper — {self.host}",
                "description": (
                    f"Auto-generated by APIReaper\n"
                    f"Target: {self.target}\n"
                    f"Scan ID: {self.scan_id}\n"
                    f"Generated: {time.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                    f"⚠️ FOR AUTHORIZED SECURITY TESTING ONLY\n\n"
                    f"HOW TO USE:\n"
                    f"1. Import this file into Postman\n"
                    f"2. Set 'auth_token' variable in Collection Variables\n"
                    f"3. After login, the token auto-saves via the Login request test script\n"
                    f"4. Run requests individually or use Collection Runner for full scan"
                ),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "auth": {
                "type": "bearer",
                "bearer": [{"key": "token", "value": "{{auth_token}}", "type": "string"}]
            },
            "variable": [
                {"key": "base_url", "value": self.target, "type": "string"},
                {"key": "auth_token", "value": self.auth_token if self.auth_token != "{{auth_token}}" else "", "type": "string"},
                {"key": "refresh_token", "value": "", "type": "string"},
                {"key": "user_id", "value": "1", "type": "string"},
                {"key": "product_id", "value": "1", "type": "string"},
                {"key": "order_id", "value": "1", "type": "string"},
                {"key": "reset_token", "value": "", "type": "string"},
            ],
            "event": [
                {
                    "listen": "prerequest",
                    "script": {
                        "type": "text/javascript",
                        "exec": ["// Global pre-request: ensure base_url has no trailing slash",
                                 "const base = pm.collectionVariables.get('base_url') || '';",
                                 "pm.collectionVariables.set('base_url', base.replace(/\\/+$/, ''));"]
                    }
                }
            ],
            "item": self._build_folders()
        }
        return collection

    def _build_folders(self):
        """Group endpoints into logical folders"""
        folders = {
            "🔐 Authentication":    [],
            "👤 Users & Profile":   [],
            "🛒 Products & Orders": [],
            "💳 Payments":          [],
            "🔧 Admin":             [],
            "🔍 Search & Data":     [],
            "📁 Files & Uploads":   [],
            "🔔 Notifications":     [],
            "🕸️ GraphQL":           [],
            "⚙️ System & Health":   [],
            "📦 Other":             [],
        }

        for ep in self.endpoints:
            path = ep['path'].lower()
            folder = self._classify_endpoint(path)
            item = self._build_item(ep)
            folders[folder].append(item)

        # Build folder objects, skip empty ones
        result = []
        for folder_name, items in folders.items():
            if items:
                result.append({
                    "name": folder_name,
                    "description": self._folder_description(folder_name),
                    "item": items,
                    "event": []
                })
        return result

    def _classify_endpoint(self, path):
        if any(k in path for k in ['/auth', '/login', '/logout', '/register', '/token', '/refresh', '/password', '/otp', '/verify', '/forgot', '/reset']):
            return "🔐 Authentication"
        if any(k in path for k in ['/admin', '/manage', '/superuser', '/internal', '/root']):
            return "🔧 Admin"
        if any(k in path for k in ['/user', '/profile', '/me', '/account']):
            return "👤 Users & Profile"
        if any(k in path for k in ['/product', '/order', '/cart', '/shop', '/item', '/catalog', '/inventory']):
            return "🛒 Products & Orders"
        if any(k in path for k in ['/payment', '/invoice', '/billing', '/checkout', '/transaction', '/wallet']):
            return "💳 Payments"
        if any(k in path for k in ['/search', '/filter', '/find', '/query', '/report', '/export', '/analytic']):
            return "🔍 Search & Data"
        if any(k in path for k in ['/upload', '/file', '/media', '/image', '/attachment', '/document']):
            return "📁 Files & Uploads"
        if any(k in path for k in ['/notification', '/message', '/chat', '/webhook', '/alert', '/email']):
            return "🔔 Notifications"
        if '/graphql' in path or '/gql' in path:
            return "🕸️ GraphQL"
        if any(k in path for k in ['/health', '/status', '/ping', '/version', '/config', '/swagger', '/openapi', '/docs']):
            return "⚙️ System & Health"
        return "📦 Other"

    def _build_item(self, ep):
        """Build a single Postman request item"""
        method = ep['method']
        path = ep['path']
        url = ep.get('url', self.target + path)
        path_key = self._path_key(path)
        body_key = self._body_key(path, method)
        sample_body = SAMPLE_BODIES.get(body_key)
        query_params = self._get_query_params(path, method)
        security_note = self._get_security_note(path)
        curl = self._generate_curl(method, url, sample_body, query_params)

        # Build URL object
        clean_path = path.lstrip('/')
        path_parts = clean_path.split('/')
        url_obj = {
            "raw": "{{base_url}}" + path + (("?" + "&".join(f"{k}={v}" for k,v in query_params)) if query_params and method == 'GET' else ""),
            "host": ["{{base_url}}"],
            "path": path_parts,
        }
        if query_params and method == 'GET':
            url_obj["query"] = [{"key": k, "value": v, "description": ""} for k, v in query_params]

        # Build request body
        body_obj = {"mode": "none"}
        if method in ['POST', 'PUT', 'PATCH'] and sample_body:
            if path_key == 'upload':
                body_obj = {
                    "mode": "formdata",
                    "formdata": [
                        {"key": "file", "type": "file", "src": "/path/to/file.jpg", "description": "File to upload"},
                        {"key": "type", "value": "image", "type": "text"},
                        {"key": "filename", "value": "photo.jpg", "type": "text"},
                    ]
                }
            else:
                body_obj = {
                    "mode": "raw",
                    "raw": json.dumps(sample_body, indent=2),
                    "options": {"raw": {"language": "json"}}
                }

        # Test script — auto-saves token on login
        test_script = self._build_test_script(path, method)
        prereq_script = self._build_prerequest_script(path, method)

        return {
            "name": f"{method} {path}",
            "event": [
                {"listen": "prerequest", "script": {"type": "text/javascript", "exec": prereq_script}},
                {"listen": "test", "script": {"type": "text/javascript", "exec": test_script}},
            ],
            "request": {
                "method": method,
                "header": [
                    {"key": "Content-Type", "value": "application/json", "type": "text"},
                    {"key": "Accept", "value": "application/json", "type": "text"},
                ],
                "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{auth_token}}", "type": "string"}]},
                "body": body_obj,
                "url": url_obj,
                "description": (
                    f"**Endpoint:** `{method} {path}`\n"
                    f"**Source:** {ep.get('source', 'discovered')}\n"
                    f"**Status (during scan):** {ep.get('status', '?')}\n\n"
                    f"---\n\n"
                    f"{security_note}\n\n"
                    f"---\n\n"
                    f"**cURL:**\n```bash\n{curl}\n```"
                )
            },
            "response": []
        }

    def _generate_curl(self, method, url, body, params):
        """Generate a ready-to-run curl command"""
        parts = ["curl -X " + method]
        
        # URL with params
        full_url = url
        if params and method == 'GET':
            param_str = "&".join(f"{k}={v}" for k, v in params)
            full_url = f"{url}?{param_str}"
        parts.append(f'  "{full_url}"')

        # Headers
        parts.append('  -H "Content-Type: application/json"')
        parts.append('  -H "Authorization: Bearer YOUR_TOKEN_HERE"')

        # Body
        if body and method in ['POST', 'PUT', 'PATCH']:
            body_str = json.dumps(body, separators=(',', ':'))
            parts.append(f"  -d '{body_str}'")

        parts.append("  -v")
        return " \\\n".join(parts)

    def _build_test_script(self, path, method):
        """Postman test script — auto-extracts and saves tokens"""
        scripts = [
            "// ─── Auto-save token after login ───",
            "if (pm.response.code === 200 || pm.response.code === 201) {",
            "  try {",
            "    const json = pm.response.json();",
            "    // Detect token field (common names)",
            "    const token = json.token || json.access_token || json.accessToken ||",
            "                  json.jwt || json.data?.token || json.data?.access_token;",
            "    if (token) {",
            "      pm.collectionVariables.set('auth_token', token);",
            "      console.log('✅ auth_token saved:', token.substring(0,20) + '...');",
            "    }",
            "    const refresh = json.refresh_token || json.refreshToken || json.data?.refresh_token;",
            "    if (refresh) {",
            "      pm.collectionVariables.set('refresh_token', refresh);",
            "      console.log('✅ refresh_token saved');",
            "    }",
            "    // Save IDs",
            "    const id = json.id || json.user_id || json.userId || json.data?.id;",
            "    if (id && !pm.collectionVariables.get('user_id')) {",
            "      pm.collectionVariables.set('user_id', String(id));",
            "    }",
            "  } catch(e) {}",
            "}",
            "",
            "// ─── Basic response tests ───",
            "pm.test('Response time < 3000ms', () => {",
            "  pm.expect(pm.response.responseTime).to.be.below(3000);",
            "});",
            "pm.test('Status is not 500', () => {",
            "  pm.expect(pm.response.code).to.not.equal(500);",
            "});",
            "if (pm.response.headers.get('Content-Type')?.includes('json')) {",
            "  pm.test('Response is valid JSON', () => {",
            "    pm.response.json(); // throws if invalid",
            "  });",
            "}",
        ]

        # Extra security tests
        if '/admin' in path:
            scripts += [
                "",
                "// ─── Security: Admin endpoint check ───",
                "pm.test('🚨 SECURITY: Admin endpoint should require auth', () => {",
                "  // If you get 200 without a token, this is BFLA",
                "  pm.expect([200, 401, 403]).to.include(pm.response.code);",
                "  if (pm.response.code === 200) console.warn('⚠️ BFLA POSSIBLE: Admin returned 200!');",
                "});",
            ]
        if re.search(r'/users?/|/profile', path):
            scripts += [
                "",
                "// ─── Security: BOLA check ───",
                "pm.test('BOLA check: note response data owner', () => {",
                "  try {",
                "    const j = pm.response.json();",
                "    const id = j.id || j.user_id || j.userId;",
                "    if (id) console.log('Response belongs to user ID:', id, '— verify this matches your token!');",
                "  } catch(e) {}",
                "});",
            ]

        return scripts

    def _build_prerequest_script(self, path, method):
        return [
            f"// Pre-request for {method} {path}",
            "// Ensure auth token is set before running",
            "const token = pm.collectionVariables.get('auth_token');",
            "if (!token) console.warn('⚠️ auth_token not set — run Login first!');",
        ]

    def _get_query_params(self, path, method):
        if method != 'GET':
            return []
        for key, params in SAMPLE_QUERY_PARAMS.items():
            if key in path:
                return params
        if any(k in path for k in ['/user', '/product', '/order']):
            return SAMPLE_QUERY_PARAMS['users']
        return SAMPLE_QUERY_PARAMS['default']

    def _get_security_note(self, path):
        path_l = path.lower()
        for key, note in SECURITY_NOTES.items():
            if key in path_l:
                return note
        return SECURITY_NOTES['default']

    def _path_key(self, path):
        path_l = path.lower()
        if 'upload' in path_l or 'file' in path_l or 'media' in path_l:
            return 'upload'
        if 'graphql' in path_l:
            return 'graphql'
        return path_l.split('/')[-1] or 'default'

    def _body_key(self, path, method):
        path_l = path.lower()
        m = method.upper()
        if 'login' in path_l or 'signin' in path_l:     return 'login'
        if 'register' in path_l or 'signup' in path_l:  return 'register'
        if 'refresh' in path_l:                          return 'refresh'
        if 'logout' in path_l:                           return 'logout'
        if 'forgot' in path_l:                           return 'forgot'
        if 'reset' in path_l and 'password' in path_l:  return 'reset'
        if 'verify' in path_l or 'otp' in path_l:       return 'verify'
        if 'upload' in path_l or 'file' in path_l:      return 'upload'
        if 'graphql' in path_l:                          return 'graphql'
        if 'payment' in path_l:                          return 'payments'
        if 'invoice' in path_l:                          return 'invoices'
        if 'message' in path_l and m == 'POST':          return 'messages_post'
        if 'webhook' in path_l and m == 'POST':          return 'webhooks_post'
        if 'webhook' in path_l and m in ['PUT','PATCH']: return 'webhooks_put'
        if 'order' in path_l and m == 'POST':            return 'orders_post'
        if 'cart' in path_l and m == 'POST':             return 'cart_post'
        if 'cart' in path_l and m in ['PUT','PATCH']:    return 'cart_put'
        if 'product' in path_l and m == 'POST':          return 'products_post'
        if 'product' in path_l and m in ['PUT','PATCH']: return 'products_put'
        if 'profile' in path_l and m in ['PUT','PATCH']: return 'profile_put'
        if 'password' in path_l:                         return 'password'
        if ('user' in path_l or '/me' in path_l) and m == 'POST': return 'users_post'
        if ('user' in path_l or '/me' in path_l) and m in ['PUT','PATCH']: return 'users_put'
        if 'admin' in path_l and 'setting' in path_l:   return 'admin_settings'
        if 'admin' in path_l and 'user' in path_l and m in ['PUT','PATCH']: return 'admin_users_put'
        if m in ['POST', 'PUT', 'PATCH']:                return 'generic_post'
        return 'search'

    def _folder_description(self, name):
        desc = {
            "🔐 Authentication":    "Login, register, token refresh. Run Login first to auto-save your auth_token.",
            "👤 Users & Profile":   "User CRUD + profile. Check for BOLA by changing user IDs.",
            "🛒 Products & Orders": "E-commerce endpoints. Test for price manipulation and IDOR.",
            "💳 Payments":          "Payment/billing endpoints. Test for amount manipulation and replay attacks.",
            "🔧 Admin":             "⚠️ Admin-only endpoints. Test with regular user token to check for BFLA.",
            "🔍 Search & Data":     "Search + reporting. Inject SQLi payloads into query params.",
            "📁 Files & Uploads":   "File handling. Test for path traversal and dangerous file type uploads.",
            "🔔 Notifications":     "Messaging + webhooks. Test webhooks for SSRF via internal URLs.",
            "🕸️ GraphQL":           "GraphQL endpoint. Always test introspection query first.",
            "⚙️ System & Health":   "Health checks + config. May expose version info or secrets.",
            "📦 Other":             "Uncategorized discovered endpoints.",
        }
        return desc.get(name, "")

    def _extract_host(self, url):
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return url

    def generate_curl_collection(self):
        """Generate a shell script with all curl commands"""
        lines = [
            "#!/bin/bash",
            "# APIReaper — cURL Collection",
            f"# Target: {self.target}",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M UTC')}",
            "# ⚠️ FOR AUTHORIZED TESTING ONLY",
            "",
            "BASE_URL=\"" + self.target + "\"",
            "TOKEN=\"YOUR_JWT_TOKEN_HERE\"",
            "",
            "# ─── Run this first to get a token ───",
            "",
        ]

        # Group by folder
        folders = {}
        for ep in self.endpoints:
            folder = self._classify_endpoint(ep['path'].lower())
            if folder not in folders:
                folders[folder] = []
            folders[folder].append(ep)

        for folder, eps in folders.items():
            lines.append(f"\n# {'='*55}")
            lines.append(f"# {folder}")
            lines.append(f"# {'='*55}\n")
            for ep in eps:
                method = ep['method']
                path = ep['path']
                body_key = self._body_key(path, method)
                sample_body = SAMPLE_BODIES.get(body_key)
                params = self._get_query_params(path, method)
                full_url = f"$BASE_URL{path}"
                if params and method == 'GET':
                    full_url += "?" + "&".join(f"{k}={v}" for k,v in params)

                lines.append(f"# {method} {path}")
                curl_parts = [f'curl -X {method} "{full_url}"']
                curl_parts.append('  -H "Content-Type: application/json"')
                curl_parts.append('  -H "Authorization: Bearer $TOKEN"')
                if sample_body and method in ['POST', 'PUT', 'PATCH']:
                    body_str = json.dumps(sample_body, separators=(',', ':'))
                    curl_parts.append(f"  -d '{body_str}'")
                curl_parts.append("  -s | python3 -m json.tool")
                lines.append(" \\\n".join(curl_parts))
                lines.append("")

        return "\n".join(lines)
