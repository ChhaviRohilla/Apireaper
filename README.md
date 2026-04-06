# APIReaper — Real API Pentest Toolkit
## Complete Setup & Usage Guide

---

## ⚠️ LEGAL NOTICE — READ FIRST
```
Only use this tool on systems you OWN or have WRITTEN AUTHORIZATION to test.
Unauthorized scanning is illegal under:
  - India: IT Act 2000, Section 43 & 66
  - USA: CFAA (Computer Fraud and Abuse Act)
  - EU: Directive on Attacks Against Information Systems
  - UK: Computer Misuse Act 1990

Safe legal targets:
  ✅ Your own local apps (localhost)
  ✅ Bug bounty programs (HackerOne, Bugcrowd, Intigriti)
  ✅ DVWA, WebGoat, VulnHub labs
  ✅ Apps you wrote yourself
  ✅ Client systems with signed pentest agreement
```

---

## INSTALLATION (5 minutes)

### Requirements
- Python 3.8+
- pip

### Step 1 — Install dependencies
```bash
cd apireaper/
pip install -r requirements.txt
```

### Step 2 — Start the backend
```bash
python server.py
```
You should see:
```
╔══════════════════════════════════════╗
║   APIReaper — API Pentest Toolkit   ║
║   http://localhost:5000             ║
║   FOR AUTHORIZED TESTING ONLY      ║
╚══════════════════════════════════════╝
```

### Step 3 — Open the UI
Open your browser to: http://localhost:5000

---

## SETTING UP A PRACTICE TARGET

Before testing real apps, practice on intentionally vulnerable ones.

### Option A — DVWA (Recommended for beginners)
```bash
docker run -p 80:80 vulnerables/web-dvwa
```
Then scan: http://localhost

### Option B — OWASP WebGoat
```bash
docker run -p 8080:8080 webgoat/webgoat-8.0
```
Then scan: http://localhost:8080/WebGoat

### Option C — Juice Shop (Best for API practice)
```bash
docker run -p 3000:3000 bkimminich/juice-shop
```
Then scan: http://localhost:3000

### Option D — crAPI (Specifically for API vulns)
```bash
git clone https://github.com/OWASP/crAPI
cd crAPI && docker-compose up
```
Then scan: http://localhost:8888

---

## USING THE TOOL

### Basic Scan
1. Enter target URL: `http://localhost:3000`
2. Click EXECUTE
3. Watch endpoints appear in real-time
4. Vulnerabilities populate as they're found
5. Click any finding for full PoC details

### Authenticated Scan (More thorough)
1. Log into the target app manually in your browser
2. Copy your JWT token from DevTools → Application → Local Storage
   OR from DevTools → Network → any request → Authorization header
3. Paste it into the AUTH TOKEN field
4. Run scan — now tests authenticated endpoints too

### Understanding Results

**Endpoints Panel:**
- Green = HTTP 200 (accessible)
- Yellow = 3xx (redirect)
- Red = 4xx/5xx (error/blocked)
- Click any endpoint → see full request template

**Vulnerabilities Panel:**
- CRITICAL = Immediate compromise possible (BOLA, JWT bypass, BFLA)
- HIGH = Serious exploitable issue (SQLi, SSRF, No-auth)
- MEDIUM = Important but harder to exploit (CORS, Rate limit)
- LOW = Defence-in-depth improvements (Headers)

---

## UNDERSTANDING THE VULNERABILITIES

### BOLA — Broken Object Level Authorization
**What it is:** The #1 API vulnerability. App returns data for ANY user ID.
**How to exploit manually:**
```
GET /api/v1/users/1  → your data
GET /api/v1/users/2  → someone else's data (VULNERABLE!)
GET /api/v1/users/3  → another person's data
```
Use Burp Suite to automate ID enumeration.

### BFLA — Broken Function Level Authorization
**What it is:** Admin endpoints reachable by normal users.
**How to exploit:**
```
GET /api/admin/users  (with your regular user token)
→ Should get 403, but returns 200? VULNERABLE!
```

### SQL Injection
**What it is:** Input goes directly into SQL queries.
**Test manually:**
```
GET /api/search?q='
GET /api/search?q=' OR '1'='1
GET /api/search?q=1; DROP TABLE users--
```
Look for: SQL errors, extra data returned, time delays (blind SQLi)

### Mass Assignment
**What it is:** Server accepts fields you shouldn't be able to set.
**Test manually:**
```json
POST /api/v1/users
{"name": "hacker", "email": "h@x.com", "role": "admin", "is_admin": true}
```
If response includes "role":"admin" → VULNERABLE!

### JWT None Algorithm
**What it is:** Server accepts tokens with no signature.
**Test manually:**
1. Take any valid JWT
2. Change header to: {"alg":"none","typ":"JWT"}
3. Change payload to: {"user_id":1,"role":"admin"}
4. Set signature to empty: token.payload.
5. If accepted → VULNERABLE!
Tool: jwt_tool on GitHub

### CORS Misconfiguration
**What it is:** Any website can make requests to the API using your session.
**Test manually with curl:**
```bash
curl -H "Origin: https://evil.com" \
     -H "Authorization: Bearer <token>" \
     http://target/api/v1/profile -v
```
Look for: Access-Control-Allow-Origin: https://evil.com + Credentials: true

### SSRF — Server-Side Request Forgery  
**What it is:** Make the server fetch internal resources.
**Test with AWS metadata (if target is on AWS):**
```json
POST /api/v1/webhooks
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```
Returns IAM credentials → instant AWS account takeover

---

## EXPORTING REPORTS

After a scan completes:
- **JSON Report** — Machine-readable, use for automation or further analysis
- **Text Report** — Human-readable, use for writing pentest reports to clients

---

## SCAN OPTIONS EXPLAINED

| Option | What it does |
|--------|-------------|
| Crawl Depth 1 | Only crawls the main page + JS |
| Crawl Depth 2 | Follows links 2 levels deep (recommended) |
| Crawl Depth 3 | Full deep crawl (slower, more thorough) |
| Vuln Scan | Run all vulnerability tests |
| Auth Bypass | Test endpoints without token (no-auth access) |
| Inject Tests | SQL injection + XSS + SSRF payloads |
| JWT Tests | Algorithm confusion, none bypass |
| Auth Token | Your Bearer token for authenticated scan |

---

## COMBINING WITH BURP SUITE (Pro workflow)

1. Set Burp as proxy: `127.0.0.1:8080`
2. Run APIReaper to discover all endpoints
3. Export JSON report
4. Import endpoint list into Burp Intruder/Repeater
5. Manually verify and exploit findings in Burp
6. Use Burp's scanner on confirmed interesting endpoints

---

## DIRECTORY STRUCTURE
```
apireaper/
├── server.py          ← Flask backend + scan orchestration
├── requirements.txt   ← Python dependencies
├── core/
│   ├── crawler.py     ← Real JS parser + path prober
│   ├── scanner.py     ← Vuln tests (SQLi, BOLA, JWT, etc.)
│   └── reporter.py    ← JSON + text report generation
├── static/
│   └── index.html     ← Full frontend UI
└── README.md          ← This file
```

---

## TROUBLESHOOTING

**"Cannot reach backend"**
→ Make sure `python server.py` is running
→ Check no other app is on port 5000

**"Connection refused" during scan**
→ Target is not reachable — check URL is correct
→ For localhost targets, make sure your test app is running

**No endpoints found**
→ Try increasing crawl depth to 3
→ Try providing an auth token (some APIs need login)
→ The site may block scanners — try with a real browser first

**False positives**
→ Always manually verify findings in Burp Suite
→ CORS/headers findings are near-universal and informational
→ BOLA/SQLi findings should be manually confirmed

---

## NEXT STEPS TO LEVEL UP

1. **Burp Suite Community** (free) — intercept + replay any request
2. **jwt_tool** — dedicated JWT attack tool
3. **sqlmap** — automate SQL injection exploitation  
4. **ffuf** — fast API path fuzzing
5. **PortSwigger Web Security Academy** — free labs for every vuln type
6. **HackTheBox / TryHackMe** — legal practice environments
7. **Bug Bounty** — HackerOne, Bugcrowd, Intigriti — get paid legally!
