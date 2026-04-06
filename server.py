"""
APIReaper - Real API Crawler & Vulnerability Scanner
Backend Server (Flask)

LEGAL NOTICE: Only use on systems you own or have written authorization to test.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import threading
import uuid
import time
import json
import os
from core.crawler import APICrawler
from core.scanner import VulnScanner
from core.reporter import ReportGenerator
from core.postman import PostmanGenerator

app = Flask(__name__, static_folder='static')
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET","POST","PUT","DELETE","OPTIONS"],
    "allow_headers": ["Content-Type","Authorization"]
}})

scans = {}

# ─────────────────────────────────────────
# CORS SAFETY NET — ensure headers on every response
# ─────────────────────────────────────────
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/ping', methods=['GET', 'OPTIONS'])
def ping():
    return jsonify({'status': 'ok', 'tool': 'APIReaper', 'version': '2.0'})


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '').strip()
    options = data.get('options', {})

    if not target:
        return jsonify({'error': 'Target URL required'}), 400
    if not target.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        'id': scan_id,
        'target': target,
        'options': options,
        'status': 'running',
        'started': time.time(),
        'endpoints': [],
        'vulns': [],
        'logs': [],
        'progress': 0,
        'phase': 'Starting...'
    }

    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, target, options),
        daemon=True
    )
    thread.start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = scans[scan_id]
    return jsonify({
        'status': scan['status'],
        'progress': scan['progress'],
        'phase': scan['phase'],
        'endpoints_count': len(scan['endpoints']),
        'vulns_count': len(scan['vulns']),
        'logs': scan['logs'][-50:],
        'endpoints': scan['endpoints'],
        'vulns': scan['vulns'],
    })


@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    scans[scan_id]['status'] = 'stopped'
    return jsonify({'ok': True})


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def get_report(scan_id):
    fmt = request.args.get('format', 'json')
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = scans[scan_id]
    reporter = ReportGenerator(scan)
    if fmt == 'txt':
        content = reporter.as_text()
        return app.response_class(content, mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename=apireaper_{scan_id}.txt'})
    return jsonify(reporter.as_json())


@app.route('/api/scan/<scan_id>/postman', methods=['GET'])
def get_postman(scan_id):
    """Export Postman Collection v2.1 — import directly into Postman"""
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = scans[scan_id]
    if not scan['endpoints']:
        return jsonify({'error': 'No endpoints discovered yet'}), 400

    auth_token = scan.get('options', {}).get('auth_token') or ''
    gen = PostmanGenerator(scan['target'], scan['endpoints'], scan_id, auth_token)
    collection = gen.generate_collection()

    return app.response_class(
        json.dumps(collection, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=apireaper_{scan_id}_postman.json'}
    )


@app.route('/api/scan/<scan_id>/curl', methods=['GET'])
def get_curl(scan_id):
    """Export shell script with all curl commands"""
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan = scans[scan_id]
    if not scan['endpoints']:
        return jsonify({'error': 'No endpoints discovered yet'}), 400

    auth_token = scan.get('options', {}).get('auth_token') or ''
    gen = PostmanGenerator(scan['target'], scan['endpoints'], scan_id, auth_token)
    script = gen.generate_curl_collection()

    return app.response_class(
        script, mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=apireaper_{scan_id}_curls.sh'}
    )


# ─────────────────────────────────────────
# SCAN THREAD
# ─────────────────────────────────────────

def run_scan_thread(scan_id, target, options):
    scan = scans[scan_id]

    def log(level, msg):
        scan['logs'].append({'time': time.strftime('%H:%M:%S'), 'level': level, 'msg': msg})

    def set_progress(pct, phase):
        scan['progress'] = pct
        scan['phase'] = phase

    try:
        set_progress(5, '// PHASE 1: CRAWLING')
        log('info', f'Starting crawl on {target}')

        crawler = APICrawler(target, options, log, lambda: scan['status'] == 'stopped')
        endpoints = crawler.run()

        for ep in endpoints:
            scan['endpoints'].append(ep)

        set_progress(50, f'// CRAWL DONE — {len(endpoints)} endpoints found')
        log('success', f'Crawl complete — {len(endpoints)} endpoints discovered')
        log('info', 'Postman collection ready — use Export Postman button after scan')

        if scan['status'] == 'stopped':
            return

        if options.get('vuln_scan', True):
            set_progress(55, '// PHASE 2: VULNERABILITY SCAN')
            log('info', 'Starting vulnerability scan...')

            scanner = VulnScanner(target, endpoints, options, log, lambda: scan['status'] == 'stopped')
            vulns = scanner.run()

            for v in vulns:
                scan['vulns'].append(v)

            log('success', f'Scan complete — {len(vulns)} vulnerabilities found')

        set_progress(100, '// SCAN COMPLETE')
        scan['status'] = 'complete'
        log('success', f'=== {len(scan["endpoints"])} endpoints | {len(scan["vulns"])} vulns | Postman collection ready ===')

    except Exception as e:
        scan['status'] = 'error'
        log('error', f'Scan error: {str(e)}')


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════╗
    ║   APIReaper — API Pentest Toolkit   ║
    ║   http://localhost:5000             ║
    ║   FOR AUTHORIZED TESTING ONLY      ║
    ╚══════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
