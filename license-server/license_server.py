#!/usr/bin/env python3
import os, sqlite3, secrets, hashlib, hmac, json, base64, sys
from datetime import datetime, timezone, timedelta

try:
    from flask import Flask, request, jsonify
except ImportError:
    print('\nMissing dependency: flask (and possibly others in requirements.txt).\n', file=sys.stderr)
    print('Fix: pip install -r requirements.txt', file=sys.stderr)
    print('Or just run ./run.sh, which does that for you before starting.\n', file=sys.stderr)
    sys.exit(1)

DB = os.getenv('LICENSE_DB', 'licenses.db')
ADMIN_TOKEN = os.getenv('LICENSE_ADMIN_TOKEN', '')
PRODUCT = os.getenv('LICENSE_PRODUCT', 'GVM-PANEL')
app = Flask(__name__)

# ---- Response signing (Ed25519) ----------------------------------------
# Every /v1/activate and /v1/check response is signed with this server's
# private key so a panel with LICENSE_PUBLIC_KEY configured can detect a
# spoofed license server / MITM'd response, and so a locally-edited
# license.db row on the panel side can't forge a still-valid signature.
# Generate a keypair with ops_generate_keypair.py.
_SIGNING_KEY = None
_signing_key_hex = os.getenv('LICENSE_SIGNING_KEY', '').strip()
if _signing_key_hex:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        _SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_signing_key_hex))
    except Exception as e:
        print(f'[License Server] FATAL: LICENSE_SIGNING_KEY is set but invalid: {e}', file=sys.stderr)
        raise SystemExit(1)
else:
    print('[License Server] WARNING: LICENSE_SIGNING_KEY not set - responses will be sent UNSIGNED. '
          'Panels with LICENSE_PUBLIC_KEY configured will reject them. Run ops_generate_keypair.py.', file=sys.stderr)

if not ADMIN_TOKEN or ADMIN_TOKEN in ('change-me', 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET'):
    print('[License Server] FATAL: LICENSE_ADMIN_TOKEN is not set to a real secret. '
          'Set it in the environment/.env before starting the server.', file=sys.stderr)
    raise SystemExit(1)

def sign_envelope(fields):
    """Returns (signed_payload_str, signature_b64) for the given dict, or
    (None, None) if no signing key is configured (unsigned/dev mode)."""
    if not _SIGNING_KEY:
        return None, None
    payload = json.dumps(fields, sort_keys=True, separators=(',', ':'))
    sig = _SIGNING_KEY.sign(payload.encode('utf-8'))
    return payload, base64.b64encode(sig).decode('ascii')

# ---- lightweight rate limiting for the public (unauthenticated)
# endpoints - /v1/activate, /v1/check, /v1/deactivate all take a
# license_key from an untrusted caller. Admin endpoints are excluded
# since they already require ADMIN_TOKEN.
_rate_buckets = {}
def rate_limited(key, max_requests=20, window_seconds=60):
    now_ts = now().timestamp()
    bucket = _rate_buckets.setdefault(key, [])
    bucket[:] = [t for t in bucket if now_ts - t < window_seconds]
    if len(bucket) >= max_requests:
        return True
    bucket.append(now_ts)
    return False

# Number of trusted reverse proxies in front of this server (0 = none,
# the default - the socket peer address is used as-is). X-Forwarded-For
# is a plain client-supplied header: trusting it unconditionally lets
# anyone rotate a fake value per request and dodge the rate limit
# entirely. Only set LICENSE_TRUSTED_PROXIES (e.g. 1 behind nginx, or 1
# on PythonAnywhere's load balancer) if a proxy you control really is
# appending to that header; we then take the entry that many hops from
# the RIGHT (the one your own proxy added), never the attacker-controlled
# leftmost value.
try:
    TRUSTED_PROXIES = max(0, int(os.getenv('LICENSE_TRUSTED_PROXIES', '0')))
except ValueError:
    TRUSTED_PROXIES = 0

def client_ip():
    peer = request.remote_addr or 'unknown'
    if TRUSTED_PROXIES <= 0:
        return peer
    hops = [h.strip() for h in request.headers.get('X-Forwarded-For', '').split(',') if h.strip()]
    if len(hops) < TRUSTED_PROXIES:
        return peer  # header shorter than expected -> don't trust it
    return hops[-TRUSTED_PROXIES]

@app.before_request
def _apply_rate_limit():
    if request.path in ('/v1/activate', '/v1/check', '/v1/deactivate'):
        if rate_limited(client_ip()):
            return jsonify(valid=False, error='Too many requests - try again in a minute'), 429

def now():
    return datetime.now(timezone.utc)

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE NOT NULL,
            license_key_last4 TEXT NOT NULL,
            product TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT "active",
            expires_at TEXT,
            max_activations INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            notes TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            installation_id TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(license_id, installation_id))''')

def kh(k):
    return hashlib.sha256(k.encode()).hexdigest()

def admin():
    return hmac.compare_digest(request.headers.get('X-License-Admin-Token', ''), ADMIN_TOKEN)

def newkey():
    x = secrets.token_hex(10).upper()
    return 'VNM-' + '-'.join(x[i:i+5] for i in range(0, 20, 5))

def parse_days(value):
    if value is None or str(value).strip().lower() in ('', 'unlimited', 'infinite', 'never', '0'):
        return None
    days = int(value)
    if days < 1:
        raise ValueError('days must be a positive integer or unlimited')
    return days

def parse_activations(value):
    if value is None or str(value).strip().lower() in ('', 'unlimited', 'infinite', '0'):
        return 0  # 0 = unlimited
    n = int(value)
    if n < 1:
        raise ValueError('max_activations must be a positive integer or unlimited')
    return n

@app.get('/health')
def health():
    return jsonify(status='ok', product=PRODUCT)

@app.post('/v1/activate')
def activate():
    d = request.get_json(silent=True) or {}
    key = str(d.get('license_key', '')).strip()
    inst = str(d.get('installation_id', '')).strip()
    if not key or not inst:
        return jsonify(valid=False, error='license_key and installation_id are required'), 400
    with db() as c:
        l = c.execute('SELECT * FROM licenses WHERE license_key_hash=? AND product=?', (kh(key), PRODUCT)).fetchone()
        if not l:
            return jsonify(valid=False, error='Invalid license'), 404
        if l['status'] != 'active':
            return jsonify(valid=False, error='License is ' + l['status']), 403
        if l['expires_at'] and now() >= datetime.fromisoformat(l['expires_at']):
            c.execute('UPDATE licenses SET status="expired" WHERE id=?', (l['id'],))
            c.commit()
            return jsonify(valid=False, error='License expired'), 403
        e = c.execute('SELECT id FROM activations WHERE license_id=? AND installation_id=?', (l['id'], inst)).fetchone()
        n = c.execute('SELECT COUNT(*) FROM activations WHERE license_id=?', (l['id'],)).fetchone()[0]
        if not e and l['max_activations'] > 0 and n >= l['max_activations']:
            return jsonify(valid=False, error='Activation limit reached'), 403
        t = now().isoformat()
        if e:
            c.execute('UPDATE activations SET last_seen_at=? WHERE id=?', (t, e['id']))
        else:
            c.execute('INSERT INTO activations(license_id,installation_id,activated_at,last_seen_at) VALUES(?,?,?,?)', (l['id'], inst, t, t))
        c.commit()
        envelope_fields = {
            'valid': True, 'license_id': l['id'], 'product': PRODUCT, 'status': l['status'],
            'expires_at': l['expires_at'], 'max_activations': l['max_activations'],
            'installation_id': inst, 'checked_at': t
        }
        signed_payload, signature = sign_envelope(envelope_fields)
        resp = dict(envelope_fields)
        if signed_payload:
            resp['signed_payload'] = signed_payload
            resp['signature'] = signature
        return jsonify(**resp)

@app.post('/v1/check')
def check():
    return activate()

@app.post('/v1/deactivate')
def deactivate():
    d = request.get_json(silent=True) or {}
    key = str(d.get('license_key', '')).strip()
    inst = str(d.get('installation_id', '')).strip()
    if not key or not inst:
        return jsonify(success=False, error='license_key and installation_id are required'), 400
    with db() as c:
        l = c.execute('SELECT * FROM licenses WHERE license_key_hash=? AND product=?', (kh(key), PRODUCT)).fetchone()
        if not l:
            return jsonify(success=False, error='Invalid license'), 404
        c.execute('DELETE FROM activations WHERE license_id=? AND installation_id=?', (l['id'], inst))
        c.commit()
        return jsonify(success=True, released=c.total_changes > 0)

@app.post('/admin/licenses')
def create():
    if not admin():
        return jsonify(error='unauthorized'), 401
    d = request.get_json(silent=True) or {}
    try:
        days = parse_days(d.get('days'))
        max_activations = parse_activations(d.get('max_activations'))
    except (ValueError, TypeError) as e:
        return jsonify(error=str(e)), 400
    k = newkey()
    exp = (now() + timedelta(days=days)).isoformat() if days is not None else None
    with db() as c:
        c.execute('''INSERT INTO licenses
            (license_key_hash,license_key_last4,product,status,expires_at,max_activations,created_at,notes)
            VALUES(?,?,?,?,?,?,?,?)''',
            (kh(k), k[-4:], PRODUCT, 'active', exp, max_activations, now().isoformat(), str(d.get('notes', ''))))
        c.commit()
    return jsonify(license_key=k, product=PRODUCT, expires_at=exp,
                   max_activations=max_activations,
                   max_activations_label='UNLIMITED' if max_activations == 0 else max_activations)

@app.get('/admin/licenses')
def listing():
    if not admin():
        return jsonify(error='unauthorized'), 401
    with db() as c:
        rows = []
        for r in c.execute('SELECT id,license_key_last4,product,status,expires_at,max_activations,created_at,notes FROM licenses ORDER BY id DESC'):
            item = dict(r)
            item['validity'] = 'UNLIMITED' if item['expires_at'] is None else item['expires_at']
            item['activation_limit'] = 'UNLIMITED' if item['max_activations'] == 0 else item['max_activations']
            rows.append(item)
        return jsonify(rows)

@app.post('/admin/licenses/<int:lid>/revoke')
def revoke(lid):
    if not admin():
        return jsonify(error='unauthorized'), 401
    with db() as c:
        c.execute('UPDATE licenses SET status="revoked" WHERE id=?', (lid,))
        c.commit()
        return jsonify(success=c.total_changes > 0)

@app.post('/admin/licenses/<int:lid>/activate')
def reactivate(lid):
    if not admin():
        return jsonify(error='unauthorized'), 401
    with db() as c:
        c.execute('UPDATE licenses SET status="active" WHERE id=?', (lid,))
        c.commit()
        return jsonify(success=c.total_changes > 0)

if __name__ == '__main__':
    init()
    app.run(host=os.getenv('LICENSE_HOST', '0.0.0.0'), port=int(os.getenv('LICENSE_PORT', '9100')))
