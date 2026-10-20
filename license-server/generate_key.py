#!/usr/bin/env python3
import os, requests

base = os.getenv('LICENSE_SERVER_URL', 'https://arinjay01.pythonanywhere.com').rstrip('/')
url = base + '/admin/licenses'
token = os.getenv('LICENSE_ADMIN_TOKEN', '').strip()

print('VNM License Generator')
print('')
if not token:
    token = input('Admin token: ').strip()

days = input('Validity (days or unlimited) [30]: ').strip() or '30'
acts = input('Max activations (number or unlimited) [1]: ').strip() or '1'
notes = input('Notes [VNM custom license]: ').strip() or 'VNM custom license'

payload = {'days': days, 'max_activations': acts, 'notes': notes}
try:
    r = requests.post(url, headers={'X-License-Admin-Token': token}, json=payload, timeout=20)
    if not r.ok:
        print('\nERROR:', r.status_code, r.text)
        raise SystemExit(1)
    x = r.json()
    print('\nVNM LICENSE KEY:', x['license_key'])
    print('Expires:', x.get('expires_at') or 'UNLIMITED')
    print('Max activations:', x.get('max_activations_label', x.get('max_activations')))
except requests.RequestException as e:
    print('\nERROR: Could not connect to license server:', e)
    raise SystemExit(1)
