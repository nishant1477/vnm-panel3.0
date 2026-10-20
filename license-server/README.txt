VNM LICENSE SERVER - CUSTOM + UNLIMITED

This folder is separate from the VNM panel. Deploy it to PythonAnywhere (or another server).

Supported validity:
- 1, 7, 30, 365, etc. days
- unlimited / infinite / never / 0 = no expiry

Supported activation limits:
- 1, 5, 10, etc.
- unlimited / infinite / 0 = unlimited activations

Examples:
30 days + 1 activation
90 days + 5 activations
Unlimited time + 1 activation
30 days + unlimited activations
Unlimited time + unlimited activations

PythonAnywhere:
1. Replace your license_server.py with this one.
2. Keep your existing licenses.db.
3. Set LICENSE_ADMIN_TOKEN in the PythonAnywhere environment/.env to your private admin token.
4. Keep LICENSE_PRODUCT=GVM-PANEL to preserve compatibility with the existing database/panel.
5. Reload/restart the PythonAnywhere web app.

Generate keys locally:
- Install Python and requests.
- Run generate-key.bat.
- Enter the admin token when prompted.
- Enter days or unlimited.
- Enter activation count or unlimited.

Security:
- Do NOT publish the admin token in the ZIP, screenshots, GitHub, or client panel.
- The panel only needs LICENSE_SERVER_URL, LICENSE_PRODUCT and (recommended)
  LICENSE_PUBLIC_KEY; it does not need the admin token or the signing key.
- The server now REFUSES to start if LICENSE_ADMIN_TOKEN is unset or left as
  a placeholder value (was previously "change-me" by default, which meant a
  panel operator who forgot to set it was silently running with a public,
  well-known admin token).
- Response signing: run `python ops_generate_keypair.py` once to generate an
  Ed25519 keypair. Put LICENSE_SIGNING_KEY (private) in this server's .env
  ONLY. Put LICENSE_PUBLIC_KEY (public) in every panel deployment's .env.
  Once LICENSE_PUBLIC_KEY is set on a panel, that panel:
    - rejects any /v1/activate or /v1/check response that isn't signed by
      this exact keypair (stops a spoofed server or a MITM'd response from
      granting activation), and
    - re-derives its "am I activated" answer from the last SIGNED envelope
      on every check, instead of trusting the plain `activated` column in
      its local license.db - so editing that DB by hand no longer bypasses
      the license.
  Without LICENSE_PUBLIC_KEY set, the panel falls back to the old
  trust-the-response behavior (still fine for local dev/testing).

---
Fixes applied when this was wired into the VNM panel:
- Generated license keys now use the VNM- prefix (was GTX-).
- Added POST /v1/deactivate {license_key, installation_id} to release an
  activation slot (the panel's "Deactivate" flow needs this; it was
  previously missing - there was no way to free up an activation without
  editing the database directly).
- Added light in-memory rate limiting (20 req/min per IP) on the public
  /v1/activate, /v1/check, /v1/deactivate endpoints - they take a
  license_key from an untrusted caller and had no abuse protection.
- IMPORTANT: LICENSE_PRODUCT is still "GVM-PANEL" by default, not
  "VNM-PANEL", even though the panel itself has been rebranded to VNM.
  This is intentional, per the original instructions above - it preserves
  compatibility with any licenses already issued under the existing
  product name/database. Do not change it unless you're intentionally
  starting a fresh license database.
- Ed25519 response signing added (see Security above) - /v1/activate and
  /v1/check responses now include signed_payload + signature when
  LICENSE_SIGNING_KEY is configured; the panel-side client verifies them
  and re-derives activation state from the signed envelope rather than an
  unsigned local column.
- LICENSE_ADMIN_TOKEN with no value, "change-me", or the .env.example
  placeholder now refuses to start the server instead of running with an
  effectively-public admin token.
