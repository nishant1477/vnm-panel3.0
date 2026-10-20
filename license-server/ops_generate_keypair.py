#!/usr/bin/env python3
"""
Generates the Ed25519 keypair used to sign license-server responses.

- LICENSE_SIGNING_KEY (private, hex) stays on the license server ONLY.
  Set it in the license server's environment/.env. Never ship it with
  the panel.
- LICENSE_PUBLIC_KEY (public, hex) ships with every panel deployment
  (panel's own .env). It lets the panel verify that an activate/check
  response really came from this license server and hasn't been
  tampered with in transit or forged by editing the panel's local
  license.db.

Run this once per license server. Re-running generates a NEW keypair,
which will invalidate verification for any panel already configured
with the old LICENSE_PUBLIC_KEY - only do that intentionally.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_hex = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
).hex()
pub_hex = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex()

print('VNM License Server - Ed25519 keypair generated\n')
print('Set this on the LICENSE SERVER only (.env):')
print(f'LICENSE_SIGNING_KEY={priv_hex}\n')
print('Set this on every PANEL deployment (.env):')
print(f'LICENSE_PUBLIC_KEY={pub_hex}\n')
print('Keep the private key secret. The public key is safe to ship with the panel.')
