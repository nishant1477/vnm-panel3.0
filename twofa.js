// =====================================================================
// VNM — TOTP (RFC 6238) for admin two-factor authentication
// ---------------------------------------------------------------------
// Self-contained HOTP/TOTP implementation using Node's built-in
// `crypto` module - no new dependency. Compatible with Google
// Authenticator, Authy, 1Password, etc. (standard 6-digit, 30s step,
// SHA-1, as basically every authenticator app expects).
// =====================================================================

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return output;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function generateSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit, standard TOTP secret strength
}

function hotp(secretBuffer, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
                   ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (binCode % 1000000).toString().padStart(6, '0');
}

// Accepts a code typed "now", tolerating ±1 step (30s) of clock drift.
function verifyToken(base32Secret, token, { window = 1, step = 30 } = {}) {
  if (!/^\d{6}$/.test(String(token || '').trim())) return false;
  const secretBuffer = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / step);
  for (let i = -window; i <= window; i++) {
    if (hotp(secretBuffer, counter + i) === String(token).trim()) return true;
  }
  return false;
}

function otpauthUrl(base32Secret, { label, issuer }) {
  const params = new URLSearchParams({ secret: base32Secret, issuer: issuer || 'VNM', algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(issuer || 'VNM')}:${encodeURIComponent(label)}?${params.toString()}`;
}

function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(crypto.randomBytes(5).toString('hex').match(/.{1,4}/g).join('-'));
  }
  return codes;
}
function hashRecoveryCode(code) {
  return crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
}

module.exports = { generateSecret, verifyToken, otpauthUrl, generateRecoveryCodes, hashRecoveryCode, base32Decode, base32Encode };
