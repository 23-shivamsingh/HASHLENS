/**
 * HASHLENS signature engine · browser/Node compatible, no network or dependencies.
 * Detection strategy adapted from the public Hash Identifier project by
 * CarterPerez-dev / AngelaMos (AGPL-3.0-or-later). See THIRD_PARTY_NOTICES.md.
 *
 * A pattern match does not prove a particular cryptographic algorithm was used.
 */

export const PREFIX_RULES = Object.freeze([
  ['$argon2id$', 'Argon2id', 'modern PHC string; hybrid Argon2 variant', 'Password KDF'],
  ['$argon2i$', 'Argon2i', 'PHC string; data-independent Argon2 variant', 'Password KDF'],
  ['$argon2d$', 'Argon2d', 'PHC string; data-dependent Argon2 variant', 'Password KDF'],
  ['$2y$', 'bcrypt', '2y variant; often produced by PHP', 'Password KDF'],
  ['$2b$', 'bcrypt', '2b variant; contemporary bcrypt encoding', 'Password KDF'],
  ['$2a$', 'bcrypt', '2a variant; older bcrypt encoding', 'Password KDF'],
  ['$2x$', 'bcrypt', '2x variant; legacy compatibility encoding', 'Password KDF'],
  ['$6$', 'SHA-512 crypt', 'Unix crypt(3) SHA-512 password storage', 'Password KDF'],
  ['$5$', 'SHA-256 crypt', 'Unix crypt(3) SHA-256 password storage', 'Password KDF'],
  ['$1$', 'MD5 crypt', 'legacy Unix MD5 password storage', 'Password KDF'],
  ['$apr1$', 'Apache MD5-crypt', 'Apache htpasswd MD5 variant', 'Password KDF'],
  ['$y$', 'yescrypt', 'modern Unix password hash encoding', 'Password KDF'],
  ['$P$', 'phpass', 'WordPress / PHP application password hash', 'Password KDF'],
  ['$H$', 'phpass', 'phpBB phpass variant', 'Password KDF'],
  ['$S$', 'Drupal 7 (SHA-512)', 'Drupal 7 password hash', 'Password KDF'],
  ['$7$', 'scrypt', 'scrypt modular-crypt encoding', 'Password KDF'],
  ['pbkdf2_sha256$', 'Django PBKDF2-SHA256', 'Django PBKDF2 password hash', 'Password KDF'],
  ['pbkdf2_sha1$', 'Django PBKDF2-SHA1', 'Django legacy PBKDF2 password hash', 'Password KDF'],
  ['bcrypt_sha256$', 'Django bcrypt-SHA256', 'Django wrapped bcrypt password hash', 'Password KDF'],
  ['argon2$', 'Django Argon2', 'Django Argon2 password hash', 'Password KDF'],
  ['{SSHA}', 'LDAP SSHA', 'LDAP salted SHA-1, base64 payload', 'Directory'],
  ['{SHA}', 'LDAP SHA', 'LDAP unsalted SHA-1, base64 payload', 'Directory'],
  ['{SMD5}', 'LDAP SMD5', 'LDAP salted MD5, base64 payload', 'Directory'],
  ['{MD5}', 'LDAP MD5', 'LDAP unsalted MD5, base64 payload', 'Directory'],
  ['{CRYPT}', 'LDAP CRYPT', 'LDAP crypt(3) wrapper', 'Directory'],
]);

export const HEX_RULES = Object.freeze({
  16: ['MySQL323', 'CRC-64'],
  32: ['MD5', 'NTLM', 'MD4', 'RIPEMD-128'],
  40: ['SHA-1', 'RIPEMD-160'],
  48: ['Tiger-192'],
  56: ['SHA-224', 'SHA3-224'],
  64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256', 'RIPEMD-256'],
  80: ['RIPEMD-320'],
  96: ['SHA-384', 'SHA3-384'],
  128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'],
});

function candidate(algorithm, confidence, reason, category = 'Digest') {
  return { algorithm, confidence, reason, category };
}
function isHex(value) { return value.length > 0 && /^[\da-f]+$/i.test(value); }
function isMySQL5(value) { return /^\*[\dA-F]{40}$/.test(value); }
function isDES(value) { return /^[./\dA-Za-z]{13}$/.test(value); }

export function characterize(raw = '') {
  const value = String(raw).trim();
  const hex = isHex(value);
  const prefix = PREFIX_RULES.find(([mark]) => value.startsWith(mark));
  const charset = !value ? '—' : hex ? 'Hexadecimal' : /^[A-Za-z0-9+/]+={0,2}$/.test(value) ? 'Base64-compatible' : /^[\x20-\x7E]+$/.test(value) ? 'Printable ASCII' : 'Mixed / Unicode';
  let shape = prefix ? 'Recognized prefix' : hex ? 'Raw hex digest' : value.startsWith('$') ? 'Modular string' : value.includes('::') ? 'Challenge / response' : 'Unclassified';
  if (isMySQL5(value)) shape = 'MySQL5 signature';
  if (isDES(value)) shape = 'Unix DES crypt';
  return {
    length: value.length,
    bytes: new TextEncoder().encode(value).length,
    charset,
    prefix: prefix?.[0] || 'None',
    shape,
    isHex: hex,
    bits: hex ? value.length * 4 : null,
  };
}

/** @returns {{algorithm:string, confidence:string, reason:string, category:string}[]} */
export function identify(rawInput = '') {
  const value = String(rawInput).trim();
  if (!value) return [];

  for (const [prefix, algorithm, detail, category] of PREFIX_RULES) {
    if (value.startsWith(prefix)) return [candidate(algorithm, 'high', `Prefix ${prefix} — ${detail}`, category)];
  }

  if (value.includes('::') && (value.match(/:/g) || []).length >= 4) {
    const parts = value.split(':');
    if (parts.length >= 6 && parts[4].length === 32 && isHex(parts[4])) {
      return [candidate('NetNTLMv2', 'high', 'User::domain:challenge:32-hex HMAC:blob shape', 'Challenge / response')];
    }
    if (parts.length >= 6 && parts[3].length === 48 && isHex(parts[3])) {
      return [candidate('NetNTLMv1', 'high', 'User::domain:48-hex LM:48-hex NT:challenge shape', 'Challenge / response')];
    }
  }
  if (isMySQL5(value)) return [candidate('MySQL5', 'high', 'Leading * followed by 40 uppercase hex characters', 'Password KDF')];
  if (isDES(value)) return [candidate('DES crypt', 'medium', '13 chars from ./0–9A–Za–z; legacy Unix password format', 'Password KDF')];

  if (isHex(value)) {
    return (HEX_RULES[value.length] || []).map((algorithm, index) => candidate(
      algorithm,
      index === 0 ? 'medium' : 'low',
      `${value.length} hex characters (${value.length * 4} bits) — ${index ? 'another possible algorithm' : 'most common candidate at this length'}`
    ));
  }

  const phc = value.match(/^\$([A-Za-z0-9_-]+)\$/);
  if (phc) return [candidate(`PHC string (${phc[1]})`, 'low', `Generic $${phc[1]}$… syntax; specific algorithm not recognized`, 'Modular crypt')];
  if (value.startsWith('eyJ')) return [candidate('JWT (not a hash)', 'low', 'Likely token-like text beginning with eyJ; not a digest', 'Non-hash')];
  if (value.length > 8 && /[+/=]/.test(value)) return [candidate('Base64 blob (not a hash)', 'low', 'Contains +, /, or =; could be encoded data rather than a digest', 'Non-hash')];
  return [];
}

export const SAMPLES = Object.freeze([
  { name: 'MD5', category: 'Raw digest', value: '5f4dcc3b5aa765d61d8327deb882cf99' },
  { name: 'SHA-256', category: 'Raw digest', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { name: 'bcrypt', category: 'Password storage', value: '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK' },
  { name: 'Argon2id', category: 'Password storage', value: '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG' },
  { name: 'MySQL5', category: 'Database', value: '*A4B6157319038724E3560894F7F932C8886EBFCF' },
  { name: 'Django', category: 'Password storage', value: 'pbkdf2_sha256$600000$exampleSalt$exampleBase64Digest' },
  { name: 'LDAP SSHA', category: 'Directory', value: '{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=' },
  { name: 'JWT-like', category: 'Non-hash', value: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature' },
]);

export function identifyBatch(raw, max = 100) {
  const lines = String(raw).split(/\r?\n/).map(x => x.trim()).filter(Boolean).slice(0, max);
  return lines.map((input, index) => ({index: index + 1, input, candidates: identify(input), characteristics: characterize(input)}));
}
