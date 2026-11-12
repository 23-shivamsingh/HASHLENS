#!/usr/bin/env python3
"""HASHLENS · Local hash signature identification CLI.

Detection strategy adapted from the Hash Identifier work in
CarterPerez-dev/Cybersecurity-Projects (credited to AngelaMos, 2026),
AGPL-3.0-or-later. Source and attribution: THIRD_PARTY_NOTICES.md.

A signature match is a heuristic, not cryptographic verification.
The CLI performs no network access, cracking, or password recovery.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Literal

Confidence = Literal['high', 'medium', 'low']


@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm: str
    confidence: Confidence
    reason: str
    category: str


# Specific prefixes must be checked before fallback shapes.
PREFIX_RULES: tuple[tuple[str, str, str, str], ...] = (
    ('$argon2id$', 'Argon2id', 'modern PHC string; hybrid Argon2 variant', 'Password KDF'),
    ('$argon2i$', 'Argon2i', 'PHC string; data-independent Argon2 variant', 'Password KDF'),
    ('$argon2d$', 'Argon2d', 'PHC string; data-dependent Argon2 variant', 'Password KDF'),
    ('$2y$', 'bcrypt', '2y variant; often produced by PHP', 'Password KDF'),
    ('$2b$', 'bcrypt', '2b variant; contemporary bcrypt encoding', 'Password KDF'),
    ('$2a$', 'bcrypt', '2a variant; older bcrypt encoding', 'Password KDF'),
    ('$2x$', 'bcrypt', '2x variant; legacy compatibility encoding', 'Password KDF'),
    ('$6$', 'SHA-512 crypt', 'Unix crypt(3) SHA-512 password storage', 'Password KDF'),
    ('$5$', 'SHA-256 crypt', 'Unix crypt(3) SHA-256 password storage', 'Password KDF'),
    ('$1$', 'MD5 crypt', 'legacy Unix MD5 password storage', 'Password KDF'),
    ('$apr1$', 'Apache MD5-crypt', 'Apache htpasswd MD5 variant', 'Password KDF'),
    ('$y$', 'yescrypt', 'modern Unix password hash encoding', 'Password KDF'),
    ('$P$', 'phpass', 'WordPress / PHP application password hash', 'Password KDF'),
    ('$H$', 'phpass', 'phpBB phpass variant', 'Password KDF'),
    ('$S$', 'Drupal 7 (SHA-512)', 'Drupal 7 password hash', 'Password KDF'),
    ('$7$', 'scrypt', 'scrypt modular-crypt encoding', 'Password KDF'),
    ('pbkdf2_sha256$', 'Django PBKDF2-SHA256', 'Django PBKDF2 password hash', 'Password KDF'),
    ('pbkdf2_sha1$', 'Django PBKDF2-SHA1', 'Django legacy PBKDF2 password hash', 'Password KDF'),
    ('bcrypt_sha256$', 'Django bcrypt-SHA256', 'Django wrapped bcrypt password hash', 'Password KDF'),
    ('argon2$', 'Django Argon2', 'Django Argon2 password hash', 'Password KDF'),
    ('{SSHA}', 'LDAP SSHA', 'LDAP salted SHA-1, base64 payload', 'Directory'),
    ('{SHA}', 'LDAP SHA', 'LDAP unsalted SHA-1, base64 payload', 'Directory'),
    ('{SMD5}', 'LDAP SMD5', 'LDAP salted MD5, base64 payload', 'Directory'),
    ('{MD5}', 'LDAP MD5', 'LDAP unsalted MD5, base64 payload', 'Directory'),
    ('{CRYPT}', 'LDAP CRYPT', 'LDAP crypt(3) wrapper', 'Directory'),
)

HEX_RULES: dict[int, tuple[str, ...]] = {
    16: ('MySQL323', 'CRC-64'),
    32: ('MD5', 'NTLM', 'MD4', 'RIPEMD-128'),
    40: ('SHA-1', 'RIPEMD-160'),
    48: ('Tiger-192',),
    56: ('SHA-224', 'SHA3-224'),
    64: ('SHA-256', 'SHA3-256', 'BLAKE2s-256', 'RIPEMD-256'),
    80: ('RIPEMD-320',),
    96: ('SHA-384', 'SHA3-384'),
    128: ('SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'),
}


def _candidate(algorithm: str, confidence: Confidence, reason: str, category: str = 'Digest') -> HashCandidate:
    return HashCandidate(algorithm, confidence, reason, category)


def _hex(text: str) -> bool:
    return bool(text) and re.fullmatch('[0-9a-fA-F]+', text) is not None


def characterize(raw: str) -> dict[str, object]:
    """Describe format clues without calculating, sending or saving digests."""
    text = raw.strip()
    is_hex = _hex(text)
    prefix = next((rule[0] for rule in PREFIX_RULES if text.startswith(rule[0])), 'None')
    if not text:
        charset = '—'
    elif is_hex:
        charset = 'Hexadecimal'
    elif re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', text):
        charset = 'Base64-compatible'
    elif all(32 <= ord(c) <= 126 for c in text):
        charset = 'Printable ASCII'
    else:
        charset = 'Mixed / Unicode'

    shape = ('Recognized prefix' if prefix != 'None' else
             'Raw hex digest' if is_hex else
             'Modular string' if text.startswith('$') else
             'Challenge / response' if '::' in text else 'Unclassified')
    if re.fullmatch(r'\*[0-9A-F]{40}', text):
        shape = 'MySQL5 signature'
    if re.fullmatch(r'[./0-9A-Za-z]{13}', text):
        shape = 'Unix DES crypt'
    return {'length': len(text), 'bytes': len(text.encode()), 'charset': charset,
            'prefix': prefix, 'shape': shape, 'isHex': is_hex,
            'bits': len(text) * 4 if is_hex else None}


def identify(raw: str) -> list[HashCandidate]:
    """Identify plausible signature families. Never claims cryptographic proof."""
    text = raw.strip()
    if not text:
        return []
    for prefix, algorithm, note, category in PREFIX_RULES:
        if text.startswith(prefix):
            return [_candidate(algorithm, 'high', f'Prefix {prefix} — {note}', category)]

    if '::' in text and text.count(':') >= 4:
        parts = text.split(':')
        if len(parts) >= 6 and len(parts[4]) == 32 and _hex(parts[4]):
            return [_candidate('NetNTLMv2', 'high', 'User::domain:challenge:32-hex HMAC:blob shape', 'Challenge / response')]
        if len(parts) >= 6 and len(parts[3]) == 48 and _hex(parts[3]):
            return [_candidate('NetNTLMv1', 'high', 'User::domain:48-hex LM:48-hex NT:challenge shape', 'Challenge / response')]

    if re.fullmatch(r'\*[0-9A-F]{40}', text):
        return [_candidate('MySQL5', 'high', 'Leading * followed by 40 uppercase hex characters', 'Password KDF')]
    if re.fullmatch(r'[./0-9A-Za-z]{13}', text):
        return [_candidate('DES crypt', 'medium', '13 chars from ./0–9A–Za–z; legacy Unix password format', 'Password KDF')]
    if _hex(text):
        return [_candidate(algorithm, 'medium' if i == 0 else 'low',
                           f'{len(text)} hex characters ({len(text)*4} bits) — '
                           + ('another possible algorithm' if i else 'most common candidate at this length'))
                for i, algorithm in enumerate(HEX_RULES.get(len(text), ()))]

    phc = re.match(r'^\$([A-Za-z0-9_-]+)\$', text)
    if phc:
        algo = phc.group(1)
        return [_candidate(f'PHC string ({algo})', 'low', f'Generic ${algo}$… syntax; specific algorithm not recognized', 'Modular crypt')]
    if text.startswith('eyJ'):
        return [_candidate('JWT (not a hash)', 'low', 'Likely token-like text beginning with eyJ; not a digest', 'Non-hash')]
    if len(text) > 8 and any(ch in text for ch in '+/='):
        return [_candidate('Base64 blob (not a hash)', 'low', 'Contains +, /, or =; could be encoded data rather than a digest', 'Non-hash')]
    return []


def _as_report(item: str, include_input: bool = False) -> dict[str, object]:
    report: dict[str, object] = {'characteristics': characterize(item),
                                 'candidates': [asdict(c) for c in identify(item)]}
    if include_input:
        report['input'] = item.strip()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='hashlens', description='Local-only hash format identification by signature.')
    parser.add_argument('hash', nargs='?', help='Hash to inspect (quote any $ prefix in your shell).')
    parser.add_argument('--top', '-n', type=int, default=5, help='Display up to N candidates.')
    parser.add_argument('--json', action='store_true', help='Emit sanitized JSON (input omitted).')
    parser.add_argument('--batch', metavar='FILE', help='Analyze newline-delimited strings from a local file. Use - for stdin.')
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error('--top must be a positive integer')
    if args.hash is not None and args.batch is not None:
        parser.error('Provide either a hash or --batch, not both')
    if args.hash is None and args.batch is None:
        parser.error('Provide one hash or --batch FILE')

    if args.batch is not None:
        try:
            if args.batch == '-':
                raw = sys.stdin.read(30001)
            else:
                with open(args.batch, encoding='utf-8') as handle:
                    raw = handle.read(30001)
        except (OSError, UnicodeError) as exc:
            print(f'Cannot read batch input: {exc}', file=sys.stderr)
            return 2
        if len(raw) > 30000:
            print('Batch input exceeds 30,000 characters.', file=sys.stderr)
            return 2
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if len(lines) > 100:
            print('Batch limit is 100 non-empty lines.', file=sys.stderr)
            return 2
        reports = [{'index': i, **_as_report(line)} for i, line in enumerate(lines, 1)]
        if args.json:
            print(json.dumps({'application': 'HASHLENS', 'mode': 'batch', 'entries': reports}, indent=2))
            return 0
        for i, report in enumerate(reports, 1):
            candidates = report['candidates']
            print(f'[{i:03d}] {candidates[0]["algorithm"]} ({candidates[0]["confidence"]})' if candidates else f'[{i:03d}] Unknown format')
        return 0

    raw = args.hash or ''
    if len(raw) > 30000:
        print('Input exceeds 30,000 characters.', file=sys.stderr)
        return 2
    report = _as_report(raw)
    if args.json:
        report.update({'application': 'HASHLENS', 'mode': 'single'})
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    candidates = identify(raw)
    print('HASHLENS  /  HASH SIGNATURE ANALYSIS')
    print('─────────────────────────────────────────')
    if not candidates:
        print('No signature pattern matched. Verify format and input.')
        return 1
    for index, entry in enumerate(candidates[:args.top], 1):
        print(f'{index:02}. {entry.algorithm:<23} [{entry.confidence.upper()}]')
        print(f'    {entry.reason}')
    print('Note: Structural patterns do not prove the original algorithm.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
