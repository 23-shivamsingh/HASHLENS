"""Hash signature engine regression tests (Python stdlib unittest)."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hash_identifier import identify, characterize, main, PREFIX_RULES, HEX_RULES  # noqa: E402


class HashIdentifierTests(unittest.TestCase):
    def test_all_registered_prefixes(self):
        for prefix, expected, *_ in PREFIX_RULES:
            with self.subTest(prefix=prefix):
                result = identify(prefix + 'demo-value')
                self.assertEqual(result[0].algorithm, expected)
                self.assertEqual(result[0].confidence, 'high')

    def test_hex_lengths(self):
        for length, algorithms in HEX_RULES.items():
            with self.subTest(length=length):
                result = identify('a' * length)
                self.assertEqual([c.algorithm for c in result], list(algorithms))
                self.assertEqual(result[0].confidence, 'medium')
                self.assertTrue(all(c.confidence == 'low' for c in result[1:]))

    def test_mixed_case_hex(self):
        self.assertEqual(identify('DeAdBEEF' * 4)[0].algorithm, 'MD5')

    def test_mysql5_requires_uppercase(self):
        self.assertEqual(identify('*' + 'A' * 40)[0].algorithm, 'MySQL5')
        self.assertNotEqual(identify('*' + 'a' * 40)[0].algorithm if identify('*' + 'a' * 40) else None, 'MySQL5')

    def test_netntlm_v1_v2(self):
        self.assertEqual(identify('user::domain:12345678:' + 'f' * 32 + ':' + 'e' * 60)[0].algorithm, 'NetNTLMv2')
        self.assertEqual(identify('user::domain:' + 'a'*48 + ':' + 'b'*48 + ':11223344')[0].algorithm, 'NetNTLMv1')

    def test_descrypt(self):
        self.assertEqual(identify('abCDeFGH0123.')[0].algorithm, 'DES crypt')

    def test_jwt_and_base64(self):
        self.assertEqual(identify('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig')[0].algorithm, 'JWT (not a hash)')
        self.assertEqual(identify('abcd1234+/xyz=')[0].algorithm, 'Base64 blob (not a hash)')

    def test_generic_phc(self):
        self.assertEqual(identify('$custom-kdf$abc')[0].algorithm, 'PHC string (custom-kdf)')
        self.assertEqual(identify('$invalid name$abc'), [])

    def test_empty_unknown_and_trim(self):
        self.assertEqual(identify('  '), [])
        self.assertEqual(identify('hello'), [])
        self.assertEqual(identify('  ' + '0' * 64 + '\n')[0].algorithm, 'SHA-256')

    def test_characteristics(self):
        result = characterize('e3b0c442' * 8)
        self.assertEqual(result['length'], 64)
        self.assertEqual(result['bits'], 256)
        self.assertEqual(result['charset'], 'Hexadecimal')

    def test_json_does_not_include_input(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(['--json', '5f4dcc3b5aa765d61d8327deb882cf99'])
        self.assertEqual(status, 0)
        doc = json.loads(stdout.getvalue())
        self.assertNotIn('input', doc)
        self.assertEqual(doc['candidates'][0]['algorithm'], 'MD5')

    def test_invalid_top(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--top', '0', 'abc'])

    def test_batch(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'hashes.txt')
            path.write_text('a'*32 + '\n' + 'b'*64 + '\n', encoding='utf-8')
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(['--batch', str(path), '--json'])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())['entries'][1]['candidates'][0]['algorithm'], 'SHA-256')

    def test_batch_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'hashes.txt')
            path.write_text(('a'*32+'\n')*101, encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--batch', str(path)]), 2)


if __name__ == '__main__':
    unittest.main()
