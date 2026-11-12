import test from 'node:test';
import assert from 'node:assert/strict';
import { identify, characterize, identifyBatch, PREFIX_RULES, HEX_RULES, SAMPLES } from '../engine.mjs';

for (const [prefix, name] of PREFIX_RULES) {
  test(`prefix ${prefix} identifies ${name}`, () => {
    const [result] = identify(`${prefix}demo`);
    assert.equal(result.algorithm, name);
    assert.equal(result.confidence, 'high');
  });
}
for (const [length, names] of Object.entries(HEX_RULES)) {
  test(`hex length ${length} has ${names.length} ranked candidates`, () => {
    const result = identify('a'.repeat(+length));
    assert.deepEqual(result.map(x => x.algorithm), names);
    assert.equal(result[0].confidence, 'medium');
    assert.ok(result.slice(1).every(x => x.confidence === 'low'));
  });
}
test('mysql uppercase signature', () => {
  assert.equal(identify('*'+'F'.repeat(40))[0].algorithm, 'MySQL5');
  assert.deepEqual(identify('*'+'f'.repeat(40)), []);
});
test('NetNTLMv2 and NetNTLMv1', () => {
  assert.equal(identify(`u::d:01234567:${'a'.repeat(32)}:${'c'.repeat(64)}`)[0].algorithm,'NetNTLMv2');
  assert.equal(identify(`u::d:${'a'.repeat(48)}:${'b'.repeat(48)}:f0`)[0].algorithm,'NetNTLMv1');
});
test('DES crypt heuristic', () => assert.equal(identify('abCDeFGH0123.')[0].algorithm,'DES crypt'));
test('JWT and base64 nonhash detection', () => {
  assert.equal(identify('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig')[0].algorithm,'JWT (not a hash)');
  assert.equal(identify('abcd1234+/xyz=')[0].algorithm,'Base64 blob (not a hash)');
});
test('generic PHC and malformed PHC',()=>{
  assert.equal(identify('$custom_kdf$abc')[0].algorithm,'PHC string (custom_kdf)');
  assert.deepEqual(identify('$space not allowed$abc'),[]);
});
test('empty / unsupported input',()=>{
  assert.deepEqual(identify(''),[]);
  assert.deepEqual(identify('hello'),[]);
  assert.equal(identify(' '+ 'a'.repeat(64)+' ')[0].algorithm,'SHA-256');
});
test('live characteristics are data only',()=>{
  assert.equal(characterize('a'.repeat(64)).bits,256);
  assert.equal(characterize('$2b$foo').prefix,'$2b$');
  assert.equal(characterize('').length,0);
});
test('batch results capped at 100',()=>{
  const batch=identifyBatch(Array.from({length:115},()=>SAMPLES[0].value).join('\n'));
  assert.equal(batch.length,100);
  assert.equal(batch[0].candidates[0].algorithm,'MD5');
});
