/* Test that the portable JS and CLI Python engines produce identical ranked candidates. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { identify, PREFIX_RULES, HEX_RULES, SAMPLES } from '../web/engine.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const samples=[...SAMPLES.map(s=>s.value),...PREFIX_RULES.map(([prefix])=>prefix+'demo'),...Object.keys(HEX_RULES).map(length=>'a'.repeat(+length)), 'hello', 'abCDeFGH0123.', '$custom_thing$abc'];
test('Python CLI and browser engine agree on candidate algorithms and confidence',()=>{
  // One subprocess for every fixture keeps this test efficient on macOS and CI.
  const python=spawnSync(process.env.PYTHON || 'python3',[resolve(root,'hash_identifier.py'),'--batch','-','--json'],{
    encoding:'utf8',input:samples.join('\n'),timeout:10000
  });
  assert.equal(python.status,0, `Python failed: ${python.stderr}`);
  const entries=JSON.parse(python.stdout).entries;
  assert.equal(entries.length,samples.length);
  for (let i=0;i<samples.length;i++) {
    const py=entries[i].candidates;
    const browser=identify(samples[i]).map(({algorithm,confidence})=>({algorithm,confidence}));
    assert.deepEqual(browser,py.map(({algorithm,confidence})=>({algorithm,confidence})), samples[i]);
  }
});
