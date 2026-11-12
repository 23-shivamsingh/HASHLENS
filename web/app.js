import { identify, characterize, identifyBatch, SAMPLES, PREFIX_RULES, HEX_RULES } from './engine.mjs';

const $ = (sel) => document.querySelector(sel);
const input = $('#hashInput');
const output = $('#resultsOutput');
const views = [...document.querySelectorAll('[data-view]')];
const navLinks = [...document.querySelectorAll('[data-view-link]')];
const state = { mode: 'single', results: null, category: 'All', query: '' };
let toastTimer;

const ICON = {
  arrow: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>',
  external: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg>',
  alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg>'
};

function notify(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 2600);
}
function make(tag, className = '', text = undefined) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}
function clear(node) { node.replaceChildren(); }
function statusBadge(confidence) { return make('span', `confidence ${confidence}`, confidence); }
function updateInputStats() {
  const value = input.value;
  const stats = characterize(value);
  $('#charCounter').textContent = `${value.length.toLocaleString()} characters`;
  $('#statLength').textContent = stats.length ? `${stats.length.toLocaleString()} chars / ${stats.bytes.toLocaleString()} bytes` : '—';
  $('#statCharset').textContent = stats.length ? stats.charset : '—';
  $('#statPrefix').textContent = stats.length ? stats.prefix : '—';
  $('#statShape').textContent = stats.length ? stats.shape : '—';
  const strength = !stats.length ? 0 : stats.prefix !== 'None' ? 100 : stats.isHex ? 67 : stats.shape !== 'Unclassified' ? 42 : 17;
  $('#signalMeter').style.width = `${strength}%`;
  $('#signalStatus').textContent = !stats.length ? 'IDLE' : stats.prefix !== 'None' ? 'STRONG' : stats.isHex ? 'PARTIAL' : 'SCANNING';
}
function setView(name, {updateHash = false} = {}) {
  const target = ['analyzer', 'library', 'guide'].includes(name) ? name : 'analyzer';
  views.forEach(view => { const active = view.dataset.view === target; view.hidden = !active; view.classList.toggle('hidden', !active); });
  navLinks.forEach(link => { const active = link.dataset.viewLink === target; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
  $('#currentCrumb').textContent = ({analyzer:'ANALYZER',library:'SIGNATURE LIBRARY',guide:'HOW IT WORKS'})[target];
  $('#sidebar').classList.remove('open');
  $('#menuToggle').setAttribute('aria-expanded', 'false');
  if (updateHash) location.hash = target;
  window.scrollTo(0, 0);
}
function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll('[data-mode]').forEach(button => {
    const active = button.dataset.mode === mode;
    button.classList.toggle('selected', active);
    button.setAttribute('aria-pressed', String(active));
  });
  $('#inputLabel').textContent = mode === 'single' ? 'SIGNATURE INPUT' : 'BATCH INPUT / ONE SIGNATURE PER LINE';
  input.placeholder = mode === 'single' ? 'Paste a hash signature to begin...' : 'Paste one hash per line…\n5f4dcc3b5aa765d61d8327deb882cf99\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  $('#moreGutter').hidden = mode !== 'batch';
  $('#analyzeLabel').textContent = mode === 'single' ? 'Analyze signature' : 'Analyze batch';
  resetResults();
}
function populateSamples() {
  const wrap = $('#sampleChips');
  SAMPLES.slice(0, 6).forEach(item => {
    const button = make('button', 'sample-chip', item.name);
    button.type = 'button';
    button.title = `Load ${item.name} example`;
    button.addEventListener('click', () => {
      if (state.mode === 'batch') {
        input.value = input.value.trim() ? `${input.value.trim()}\n${item.value}` : item.value;
      } else input.value = item.value;
      updateInputStats();
      input.focus();
      notify(`${item.name} example loaded`);
    });
    wrap.append(button);
  });
}
function resetResults() {
  state.results = null;
  $('#resultTools').hidden = true;
  clear(output);
  const empty = make('div', 'empty-results');
  empty.innerHTML = '<div class="empty-graphic"><svg viewBox="0 0 120 120" fill="none" aria-hidden="true"><circle cx="60" cy="60" r="39" stroke="currentColor" stroke-dasharray="4 8"/><circle cx="60" cy="60" r="25" stroke="currentColor" opacity=".38"/><path d="M47 60h26M60 47v26" stroke="currentColor" stroke-width="2"/><path d="m89 90 14 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><span class="empty-cross">+</span></div><strong>Awaiting a signature.</strong><p>Enter a hash and run analysis to explore possible formats, confidence levels, and supporting signals.</p><span class="empty-badge">NO DATA YET</span>';
  output.append(empty);
}
function buildSummary(title, description, count) {
  const summary = make('div', 'results-summary');
  const column = make('div');
  column.append(make('h3', '', title), make('p', '', description));
  summary.append(column, make('span', 'summary-count', count));
  return summary;
}
function showNoMatch() {
  const wrap = make('div', 'no-matches');
  const icon = make('span'); icon.innerHTML = ICON.alert;
  wrap.append(icon, make('h3', '', 'No confident format match'), make('p', '', 'This signature does not fit the currently recognized patterns. Try verifying the input, encoding, or any missing prefix.'));
  output.append(wrap);
}
function renderSingle(candidates) {
  clear(output);
  if (!candidates.length) { showNoMatch(); return; }
  output.append(buildSummary('Ranked possibilities', 'Ordered by recognition strength. Similar formats may overlap.', `${candidates.length.toString().padStart(2, '0')} FOUND`));
  const list = make('div', 'candidates');
  candidates.forEach((entry, index) => {
    const item = make('article', 'candidate');
    const rank = make('span', 'rank', String(index + 1).padStart(2, '0'));
    const main = make('div', 'candidate-main');
    const top = make('div', 'candidate-top');
    top.append(make('h4', '', entry.algorithm), statusBadge(entry.confidence));
    main.append(top, make('p', '', entry.reason));
    item.append(rank, main);
    list.append(item);
  });
  output.append(list);
}
function renderBatch(records, truncated) {
  clear(output);
  output.append(buildSummary('Batch analysis complete', `${records.filter(row => row.candidates.length).length} recognized / ${records.length} inspected`, `${records.length.toString().padStart(2, '0')} ITEMS`));
  const wrap = make('div', 'batch-results');
  records.forEach(record => {
    const item = make('article', 'batch-line');
    const main = make('div', 'batch-main');
    main.append(make('code', '', record.input), make('strong', '', record.candidates[0]?.algorithm || 'No match found'));
    item.append(make('span', 'batch-number', String(record.index).padStart(2, '0')), main);
    if (record.candidates.length) item.append(statusBadge(record.candidates[0].confidence));
    wrap.append(item);
  });
  output.append(wrap);
  if (truncated) output.append(make('p', 'batch-hint', 'Only the first 100 non-empty lines were analyzed.'));
}
function analyze() {
  const text = input.value.trim();
  if (!text) { input.focus(); notify('Paste or load a signature to begin'); return; }
  if (state.mode === 'single' && text.includes('\n')) { notify('Single mode supports one signature. Use batch mode for multiple lines.'); return; }
  if (state.mode === 'single') {
    const candidates = identify(text);
    state.results = {mode:'single', data:candidates, characteristics:characterize(text)};
    renderSingle(candidates);
  } else {
    const lines = text.split(/\r?\n/).filter(line => line.trim());
    const records = identifyBatch(text);
    state.results = {mode:'batch', data:records, total:lines.length};
    renderBatch(records, lines.length > 100);
  }
  $('#resultTools').hidden = false;
  if (window.matchMedia('(max-width: 650px)').matches) $('#resultsPanel').scrollIntoView({behavior:'smooth',block:'start'});
}
function sanitizedExport() {
  const result = state.results;
  if (!result) return null;
  // Never include raw hash strings in exported data. Users can copy them separately.
  if (result.mode === 'single') return {application:'HASHLENS',version:'1.0.0',mode:'single',characteristics:result.characteristics,candidates:result.data,privacy:'Input value intentionally omitted'};
  return {application:'HASHLENS',version:'1.0.0',mode:'batch',analyzed:result.data.length,total:result.total,entries:result.data.map(({index,candidates,characteristics}) => ({index,characteristics,candidates})),privacy:'Input values intentionally omitted'};
}
async function copyResults() {
  const payload = sanitizedExport(); if (!payload) return;
  const text = JSON.stringify(payload,null,2);
  try { await navigator.clipboard.writeText(text); notify('Sanitized results copied'); }
  catch { notify('Clipboard not available in this context'); }
}
function downloadResults() {
  const payload = sanitizedExport(); if (!payload) return;
  const blob = new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
  const url = URL.createObjectURL(blob);
  const anchor = make('a'); anchor.href=url; anchor.download='hashlens-results.json';
  document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  notify('Sanitized report downloaded');
}

const library = [
  ...PREFIX_RULES.map(([prefix, algorithm, note, group]) => ({name:algorithm, mark:prefix, description:note, category:group, input:prefix + 'example-demo'})),
  ...Object.entries(HEX_RULES).flatMap(([length, names]) => names.map((name, i) => ({name, mark:`${length} HEX`, description:`${Number(length)*4}-bit digest-like output. ${i ? 'Possible alternative at this length.' : 'Common first candidate for this length.'}`, category:'Digest', input: 'a'.repeat(Number(length))}))),
  {name:'NetNTLMv2',mark:'::',description:'Windows authentication challenge-response record, recognizable by its field structure.',category:'Challenge / response',input:'user::domain:1234567890abcdef:'+'a'.repeat(32)+':'+'b'.repeat(64)},
  {name:'MySQL5',mark:'* + 40',description:'MySQL legacy password format with a leading asterisk and uppercase hex.',category:'Password KDF',input:SAMPLES[4].value},
  {name:'DES crypt',mark:'13 CHAR',description:'Traditional Unix password crypt format with a 13-character alphabet.',category:'Password KDF',input:'abCDeFGH0123.'},
].filter((x,i,arr)=>arr.findIndex(y=>y.name===x.name)===i);
const categories = ['All','Digest','Password KDF','Directory','Challenge / response'];
function buildLibrary() {
  const wrap = $('#libraryFilters');
  categories.forEach(category => {
    const btn = make('button', `filter-chip${category === state.category ? ' selected' : ''}`, category);
    btn.type = 'button';btn.dataset.category=category;
    btn.setAttribute('aria-pressed',String(category===state.category));
    btn.addEventListener('click',()=>{state.category=category;wrap.querySelectorAll('.filter-chip').forEach(b=>{b.classList.toggle('selected',b.dataset.category===category);b.setAttribute('aria-pressed',String(b.dataset.category===category));});renderLibrary();});
    wrap.append(btn);
  });
  renderLibrary();
}
function renderLibrary() {
  const matches = library.filter(item => (state.category==='All'||item.category===state.category)&&[item.name,item.mark,item.description,item.category].some(text=>text.toLowerCase().includes(state.query)));
  $('#libraryCount').textContent = `${matches.length.toString().padStart(2,'0')} FORMATS`;
  const grid = $('#libraryGrid'); clear(grid);
  if (!matches.length) {grid.append(make('div','library-empty','No matching signatures. Try a different search or filter.'));return;}
  const frag = document.createDocumentFragment();
  matches.forEach((item,index) => {
    const card = make('article','library-card');
    card.append(make('span','library-card-number',String(index+1).padStart(2,'0')));
    card.append(make('span','library-card-mark',item.mark.startsWith('$')?'$':item.mark.startsWith('{')?'{}':'#'));
    card.append(make('h2','',item.name),make('p','',item.description));
    const foot = make('div','library-card-foot');
    foot.append(make('span','',item.mark));
    const btn = make('button','','Try signature ↗');btn.type='button';
    btn.title='Load representative structure into analyzer (may be synthetic)';
    btn.addEventListener('click',()=>{setMode('single');input.value=item.input;updateInputStats();setView('analyzer',{updateHash:true});notify('Synthetic format example loaded');});
    foot.append(btn);card.append(foot);frag.append(card);
  });
  grid.append(frag);
}

function bind() {
  populateSamples();buildLibrary();updateInputStats();
  input.addEventListener('input', updateInputStats);
  input.addEventListener('keydown',event=>{if ((event.metaKey||event.ctrlKey)&&event.key==='Enter'){event.preventDefault();analyze();}});
  $('#analyzeBtn').addEventListener('click',analyze);
  $('#resetBtn').addEventListener('click',()=>{input.value='';updateInputStats();resetResults();input.focus();notify('Analysis reset');});
  $('#clearInputBtn').addEventListener('click',()=>{input.value='';updateInputStats();input.focus();});
  document.querySelectorAll('[data-mode]').forEach(btn=>btn.addEventListener('click',()=>setMode(btn.dataset.mode)));
  $('#copyResults').addEventListener('click',copyResults);
  $('#downloadResults').addEventListener('click',downloadResults);
  $('#librarySearch').addEventListener('input',event=>{state.query=event.target.value.trim().toLowerCase();renderLibrary();});
  $('#menuToggle').addEventListener('click',()=>{const open=$('#sidebar').classList.toggle('open');$('#menuToggle').setAttribute('aria-expanded',String(open));});
  navLinks.forEach(link=>link.addEventListener('click',()=>setView(link.dataset.viewLink)));
  window.addEventListener('hashchange',()=>setView(location.hash.slice(1)));
  setView(location.hash.slice(1));
}
bind();
