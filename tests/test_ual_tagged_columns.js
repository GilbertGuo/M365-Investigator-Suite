const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
const start = source.indexOf("$('#taggedAction').onclick=");
const handler = source.slice(start, source.indexOf("$('#tagFilteredAction').onclick=", start));
const nodes = new Map();
const element = selector => {
  if (!nodes.has(selector)) nodes.set(selector, {});
  return nodes.get(selector);
};
const original = ['_Row', 'CreationTime', 'Operation', ...Array.from({length: 47}, (_, i) => `Custom${i}`)];
const mail = ['UserAgentString', 'AuditData.UserAgentString', 'Mail.UserAgent', 'Mail.ClientInfoString'];
const state = {query: '', category: 'email_access', operation: 'MailItemsAccessed', page: 4,
  columns: [...original], overview: {summary: {tagged: 1}, columns: [...original, ...mail, 'Review.Tag']}};
const context = vm.createContext({$: element, state, toast() { assert.fail('Unexpected toast'); },
  restoreColumnPreferences() { return ['_Row']; }, renderTaggedAction() {}, renderFacetControls() {}, renderPicker() {}, loadRows() {}});
vm.runInContext(handler, context);
element('#taggedAction').onclick();
assert.equal(state.query, 'Review.Tag:="Of interest"');
assert.equal(state.page, 1);
for (const column of [...original, ...mail, 'Review.Tag']) assert(state.columns.includes(column), `Missing ${column}`);
assert.deepEqual(Array.from(state.columns).filter(column => original.includes(column)), original);
assert.equal(new Set(state.columns).size, state.columns.length);
console.log('Tagged UAL review preserves selected columns and shows available user-agent fields beyond 50 columns.');
