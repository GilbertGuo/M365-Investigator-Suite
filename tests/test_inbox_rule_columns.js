const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
const state = {ualId: 'synthetic', category: '', frozenColumns: []};
let saved = null;
const context = vm.createContext({state, localStorage: {getItem() { return saved; }}, orderColumnsWithFrozen: columns => columns});
vm.runInContext(source.slice(source.indexOf('const PREFERRED_COLUMNS'), source.indexOf('const SUSPICIOUS_LOGIN_COLUMNS')), context);
vm.runInContext(source.match(/const COLUMN_PREFERENCE_VERSION=.*;/)[0], context);
vm.runInContext(source.match(/const IP_ENRICHMENT_SUFFIX_ORDER=.*;/)[0], context);
vm.runInContext(source.slice(source.indexOf('function orderEnrichmentColumns('), source.indexOf('function addAppMappingColumns(')), context);
for (const category of ['', 'inbox_rules']) {
  state.category = category;
  const columns = ['_Row', 'CreationTime', 'Operation', 'InboxRule.Name', ...Array.from({length: 50}, (_, index) => `Custom${index}`)];
  const overview = {columns};
  saved = null;
  assert(vm.runInContext('restoreColumnPreferences', context)(overview).includes('InboxRule.Name'));
  saved = JSON.stringify({version: 6, known: columns, visible: columns.filter(column => column !== 'InboxRule.Name').slice(0, 50)});
  const restored = vm.runInContext('restoreColumnPreferences', context)(overview);
  assert(restored.includes('InboxRule.Name'));
  assert.equal(restored.indexOf('InboxRule.Name'), 3);
}
console.log('InboxRule.Name is visible by default and restored for previous column preferences.');
