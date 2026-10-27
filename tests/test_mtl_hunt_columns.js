const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
const nodes = new Map();
const element = selector => {
  if (!nodes.has(selector)) nodes.set(selector, {value: '', checked: false, classList: {add() {}}});
  return nodes.get(selector);
};
const original = ['Subject', ...Array.from({length: 48}, (_, i) => `Custom${i}`), 'date_time_utc'];
const columns = [...original, 'MessageTraceHunt.Flag', 'MessageTraceHunt.SuspiciousReason'];
const trace = {traceId: 'synthetic', query: '', columns: [...original], overview: {columns}};
const context = vm.createContext({
  $: element, URLSearchParams, state: {caseId: 'synthetic'}, messageTraceState: trace,
  api: async () => ({columns, findingCount: 1}), saveMessageTraceView() {},
  loadMessageTraceRows: async () => {}, toast(message) { assert(!message.includes('Error')); },
});
vm.runInContext(source.match(/const MESSAGE_TRACE_HUNT_COLUMNS=.*;/)[0], context);
vm.runInContext(source.slice(source.indexOf('function addMessageTraceHuntColumns('), source.indexOf('function addMessageTraceTagColumn(')), context);
vm.runInContext(source.slice(source.indexOf("$('#messageTraceHuntButton').onclick="), source.indexOf("$('#messageTraceHuntButton').onclick=") + source.slice(source.indexOf("$('#messageTraceHuntButton').onclick=")).indexOf('\n};') + 3), context);

(async () => {
  await element('#messageTraceHuntButton').onclick();
  assert.deepEqual(Array.from(trace.columns).filter(column => !column.startsWith('MessageTraceHunt.')), original);
  assert(trace.columns.includes('MessageTraceHunt.SuspiciousReason'));
  assert.equal(trace.columns.length, 52);
  assert.equal(trace.query, 'MessageTraceHunt.Flag:=True');
  await element('#messageTraceHuntButton').onclick();
  assert.equal(trace.columns.length, 52);
  context.api = async () => ({columns, findingCount: 0});
  await element('#messageTraceHuntButton').onclick();
  assert(trace.columns.includes('date_time_utc'));
  assert.equal(trace.query, '');
  console.log('MTL hunt preserves selected columns, timestamp, order, and repeated-hunt results.');
})().catch(error => { console.error(error); process.exitCode = 1; });
