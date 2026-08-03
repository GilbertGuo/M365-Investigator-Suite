const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const THEME_KEY='m365InvestigatorTheme';
function preferredTheme(){
  const saved=localStorage.getItem(THEME_KEY);
  if(saved==='light'||saved==='dark')return saved;
  return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
}
function applyTheme(theme,persist=true){
  const dark=theme==='dark',button=$('#themeToggle'),meta=$('meta[name="theme-color"]');
  document.documentElement.dataset.theme=dark?'dark':'light';
  if(button){button.textContent=dark?'Light mode':'Dark mode';button.setAttribute('aria-pressed',dark?'true':'false');button.setAttribute('aria-label',dark?'Switch to light mode':'Switch to dark mode');}
  if(meta)meta.setAttribute('content',dark?'#171218':'#5b167a');
  if(persist)localStorage.setItem(THEME_KEY,dark?'dark':'light');
}
applyTheme(preferredTheme(),false);
$('#themeToggle').onclick=()=>applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
const PREFERRED_COLUMNS = [
  '_Row','CreationTime','Operation','Login.SessionId','UserId','UserKey','UserType','ClientIP','ClientIPAddress',
  'Workload','RecordType','ResultStatus','ObjectId','ItemName','FolderPathName','MailboxOwnerUPN',
  'SiteUrl','SourceFileName','DestinationFileName','ExternalAccess','LogonType','ActorIpAddress',
  'InternetMessageId','InternetMessageIDs'
];
const CATEGORY_COLUMNS = {
  logon:['_Row','CreationTime','Operation','UserId','UserKey','ClientIP','ActorIpAddress','ResultStatus','LogonError','Login.ResultStatusDetail','Login.SessionId','Login.IsCompliant','Login.IsManaged','Login.IsCompliantAndManaged','Login.DeviceId','Login.DeviceName','Login.OS','Login.BrowserType','Login.TrustType','Login.UserAuthenticationMethod','Login.RequestType','Login.UserAgent','Workload','RecordType'],
  inbox_rules:['_Row','CreationTime','Operation','InboxRule.Name','InboxRule.Details','InboxRule.From','InboxRule.SentTo','InboxRule.SubjectContainsWords','InboxRule.MoveToFolder','InboxRule.ForwardTo','InboxRule.RedirectTo','InboxRule.ForwardAsAttachmentTo','InboxRule.DeleteMessage','InboxRule.MarkAsRead','InboxRule.StopProcessingRules','UserId','ClientIP','ResultStatus'],
  transport_rules:['_Row','CreationTime','Operation','UserId','ClientIP','Workload','ObjectId','Name','Parameters','ResultStatus'],
  mailbox_permissions:['_Row','CreationTime','Operation','UserId','ClientIP','Workload','ObjectId','MailboxOwnerUPN','Parameters','ResultStatus'],
  email_access:['_Row','CreationTime','Operation','UserId','ClientIP','ClientIPAddress','MailboxOwnerUPN','Mail.ActorInfoString','Mail.UserAgent','Mail.ClientInfoString','UserAgent','SessionId','InternetMessageId','InternetMessageIDs','ItemName','FolderPathName','Subject','AffectedItems','Folders','Workload','ResultStatus'],
  file_access:['_Row','CreationTime','Operation','UserId','ClientIP','Workload','ObjectId','SiteUrl','SourceFileName','DestinationFileName','SourceRelativeUrl','DestinationRelativeUrl','ItemName','FolderPathName','UserAgent','ResultStatus'],
  other:PREFERRED_COLUMNS
};
const SUSPICIOUS_LOGIN_COLUMNS=['SuspiciousLogin.Flag','SuspiciousLogin.Risk','SuspiciousLogin.Score','SuspiciousLogin.IP','SuspiciousLogin.Location','SuspiciousLogin.ISP','SuspiciousLogin.Proxy_VPN_TOR','SuspiciousLogin.Hosting','SuspiciousLogin.IsCompliant','SuspiciousLogin.IsCompliantAndManaged','SuspiciousLogin.Reasons'];
const TRAVEL_COLUMNS=['Travel.Flag','Travel.Risk','Travel.Score','Travel.ElapsedHours','Travel.PreviousTime','Travel.PreviousIP','Travel.PreviousISP','Travel.PreviousLocation','Travel.CurrentISP','Travel.CurrentLocation','Travel.HostingOrVPN','Travel.DeviceRisk','Travel.Reasons'];
const MESSAGE_SUBJECT_COLUMNS=['MessageSubject.InternetMessageIDs','MessageSubject.Subjects','MessageSubject.SizeInBytes','MessageSubject.Pairs'];
const IP_ENRICHMENT_SUFFIX_ORDER=['Country','Region','City','ISP','AS','Mobile','Proxy_VPN_TOR','Hosting'];
const VIEW_DEFS=[['','All activity'],['logon','Logon'],['inbox_rules','Inbox rules'],['transport_rules','Transport rules'],['mailbox_permissions','Mailbox permissions'],['email_access','Email access'],['file_access','File access'],['other','Other']];
const CATEGORY_MIGRATIONS={logins:'logon',files:'file_access',mail:'email_access',teams:'other'};
const COLUMN_PREFERENCE_VERSION=6;
const state = {caseId:null,caseMeta:null,ualId:null,ualDatasets:[],ualViews:{},overview:null,page:1,size:50,query:'',operation:'',category:'',sortField:'',sortDirection:'asc',columns:[],frozenColumns:[],currentRows:[],currentTotal:0,currentTagged:0};
const MESSAGE_TRACE_PREFERRED=['_Row','Received','SenderAddress','RecipientAddress','Subject','Status','MessageId','NetworkMessageId','OriginalClientIP','ClientIP','FromIP','ToIP','Directionality','Size'];
const WHOIS_SUFFIX_ORDER=['Domain','RegisteredDomain','Registrar','RegistrationDate','ExpirationDate','LastChangedDate','Status','NameServers','DNSSEC','Lookup_Status','Error'];
const MESSAGE_TRACE_HUNT_COLUMNS=['MessageTraceHunt.Flag','MessageTraceHunt.Risk','MessageTraceHunt.Score','MessageTraceHunt.SuspiciousReason','MessageTraceHunt.NewDomains','MessageTraceHunt.DomainAgeDays','MessageTraceHunt.DomainRegistrationDates','MessageTraceHunt.SubjectKeywords','MessageTraceHunt.ServiceDomains'];
const messageTraceState={overview:null,traces:[],traceId:null,page:1,size:50,query:'',sortField:'',sortDirection:'asc',columns:[],frozenColumns:[],views:{},currentRows:[],currentTotal:0,currentTagged:0};
function isTimestampColumn(column){const name=String(column||'');return name.toLowerCase()==='received'||/time|date|timestamp/i.test(name);}

async function api(url, opts={}) {
  const response = await fetch(url, opts);
  let data;
  try { data = await response.json(); } catch { data = {error:response.statusText}; }
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function toast(message) { const el=$('#toast'); el.textContent=message; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2400); }
function params() {
  const p=new URLSearchParams({q:state.query,page:state.page,size:state.size,columns:state.columns.join(',')});
  if(state.operation) p.set('operation',state.operation);
  if(state.category) p.set('category',state.category);
  if(state.sortField) {p.set('sort',state.sortField);p.set('direction',state.sortDirection);}
  return p;
}
function activeUalId(){return encodeURIComponent(state.ualId||'');}
function orderEnrichmentColumns(columns,enrichmentSources=[]) {
  const sourceFor=column=>enrichmentSources.find(source=>column.startsWith(`${source}_IPAPI_`))||column.split('_IPAPI_')[0];
  const suffixFor=column=>column.split('_IPAPI_')[1]||'';
  const enrichment=columns.filter(column=>column.includes('_IPAPI_')).sort((left,right)=>{
    const leftSource=sourceFor(left), rightSource=sourceFor(right);
    const leftSourceRank=enrichmentSources.indexOf(leftSource), rightSourceRank=enrichmentSources.indexOf(rightSource);
    const sourceComparison=(leftSourceRank<0?Number.MAX_SAFE_INTEGER:leftSourceRank)-(rightSourceRank<0?Number.MAX_SAFE_INTEGER:rightSourceRank)||leftSource.localeCompare(rightSource);
    if(sourceComparison) return sourceComparison;
    const leftRank=IP_ENRICHMENT_SUFFIX_ORDER.indexOf(suffixFor(left));
    const rightRank=IP_ENRICHMENT_SUFFIX_ORDER.indexOf(suffixFor(right));
    return (leftRank<0?Number.MAX_SAFE_INTEGER:leftRank)-(rightRank<0?Number.MAX_SAFE_INTEGER:rightRank)||suffixFor(left).localeCompare(suffixFor(right));
  });
  let enrichmentIndex=0;
  return columns.map(column=>column.includes('_IPAPI_')?enrichment[enrichmentIndex++]:column);
}
function chooseDefaults(columns, enrichmentSources=[], preferredNames=PREFERRED_COLUMNS) {
  const preferred=preferredNames.filter(c=>columns.includes(c));
  const enriched=orderEnrichmentColumns(columns.filter(c=>c.includes('_IPAPI_') && (enrichmentSources.length===0 || enrichmentSources.some(source=>c.startsWith(`${source}_IPAPI_`)))),enrichmentSources);
  const selected=[...preferred,...enriched.filter(c=>!preferred.includes(c))];
  const showInboxRuleFields=preferredNames.some(c=>c.startsWith('InboxRule.'));
  const showLoginFields=preferredNames.filter(c=>c.startsWith('Login.')).length>1;
  const showTravelFields=preferredNames.some(c=>c.startsWith('Travel.'));
  const showSuspiciousLoginFields=preferredNames.some(c=>c.startsWith('SuspiciousLogin.'));
  const showMessageSubjectFields=preferredNames.some(c=>c.startsWith('MessageSubject.'));
  const showAppMappingFields=preferredNames.some(c=>c.startsWith('AppMapping.'));
  const remaining=columns.filter(c=>!selected.includes(c) && !c.startsWith('_') && (showInboxRuleFields||!c.startsWith('InboxRule.')) && (showLoginFields||!c.startsWith('Login.')) && (showTravelFields||!c.startsWith('Travel.')) && (showSuspiciousLoginFields||!c.startsWith('SuspiciousLogin.')) && (showMessageSubjectFields||!c.startsWith('MessageSubject.')) && (showAppMappingFields||!c.startsWith('AppMapping.'))).slice(0, Math.max(0,24-preferred.length));
  return [...selected,...remaining].slice(0,50);
}
function columnPreferenceKey(){ return state.ualId?`ualColumnPreferences:${state.ualId}:${state.category||'all'}`:''; }
function addSessionIdDefaults(preferred,available){
  if(state.category&&state.category!=='logon') return preferred;
  const sessionColumns=available.filter(column=>/sessionid/i.test(column));
  const withoutSessions=preferred.filter(column=>!/sessionid/i.test(column));
  const insertAt=Math.min(3,withoutSessions.length);
  return [...withoutSessions.slice(0,insertAt),...sessionColumns,...withoutSessions.slice(insertAt)];
}
function isAppIdColumn(column){return !column.startsWith('AppMapping.')&&/(?:app|application)id$/i.test(column);}
function addLoginAppIdDefaults(preferred,available){
  if(state.category!=='logon') return preferred;
  const appIdColumns=available.filter(isAppIdColumn);
  const withoutAppIds=preferred.filter(column=>!isAppIdColumn(column));
  const lastSession=withoutAppIds.reduce((last,column,index)=>/sessionid/i.test(column)?index:last,-1);
  const insertAt=lastSession>=0?lastSession+1:Math.min(3,withoutAppIds.length);
  return [...withoutAppIds.slice(0,insertAt),...appIdColumns,...withoutAppIds.slice(insertAt)];
}
function saveColumnPreferences(){
  if(!state.ualId || !state.overview) return;
  localStorage.setItem(columnPreferenceKey(),JSON.stringify({version:COLUMN_PREFERENCE_VERSION,visible:state.columns,frozen:state.frozenColumns,known:state.overview.columns}));
}
function restoreColumnPreferences(overview){
  const basePreferred=state.category?CATEGORY_COLUMNS[state.category]:PREFERRED_COLUMNS;
  const preferred=addLoginAppIdDefaults(addSessionIdDefaults(basePreferred,overview.columns),overview.columns);
  const defaults=chooseDefaults(overview.columns,overview.enrichmentColumns||[],preferred);
  try {
    const saved=JSON.parse(localStorage.getItem(columnPreferenceKey())||'null');
    if(!saved || !Array.isArray(saved.visible)){state.frozenColumns=[];return defaults;}
    const allowedSpecialized=column=>(!column.startsWith('InboxRule.')||preferred.includes(column)) &&
      (!column.startsWith('Login.')||preferred.includes(column)) &&
      !column.startsWith('Travel.') && !column.startsWith('SuspiciousLogin.');
    const visible=saved.visible.filter(c=>overview.columns.includes(c) && allowedSpecialized(c));
    const known=Array.isArray(saved.known)?saved.known:[];
    const newImportant=overview.columns.filter(c=>!known.includes(c) && (preferred.includes(c)||c.includes('_IPAPI_')));
    const migrationColumns=saved.version===COLUMN_PREFERENCE_VERSION?[]:preferred.filter(c=>/sessionid/i.test(c)||isAppIdColumn(c));
    let restored=[...visible,...migrationColumns.filter(c=>overview.columns.includes(c)&&!visible.includes(c)),...newImportant.filter(c=>!visible.includes(c))].slice(0,50);
    if(saved.version!==COLUMN_PREFERENCE_VERSION) restored=orderEnrichmentColumns(restored,overview.enrichmentColumns||[]);
    const result=restored.length?restored:defaults;
    state.frozenColumns=(Array.isArray(saved.frozen)?saved.frozen:[]).filter(column=>result.includes(column));
    return orderColumnsWithFrozen(result,state.frozenColumns);
  } catch { state.frozenColumns=[];return defaults; }
}
function addContextColumns(base,context,available){
  const additions=context.filter(c=>available.includes(c)&&!base.includes(c)); const insertAt=Math.min(3,base.length);
  return [...base.slice(0,insertAt),...additions,...base.slice(insertAt)].slice(0,50);
}
function addAppMappingColumns(base,mappings){
  const result=[...base];
  const visibleSources=mappings.filter(({source})=>result.includes(source));
  const candidates=visibleSources.length?visibleSources:mappings.slice(0,3);
  for(const {source,column} of candidates){
    if(result.includes(column)) continue;
    const sourceIndex=result.indexOf(source);
    if(sourceIndex>=0) result.splice(sourceIndex+1,0,column);
    else if(result.length<49) result.push(source,column);
  }
  return result.slice(0,50);
}

async function loadCases() {
  const {cases}=await api('/api/cases');
  $('#caseList').innerHTML=cases.length ? cases.map(c=>`<article class="case-item"><button class="case-open" data-id="${c.id}"><b>${esc(c.name)}</b><span>${esc(c.sourceFile||'No UAL datasets')}</span><small>${Number(c.rowCount||0).toLocaleString()} UAL rows · ${new Date(c.createdAt).toLocaleString()}</small></button><button class="case-delete" data-id="${c.id}" data-name="${esc(c.name)}">Delete</button></article>`).join('') : '<p class="status">No cases yet. Create a case to begin.</p>';
  $$('.case-open').forEach(button=>button.onclick=()=>openCase(button.dataset.id));
  $$('.case-delete').forEach(button=>button.onclick=()=>openDeleteConfirmation(button.dataset.id,button.dataset.name));
}
$('#refreshCases').onclick=loadCases;
let pendingDeleteCase=null;
function openDeleteConfirmation(id,name){pendingDeleteCase={id,name};$('#deleteCaseName').textContent=name;$('#deleteModal').classList.remove('hidden');$('#confirmDelete').focus();}
function closeDeleteConfirmation(){pendingDeleteCase=null;$('#deleteModal').classList.add('hidden');$('#confirmDelete').disabled=false;$('#confirmDelete').textContent='Delete case';}
$('#cancelDelete').onclick=closeDeleteConfirmation;
$('#deleteModal').onclick=event=>{if(event.target===$('#deleteModal'))closeDeleteConfirmation();};
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('#deleteModal').classList.contains('hidden'))closeDeleteConfirmation();});
$('#confirmDelete').onclick=async()=>{
  if(!pendingDeleteCase)return; const deleting={...pendingDeleteCase}; const button=$('#confirmDelete'); button.disabled=true; button.textContent='Deleting…';
  try{await api(`/api/cases/${deleting.id}`,{method:'DELETE'});Object.keys(localStorage).filter(key=>key.startsWith(`ualColumnPreferences:${deleting.id}:`)).forEach(key=>localStorage.removeItem(key));closeDeleteConfirmation();await loadCases();toast(`Deleted ${deleting.name}`);}
  catch(error){button.disabled=false;button.textContent='Delete case';toast(error.message);}
};
$('#back').onclick=()=>{state.caseId=null;state.ualId=null;state.overview=null;document.body.classList.remove('workspace-active');$('#workspace').classList.add('hidden');$('#home').classList.remove('hidden');loadCases();};

function switchWorkspaceTool(tool){
  $$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));
  $('#ipApiKey').value='';
  $('#messageTraceIpApiKey').value='';
  if(tool!=='review')setReviewLoading('ual',false);
  if(tool!=='message-trace')setReviewLoading('mtl',false);
  const review=tool==='review';
  const messageTrace=tool==='message-trace';
  const emailCollection=tool==='email-collection';
  const clientXlsx=tool==='client-xlsx';
  const documentation=tool==='documentation';
  $('#reviewNav').classList.toggle('active',review); $('#messageTraceNav').classList.toggle('active',messageTrace); $('#emailCollectionNav').classList.toggle('active',emailCollection); $('#clientXlsxNav').classList.toggle('active',clientXlsx); $('#documentationNav').classList.toggle('active',documentation);
  $('#reviewTab').classList.toggle('hidden',!review); $('#messageTraceTab').classList.toggle('hidden',!messageTrace); $('#emailCollectionTab').classList.toggle('hidden',!emailCollection); $('#clientXlsxTab').classList.toggle('hidden',!clientXlsx); $('#documentationTab').classList.toggle('hidden',!documentation);
  const activeUal=review&&Boolean(state.ualId)&&!$('#ualReview').classList.contains('hidden');
  const activeMtl=messageTrace&&Boolean(messageTraceState.traceId)&&!$('#messageTraceReview').classList.contains('hidden');
  $('#metrics').classList.toggle('hidden',!activeUal); $('#reviewActions').classList.toggle('hidden',!activeUal);
  $('#messageTraceActions').classList.toggle('hidden',!activeMtl);
  $('#viewTitle').textContent=review?'UAL Review':messageTrace?'MTL Review':emailCollection?'Email Collection':clientXlsx?'Client XLSX':'Documentation';
}
function ualToolIsActive(){return !$('#reviewTab').classList.contains('hidden');}
function mtlToolIsActive(){return !$('#messageTraceTab').classList.contains('hidden');}
function setReviewLoading(scope,loading,title,detail){
  const element=$(scope==='mtl'?'#messageTraceLoading':'#tableLoading');
  const active=scope==='mtl'?mtlToolIsActive():ualToolIsActive();
  const visible=Boolean(loading&&active);
  element.querySelector('b').textContent=title||(scope==='mtl'?'Loading MTL activity…':'Loading activity…');
  const help=element.querySelector('small');if(help)help.textContent=detail||'Applying filters and preparing rows';
  element.classList.toggle('hidden',!visible);
  const busy=!$('#tableLoading').classList.contains('hidden')||!$('#messageTraceLoading').classList.contains('hidden');
  $('#workspace').setAttribute('aria-busy',busy?'true':'false');
}
const enrichmentUi={ual:{timer:null,running:false},mtl:{timer:null,running:false},domain:{timer:null,running:false}};
function enrichmentElements(scope){
  if(scope==='domain')return {progress:$('#messageTraceWhoisProgress'),status:$('#messageTraceWhoisStatus'),button:$('#messageTraceWhoisButton')};
  const mtl=scope==='mtl';
  return {progress:$(mtl?'#messageTraceEnrichProgress':'#enrichProgress'),status:$(mtl?'#messageTraceEnrichStatus':'#enrichStatus'),button:$(mtl?'#messageTraceEnrichButton':'#enrichBtn')};
}
function startEnrichmentProgress(scope,label='IP enrichment',initial='Contacting IP-API…'){
  const ui=enrichmentUi[scope],{progress}=enrichmentElements(scope),detail=progress.querySelector('small');
  if(ui.timer)clearInterval(ui.timer);
  ui.running=true;
  const started=performance.now();
  progress.classList.remove('hidden');
  progress.setAttribute('aria-valuetext',`${label} in progress`);
  detail.textContent=initial;
  ui.timer=setInterval(()=>{const seconds=Math.max(1,Math.floor((performance.now()-started)/1000));detail.textContent=`${label} running · ${seconds}s elapsed`;},1000);
}
function stopEnrichmentProgress(scope){
  const ui=enrichmentUi[scope],{progress}=enrichmentElements(scope);
  if(ui.timer)clearInterval(ui.timer);
  ui.timer=null;ui.running=false;
  progress.classList.add('hidden');
  progress.setAttribute('aria-valuetext','Waiting');
  progress.querySelector('small').textContent=scope==='domain'?'Preparing domain enrichment…':'Preparing enrichment…';
}
function resetEnrichmentStatus(scope){
  if(enrichmentUi[scope].running)return;
  const {progress,status}=enrichmentElements(scope);
  progress.classList.add('hidden');status.className='status';status.textContent='';
}
$('#reviewNav').onclick=()=>switchWorkspaceTool('review');
$('#messageTraceNav').onclick=()=>{switchWorkspaceTool('message-trace');loadMessageTraceOverview();};
$('#emailCollectionNav').onclick=()=>switchWorkspaceTool('email-collection');
$('#clientXlsxNav').onclick=()=>switchWorkspaceTool('client-xlsx');
$('#documentationNav').onclick=()=>switchWorkspaceTool('documentation');

$('#uploadForm').onsubmit=async e=>{
  e.preventDefault(); const status=$('#uploadStatus'); status.className='status'; status.textContent='Creating case…';
  try { const created=await api('/api/cases',{method:'POST',body:new FormData(e.target)}); status.textContent='Case ready.';e.target.reset();await openCase(created.id); }
  catch(error) { status.className='status error'; status.textContent=error.message; }
};

const clientXlsxFile=$('#clientXlsxFile'), clientXlsxDropzone=$('#clientXlsxDropzone');
clientXlsxFile.onchange=()=>$('#clientXlsxFileName').textContent=clientXlsxFile.files[0]?.name||'No file selected';
['dragenter','dragover'].forEach(name=>clientXlsxDropzone.addEventListener(name,event=>{event.preventDefault();clientXlsxDropzone.classList.add('drag');}));
['dragleave','drop'].forEach(name=>clientXlsxDropzone.addEventListener(name,event=>{event.preventDefault();clientXlsxDropzone.classList.remove('drag');}));
clientXlsxDropzone.addEventListener('drop',event=>{clientXlsxFile.files=event.dataTransfer.files;clientXlsxFile.onchange();});
$('#clientXlsxForm').onsubmit=async event=>{
  event.preventDefault();
  const status=$('#clientXlsxStatus'), button=$('#clientXlsxButton');
  status.className='status'; status.textContent='Building the client-shareable workbook…'; button.disabled=true;
  try {
    const response=await fetch('/api/client-xlsx',{method:'POST',body:new FormData(event.target)});
    if(!response.ok){
      let message='XLSX conversion failed';
      try{message=(await response.json()).error||message;}catch{}
      throw new Error(message);
    }
    const blob=await response.blob();
    const disposition=response.headers.get('Content-Disposition')||'';
    const filename=disposition.match(/filename="([^"]+)"/i)?.[1]||'client-shareable.xlsx';
    const url=URL.createObjectURL(blob), link=document.createElement('a');
    link.href=url; link.download=filename; document.body.appendChild(link); link.click(); link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
    status.textContent=`Downloaded ${filename}`; toast('Client-shareable XLSX created');
  } catch(error) {status.className='status error';status.textContent=error.message;}
  finally {button.disabled=false;}
};

const collectionFile=$('#collectionFile'),collectionDropzone=$('#collectionDropzone');
function setCollectionMode(){
  const mode=document.querySelector('input[name="mode"]:checked')?.value||'manual',manual=mode==='manual';
  $('#collectionManualFields').classList.toggle('hidden',!manual);$('#collectionCsvFields').classList.toggle('hidden',manual);
  $('#collectionMailboxUPN').required=manual;$('#collectionMessageIds').required=manual;collectionFile.required=!manual;
}
document.querySelectorAll('input[name="mode"]').forEach(input=>input.onchange=setCollectionMode);
collectionFile.onchange=()=>$('#collectionFileName').textContent=collectionFile.files[0]?.name||'No file selected';
['dragenter','dragover'].forEach(name=>collectionDropzone.addEventListener(name,event=>{event.preventDefault();collectionDropzone.classList.add('drag');}));
['dragleave','drop'].forEach(name=>collectionDropzone.addEventListener(name,event=>{event.preventDefault();collectionDropzone.classList.remove('drag');}));
collectionDropzone.addEventListener('drop',event=>{collectionFile.files=event.dataTransfer.files;collectionFile.onchange();});
setCollectionMode();
$('#emailCollectionForm').onsubmit=async event=>{
  event.preventDefault();
  const status=$('#emailCollectionStatus'),button=$('#emailCollectionButton'),secret=$('#collectionClientSecret');
  status.className='status';status.textContent='Authenticating with Microsoft Graph and collecting messages…';button.disabled=true;button.textContent='Collecting…';
  try{
    const data=await api('/api/email-collection',{method:'POST',body:new FormData(event.target)});
    status.className='status success';
    status.textContent=`Complete: ${Number(data.collected).toLocaleString()} collected, ${Number(data.notFound).toLocaleString()} not found, ${Number(data.errors).toLocaleString()} errors. Report: ${data.reportPath}`;
    toast(`Email collection complete · ${data.collected} collected`);
  }catch(error){status.className='status error';status.textContent=error.message;}
  finally{secret.value='';button.disabled=false;button.innerHTML='Start email collection <span>→</span>';}
};

function saveUalView(){
  if(!state.ualId)return;
  state.ualViews[state.ualId]={page:state.page,size:state.size,query:state.query,operation:state.operation,category:state.category,sortField:state.sortField,sortDirection:state.sortDirection,columns:[...state.columns],frozenColumns:[...state.frozenColumns]};
}
async function selectUalDataset(datasetId){
  saveUalView();
  setReviewLoading('ual',true,'Opening UAL dataset…','Reading parsed fields and preparing the first page');
  let overview;
  try{overview=await api(`/api/cases/${encodeURIComponent(datasetId)}`);}catch(error){setReviewLoading('ual',false);throw error;}
  const saved=state.ualViews[datasetId];
  state.ualId=datasetId;state.overview=overview;
  state.page=saved?.page||1;state.size=saved?.size||50;state.query=saved?.query||'';state.operation=saved?.operation||'';state.category=CATEGORY_MIGRATIONS[saved?.category]||saved?.category||'';state.sortField=saved?.sortField||'';state.sortDirection=saved?.sortDirection||'asc';
  state.columns=(saved?.columns||restoreColumnPreferences(overview)).filter(column=>overview.columns.includes(column));
  state.frozenColumns=(saved?.frozenColumns||state.frozenColumns||[]).filter(column=>state.columns.includes(column));
  state.columns=orderColumnsWithFrozen(state.columns,state.frozenColumns);
  $('#query').value=state.query;$('#pageSize').value=String(state.size);$('#ualSelector').value=datasetId;
  $('#ualSource').textContent=`${overview.meta.sourceFile} · uploaded ${new Date(overview.meta.uploadedAt||overview.meta.createdAt).toLocaleString()}`;
  $('#activeFile').textContent=overview.meta.sourceFile;
  const showUalHeader=ualToolIsActive()&&!$('#ualReview').classList.contains('hidden');
  $('#metrics').classList.toggle('hidden',!showUalHeader);$('#reviewActions').classList.toggle('hidden',!showUalHeader);
  renderOverview();renderPicker();await loadRows();
}
async function loadUalOverview(preferredDatasetId=''){
  try{
    const {datasets}=await api(`/api/cases/${state.caseId}/ual-datasets`);state.ualDatasets=datasets;
    const hasDatasets=datasets.length>0;
    $('#ualUpload').classList.toggle('hidden',hasDatasets);$('#ualReview').classList.toggle('hidden',!hasDatasets);$('#ualCancelUpload').classList.toggle('hidden',!hasDatasets);
    const showUalHeader=hasDatasets&&ualToolIsActive();
    $('#metrics').classList.toggle('hidden',!showUalHeader);$('#reviewActions').classList.toggle('hidden',!showUalHeader);
    if(!hasDatasets){state.ualId=null;state.overview=null;$('#activeFile').textContent='No UAL datasets';return;}
    const datasetId=preferredDatasetId||((state.ualId&&datasets.some(dataset=>dataset.id===state.ualId))?state.ualId:datasets[0].id);
    $('#ualSelector').innerHTML=datasets.map(dataset=>`<option value="${esc(dataset.id)}">${esc(dataset.name||dataset.sourceFile)} · ${Number(dataset.rowCount||0).toLocaleString()} rows</option>`).join('');
    await selectUalDataset(datasetId);
  }catch(error){toast(error.message);}
}
const ualFile=$('#ualFile'),ualDropzone=$('#ualDropzone');
ualFile.onchange=()=>$('#ualFileName').textContent=ualFile.files[0]?.name||'No file selected';
['dragenter','dragover'].forEach(name=>ualDropzone.addEventListener(name,event=>{event.preventDefault();ualDropzone.classList.add('drag');}));
['dragleave','drop'].forEach(name=>ualDropzone.addEventListener(name,event=>{event.preventDefault();ualDropzone.classList.remove('drag');}));
ualDropzone.addEventListener('drop',event=>{ualFile.files=event.dataTransfer.files;ualFile.onchange();});
$('#ualForm').onsubmit=async event=>{
  event.preventDefault();const status=$('#ualUploadStatus'),button=$('#ualUploadButton');status.className='status';status.textContent='Uploading and parsing UAL evidence…';button.disabled=true;
  try{const created=await api(`/api/cases/${state.caseId}/ual-datasets`,{method:'POST',body:new FormData(event.target)});status.textContent='UAL dataset ready.';event.target.reset();$('#ualFileName').textContent='No file selected';await loadUalOverview(created.meta.id);toast('UAL dataset added');}
  catch(error){status.className='status error';status.textContent=error.message;}
  finally{button.disabled=false;}
};
$('#ualReplace').onclick=()=>{$('#ualReview').classList.add('hidden');$('#ualUpload').classList.remove('hidden');$('#metrics').classList.add('hidden');$('#reviewActions').classList.add('hidden');ualFile.value='';$('#ualFileName').textContent='No file selected';$('#ualName').value='';};
$('#ualCancelUpload').onclick=()=>{$('#ualUpload').classList.add('hidden');$('#ualReview').classList.remove('hidden');const show=ualToolIsActive();$('#metrics').classList.toggle('hidden',!show);$('#reviewActions').classList.toggle('hidden',!show);};
$('#ualSelector').onchange=event=>selectUalDataset(event.target.value).catch(error=>toast(error.message));
$('#ualDelete').onclick=async()=>{
  const current=state.ualDatasets.find(dataset=>dataset.id===state.ualId);if(!current)return;
  if(!confirm(`Delete UAL dataset “${current.name||current.sourceFile}”?\n\nIt will be moved to recoverable local case trash.`))return;
  try{await api(`/api/cases/${state.caseId}/ual-datasets/${encodeURIComponent(current.id)}`,{method:'DELETE'});delete state.ualViews[current.id];Object.keys(localStorage).filter(key=>key.startsWith(`ualColumnPreferences:${current.id}:`)).forEach(key=>localStorage.removeItem(key));state.ualId=null;await loadUalOverview();toast('UAL dataset deleted');}catch(error){toast(error.message);}
};

function messageTraceDefaultColumns(columns,enrichmentColumns=[]){
  const preferred=MESSAGE_TRACE_PREFERRED.filter(column=>columns.includes(column));
  const enriched=orderEnrichmentColumns(columns.filter(column=>column.includes('_IPAPI_')),enrichmentColumns);
  const result=[...preferred];
  for(const source of ['SenderAddress','RecipientAddress']){
    const whois=WHOIS_SUFFIX_ORDER.map(suffix=>`${source}_WHOIS_${suffix}`).filter(column=>columns.includes(column));
    const sourceIndex=result.indexOf(source),insertAt=sourceIndex>=0?sourceIndex+1:result.length;
    result.splice(insertAt,0,...whois.filter(column=>!result.includes(column)));
  }
  enriched.filter(column=>!result.includes(column)).forEach(column=>result.push(column));
  const remaining=columns.filter(column=>!result.includes(column)&&!column.includes('_WHOIS_')&&!column.startsWith('_'));
  return [...result,...remaining].slice(0,50);
}
function messageTraceIpColumns(columns){
  return columns.filter(column=>!column.includes('_IPAPI_')&&/(?:^|[ _.\-])ip(?:$|[ _.\-])|ipaddress|clientip|fromip|toip/i.test(column));
}
function addMessageTraceHuntColumns(base,available){
  const additions=MESSAGE_TRACE_HUNT_COLUMNS.filter(column=>available.includes(column)&&!base.includes(column));
  const result=[...base],subjectIndex=result.indexOf('Subject'),insertAt=subjectIndex>=0?subjectIndex+1:Math.min(4,result.length);
  result.splice(insertAt,0,...additions);return result.slice(0,50);
}
function addMessageTraceTagColumn(base,available){
  if(!available.includes('Review.Tag')||base.includes('Review.Tag'))return base;
  const result=[...base],insertAt=Math.min(1,result.length);result.splice(insertAt,0,'Review.Tag');return result.slice(0,50);
}
function renderMessageTraceTagActions(){
  const count=Number(messageTraceState.overview?.summary?.tagged||0),hasFilter=Boolean(messageTraceState.query.trim());
  const allFilteredTagged=hasFilter&&messageTraceState.currentTotal>0&&messageTraceState.currentTagged===messageTraceState.currentTotal;
  $('#messageTraceTaggedCount').textContent=count.toLocaleString();
  $('#messageTraceTaggedAction').classList.toggle('has-tags',count>0);$('#messageTraceTaggedAction').classList.toggle('active',messageTraceState.query==='Review.Tag:="Of interest"');
  $('#messageTraceTagFilteredAction').disabled=!hasFilter||messageTraceState.currentTotal===0;
  $('#messageTraceTagFilteredAction').textContent=allFilteredTagged?'☆ Untag filtered rows':'★ Tag filtered rows';
  $('#messageTraceTagFilteredAction').classList.toggle('untag-mode',allFilteredTagged);
}
function saveMessageTraceView(){
  if(!messageTraceState.traceId)return;
  messageTraceState.views[messageTraceState.traceId]={page:messageTraceState.page,size:messageTraceState.size,query:messageTraceState.query,sortField:messageTraceState.sortField,sortDirection:messageTraceState.sortDirection,columns:[...messageTraceState.columns],frozenColumns:[...messageTraceState.frozenColumns]};
}
async function selectMessageTrace(traceId){
  saveMessageTraceView();
  setReviewLoading('mtl',true,'Opening MTL dataset…','Reading trace fields and preparing the first page');
  let overview;
  try{overview=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(traceId)}`);}catch(error){setReviewLoading('mtl',false);throw error;}
  messageTraceState.traceId=traceId;messageTraceState.overview=overview;
  const saved=messageTraceState.views[traceId];
  messageTraceState.page=saved?.page||1;messageTraceState.size=saved?.size||50;messageTraceState.query=saved?.query||'';messageTraceState.sortField=saved?.sortField||'';messageTraceState.sortDirection=saved?.sortDirection||'asc';
  messageTraceState.columns=(saved?.columns||messageTraceDefaultColumns(overview.columns,overview.enrichmentColumns||[])).filter(column=>overview.columns.includes(column));
  messageTraceState.frozenColumns=(saved?.frozenColumns||[]).filter(column=>messageTraceState.columns.includes(column));
  messageTraceState.columns=orderColumnsWithFrozen(messageTraceState.columns,messageTraceState.frozenColumns);
  $('#messageTraceQuery').value=messageTraceState.query;$('#messageTracePageSize').value=String(messageTraceState.size);
  $('#messageTraceSelector').value=traceId;
  $('#messageTraceSource').textContent=`${overview.meta.sourceFile} · uploaded ${new Date(overview.meta.uploadedAt).toLocaleString()}`;
  $('#messageTraceIpColumn').innerHTML='<option value="">Auto-detect Message Trace IP fields</option>'+messageTraceIpColumns(overview.columns).map(column=>`<option>${esc(column)}</option>`).join('');
  renderMessageTraceTagActions();
  await loadMessageTraceRows();
}
async function loadMessageTraceOverview(preferredTraceId=''){
  try{
    const {traces}=await api(`/api/cases/${state.caseId}/message-traces`);
    messageTraceState.traces=traces;
    const hasTraces=traces.length>0;
    $('#messageTraceUpload').classList.toggle('hidden',hasTraces);
    $('#messageTraceReview').classList.toggle('hidden',!hasTraces);
    $('#messageTraceCancelUpload').classList.toggle('hidden',!hasTraces);
    $('#messageTraceActions').classList.toggle('hidden',!hasTraces||!mtlToolIsActive());
    if(!hasTraces){messageTraceState.traceId=null;messageTraceState.overview=null;return;}
    const traceId=preferredTraceId||((messageTraceState.traceId&&traces.some(trace=>trace.id===messageTraceState.traceId))?messageTraceState.traceId:traces[0].id);
    $('#messageTraceSelector').innerHTML=traces.map(trace=>`<option value="${esc(trace.id)}">${esc(trace.name||trace.sourceFile)} · ${Number(trace.rowCount||0).toLocaleString()} rows</option>`).join('');
    await selectMessageTrace(traceId);
  }catch(error){toast(error.message);}
}
function messageTraceParams(){
  const params=new URLSearchParams({q:messageTraceState.query,page:messageTraceState.page,size:messageTraceState.size,columns:messageTraceState.columns.join(',')});
  if(messageTraceState.sortField){params.set('sort',messageTraceState.sortField);params.set('direction',messageTraceState.sortDirection);}
  return params;
}
let messageTraceRequest=0;
async function loadMessageTraceRows(){
  if(!messageTraceState.overview?.exists)return;
  const request=++messageTraceRequest;setReviewLoading('mtl',true,'Loading MTL activity…','Applying filters and preparing rows');
  try{
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/rows?${messageTraceParams()}`);
    if(request!==messageTraceRequest)return;
    messageTraceState.currentRows=data.rows;messageTraceState.currentTotal=data.total;messageTraceState.currentTagged=Number(data.metrics.tagged||0);renderMessageTraceTagActions();
    $('#messageTraceMetrics').innerHTML=[['Rows',data.metrics.rows],['Fields',data.metrics.columns],['Senders',data.metrics.senders],['Recipients',data.metrics.recipients],['IP indicators',data.metrics.ips]].map(([label,count])=>`<div class="metric"><b>${Number(count).toLocaleString()}</b><span>${label}</span></div>`).join('');
    $('#messageTraceRowCount').textContent=`${data.total.toLocaleString()} matching rows`;
    const pages=Math.max(1,Math.ceil(data.total/data.size));$('#messageTracePageInfo').textContent=`Page ${data.page} of ${pages}`;
    $('#messageTracePrev').disabled=data.page<=1;$('#messageTraceNext').disabled=data.page>=pages;
    $('#messageTraceHead').innerHTML='<tr>'+data.selected.map(column=>{
      const timestamp=isTimestampColumn(column),sortable=timestamp||['_Row','MessageTraceHunt.Risk','MessageTraceHunt.Score','MessageTraceHunt.DomainAgeDays'].includes(column),active=messageTraceState.sortField===column,indicator=active?(messageTraceState.sortDirection==='asc'?' ↑':' ↓'):'',sortLabel=timestamp?'chronologically':'by value';
      return `<th data-column="${esc(column)}" class="${sortable?'sortable':''}" ${sortable?`tabindex="0" role="button" title="Click to sort ${sortLabel} · drag to reorder · right-click for options"`:''}>${esc(column)}${indicator}</th>`;
    }).join('')+'</tr>';
    $('#messageTraceBody').innerHTML=data.rows.length?data.rows.map((row,rowIndex)=>`<tr class="${row.__Tagged?'tagged-row':''}">`+data.selected.map(column=>`<td data-row="${rowIndex}" data-column="${esc(column)}" data-value="${esc(row[column])}" title="${esc(row[column])}">${esc(row[column])}</td>`).join('')+'</tr>').join(''):`<tr><td colspan="${Math.max(1,data.selected.length)}">No matching MTL rows</td></tr>`;
    bindMessageTraceInteractions();
    applyFrozenColumns('mtl');
  }catch(error){toast(error.message);}
  finally{if(request===messageTraceRequest)setReviewLoading('mtl',false);}
}
const messageTraceFile=$('#messageTraceFile'),messageTraceDropzone=$('#messageTraceDropzone');
messageTraceFile.onchange=()=>$('#messageTraceFileName').textContent=messageTraceFile.files[0]?.name||'No file selected';
['dragenter','dragover'].forEach(name=>messageTraceDropzone.addEventListener(name,event=>{event.preventDefault();messageTraceDropzone.classList.add('drag');}));
['dragleave','drop'].forEach(name=>messageTraceDropzone.addEventListener(name,event=>{event.preventDefault();messageTraceDropzone.classList.remove('drag');}));
messageTraceDropzone.addEventListener('drop',event=>{messageTraceFile.files=event.dataTransfer.files;messageTraceFile.onchange();});
$('#messageTraceForm').onsubmit=async event=>{
  event.preventDefault();const status=$('#messageTraceUploadStatus'),button=$('#messageTraceUploadButton');status.className='status';status.textContent='Uploading and parsing Message Trace…';button.disabled=true;
  try{const created=await api(`/api/cases/${state.caseId}/message-traces`,{method:'POST',body:new FormData(event.target)});status.textContent='Message Trace ready.';event.target.reset();$('#messageTraceFileName').textContent='No file selected';await loadMessageTraceOverview(created.meta.id);toast('Message Trace CSV added');}
  catch(error){status.className='status error';status.textContent=error.message;}
  finally{button.disabled=false;}
};
$('#messageTraceReplace').onclick=()=>{$('#messageTraceReview').classList.add('hidden');$('#messageTraceUpload').classList.remove('hidden');$('#messageTraceActions').classList.add('hidden');messageTraceFile.value='';$('#messageTraceFileName').textContent='No file selected';$('#messageTraceName').value='';};
$('#messageTraceCancelUpload').onclick=()=>{$('#messageTraceUpload').classList.add('hidden');$('#messageTraceReview').classList.remove('hidden');$('#messageTraceActions').classList.toggle('hidden',!mtlToolIsActive());};
$('#messageTraceSelector').onchange=event=>selectMessageTrace(event.target.value).catch(error=>toast(error.message));
$('#messageTraceDelete').onclick=async()=>{
  const current=messageTraceState.traces.find(trace=>trace.id===messageTraceState.traceId);if(!current)return;
  if(!confirm(`Delete Message Trace “${current.name||current.sourceFile}”?\n\nIt will be moved to recoverable local case trash.`))return;
  try{await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(current.id)}`,{method:'DELETE'});delete messageTraceState.views[current.id];messageTraceState.traceId=null;await loadMessageTraceOverview();toast('Message Trace deleted');}catch(error){toast(error.message);}
};
$('#messageTraceRun').onclick=()=>{messageTraceState.query=$('#messageTraceQuery').value.trim();messageTraceState.page=1;loadMessageTraceRows();};
$('#messageTraceQuery').onkeydown=event=>{if(event.key==='Enter')$('#messageTraceRun').click();};
$('#messageTraceClear').onclick=()=>{$('#messageTraceQuery').value='';messageTraceState.query='';messageTraceState.page=1;loadMessageTraceRows();};
$('#messageTraceTaggedAction').onclick=()=>{
  const count=Number(messageTraceState.overview?.summary?.tagged||0),clearing=messageTraceState.query==='Review.Tag:="Of interest"';
  if(!count&&!clearing)return toast('No MTL rows are tagged yet');
  messageTraceState.query=clearing?'':'Review.Tag:="Of interest"';$('#messageTraceQuery').value=messageTraceState.query;messageTraceState.page=1;
  messageTraceState.columns=clearing?messageTraceDefaultColumns(messageTraceState.overview.columns,messageTraceState.overview.enrichmentColumns||[]):addMessageTraceTagColumn(messageTraceDefaultColumns(messageTraceState.overview.columns,messageTraceState.overview.enrichmentColumns||[]),messageTraceState.overview.columns);
  saveMessageTraceView();renderMessageTraceTagActions();loadMessageTraceRows();
};
$('#messageTraceTagFilteredAction').onclick=async()=>{
  if(!messageTraceState.query.trim())return toast('Apply an MTL query before tagging rows');
  const button=$('#messageTraceTagFilteredAction'),tagged=!(messageTraceState.currentTotal>0&&messageTraceState.currentTagged===messageTraceState.currentTotal);button.disabled=true;
  button.textContent=`${tagged?'Tagging':'Untagging'} ${messageTraceState.currentTotal.toLocaleString()} rows…`;
  try{
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/bulk-row-tag`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q:messageTraceState.query,tagged})});
    const hadColumn=messageTraceState.overview.columns.includes('Review.Tag');
    if(data.taggedCount&&!hadColumn)messageTraceState.overview.columns.push('Review.Tag');
    if(!data.taggedCount&&hadColumn){messageTraceState.overview.columns=messageTraceState.overview.columns.filter(column=>column!=='Review.Tag');messageTraceState.columns=messageTraceState.columns.filter(column=>column!=='Review.Tag');}
    messageTraceState.overview.summary.tagged=data.taggedCount;messageTraceState.overview.summary.columns=messageTraceState.overview.columns.length;
    await loadMessageTraceRows();toast(tagged?`${data.changed.toLocaleString()} MTL row${data.changed===1?'':'s'} newly tagged`:`Tag removed from ${data.changed.toLocaleString()} MTL row${data.changed===1?'':'s'}`);
  }catch(error){toast(error.message);}finally{renderMessageTraceTagActions();}
};
$('#messageTracePageSize').onchange=event=>{messageTraceState.size=Number(event.target.value);messageTraceState.page=1;loadMessageTraceRows();};
$('#messageTracePrev').onclick=()=>{if(messageTraceState.page>1){messageTraceState.page--;loadMessageTraceRows();}};
$('#messageTraceNext').onclick=()=>{messageTraceState.page++;loadMessageTraceRows();};
function setIpApiMode(scope){
  const mtl=scope==='mtl',mode=$(mtl?'#messageTraceIpApiMode':'#ipApiMode').value,commercial=mode==='commercial';
  $(mtl?'#messageTraceIpApiKeyField':'#ipApiKeyField').classList.toggle('hidden',!commercial);
  $(mtl?'#messageTraceFreeIpApiNotice':'#freeIpApiNotice').classList.toggle('hidden',commercial);
  $(mtl?'#messageTraceCommercialIpApiNotice':'#commercialIpApiNotice').classList.toggle('hidden',!commercial);
  $(mtl?'#messageTraceEnrichButton':'#enrichBtn').textContent=commercial?'Enrich filtered rows with Pro API':'Accept terms & enrich filtered rows';
}
$('#ipApiMode').onchange=()=>setIpApiMode('ual');
$('#messageTraceIpApiMode').onchange=()=>setIpApiMode('mtl');
setIpApiMode('ual');setIpApiMode('mtl');
$('#messageTraceEnrich').onclick=()=>{$$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));$('#messageTraceIpApiKey').value='';resetEnrichmentStatus('mtl');setIpApiMode('mtl');$('#messageTraceEnrichDrawer').classList.remove('hidden');};
$('#closeMessageTraceEnrich').onclick=()=>{$('#messageTraceIpApiKey').value='';$('#messageTraceEnrichDrawer').classList.add('hidden');resetEnrichmentStatus('mtl');};
$('#messageTraceEnrichButton').onclick=async()=>{
  const status=$('#messageTraceEnrichStatus'),button=$('#messageTraceEnrichButton');status.className='status';status.textContent='Calling IP-API and adding enrichment columns…';button.disabled=true;startEnrichmentProgress('mtl');
  try{
    const commercial=$('#messageTraceIpApiMode').value==='commercial',apiKey=commercial?$('#messageTraceIpApiKey').value.trim():'';
    if(commercial&&!apiKey)throw new Error('Enter a commercial IP-API key');
    const params=new URLSearchParams({q:messageTraceState.query});
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/enrich?${params}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({column:$('#messageTraceIpColumn').value,acceptNonCommercialTerms:!commercial,apiKey})});
    messageTraceState.overview.columns=data.columns;messageTraceState.overview.enrichmentColumns=data.enrichedColumns;
    messageTraceState.columns=messageTraceDefaultColumns(data.columns,data.enrichedColumns);await loadMessageTraceRows();status.textContent='';$('#messageTraceEnrichDrawer').classList.add('hidden');toast(`${data.found.toLocaleString()} Message Trace IP${data.found===1?'':'s'} processed`);
  }catch(error){status.className='status error';status.textContent=error.message;}
  finally{stopEnrichmentProgress('mtl');$('#messageTraceIpApiKey').value='';button.disabled=false;}
};
function messageTraceDomain(value){return String(value||'').match(/@([a-z0-9.-]+\.[a-z]{2,63})/i)?.[1]?.replace(/\.+$/,'').toLowerCase()||'';}
function messageTraceCellFromElement(cell){
  const row=messageTraceState.currentRows[Number(cell.dataset.row)]||{};
  return {scope:'mtl',column:cell.dataset.column,value:row[cell.dataset.column],rowNumber:row.__RowId||Number(cell.dataset.row)+1,tagged:Boolean(row.__Tagged)};
}
function bindMessageTraceInteractions(){
  $$('#messageTraceHead th').forEach(header=>{
    const sortable=header.classList.contains('sortable');
    const sort=()=>{const column=header.dataset.column;messageTraceState.sortDirection=messageTraceState.sortField===column&&messageTraceState.sortDirection==='asc'?'desc':'asc';messageTraceState.sortField=column;messageTraceState.page=1;loadMessageTraceRows();};
    if(sortable){header.onclick=sort;header.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();sort();}};}
    header.draggable=true;
    header.addEventListener('dragstart',event=>{draggedColumn=header.dataset.column;contextScope='mtl';header.classList.add('dragging');event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('text/plain',draggedColumn);});
    header.addEventListener('dragend',()=>{draggedColumn=null;$$('#messageTraceHead th').forEach(item=>item.classList.remove('dragging','drag-target'));});
    header.addEventListener('dragover',event=>{event.preventDefault();$$('#messageTraceHead th').forEach(item=>item.classList.remove('drag-target'));header.classList.add('drag-target');});
    header.addEventListener('drop',event=>{event.preventDefault();const target=header.dataset.column;if(!draggedColumn||draggedColumn===target)return;const from=messageTraceState.columns.indexOf(draggedColumn);let to=messageTraceState.columns.indexOf(target);const [moved]=messageTraceState.columns.splice(from,1);if(from<to)to-=1;messageTraceState.columns.splice(to,0,moved);refreshColumns('mtl');});
    header.addEventListener('contextmenu',event=>{event.preventDefault();hideValueMenu();contextScope='mtl';contextColumn=header.dataset.column;$('#contextColumnName').textContent=contextColumn;updateFreezeMenu();const menu=$('#columnMenu');menu.classList.remove('hidden');menu.style.left=`${Math.max(8,Math.min(event.clientX,window.innerWidth-menu.offsetWidth-8))}px`;menu.style.top=`${Math.max(8,Math.min(event.clientY,window.innerHeight-menu.offsetHeight-8))}px`;});
  });
  $$('#messageTraceBody td[data-column]').forEach(cell=>{
    cell.addEventListener('click',()=>openValueDetails(messageTraceCellFromElement(cell)));
    cell.addEventListener('contextmenu',event=>{
      event.preventDefault();hideColumnMenu();contextCell=messageTraceCellFromElement(cell);contextScope='mtl';
      $('#contextValueName').textContent=`${contextCell.column}: ${String(contextCell.value??'').slice(0,80)}`;
      $('#valueMenu button[data-action="tag"]').textContent=contextCell.tagged?'★ Remove interest tag':'★ Mark row of interest';
      $$('#valueMenu .timestamp-filter').forEach(button=>button.classList.toggle('hidden',!isTimestampCell(contextCell)));
      const domain=['SenderAddress','RecipientAddress'].includes(contextCell.column)?messageTraceDomain(contextCell.value):'',link=$('#contextDomainToolsLink');link.classList.toggle('hidden',!domain);if(domain)link.href=`https://whois.domaintools.com/${encodeURIComponent(domain)}`;
      const menu=$('#valueMenu');menu.classList.remove('hidden');menu.style.left=`${Math.max(8,Math.min(event.clientX,window.innerWidth-menu.offsetWidth-8))}px`;menu.style.top=`${Math.max(8,Math.min(event.clientY,window.innerHeight-menu.offsetHeight-8))}px`;
    });
  });
}
$('#messageTraceWhois').onclick=()=>{$$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));resetEnrichmentStatus('domain');$('#messageTraceWhoisDrawer').classList.remove('hidden');};
$('#closeMessageTraceWhois').onclick=()=>{$('#messageTraceWhoisDrawer').classList.add('hidden');resetEnrichmentStatus('domain');};
$('#messageTraceWhoisButton').onclick=async()=>{
  const status=$('#messageTraceWhoisStatus'),button=$('#messageTraceWhoisButton');status.className='status';status.textContent='Looking up domains from filtered Message Trace rows…';button.disabled=true;startEnrichmentProgress('domain','Domain enrichment','Contacting RDAP services…');
  try{
    const params=new URLSearchParams({q:messageTraceState.query});
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/enrich-domains?${params}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({column:$('#messageTraceWhoisColumn').value})});
    messageTraceState.overview.columns=data.columns;messageTraceState.overview.domainEnrichmentColumns=data.enrichedColumns;
    messageTraceState.columns=messageTraceDefaultColumns(data.columns,messageTraceState.overview.enrichmentColumns||[]);saveMessageTraceView();
    await loadMessageTraceRows();status.textContent='';$('#messageTraceWhoisDrawer').classList.add('hidden');toast(`${data.found.toLocaleString()} email domain${data.found===1?'':'s'} processed`);
  }catch(error){status.className='status error';status.textContent=error.message;}
  finally{stopEnrichmentProgress('domain');button.disabled=false;}
};
function updateMessageTraceHuntControls(){
  const enabled=$('#messageTraceUseDomainAge').checked;
  ['#messageTraceMaxDomainAge','#messageTraceRegisteredAfter','#messageTraceRegisteredBefore'].forEach(selector=>$(selector).disabled=!enabled);
}
$('#messageTraceUseDomainAge').onchange=updateMessageTraceHuntControls;
$('#messageTraceHunt').onclick=()=>{
  $$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));
  if(!messageTraceState.overview?.domainEnrichmentColumns?.length){
    $('#messageTraceWhoisStatus').className='status';
    $('#messageTraceWhoisStatus').textContent='Domain enrichment is required before running the Suspicious Mail hunt.';
    $('#messageTraceWhoisDrawer').classList.remove('hidden');
    toast('Enrich sender or recipient domains before hunting suspicious mail');
    return;
  }
  $('#messageTraceHuntStatus').textContent='';$('#messageTraceHuntDrawer').classList.remove('hidden');updateMessageTraceHuntControls();
};
$('#messageTraceEvent').onclick=async()=>{
  const button=$('#messageTraceEvent'),original=button.textContent;button.disabled=true;button.textContent='Generating…';
  try{
    const params=new URLSearchParams({q:messageTraceState.query});
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/generate-events?${params}`,{method:'POST'});
    messageTraceState.overview.columns=data.columns;
    messageTraceState.columns=addContextColumns(messageTraceState.columns,['Event'],data.columns);
    saveMessageTraceView();await loadMessageTraceRows();
    toast(`MTL Event narratives generated for ${data.rowCount.toLocaleString()} filtered row${data.rowCount===1?'':'s'}`);
  }catch(error){toast(error.message);}
  finally{button.disabled=false;button.textContent=original;}
};
$('#closeMessageTraceHunt').onclick=()=>$('#messageTraceHuntDrawer').classList.add('hidden');
$('#messageTraceHuntButton').onclick=async()=>{
  const status=$('#messageTraceHuntStatus'),button=$('#messageTraceHuntButton');status.className='status';status.textContent='Hunting suspicious Message Trace rows…';button.disabled=true;
  const keywords=$('#messageTraceSubjectKeywords').value.split(/[\n,]+/).map(value=>value.trim()).filter(Boolean);
  const serviceDomains=$('#messageTraceServiceDomains').value.split(/[\n,]+/).map(value=>value.trim()).filter(Boolean);
  try{
    const params=new URLSearchParams({q:messageTraceState.query});
    const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/hunt-suspicious-mail?${params}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({useDomainAge:$('#messageTraceUseDomainAge').checked,maxAgeDays:Number($('#messageTraceMaxDomainAge').value||365),registeredAfter:$('#messageTraceRegisteredAfter').value,registeredBefore:$('#messageTraceRegisteredBefore').value,keywords,useServiceDomains:$('#messageTraceUseServiceDomains').checked,serviceDomains})});
    messageTraceState.overview.columns=data.columns;messageTraceState.page=1;
    if(data.findingCount){
      messageTraceState.query='MessageTraceHunt.Flag:=True';$('#messageTraceQuery').value=messageTraceState.query;
      messageTraceState.columns=addMessageTraceHuntColumns(messageTraceDefaultColumns(data.columns,messageTraceState.overview.enrichmentColumns||[]),data.columns);
    }else{
      messageTraceState.columns=messageTraceState.columns.filter(column=>data.columns.includes(column));
      if(messageTraceState.query==='MessageTraceHunt.Flag:=True'){messageTraceState.query='';$('#messageTraceQuery').value='';}
    }
    saveMessageTraceView();$('#messageTraceHuntDrawer').classList.add('hidden');await loadMessageTraceRows();
    toast(data.findingCount?`${data.findingCount.toLocaleString()} suspicious mail candidate${data.findingCount===1?'':'s'} found`:'No suspicious mail candidates found');
  }catch(error){status.className='status error';status.textContent=error.message;toast(error.message);}
  finally{button.disabled=false;}
};

async function openCase(id) {
  state.caseId=id;state.caseMeta=null;state.ualId=null;state.ualDatasets=[];state.ualViews={};state.overview=null;state.page=1;state.query='';state.operation='';state.category='';state.sortField='';state.sortDirection='asc';state.size=50;state.currentTotal=0;state.currentTagged=0;
  messageTraceState.overview=null;messageTraceState.traces=[];messageTraceState.traceId=null;messageTraceState.frozenColumns=[];messageTraceState.views={};
  const info=await api(`/api/cases/${id}/info`);state.caseMeta=info.meta;
  $('#pageSize').value='50'; document.body.classList.add('workspace-active'); window.scrollTo(0,0); $('#home').classList.add('hidden'); $('#workspace').classList.remove('hidden');
  $('#activeName').textContent=info.meta.name;$('#activeFile').textContent='Loading UAL datasets…';
  switchWorkspaceTool('review');
  await loadUalOverview();
}
function renderOverview() {
  const summary=state.overview.summary;
  renderMetrics(summary);
  renderTaggedAction();
  renderFacetControls();
  const ipColumns=state.overview.columns.filter(c=>/ip|address/i.test(c) && !c.includes('_IPAPI_'));
  $('#ipColumn').innerHTML='<option value="">Auto-detect known IP fields</option>'+ipColumns.map(c=>`<option>${esc(c)}</option>`).join('');
}
function renderMetrics(summary){
  $('#metrics').innerHTML=[['Rows',summary.rows],['Fields',summary.columns],['Users',summary.users],['IP indicators',summary.ips],['Message IDs',summary.messageIds]].map(([label,value])=>`<div class="metric"><b>${Number(value).toLocaleString()}</b><span>${label}</span></div>`).join('');
}
function renderTaggedAction(){
  const count=Number(state.overview?.summary?.tagged||0);
  const hasFilter=Boolean(state.query.trim()||state.category||state.operation);
  const allFilteredTagged=hasFilter&&state.currentTotal>0&&state.currentTagged===state.currentTotal;
  $('#taggedCount').textContent=count.toLocaleString();
  $('#taggedAction').classList.toggle('has-tags',count>0);
  $('#taggedAction').classList.toggle('active',state.query==='Review.Tag:="Of interest"');
  $('#tagFilteredAction').disabled=!hasFilter||state.currentTotal===0;
  $('#tagFilteredAction').textContent=allFilteredTagged?'☆ Untag filtered rows':'★ Tag filtered rows';
  $('#tagFilteredAction').classList.toggle('untag-mode',allFilteredTagged);
  $('#tagFilteredAction').title=!hasFilter?'Apply a query, category, or operation filter first':state.currentTotal===0?'No matching rows to tag':allFilteredTagged?'Remove the Of interest tag from every matching row':'Mark every matching row as Of interest';
}
function renderFacetControls(facets=null) {
  const summary=state.overview.summary;
  const categoryCounts=facets?.categories||summary.categories||{};
  const allCount=facets?.all??summary.rows;
  const operations=facets?.operations||summary.operations||[];
  const operationTotal=facets?.operationTotal??allCount;
  $('#eventViews').innerHTML=VIEW_DEFS.map(([key,label])=>`<button class="view-chip ${state.category===key?'active':''}" data-view="${key}">${label} <b>${key?(categoryCounts[key]||0):allCount}</b></button>`).join('');
  $$('.view-chip').forEach(button=>button.onclick=()=>{
    state.category=button.dataset.view; state.operation=''; state.page=1;
    state.columns=restoreColumnPreferences(state.overview); renderFacetControls(facets); renderPicker(); loadRows();
  });
  $('#ops').innerHTML=`<button class="chip ${state.operation===''?'active':''}" data-op="">All operations <b>${operationTotal}</b></button>`+operations.map(x=>`<button class="chip ${state.operation===x.name?'active':''}" data-op="${esc(x.name)}">${esc(x.name)} <b>${x.count}</b></button>`).join('');
  $$('.chip').forEach(button=>button.onclick=()=>{
    state.operation=button.dataset.op; state.page=1;
    $$('.chip').forEach(item=>item.classList.toggle('active',item===button));
    loadRows();
  });
}
let rowsRequestSequence=0;
async function loadRows() {
  const requestSequence=++rowsRequestSequence;
  setReviewLoading('ual',true,'Loading activity…','Applying filters and preparing rows');
  try {
    const data=await api(`/api/cases/${activeUalId()}/rows?${params()}`);
    if(requestSequence!==rowsRequestSequence) return;
    state.currentRows=data.rows;
    state.currentTotal=data.total;
    state.currentTagged=Number(data.metrics.tagged||0);
    renderMetrics(data.metrics);
    renderTaggedAction();
    renderFacetControls(data.facets);
    $('#rowCount').textContent=`${data.total.toLocaleString()} matching rows`;
    const pages=Math.max(1,Math.ceil(data.total/data.size)); $('#pageInfo').textContent=`Page ${data.page} of ${pages}`;
    $('#prev').disabled=data.page<=1; $('#next').disabled=data.page>=pages;
    $('#thead').innerHTML='<tr>'+data.selected.map(c=>{
      const sortable=isTimestampColumn(c)||['_Row','Travel.Risk','Travel.Score'].includes(c);
      const active=state.sortField===c;
      const indicator=active?(state.sortDirection==='asc'?' ↑':' ↓'):'';
      const ariaSort=active?(state.sortDirection==='asc'?'ascending':'descending'):'none';
      const descendingNext=active&&state.sortDirection==='asc';
      const nextOrder=isTimestampColumn(c)?(descendingNext?'newest first':'oldest first'):c==='Travel.Risk'?(descendingNext?'highest risk first':'lowest risk first'):(descendingNext?'highest first':'lowest first');
      const title=sortable?`Click to sort ${nextOrder} · drag to reorder · right-click for options`:'Drag to reorder · right-click for options';
      return `<th draggable="true" data-column="${esc(c)}" ${sortable?'data-sortable="true" tabindex="0" role="button"':''} aria-sort="${ariaSort}" class="${sortable?'sortable':''}" title="${title}">${esc(c)}${indicator}</th>`;
    }).join('')+'</tr>';
    $('#tbody').innerHTML=data.rows.length ? data.rows.map((row,rowIndex)=>`<tr class="${row.__Tagged?'tagged-row':''}">`+data.selected.map(c=>`<td data-row="${rowIndex}" data-column="${esc(c)}" title="Click to show full value · right-click for row actions and filters">${esc(row[c])}</td>`).join('')+'</tr>').join('') : `<tr><td colspan="${data.selected.length}">No matching activity</td></tr>`;
    bindHeaderInteractions(); bindCellInteractions(); applyFrozenColumns('ual');
  } finally {
    if(requestSequence===rowsRequestSequence) {
      setReviewLoading('ual',false);
    }
  }
}
$('#runQuery').onclick=()=>{state.query=$('#query').value.trim();state.page=1;loadRows();};
$('#query').onkeydown=e=>{if(e.key==='Enter') $('#runQuery').click();};
$('#clearQuery').onclick=()=>{$('#query').value='';state.query='';state.page=1;state.columns=restoreColumnPreferences(state.overview);renderPicker();loadRows();};
$('#taggedAction').onclick=()=>{
  const count=Number(state.overview?.summary?.tagged||0);
  const clearing=state.query==='Review.Tag:="Of interest"';
  if(!count&&!clearing) return toast('No rows are tagged yet');
  state.query=clearing?'':'Review.Tag:="Of interest"'; $('#query').value=state.query;
  state.category=''; state.operation=''; state.page=1;
  state.columns=clearing?restoreColumnPreferences(state.overview):addContextColumns(restoreColumnPreferences(state.overview),['Review.Tag'],state.overview.columns);
  renderTaggedAction(); renderFacetControls(); renderPicker(); loadRows();
};
$('#tagFilteredAction').onclick=async()=>{
  if(!(state.query.trim()||state.category||state.operation)) return toast('Apply a filter before tagging rows');
  const button=$('#tagFilteredAction');
  const tagged=!(state.currentTotal>0&&state.currentTagged===state.currentTotal);
  button.disabled=true; button.textContent=`${tagged?'Tagging':'Untagging'} ${state.currentTotal.toLocaleString()} rows…`;
  try {
    const data=await api(`/api/cases/${activeUalId()}/bulk-row-tag`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q:state.query,category:state.category,operation:state.operation,tagged})});
    const hadTagColumn=state.overview.columns.includes('Review.Tag');
    if(data.taggedCount&&!hadTagColumn) state.overview.columns.push('Review.Tag');
    if(!data.taggedCount&&hadTagColumn) {
      state.overview.columns=state.overview.columns.filter(column=>column!=='Review.Tag');
      state.columns=state.columns.filter(column=>column!=='Review.Tag');
    }
    state.overview.summary.tagged=data.taggedCount;
    state.overview.summary.columns=state.overview.columns.length;
    renderTaggedAction(); renderPicker(); await loadRows();
    toast(tagged?`${data.changed.toLocaleString()} row${data.changed===1?'':'s'} newly marked; ${data.matched.toLocaleString()} filtered row${data.matched===1?'':'s'} tagged`:`Tag removed from ${data.changed.toLocaleString()} row${data.changed===1?'':'s'}; ${data.matched.toLocaleString()} filtered row${data.matched===1?'':'s'} reviewed`);
  } catch(error) {toast(error.message);}
  finally {renderTaggedAction();}
};
$('#pageSize').onchange=e=>{state.size=Number(e.target.value);state.page=1;loadRows();};
$('#prev').onclick=()=>{if(state.page>1){state.page--;loadRows();}};
$('#next').onclick=()=>{state.page++;loadRows();};

let draggedColumn=null;
let contextColumn=null;
let contextCell=null;
let contextScope='ual';
const uniqueValueState={scope:'ual',column:'',search:'',offset:0,values:[],request:0,includes:new Set(),excludes:new Set()};
function hideColumnMenu(){ $('#columnMenu').classList.add('hidden'); }
function hideValueMenu(){ $('#valueMenu').classList.add('hidden'); }
function hideMenus(){ hideColumnMenu(); hideValueMenu(); }
function orderColumnsWithFrozen(columns,frozenColumns){
  const frozen=new Set(frozenColumns);
  return [...columns.filter(column=>frozen.has(column)),...columns.filter(column=>!frozen.has(column))];
}
function refreshColumns(scope=contextScope){
  const target=frozenState(scope);
  target.frozenColumns=target.frozenColumns.filter(column=>target.columns.includes(column));
  target.columns=orderColumnsWithFrozen(target.columns,target.frozenColumns);
  if(scope==='mtl'){saveMessageTraceView();loadMessageTraceRows();}else{saveColumnPreferences();renderPicker();loadRows();}
}
function frozenState(scope){return scope==='mtl'?messageTraceState:state;}
function updateFreezeMenu(scope=contextScope,column=contextColumn){
  const button=$('#columnMenu button[data-action="freeze"]'),frozen=frozenState(scope).frozenColumns.includes(column);
  button.textContent=frozen?'Unfreeze column':'Freeze column';
}
function applyFrozenColumns(scope='ual'){
  requestAnimationFrame(()=>{
    const head=scope==='mtl'?$('#messageTraceHead'):$('#thead'),body=scope==='mtl'?$('#messageTraceBody'):$('#tbody');
    if(!head||!body)return;
    const frozen=new Set(frozenState(scope).frozenColumns),headers=[...head.querySelectorAll('th[data-column]')],rows=[...body.querySelectorAll('tr')];
    let left=0,lastFrozen=null;
    headers.forEach((header,index)=>{
      const cells=[header,...rows.map(row=>row.children[index]).filter(Boolean)];
      cells.forEach(cell=>{cell.classList.remove('frozen-column','frozen-column-last');cell.style.removeProperty('--frozen-left');});
      if(!frozen.has(header.dataset.column))return;
      cells.forEach(cell=>{cell.classList.add('frozen-column');cell.style.setProperty('--frozen-left',`${left}px`);});
      left+=header.getBoundingClientRect().width;lastFrozen=cells;
    });
    lastFrozen?.forEach(cell=>cell.classList.add('frozen-column-last'));
  });
}
function toggleColumnSort(column){
  state.sortDirection=state.sortField===column&&state.sortDirection==='asc'?'desc':'asc';
  state.sortField=column; state.page=1; loadRows();
}
function bindHeaderInteractions() {
  $$('#thead th').forEach(header=>{
    if(header.dataset.sortable==='true') {
      header.addEventListener('click',()=>toggleColumnSort(header.dataset.column));
      header.addEventListener('keydown',event=>{
        if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleColumnSort(header.dataset.column);}
      });
    }
    header.addEventListener('dragstart',event=>{
      draggedColumn=header.dataset.column; contextScope='ual'; header.classList.add('dragging');
      event.dataTransfer.effectAllowed='move'; event.dataTransfer.setData('text/plain',draggedColumn);
    });
    header.addEventListener('dragend',()=>{
      draggedColumn=null; $$('#thead th').forEach(item=>item.classList.remove('dragging','drag-target'));
    });
    header.addEventListener('dragover',event=>{
      event.preventDefault(); $$('#thead th').forEach(item=>item.classList.remove('drag-target')); header.classList.add('drag-target');
    });
    header.addEventListener('drop',event=>{
      event.preventDefault(); const target=header.dataset.column;
      if(!draggedColumn || draggedColumn===target) return;
      const from=state.columns.indexOf(draggedColumn); let to=state.columns.indexOf(target);
      const [moved]=state.columns.splice(from,1); if(from<to) to-=1; state.columns.splice(to,0,moved);
      refreshColumns();
    });
    header.addEventListener('contextmenu',event=>{
      event.preventDefault(); hideValueMenu(); contextScope='ual'; contextColumn=header.dataset.column; $('#contextColumnName').textContent=contextColumn;
      updateFreezeMenu();
      const menu=$('#columnMenu'); menu.classList.remove('hidden');
      menu.style.left=`${Math.min(event.clientX,window.innerWidth-menu.offsetWidth-8)}px`;
      menu.style.top=`${Math.min(event.clientY,window.innerHeight-menu.offsetHeight-8)}px`;
    });
  });
}
function cellFromElement(cell){
  const row=state.currentRows[Number(cell.dataset.row)]||{};
  return {scope:'ual',column:cell.dataset.column,value:row[cell.dataset.column],rowNumber:row.__RowId||row._Row||Number(cell.dataset.row)+1,tagged:Boolean(row.__Tagged)};
}
function prettyValue(value){
  if(typeof value!=='string') return JSON.stringify(value??'',null,2);
  try { const parsed=JSON.parse(value); return JSON.stringify(parsed,null,2); } catch { return value; }
}
function openValueDetails(cell){
  closeUniqueValues(); $$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));
  contextCell=cell;contextScope=cell.scope||'ual'; $('#valueDrawerColumn').textContent=cell.column; $('#valueDrawerRow').textContent=`Source row ${cell.rowNumber}`;
  $('#tagRowValue').textContent=cell.tagged?'★ Remove interest tag':'★ Mark row of interest';
  $('#tagRowValue').classList.toggle('active-tag',cell.tagged);
  $$('#valueDrawer .timestamp-value-action').forEach(button=>button.classList.toggle('hidden',!isTimestampCell(cell)));
  $('#valueDrawerContent').textContent=prettyValue(cell.value); $('#valueDrawer').classList.remove('hidden'); hideValueMenu();
}
async function toggleRowTag(cell){
  if(cell.scope==='mtl'){
    try{
      const data=await api(`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/row-tag`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({row:cell.rowNumber,tagged:!cell.tagged})});
      const hadColumn=messageTraceState.overview.columns.includes('Review.Tag');
      if(data.taggedCount&&!hadColumn)messageTraceState.overview.columns.push('Review.Tag');
      if(!data.taggedCount&&hadColumn){messageTraceState.overview.columns=messageTraceState.overview.columns.filter(column=>column!=='Review.Tag');messageTraceState.columns=messageTraceState.columns.filter(column=>column!=='Review.Tag');}
      messageTraceState.overview.summary.tagged=data.taggedCount;messageTraceState.overview.summary.columns=messageTraceState.overview.columns.length;
      $('#valueDrawer').classList.add('hidden');hideMenus();await loadMessageTraceRows();toast(data.tagged?`MTL row ${data.row} marked of interest`:`Interest tag removed from MTL row ${data.row}`);
    }catch(error){toast(error.message);}
    return;
  }
  try {
    const data=await api(`/api/cases/${activeUalId()}/row-tag`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({row:cell.rowNumber,tagged:!cell.tagged})});
    cell.tagged=data.tagged;
    const hadTagColumn=state.overview.columns.includes('Review.Tag');
    if(data.tagged&&!hadTagColumn) state.overview.columns.push('Review.Tag');
    if(!data.tagged&&data.taggedCount===0&&hadTagColumn) {
      state.overview.columns=state.overview.columns.filter(column=>column!=='Review.Tag');
      state.columns=state.columns.filter(column=>column!=='Review.Tag');
    }
    state.overview.summary.tagged=data.taggedCount;
    state.overview.summary.columns=state.overview.columns.length;
    $('#valueDrawer').classList.add('hidden'); hideMenus();
    renderTaggedAction(); renderPicker(); await loadRows();
    toast(data.tagged?`Row ${data.row} marked of interest`:`Interest tag removed from row ${data.row}`);
  } catch(error) {toast(error.message);}
}
function exactFilterToken(cell,exclude=false){
  return `${exclude?'-':''}${cell.column}:=${JSON.stringify(String(cell.value??''))}`;
}
function applyCellFilter(cell,exclude=false){
  const token=exactFilterToken(cell,exclude);
  if(cell.scope==='mtl'){
    const existing=$('#messageTraceQuery').value.trim();$('#messageTraceQuery').value=existing?`${existing} ${token}`:token;messageTraceState.query=$('#messageTraceQuery').value;messageTraceState.page=1;
    $('#valueDrawer').classList.add('hidden');hideMenus();loadMessageTraceRows();return;
  }
  const existing=$('#query').value.trim();$('#query').value=existing?`${existing} ${token}`:token; state.query=$('#query').value; state.page=1;
  $('#valueDrawer').classList.add('hidden');hideMenus();loadRows();
}
function isTimestampCell(cell){
  const value=String(cell.value??'').trim();
  return /(?:time|date|timestamp)/i.test(cell.column)&&/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(value)&&!Number.isNaN(Date.parse(value));
}
function applyComparisonFilter(cell,operator){
  const token=`${cell.column}:${operator}${JSON.stringify(String(cell.value??''))}`;
  if(cell.scope==='mtl'){
    const existing=$('#messageTraceQuery').value.trim();$('#messageTraceQuery').value=existing?`${existing} ${token}`:token;messageTraceState.query=$('#messageTraceQuery').value;messageTraceState.page=1;
    $('#valueDrawer').classList.add('hidden');hideMenus();loadMessageTraceRows();return;
  }
  const existing=$('#query').value.trim();$('#query').value=existing?`${existing} ${token}`:token; state.query=$('#query').value; state.page=1;
  $('#valueDrawer').classList.add('hidden'); hideMenus(); loadRows();
}
function hideUniqueValueTooltip(){document.querySelector('#uniqueValueTooltip')?.classList.add('hidden');}
function showUniqueValueTooltip(button,item){
  let tooltip=$('#uniqueValueTooltip');
  if(!tooltip){tooltip=document.createElement('div');tooltip.id='uniqueValueTooltip';tooltip.className='unique-value-tooltip hidden';tooltip.setAttribute('role','tooltip');document.body.appendChild(tooltip);}
  tooltip.textContent=item.value===''?'(empty)':String(item.value);
  tooltip.classList.remove('hidden');
  const anchor=button.getBoundingClientRect(),bounds=tooltip.getBoundingClientRect(),gap=8;
  const left=Math.max(12,Math.min(anchor.left,window.innerWidth-bounds.width-12));
  let top=anchor.bottom+gap;
  if(top+bounds.height>window.innerHeight-12)top=Math.max(12,anchor.top-bounds.height-gap);
  tooltip.style.left=`${left}px`;tooltip.style.top=`${top}px`;
}
function closeUniqueValues(){uniqueValueState.request+=1;hideUniqueValueTooltip();$('#uniqueValuesDrawer').classList.add('hidden');}
function updateUniqueSelectionControls(){
  const includeCount=uniqueValueState.includes.size, excludeCount=uniqueValueState.excludes.size, total=includeCount+excludeCount;
  $('#uniqueSelectionSummary').textContent=total?`${includeCount} included · ${excludeCount} excluded`:'No values selected';
  $('#applyUniqueSelection').disabled=!total;
  $('#applyUniqueSelection').textContent=total?`Apply selected (${total})`:'Apply selected';
  $$('#uniqueValuesList [data-unique-index]').forEach(button=>{
    const item=uniqueValueState.values[Number(button.dataset.uniqueIndex)];
    if(!item) return;
    const selected=button.dataset.uniqueMode==='exclude'?uniqueValueState.excludes.has(item.value):uniqueValueState.includes.has(item.value);
    button.classList.toggle('selected',selected);
    button.closest('.unique-value-item')?.classList.toggle('has-selection',uniqueValueState.includes.has(item.value)||uniqueValueState.excludes.has(item.value));
  });
}
function toggleUniqueSelection(item,mode){
  const selected=mode==='exclude'?uniqueValueState.excludes:uniqueValueState.includes;
  const opposite=mode==='exclude'?uniqueValueState.includes:uniqueValueState.excludes;
  if(selected.has(item.value)) selected.delete(item.value);
  else {opposite.delete(item.value);selected.add(item.value);}
  updateUniqueSelectionControls();
}
function renderUniqueValues(data,append=false){
  hideUniqueValueTooltip();
  uniqueValueState.values=append?[...uniqueValueState.values,...data.values]:data.values;
  const shown=uniqueValueState.values.length;
  $('#uniqueValuesSummary').textContent=`${data.totalUnique.toLocaleString()} unique value${data.totalUnique===1?'':'s'} in ${data.matchingRows.toLocaleString()} matching row${data.matchingRows===1?'':'s'} · showing ${shown.toLocaleString()} of ${data.matchingUnique.toLocaleString()}${data.matchingUnique!==data.totalUnique?' search matches':''}`;
  $('#uniqueValuesList').innerHTML=uniqueValueState.values.length?uniqueValueState.values.map((item,index)=>`<div class="unique-value-item"><button class="unique-value-label ${item.value===''?'empty':''}" data-unique-index="${index}" data-unique-mode="include" aria-label="Include value: ${esc(item.label)}">${esc(item.label)}</button><span>${item.count.toLocaleString()}</span><button data-unique-index="${index}" data-unique-mode="include" title="Include">+</button><button data-unique-index="${index}" data-unique-mode="exclude" title="Exclude">−</button></div>`).join(''):'<p class="status">No values match this search.</p>';
  $('#loadMoreUniqueValues').classList.toggle('hidden',!data.hasMore);
  $$('#uniqueValuesList button[data-unique-index]').forEach(button=>button.onclick=()=>{
    const item=uniqueValueState.values[Number(button.dataset.uniqueIndex)];
    toggleUniqueSelection(item,button.dataset.uniqueMode);
  });
  $$('#uniqueValuesList .unique-value-label').forEach(button=>{
    const show=()=>showUniqueValueTooltip(button,uniqueValueState.values[Number(button.dataset.uniqueIndex)]);
    button.addEventListener('mouseenter',show);button.addEventListener('mouseleave',hideUniqueValueTooltip);
    button.addEventListener('focus',show);button.addEventListener('blur',hideUniqueValueTooltip);
  });
  $('#uniqueValuesList').onscroll=hideUniqueValueTooltip;
  updateUniqueSelectionControls();
}
async function loadUniqueValues(reset=true){
  const request=++uniqueValueState.request;
  if(reset){uniqueValueState.offset=0;uniqueValueState.values=[];$('#uniqueValuesList').innerHTML='<p class="status">Loading values…</p>';}
  const mtl=uniqueValueState.scope==='mtl',p=new URLSearchParams({column:uniqueValueState.column,q:mtl?messageTraceState.query:state.query,search:uniqueValueState.search,offset:uniqueValueState.offset,limit:200});
  if(!mtl&&state.operation)p.set('operation',state.operation);if(!mtl&&state.category)p.set('category',state.category);
  const url=mtl?`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/column-values?${p}`:`/api/cases/${activeUalId()}/column-values?${p}`;
  try{const data=await api(url);if(request!==uniqueValueState.request)return;renderUniqueValues(data,!reset);}
  catch(error){if(request===uniqueValueState.request)$('#uniqueValuesList').innerHTML=`<p class="status error">${esc(error.message)}</p>`;}
}
function openUniqueValues(column,scope='ual'){
  uniqueValueState.scope=scope;uniqueValueState.column=column;uniqueValueState.search='';uniqueValueState.includes.clear();uniqueValueState.excludes.clear();$('#uniqueValuesColumn').textContent=column;$('#uniqueValuesSearch').value='';
  $$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));$('#uniqueValuesDrawer').classList.remove('hidden');hideColumnMenu();loadUniqueValues(true);$('#uniqueValuesSearch').focus();
  updateUniqueSelectionControls();
}
function bindCellInteractions(){
  $$('#tbody td[data-column]').forEach(cell=>{
    cell.addEventListener('click',()=>openValueDetails(cellFromElement(cell)));
    cell.addEventListener('contextmenu',event=>{
      event.preventDefault(); hideColumnMenu(); contextCell=cellFromElement(cell);contextScope='ual';
      $('#contextValueName').textContent=`${contextCell.column}: ${String(contextCell.value??'').slice(0,80)}`;
      const tagButton=$('#valueMenu button[data-action="tag"]');
      tagButton.textContent=contextCell.tagged?'★ Remove interest tag':'★ Mark row of interest';
      $$('#valueMenu .timestamp-filter').forEach(button=>button.classList.toggle('hidden',!isTimestampCell(contextCell)));
      $('#contextDomainToolsLink').classList.add('hidden');
      const menu=$('#valueMenu'); menu.classList.remove('hidden');
      menu.style.left=`${Math.max(8,Math.min(event.clientX,window.innerWidth-menu.offsetWidth-8))}px`;
      menu.style.top=`${Math.max(8,Math.min(event.clientY,window.innerHeight-menu.offsetHeight-8))}px`;
    });
  });
}
$$('#columnMenu button').forEach(button=>button.onclick=event=>{
  event.stopPropagation(); if(!contextColumn) return;
  const targetState=contextScope==='mtl'?messageTraceState:state,index=targetState.columns.indexOf(contextColumn),action=button.dataset.action;
  if(action==='hide') {
    if(targetState.columns.length===1) return toast('At least one column must remain visible');
    targetState.columns.splice(index,1);
    targetState.frozenColumns=targetState.frozenColumns.filter(column=>column!==contextColumn);
  } else if(action==='freeze') {
    if(targetState.frozenColumns.includes(contextColumn)){
      targetState.frozenColumns=targetState.frozenColumns.filter(column=>column!==contextColumn);
      toast(`${contextColumn} unfrozen`);
    }else{
      targetState.frozenColumns.push(contextColumn);
      targetState.columns=orderColumnsWithFrozen(targetState.columns,targetState.frozenColumns);
      toast(`${contextColumn} frozen on the left`);
    }
  } else if(action==='first' && index>0) {
    targetState.columns.unshift(targetState.columns.splice(index,1)[0]);
  } else if(action==='left' && index>0) {
    [targetState.columns[index-1],targetState.columns[index]]=[targetState.columns[index],targetState.columns[index-1]];
  } else if(action==='right' && index<targetState.columns.length-1) {
    [targetState.columns[index+1],targetState.columns[index]]=[targetState.columns[index],targetState.columns[index+1]];
  } else if(action==='values') {
    return openUniqueValues(contextColumn,contextScope);
  } else if(action==='copy') {
    navigator.clipboard.writeText(contextColumn).then(()=>toast('Column name copied'));
    return hideColumnMenu();
  }
  hideColumnMenu(); refreshColumns(contextScope);
});
$$('#valueMenu button').forEach(button=>button.onclick=event=>{
  event.stopPropagation(); if(!contextCell) return;
  const action=button.dataset.action;
  if(action==='tag') return toggleRowTag(contextCell);
  if(action==='details') openValueDetails(contextCell);
  else if(action==='include') applyCellFilter(contextCell,false);
  else if(action==='exclude') applyCellFilter(contextCell,true);
  else if(action==='after') applyComparisonFilter(contextCell,'>');
  else if(action==='before') applyComparisonFilter(contextCell,'<');
  else if(action==='copy') navigator.clipboard.writeText(String(contextCell.value??'')).then(()=>toast('Value copied'));
  hideValueMenu();
});
$('#closeValueDrawer').onclick=()=>$('#valueDrawer').classList.add('hidden');
$('#closeUniqueValues').onclick=closeUniqueValues;
let uniqueSearchTimer=null;
$('#uniqueValuesSearch').oninput=()=>{clearTimeout(uniqueSearchTimer);uniqueSearchTimer=setTimeout(()=>{uniqueValueState.search=$('#uniqueValuesSearch').value.trim();loadUniqueValues(true);},220);};
$('#loadMoreUniqueValues').onclick=()=>{uniqueValueState.offset=uniqueValueState.values.length;loadUniqueValues(false);};
$('#clearUniqueSelection').onclick=()=>{uniqueValueState.includes.clear();uniqueValueState.excludes.clear();updateUniqueSelectionControls();};
$('#applyUniqueSelection').onclick=()=>{
  const includes=[...uniqueValueState.includes].map(value=>exactFilterToken({column:uniqueValueState.column,value}));
  const excludes=[...uniqueValueState.excludes].map(value=>exactFilterToken({column:uniqueValueState.column,value},true));
  if(!includes.length&&!excludes.length) return;
  const selectedParts=[];
  if(includes.length) selectedParts.push(includes.length===1?includes[0]:`(${includes.join(' OR ')})`);
  selectedParts.push(...excludes);
  const selection=selectedParts.join(' AND ');
  if(uniqueValueState.scope==='mtl'){
    const existing=$('#messageTraceQuery').value.trim();$('#messageTraceQuery').value=existing?`(${existing}) AND (${selection})`:selection;
    messageTraceState.query=$('#messageTraceQuery').value;messageTraceState.page=1;closeUniqueValues();loadMessageTraceRows();return;
  }
  const existing=$('#query').value.trim();$('#query').value=existing?`(${existing}) AND (${selection})`:selection;
  state.query=$('#query').value;state.page=1;closeUniqueValues();loadRows();
};
$('#tagRowValue').onclick=()=>contextCell&&toggleRowTag(contextCell);
$('#includeValue').onclick=()=>contextCell&&applyCellFilter(contextCell,false);
$('#excludeValue').onclick=()=>contextCell&&applyCellFilter(contextCell,true);
$('#afterValue').onclick=()=>contextCell&&applyComparisonFilter(contextCell,'>');
$('#beforeValue').onclick=()=>contextCell&&applyComparisonFilter(contextCell,'<');
$('#copyValue').onclick=()=>contextCell&&navigator.clipboard.writeText(String(contextCell.value??'')).then(()=>toast('Value copied'));
document.addEventListener('click',hideMenus);
document.addEventListener('keydown',event=>{if(event.key==='Escape'){hideMenus();$('#valueDrawer').classList.add('hidden');closeUniqueValues();closeExportModal();}});
window.addEventListener('blur',hideMenus);

let columnPickerScope='ual';
function renderPicker(scope='ual') {
  const target=scope==='mtl'?messageTraceState:state;
  if(!target.overview)return;
  const ordered=[...target.columns,...target.overview.columns.filter(column=>!target.columns.includes(column))];
  $('#columnList').innerHTML=ordered.map(column=>`<label><input type="checkbox" value="${esc(column)}" ${target.columns.includes(column)?'checked':''}> ${esc(column)}</label>`).join('');
}
function openColumnPicker(scope){
  columnPickerScope=scope;closeUniqueValues();$$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));
  const isMtl=scope==='mtl';$('#columnPickerTitle').textContent=isMtl?'Visible MTL columns':'Visible UAL columns';
  $('#columnPickerDescription').textContent=isMtl?'Choose fields for the Message Trace review table.':'Choose fields for the UAL review table.';
  renderPicker(scope);$('#columnPicker').classList.remove('hidden');
}
$('#columnsBtn').onclick=()=>openColumnPicker('ual');
$('#messageTraceColumns').onclick=()=>openColumnPicker('mtl');
$('#closeColumns').onclick=()=>$('#columnPicker').classList.add('hidden');
$('#applyColumns').onclick=()=>{
  const selected=$$('#columnList input:checked').map(input=>input.value).slice(0,50);
  if(!selected.length)return toast('Select at least one column');
  $('#columnPicker').classList.add('hidden');
  if(columnPickerScope==='mtl'){
    messageTraceState.columns=selected;messageTraceState.frozenColumns=messageTraceState.frozenColumns.filter(column=>selected.includes(column));
    saveMessageTraceView();loadMessageTraceRows();return;
  }
  state.columns=selected;state.frozenColumns=state.frozenColumns.filter(column=>selected.includes(column));
  saveColumnPreferences();loadRows();
};
window.addEventListener('resize',()=>{applyFrozenColumns('ual');applyFrozenColumns('mtl');});
let exportScope='ual';
function closeExportModal(){$('#exportModal').classList.add('hidden');}
function safeExportBase(value,fallback){return String(value||fallback).replace(/[^A-Za-z0-9._ -]+/g,'_').replace(/[ ._]+$/,'').slice(0,100)||fallback;}
function openExportModal(scope){
  exportScope=scope;
  const isMtl=scope==='mtl';
  const base=isMtl?safeExportBase(messageTraceState.overview?.meta?.name,'message-trace'):safeExportBase(state.overview?.meta?.name,'ual-export');
  $('#exportFilename').value=`${base}-${isMtl?'mtl':'ual'}-export`;
  $('#exportDescription').textContent=isMtl?'Name the CSV containing all rows matching the current MTL query.':'Name the CSV containing the current UAL query and category results.';
  $('#exportModal').classList.remove('hidden');
  requestAnimationFrame(()=>{$('#exportFilename').focus();$('#exportFilename').select();});
}
$('#exportBtn').onclick=()=>openExportModal('ual');
$('#messageTraceExport').onclick=()=>openExportModal('mtl');
$('#cancelExport').onclick=closeExportModal;
$('#exportModal').onclick=event=>{if(event.target===$('#exportModal'))closeExportModal();};
$('#exportForm').onsubmit=event=>{
  event.preventDefault();
  const filename=$('#exportFilename').value.trim();
  if(!filename)return;
  const isMtl=exportScope==='mtl';
  const p=new URLSearchParams({q:isMtl?messageTraceState.query:state.query,filename});
  if(!isMtl&&state.operation)p.set('operation',state.operation);
  if(!isMtl&&state.category)p.set('category',state.category);
  closeExportModal();
  location.href=isMtl?`/api/cases/${state.caseId}/message-traces/${encodeURIComponent(messageTraceState.traceId)}/export?${p}`:`/api/cases/${activeUalId()}/export?${p}`;
};

function openLoginHuntDrawer(drawer,status,message){
  $$('.drawer').forEach(item=>item.classList.add('hidden'));
  if(!state.overview?.enrichmentColumns?.length){
    $('#enrichStatus').className='status error';$('#enrichStatus').textContent=message;$('#enrichDrawer').classList.remove('hidden');toast(message);return false;
  }
  $(status).className='status';$(status).textContent='';$(drawer).classList.remove('hidden');return true;
}
function updateSuspiciousLoginControls(){
  $('#loginTrustedCountries').disabled=!$('#loginUseCountry').checked;
  const infrastructure=$('#loginUseProxy').checked||$('#loginUseHosting').checked;
  $('#loginRequireDeviceRisk').disabled=!infrastructure;
  $('#loginMissingDeviceRisky').disabled=!infrastructure||!$('#loginRequireDeviceRisk').checked;
}
['#loginUseCountry','#loginUseProxy','#loginUseHosting','#loginRequireDeviceRisk'].forEach(selector=>$(selector).onchange=updateSuspiciousLoginControls);
$('#suspiciousLoginAction').onclick=()=>{if(openLoginHuntDrawer('#suspiciousLoginDrawer','#suspiciousLoginHuntStatus','Run IP enrichment before hunting suspicious logins.'))updateSuspiciousLoginControls();};
$('#closeSuspiciousLoginHunt').onclick=()=>$('#suspiciousLoginDrawer').classList.add('hidden');
$('#suspiciousLoginHuntButton').onclick=async()=>{
  const button=$('#suspiciousLoginHuntButton'),status=$('#suspiciousLoginHuntStatus');button.disabled=true;status.className='status';status.textContent='Hunting login activity…';
  const trustedCountries=$('#loginTrustedCountries').value.split(/[\n,]+/).map(value=>value.trim()).filter(Boolean);
  try {
    const data=await api(`/api/cases/${activeUalId()}/hunt-suspicious-logins`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({useCountry:$('#loginUseCountry').checked,trustedCountries,useProxy:$('#loginUseProxy').checked,useHosting:$('#loginUseHosting').checked,requireDeviceRisk:$('#loginRequireDeviceRisk').checked,missingDeviceRisky:$('#loginMissingDeviceRisky').checked})});
    state.overview.columns=data.columns;state.category='logon';state.operation='';state.page=1;state.query='SuspiciousLogin.Flag:=True';$('#query').value=state.query;
    state.columns=addContextColumns(restoreColumnPreferences(state.overview),SUSPICIOUS_LOGIN_COLUMNS,data.columns);
    $('#suspiciousLoginDrawer').classList.add('hidden');renderOverview();renderPicker();await loadRows();
    toast(data.findingCount?`${data.findingCount} suspicious login${data.findingCount===1?'':'s'} found`:'No suspicious logins found');
  }catch(error){status.className='status error';status.textContent=error.message;toast(error.message);}
  finally{button.disabled=false;}
};
function updateTravelHuntControls(){
  $('#travelCountryHours').disabled=!$('#travelUseCountryChange').checked;
  $('#travelRegionHours').disabled=!$('#travelUseRegionChange').checked;
  const elevated=$('#travelUseElevatedWindow').checked;
  ['#travelElevatedHours','#travelUseHosting','#travelUseProxy','#travelUseDeviceRisk'].forEach(selector=>$(selector).disabled=!elevated);
}
['#travelUseCountryChange','#travelUseRegionChange','#travelUseElevatedWindow'].forEach(selector=>$(selector).onchange=updateTravelHuntControls);
$('#travelAction').onclick=()=>{if(openLoginHuntDrawer('#travelHuntDrawer','#travelHuntStatus','Run IP enrichment before hunting for impossible travel.'))updateTravelHuntControls();};
$('#closeTravelHunt').onclick=()=>$('#travelHuntDrawer').classList.add('hidden');
$('#travelHuntButton').onclick=async()=>{
  const button=$('#travelHuntButton'),status=$('#travelHuntStatus');button.disabled=true;status.className='status';status.textContent='Analyzing login travel…';
  try {
    const data=await api(`/api/cases/${activeUalId()}/hunt-travel`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({useCountryChange:$('#travelUseCountryChange').checked,countryHours:Number($('#travelCountryHours').value||12),useRegionChange:$('#travelUseRegionChange').checked,regionHours:Number($('#travelRegionHours').value||3),useElevatedWindow:$('#travelUseElevatedWindow').checked,elevatedHours:Number($('#travelElevatedHours').value||24),useHosting:$('#travelUseHosting').checked,useProxy:$('#travelUseProxy').checked,useDeviceRisk:$('#travelUseDeviceRisk').checked})});
    state.overview.columns=data.columns;state.category='logon';state.operation='';state.page=1;state.query='Travel.Flag:=True';$('#query').value=state.query;
    state.columns=addContextColumns(restoreColumnPreferences(state.overview),TRAVEL_COLUMNS,data.columns);
    $('#travelHuntDrawer').classList.add('hidden');renderOverview();renderPicker();await loadRows();
    toast(data.findingCount?`${data.findingCount} impossible-travel candidate${data.findingCount===1?'':'s'} found`:'No impossible-travel candidates found');
  }catch(error){status.className='status error';status.textContent=error.message;toast(error.message);}
  finally{button.disabled=false;}
};

$('#messageAction').onclick=async()=>{
  const p=new URLSearchParams({q:state.query}); if(state.operation)p.set('operation',state.operation); if(state.category)p.set('category',state.category);
  const data=await api(`/api/cases/${activeUalId()}/message-ids?${p}`);
  if(!state.columns.includes('InternetMessageIDs')) state.columns.push('InternetMessageIDs');
  saveColumnPreferences(); renderPicker(); await loadRows(); toast(`${data.count} unique Message ID${data.count===1?'':'s'} collected into the table`);
};
function currentUalFilterParams(){
  const params=new URLSearchParams({q:state.query});
  if(state.operation)params.set('operation',state.operation);
  if(state.category)params.set('category',state.category);
  return params;
}
async function runMessageSubjectExtraction(refreshTable=true){
  const data=await api(`/api/cases/${activeUalId()}/extract-message-subjects?${currentUalFilterParams()}`,{method:'POST'});
  state.overview.columns=data.columns;
  state.columns=addContextColumns(state.columns,MESSAGE_SUBJECT_COLUMNS,data.columns);
  saveColumnPreferences();renderPicker();
  if(refreshTable)await loadRows();
  return data;
}
$('#messageSubjectAction').onclick=async()=>{
  const button=$('#messageSubjectAction'), original=button.textContent; button.disabled=true; button.textContent='Extracting…';
  try {
    const data=await runMessageSubjectExtraction();
    toast(`${data.pairCount.toLocaleString()} message/subject association${data.pairCount===1?'':'s'} found in ${data.rowCount.toLocaleString()} row${data.rowCount===1?'':'s'}`);
  } catch(error) {toast(error.message);}
  finally {button.disabled=false;button.textContent=original;}
};
function closeMessageSubjectExportModal(){$('#messageSubjectExportModal').classList.add('hidden');}
function openMessageSubjectExportModal(){
  const base=safeExportBase(state.overview?.meta?.name,'ual-export');
  $('#messageSubjectExportFilename').value=`${base}-message-ids-subjects`;
  $('#messageSubjectExportSize').checked=false;
  $('#messageSubjectExportModal').classList.remove('hidden');
  requestAnimationFrame(()=>{$('#messageSubjectExportFilename').focus();$('#messageSubjectExportFilename').select();});
}
$('#messageSubjectExport').onclick=openMessageSubjectExportModal;
$('#cancelMessageSubjectExport').onclick=closeMessageSubjectExportModal;
$('#messageSubjectExportModal').onclick=event=>{if(event.target===$('#messageSubjectExportModal'))closeMessageSubjectExportModal();};
$('#messageSubjectExportForm').onsubmit=async event=>{
  event.preventDefault();
  const requestedFilename=$('#messageSubjectExportFilename').value.trim();
  if(!requestedFilename)return;
  const includeSize=$('#messageSubjectExportSize').checked;
  closeMessageSubjectExportModal();
  const button=$('#messageSubjectExport'),original=button.textContent;button.disabled=true;button.textContent='Preparing CSV…';
  try{
    const exportUrl=()=>{
      const params=currentUalFilterParams();params.set('filename',requestedFilename);
      if(includeSize)params.set('includeSize','true');
      return `/api/cases/${activeUalId()}/message-subject-export?${params}`;
    };
    let response=await fetch(exportUrl());
    if(!response.ok){
      let message='Run MessageIds + Subjects before exporting';
      try{message=(await response.json()).error||message;}catch{}
      if(!message.includes('Run MessageIds + Subjects'))throw new Error(message);
      button.textContent='Running MessageIds + Subjects…';
      toast('MessageIds + Subjects has not been run. Running it before exporting the current filtered view…');
      await runMessageSubjectExtraction();
      button.textContent='Preparing CSV…';
      response=await fetch(exportUrl());
      if(!response.ok){
        try{message=(await response.json()).error||message;}catch{}
        throw new Error(message);
      }
    }
    const blob=await response.blob(),disposition=response.headers.get('Content-Disposition')||'';
    const downloadedFilename=disposition.match(/filename="([^"]+)"/i)?.[1]||'message-ids-subjects.csv';
    const url=URL.createObjectURL(blob),link=document.createElement('a');
    link.href=url;link.download=downloadedFilename;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    toast(`Downloaded ${downloadedFilename}`);
  }catch(error){toast(error.message);}
  finally{button.disabled=false;button.textContent=original;}
};
$('#appMapAction').onclick=async()=>{
  const button=$('#appMapAction'), original=button.textContent; button.disabled=true; button.textContent='Mapping…';
  try {
    const p=new URLSearchParams({q:state.query}); if(state.operation)p.set('operation',state.operation); if(state.category)p.set('category',state.category);
    const data=await api(`/api/cases/${activeUalId()}/map-app-ids?${p}`,{method:'POST'});
    if(!data.mappings.length) return toast('No application ID values found in the current results');
    state.overview.columns=[...new Set([...state.overview.columns,...data.mappings.map(item=>item.column)])];
    state.columns=addAppMappingColumns(state.columns,data.mappings);
    saveColumnPreferences(); renderPicker(); await loadRows();
    toast(`${data.known.toLocaleString()} recognized App ID${data.known===1?'':'s'}; ${data.unlisted.toLocaleString()} not listed by Microsoft`);
  } catch(error) {toast(error.message);}
  finally {button.disabled=false;button.textContent=original;}
};
$('#eventAction').onclick=async()=>{
  const button=$('#eventAction'), original=button.textContent; button.disabled=true; button.textContent='Generating…';
  try {
    const p=new URLSearchParams({q:state.query});if(state.operation)p.set('operation',state.operation);if(state.category)p.set('category',state.category);
    const data=await api(`/api/cases/${activeUalId()}/generate-events?${p}`,{method:'POST'});
    state.overview.columns=data.columns;
    state.columns=addContextColumns(state.columns,['Event'],data.columns);
    saveColumnPreferences(); renderPicker(); await loadRows();
    toast(`Event narratives generated for ${data.rowCount.toLocaleString()} filtered row${data.rowCount===1?'':'s'}`);
  } catch(error) {toast(error.message);}
  finally {button.disabled=false;button.textContent=original;}
};
$('#enrichAction').onclick=()=>{closeUniqueValues();$$('.drawer').forEach(drawer=>drawer.classList.add('hidden'));$('#ipApiKey').value='';resetEnrichmentStatus('ual');setIpApiMode('ual');$('#enrichDrawer').classList.remove('hidden');};
$('#closeEnrich').onclick=()=>{$('#ipApiKey').value='';$('#enrichDrawer').classList.add('hidden');resetEnrichmentStatus('ual');};
$('#enrichBtn').onclick=async()=>{
  const status=$('#enrichStatus'); status.className='status'; status.textContent='Calling IP-API and adding enrichment columns…'; $('#enrichBtn').disabled=true;startEnrichmentProgress('ual');
  try {
    const commercial=$('#ipApiMode').value==='commercial',apiKey=commercial?$('#ipApiKey').value.trim():'';
    if(commercial&&!apiKey)throw new Error('Enter a commercial IP-API key');
    const p=new URLSearchParams({q:state.query});if(state.operation)p.set('operation',state.operation);if(state.category)p.set('category',state.category);
    const data=await api(`/api/cases/${activeUalId()}/enrich?${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({column:$('#ipColumn').value,acceptNonCommercialTerms:!commercial,apiKey})});
    state.overview.columns=data.columns;
    state.overview.enrichmentColumns=data.enrichedColumns;
    const newColumns=orderEnrichmentColumns(data.columns.filter(c=>data.enrichedColumns.some(ipCol=>c.startsWith(`${ipCol}_IPAPI_`))),data.enrichedColumns);
    state.columns=orderEnrichmentColumns([...state.columns,...newColumns.filter(c=>!state.columns.includes(c))].slice(0,50),data.enrichedColumns);
    saveColumnPreferences(); renderPicker(); await loadRows(); status.textContent='';$('#enrichDrawer').classList.add('hidden');
    toast(`${data.found} unique IPs from the filtered rows processed; enrichment columns added`);
  } catch(error) { status.className='status error'; status.textContent=error.message; }
  finally { stopEnrichmentProgress('ual');$('#ipApiKey').value='';$('#enrichBtn').disabled=false; }
};

function setSidebarCollapsed(collapsed, persist=true) {
  const effective=collapsed && window.innerWidth>900;
  $('#workspace').classList.toggle('sidebar-collapsed',effective);
  $('#collapseSidebar').title=effective?'Expand sidebar':'Collapse sidebar';
  $('#collapseSidebar').setAttribute('aria-label',effective?'Expand sidebar':'Collapse sidebar');
  if(persist) localStorage.setItem('ualSidebarCollapsed',collapsed?'1':'0');
}
$('#collapseSidebar').onclick=()=>setSidebarCollapsed(!$('#workspace').classList.contains('sidebar-collapsed'));
setSidebarCollapsed(localStorage.getItem('ualSidebarCollapsed')==='1',false);
window.addEventListener('resize',()=>setSidebarCollapsed(localStorage.getItem('ualSidebarCollapsed')==='1',false));

loadCases().catch(error=>toast(error.message));
