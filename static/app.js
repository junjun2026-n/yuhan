// ============================================================
// 文件名称：app.js
// 生成日期：2026-10-27
// 修改日期：2026-11-20
// 版本信息：v0.261115
// 作    者：JUN
// 备    注：本程序由AI辅助完成。
//           文件功能：组织应用界面或应用服务逻辑。
//           文件用途：供WAF的 yuhan/static/app.js 模块使用。
//           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
// ============================================================
'use strict';
const $ = id => document.getElementById(id);
let config = null, page = 1, eventPages = 0, eventRequest = 0, certificates = [];
let identity=null, userCatalog=null, editingUser='';
let eventFilters={},eventFilterLabel='',overviewRequest=0;
const can=permission=>identity?.permissions.includes(permission);
const names = {blocked:'已拦截', detected:'观察命中', allowed:'已转发', observed:'旁挂已审计', error:'代理异常', admin:'配置变更'};
function message(text, error=false) { $('message').textContent=text; $('message').classList.toggle('error',error); }
async function api(path, options={}) {
  const response=await fetch(path,{credentials:'same-origin',...options});
  if(response.status===401){document.body.hidden=true;location.replace('/login');throw Error('登录已失效，请重新登录。');}
  if(!response.ok) { const data=await response.json().catch(()=>({})); throw new Error(typeof data.detail==='string'?data.detail:Array.isArray(data.detail)?data.detail.map(item=>item.msg).join('；'):`请求失败 (${response.status})，请检查配置和登录凭据。`); }
  return response.json();
}
function element(tag,text,cls) {const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
async function loadEvents() {
  const request=++eventRequest;
  const query=new URLSearchParams({...eventFilters,action:$('action').value,page:String(page),page_size:$('event-page-size').value,paginated:'true'});
  const result=await api('/api/events?'+query);
  if(request!==eventRequest)return;
  const events=result.items;page=result.page;eventPages=result.pages;$('event-list').replaceChildren();
  for(const item of events) {const row=element('tr');for(const value of [new Date(item.created_at).toLocaleString(),item.ip,item.source_scope==='external'?countryName(item.country):item.source_scope==='internal'?'内网 / 特殊地址':'—',item.domain||'未记录',`${item.method} ${item.path}`,names[item.action]||item.action,item.rule_id||'—',item.status||'—',item.request_id])row.append(element('td',value));$('event-list').append(row);}
  if(!events.length){const row=element('tr'),cell=element('td','暂无记录');cell.colSpan=9;row.append(cell);$('event-list').append(row);}
  $('event-filter-bar').hidden=!Object.keys(eventFilters).length;$('event-filter-summary').textContent=eventFilterLabel;
  $('page-label').textContent=`共 ${result.total} 条 · 第 ${result.total?page:0} / ${eventPages} 页`;$('prev').disabled=page<=1;$('next').disabled=page>=eventPages;
}
async function load() {
  identity=await api('/api/me');applyBrand(identity.platform_name);applyPermissions();
  const protection=identity.protection;$('protection-status').textContent=`当前模式：${protection.mode==='block'?'拦截':'观察'} · 特征检测：${protection.enabled?'启用':'关闭'} · ${protection.upstream_configured?'源站已配置':'等待配置源站'}`;
  const [settings,rules]=await Promise.all([can('sites')||can('rules')?api('/api/settings'):null,can('rules')?api('/api/rules'):[],can('overview')?loadOverview():null]);
  config=settings;
  if(settings){
  for(const key of ['upstream','mode','rate_limit','max_body_bytes','tls_port'])$(key).value=settings[key];
  $('protected_domains').value=settings.protected_domains.join('\n');
  renderDomainUpstreams(settings.domain_upstreams||{});
  renderOriginRules(settings.origin_rules||[]);
  $('tls_enabled').checked=settings.tls_enabled;
  $('enabled').checked=settings.enabled;
  $('honeypot_enabled').checked=!!settings.honeypot_enabled;
  $('honeypot_url').value=settings.honeypot_url||'';
  $('honeypot_url').disabled=!settings.honeypot_enabled;
  $('honeypot_url').required=!!settings.honeypot_enabled;
  $('protection-status').textContent=`当前模式：${settings.mode==='block'?'拦截':'观察'} · 特征检测：${settings.enabled?'启用':'关闭'} · ${settings.upstream||Object.keys(settings.domain_upstreams||{}).length||settings.origin_rules?.length?'源站已配置':'等待配置源站'}`;
  }
  if(settings){
  $('rule-list').replaceChildren();for(const rule of rules){const row=element('div',undefined,'rule'),info=element('div');info.append(element('strong',rule.name),element('br'),element('small',`${rule.id} / ${rule.category}`));const label=element('label',undefined,'check'),check=element('input');check.type='checkbox';check.dataset.rule=rule.id;check.checked=!settings.disabled_rules.includes(rule.id);label.append(check,document.createTextNode('启用'));row.append(info,label);$('rule-list').append(row);}
  $('domain-certificate-list').replaceChildren();
  }
  await Promise.all([can('audit')?loadEvents():null,can('sites')?loadTLS():null,can('rules')?Promise.all([loadCustomRules(),loadTrafficProtection()]):null]);
}
async function save(value){
  if(!$('settings').hidden){
    value.origin_rules=readOriginRules();
    value.honeypot_enabled=$('honeypot_enabled').checked;
    value.honeypot_url=$('honeypot_url').value.trim();
  }
  await api('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});await load();message('配置已保存，域名和防护策略已生效；启用 HTTPS 后请刷新 HTTPS 状态确认入口运行。');}
function run(fn){return async e=>{try{await fn(e);}catch(error){message(error.message,true);}};}
$('honeypot_enabled').addEventListener('change',()=>{const enabled=$('honeypot_enabled').checked;$('honeypot_url').disabled=!enabled;$('honeypot_url').required=enabled;});
$('logout').addEventListener('click',run(async()=>{
  $('logout').disabled=true;
  try{
    await api('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    identity=null;config=null;document.body.hidden=true;
    try{localStorage.setItem('waf-logout',String(Date.now()));}catch{}
    location.replace('/login?reason=logout');
  }finally{$('logout').disabled=false;}
}));
window.addEventListener('storage',event=>{if(event.key==='waf-logout'){document.body.hidden=true;location.replace('/login?reason=logout');}});
window.addEventListener('pagehide',()=>{document.body.hidden=true;});
window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
function countryName(code){
  if(!code||code==='ZZ')return '未知国家 / 地区';
  try{return new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(code)||code;}catch{return code;}
}
async function openOverviewEvents(snapshot,action,label,filters={}){
  if(!can('audit'))return;
  eventFilters={since:snapshot.since,until:snapshot.until,...filters};
  if(!eventFilters.since)delete eventFilters.since;
  eventFilterLabel=`${{all:'全部留存记录','24h':'最近 24 小时','7d':'最近 7 天','30d':'最近 30 天'}[snapshot.period]} · ${label} · 截至 ${new Date(snapshot.until).toLocaleString()}`;
  $('action').value=action;page=1;
  document.querySelector('[data-tab=events]').click();await loadEvents();
}
async function loadOverview(){
  const request=++overviewRequest;
  const snapshot=await api('/api/stats/overview?period='+$('overview-period').value);
  if(request!==overviewRequest)return;
  $('metrics').replaceChildren();
  for(const [key,label,action] of [['total','请求总数','business'],['blocked','已拦截','blocked'],['detected','观察命中','detected'],['allowed','已转发','allowed'],['observed','旁挂已审计','observed'],['errors','代理异常','error']]){
    const card=element('button',undefined,`metric ${key}`);card.type='button';card.dataset.action=action;
    card.append(element('span',label),element('strong',snapshot.counts[key].toLocaleString()));
    card.disabled=!can('audit');card.title=can('audit')?'查看对应访问记录':'需要访问审计权限才能查看记录';
    card.addEventListener('click',run(()=>openOverviewEvents(snapshot,action,label)));$('metrics').append(card);
  }
  const definitions=[['domains','域名 TOP5','domain'],['external_ips','外部 IP TOP5','ip'],['countries','外部来源国家 TOP5','country'],['blacklist_ips','黑名单 TOP5','ip'],['attacks','攻击 TOP5','threat_type'],['rules','防护命中规则 TOP5','rule_id'],['paths','访问路径 TOP5','path'],['methods','请求方法 TOP5','method'],['statuses','响应状态码 TOP5','status']];
  $('overview-rankings').replaceChildren();
  for(const [key,title,field] of definitions){
    const panel=element('div',undefined,'panel rank-panel');panel.dataset.ranking=key;panel.append(element('h2',title));
    const list=element('ol',undefined,'rank-list'),items=snapshot.rankings[key];
    for(const item of items){
      const row=element('li'),button=element('button',undefined,'rank-link');button.type='button';
      const label=key==='countries'?countryName(item.value):item.label||String(item.value);
      const name=element('span',label,'rank-name');name.title=label;
      button.append(name,element('strong',item.count.toLocaleString()+' 次'));
      button.style.setProperty('--rank-width',(item.count/items[0].count*100)+'%');
      button.disabled=!can('audit');button.title=can('audit')?'查看对应访问记录':'需要访问审计权限才能查看记录';
      const filters={[field]:String(item.value)};
      if(key==='external_ips'||key==='countries')filters.external='true';
      const action={rules:'hits',blacklist_ips:'blacklist',attacks:'attacks'}[key]||'business';
      button.addEventListener('click',run(()=>openOverviewEvents(snapshot,action,title+'：'+label,filters)));
      row.append(button);list.append(row);
    }
    if(key==='blacklist_ips')panel.append(element('p','按命中黑名单的来源 IP 统计，包含观察命中。','muted'));
    if(key==='attacks')panel.append(element('p','按防护命中类型统计，包含拦截及观察，不含黑名单。','muted'));
    panel.append(list);
    if(!items.length)panel.append(element('p',key==='domains'?'暂无已记录域名的请求':key==='external_ips'||key==='countries'?'暂无公网来源请求':'暂无记录','muted'));
    $('overview-rankings').append(panel);
  }
  $('overview-summary').textContent=`按业务审计记录计数，管理操作不计入；公网来源 ${snapshot.external_requests.toLocaleString()} 次，未记录域名 ${snapshot.missing_domains.toLocaleString()} 次。${snapshot.geoip_available?'已加载离线国家库。':'离线国家库不可用，国家显示为未知。'}统计截至 ${new Date(snapshot.until).toLocaleString()}。`;
}
$('overview-period').addEventListener('change',run(loadOverview));
$('event-filter-clear').addEventListener('click',run(async()=>{eventFilters={};eventFilterLabel='';page=1;$('action').value='';await loadEvents();}));
async function loadTLS(){
  const status=await api('/api/tls');
  certificates=status.certificates||[];
  const bindings={...config?.domain_certificates};
  for(const domain of config?.protected_domains||[])if(!bindings[domain]&&config.tls_certificate)bindings[domain]=config.tls_certificate;
  renderDomainCertificates(document.querySelector('#domain-certificate-list select')?readDomainCertificates():bindings);
  $('certificate-library').replaceChildren();
  for(const item of certificates){const row=element('tr');row.append(element('td',item.domains.join('、')),element('td',item.id.slice(0,16)),element('td',`${new Date(item.not_after).toLocaleString()}${item.expired?'（已过期）':''}`));$('certificate-library').append(row);}
  $('certificate-info').textContent=certificates.length?`证书库共 ${certificates.length} 张证书，上传不会自动改变域名的加载配置。`:'尚未上传证书';
  $('tls-status').textContent=`HTTPS / TLS 卸载：${status.enabled?status.running?'运行中，已加载域名证书':'等待加载 / 未运行':'未启用'} · 端口 ${status.port}${status.detail?' · '+status.detail:''}`;
}
function certificateLabel(item){return `${item.domains.join(', ')} · ${item.id.slice(0,10)} · ${item.expired?'已过期':'有效至 '+new Date(item.not_after).toLocaleDateString()}`;}
function readDomainCertificates(){
  const result={};
  document.querySelectorAll('#domain-certificate-list select').forEach(select=>{if(select.value)result[select.dataset.domain]=select.value;});
  return result;
}
function certificateCovers(item,domain){
  const now=Date.now();
  if(item.expired||new Date(item.not_before).getTime()>now)return false;
  return item.domains.some(name=>{name=name.toLowerCase();return domain===name||(name.startsWith('*.')&&domain.split('.').length===name.split('.').length&&domain.endsWith(name.slice(1)));});
}
function renderDomainCertificates(bindings=readDomainCertificates()){
  const domains=[...new Set($('protected_domains').value.split(/[\n,，]/).map(x=>{x=x.trim().toLowerCase().replace(/\.$/,'');try{const prefix=x.startsWith('*.')?'*.':'';return prefix+new URL('http://'+(prefix?x.slice(2):x)).hostname;}catch{return x;}}).filter(Boolean))];
  const selected=$('certificate-domain').value;
  $('certificate-domain').replaceChildren(option('','仅上传到证书库，暂不绑定域名'));
  for(const domain of domains)$('certificate-domain').append(option(domain,domain));
  $('certificate-domain').value=domains.includes(selected)?selected:'';
  $('certificate-domain-help').textContent=domains.length?'选择已配置域名，上传后回填对应证书；返回“站点配置”页签，点击“保存站点配置”后加载。':'暂无已配置域名，请先在“站点配置”页签填写“受保护域名”，此处会自动显示对应选择项。';
  $('domain-certificate-list').replaceChildren();
  if(!domains.length){const row=element('tr'),cell=element('td','请先填写上方“受保护域名”，填写后会显示域名与证书选择项。');cell.colSpan=2;row.append(cell);$('domain-certificate-list').append(row);}
  for(const domain of domains){
    const row=element('tr'),cell=element('td'),select=element('select');
    select.dataset.domain=domain;select.setAttribute('aria-label',`${domain} 的 HTTPS 证书`);
    const matching=certificates.filter(item=>certificateCovers(item,domain));
    select.append(option('',matching.length?'请选择要加载的证书':'无匹配证书，请在下方上传'));
    for(const item of matching)select.append(option(item.id,certificateLabel(item)));
    if(bindings[domain]&&!matching.some(item=>item.id===bindings[domain])){const invalid=option(bindings[domain],'原绑定证书无效或不匹配，请重新选择');invalid.disabled=true;select.append(invalid);}
    select.value=bindings[domain]||'';cell.append(select);row.append(element('td',domain),cell);$('domain-certificate-list').append(row);
  }
}
function readOriginRules(){
  return [...document.querySelectorAll('#origin-rule-list fieldset')].map(row=>{
    const read=key=>row.querySelector(`[data-field="${key}"]`).value;
    return {domain:read('domain').trim(),port:read('port')?Number(read('port')):null,path_prefix:read('path_prefix'),priority:Number(read('priority')),origins:read('origins').split(/\r?\n/).map(value=>value.trim()).filter(Boolean)};
  });
}
function renderOriginRules(rules){
  $('origin-rule-list').replaceChildren();
  for(const rule of rules)addOriginRule(rule);
}
function addOriginRule(rule={}){
  const row=element('fieldset'),grid=element('div',undefined,'form-grid');
  row.append(element('legend','域名与源站匹配'));
  for(const [key,title,type] of [['domain','受保护域名','text'],['port','访问端口（可选）','number'],['path_prefix','路径前缀','text'],['priority','优先级（0—10000）','number']]){
    const label=element('label',title),input=element('input');input.type=type;input.dataset.field=key;
    input.value=rule[key]??({path_prefix:'/',priority:100}[key]??'');
    input.required=key!=='port';
    if(type==='number'){input.min=key==='port'?'1':'0';input.max=key==='port'?'65535':'10000';}
    if(key==='domain')input.placeholder='api.example.com 或 *.example.com';
    label.append(input);grid.append(label);
  }
  row.append(grid);
  const label=element('label','后端源站（每行一个，最多 16 个）'),origins=element('textarea');
  origins.dataset.field='origins';origins.rows=3;origins.required=true;origins.value=(rule.origins||[]).join('\n');origins.placeholder='http://10.0.0.21:8080\nhttp://10.0.0.22:8080';label.append(origins);row.append(label);
  const remove=element('button','删除此规则','secondary');remove.type='button';remove.addEventListener('click',()=>row.remove());row.append(remove);
  $('origin-rule-list').append(row);
}
$('add-origin-rule').addEventListener('click',()=>addOriginRule());
function readDomainUpstreams(){
  const result=Object.create(null);
  document.querySelectorAll('#domain-upstream-list textarea').forEach(input=>{
    const origins=input.value.split(/\r?\n/).map(value=>value.trim()).filter(Boolean);
    if(origins.length)result[input.dataset.domain]=origins;
  });
  return result;
}
function renderDomainUpstreams(bindings=readDomainUpstreams()){
  const domains=[...new Set($('protected_domains').value.split(/[\n,，]/).map(value=>value.trim().toLowerCase().replace(/\.$/,'')).filter(Boolean))];
  $('domain-upstream-list').replaceChildren();
  for(const domain of domains){
    const row=element('tr'),cell=element('td'),input=element('textarea');
    input.dataset.domain=domain;input.rows=3;input.maxLength=32768;
    input.setAttribute('aria-label',`${domain} 的后端源站`);
    input.placeholder='http://10.0.0.11:8080\nhttp://10.0.0.12:8080';
    input.value=(bindings[domain]||[]).join('\n');
    cell.append(input);row.append(element('td',domain),cell);$('domain-upstream-list').append(row);
  }
  if(!domains.length){const row=element('tr'),cell=element('td','请先填写上方受保护域名；每个域名对应一组后端源站。');cell.colSpan=2;row.append(cell);$('domain-upstream-list').append(row);}
}
$('protected_domains').addEventListener('input',()=>{renderDomainCertificates();renderDomainUpstreams();});
$('refresh-tls').addEventListener('click',run(loadTLS));
$('show-certificate-password').addEventListener('change',()=>{$('certificate-password').type=$('show-certificate-password').checked?'text':'password';});
async function certificateFileBase64(file){
  if(!file)return '';
  const bytes=new Uint8Array(await file.arrayBuffer()),chunks=[];
  for(let i=0;i<bytes.length;i+=32768)chunks.push(String.fromCharCode(...bytes.subarray(i,i+32768)));
  return btoa(chunks.join(''));
}
$('certificate-form').addEventListener('submit',run(async e=>{
  e.preventDefault();const button=e.currentTarget.querySelector('button[type=submit]');button.disabled=true;
  try{
    const cert=$('certificate-file').files[0],key=$('private-key-file').files[0];
    const selectedDomain=$('certificate-domain').value;
    if(!cert)throw Error('请选择证书文件');
    if(cert.size>1048576||(key&&key.size>65536))throw Error('证书文件上限 1 MiB，私钥文件上限 64 KiB');
    const info=await api('/api/tls/certificate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({certificate:await certificateFileBase64(cert),private_key:await certificateFileBase64(key),encoding:'base64',password:$('certificate-password').value})});
    $('certificate-form').reset();$('certificate-password').type='password';await loadTLS();
    const format=info.source_format||'证书';
    if(selectedDomain){
      if(!certificateCovers(info,selectedDomain)){message(`证书已上传，但不覆盖所选域名 ${selectedDomain}，原绑定保持不变。`,true);return;}
      if(![...$('certificate-domain').options].some(item=>item.value===selectedDomain)){message('证书已上传，所选域名已移除，请重新配置域名后绑定。',true);return;}
      renderDomainCertificates({...readDomainCertificates(),[selectedDomain]:info.id});$('certificate-domain').value=selectedDomain;
      message(`已识别 ${format}，证书已回填至 ${selectedDomain}，请点击“保存站点配置”加载。`);
    }else message(`已识别 ${format} 并导入证书库，请按域名选择证书后保存加载。`);
  }finally{button.disabled=false;}
}));
document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',run(async()=>{if(button.hidden)return;document.querySelectorAll('main section').forEach(s=>s.hidden=s.id!==button.dataset.tab);document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b===button));$('title').textContent=button.textContent;message('');if(button.dataset.tab==='system')await loadSystem();if(button.dataset.tab==='rules')await loadCustomRules();if(button.dataset.tab==='users')await loadUsers();})));
$('refresh').addEventListener('click',run(async()=>{await load();if(!$('system').hidden)await loadSystem();message('数据已刷新。');}));
$('settings-form').addEventListener('submit',run(async e=>{e.preventDefault();await save({...config,upstream:$('upstream').value.trim(),domain_upstreams:readDomainUpstreams(),mode:$('mode').value,enabled:$('enabled').checked,rate_limit:Number($('rate_limit').value),max_body_bytes:Number($('max_body_bytes').value),protected_domains:$('protected_domains').value.split(/[\n,，]/).map(x=>x.trim()).filter(Boolean),tls_enabled:$('tls_enabled').checked,tls_port:Number($('tls_port').value),tls_certificate:'',domain_certificates:readDomainCertificates()});}));
$('honeypot-form').addEventListener('submit',run(async e=>{e.preventDefault();await api('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...config,honeypot_enabled:$('honeypot_enabled').checked,honeypot_url:$('honeypot_url').value.trim()})});await load();message('蜜罐配置已保存。');}));
$('save-rules').addEventListener('click',run(async()=>{await save({...config,disabled_rules:[...document.querySelectorAll('[data-rule]')].filter(c=>!c.checked).map(c=>c.dataset.rule)});}));
$('action').addEventListener('change',run(async()=>{page=1;await loadEvents();}));
$('event-page-size').addEventListener('change',run(async()=>{page=1;await loadEvents();}));
$('prev').addEventListener('click',run(async()=>{page=Math.max(1,page-1);await loadEvents();}));
$('next').addEventListener('click',run(async()=>{page=Math.min(Math.max(1,eventPages),page+1);await loadEvents();}));
function applyPermissions(){
  $('open-traffic-map').hidden=!can('overview')||$('overview').hidden;
  const mapping={overview:'overview',settings:'sites',rules:'rules',events:'audit',system:'system',users:'users'};
  document.querySelectorAll('[data-tab]').forEach(button=>{button.hidden=button.dataset.tab!=='password'&&!can(mapping[button.dataset.tab]);});
  const active=document.querySelector('[data-tab].active');
  if(!active||active.hidden){
    const first=document.querySelector('[data-tab]:not([hidden])');
    document.querySelectorAll('[data-tab]').forEach(button=>button.classList.toggle('active',button===first));
    document.querySelectorAll('main section').forEach(section=>section.hidden=section.id!==first.dataset.tab);
    $('title').textContent=first.textContent;
  }
  $('current-user').textContent=`当前用户：${identity.username}`;
}
function updateUserPermissions(){
  const custom=$('user-role').value==='custom';
  const assigned=userCatalog.role_permissions[$('user-role').value];
  document.querySelectorAll('[data-user-permission]').forEach(check=>{check.disabled=!custom;if(!custom)check.checked=assigned.includes(check.dataset.userPermission);});
}
function resetUser(){editingUser='';$('user-form').reset();$('user-username').disabled=false;$('user-password').required=true;$('user-form-title').textContent='新增用户';$('user-role').value='operator';updateUserPermissions();}
async function loadUsers(){
  const [users,catalog]=await Promise.all([api('/api/users'),api('/api/permissions')]);userCatalog=catalog;
  if(!$('user-role').options.length){
    for(const [key,label] of Object.entries(catalog.roles))$('user-role').append(option(key,label));
    for(const [key,label] of Object.entries(catalog.permissions)){const field=element('label',undefined,'check'),check=element('input');check.type='checkbox';check.dataset.userPermission=key;field.append(check,document.createTextNode(label));$('user-permissions').append(field);}
    resetUser();
  }
  $('user-list').replaceChildren();
  for(const user of users){
    const row=element('tr'),actions=element('td');
    const perms=user.role==='custom'?user.permissions:catalog.role_permissions[user.role];
    row.append(element('td',user.username),element('td',catalog.roles[user.role]),element('td',user.enabled?'启用':'停用'),element('td',perms.map(key=>catalog.permissions[key]).join('、')||'仅修改本人密码'));
    const edit=element('button','编辑','secondary');edit.type='button';edit.addEventListener('click',()=>{editingUser=user.username;$('user-form-title').textContent=`编辑用户：${user.username}`;$('user-username').value=user.username;$('user-username').disabled=true;$('user-password').value='';$('user-password').required=false;$('user-role').value=user.role;$('user-enabled').checked=user.enabled;document.querySelectorAll('[data-user-permission]').forEach(check=>check.checked=user.permissions.includes(check.dataset.userPermission));updateUserPermissions();$('user-form').scrollIntoView({block:'start'});});
    const remove=element('button','删除','secondary');remove.type='button';remove.disabled=user.username===identity.username;
    remove.addEventListener('click',run(async()=>{if(!window.confirm(`确认删除用户 ${user.username}？`))return;await api(`/api/users/${encodeURIComponent(user.username)}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:'{}'});await loadUsers();message('用户已删除。');}));
    actions.append(edit,remove);row.append(actions);$('user-list').append(row);
  }
}
$('user-role').addEventListener('change',updateUserPermissions);
$('user-reset').addEventListener('click',resetUser);
$('user-form').addEventListener('submit',run(async event=>{
  event.preventDefault();const value={username:$('user-username').value,role:$('user-role').value,enabled:$('user-enabled').checked,password:$('user-password').value,permissions:[...document.querySelectorAll('[data-user-permission]:checked')].map(check=>check.dataset.userPermission)};
  await api(editingUser?`/api/users/${encodeURIComponent(editingUser)}`:'/api/users',{method:editingUser?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
  if(value.username===identity.username&&value.password){location.replace('/login?reason=password');return;}
  resetUser();await load();if(can('users'))await loadUsers();message('用户及权限已保存。');
}));
$('password-form').addEventListener('submit',run(async event=>{
  event.preventDefault();const password=$('new-password').value;if(password!==$('confirm-password').value)throw Error('两次新密码不一致');
  await api('/api/me/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:$('current-password').value,new_password:password})});
  $('password-form').reset();location.replace('/login?reason=password');
}));
let networkConfig=null, physicalNICs=[];
function option(value,label){const el=element('option',label);el.value=value;return el;}
function readNICs(){return [...$('nic-list').children].map(row=>({alias:row.querySelector('[data-field=alias]').value.trim(),role:row.querySelector('[data-field=role]').value,physical_id:row.querySelector('[data-field=physical_id]').value}));}
function selectAliases(){
  const nics=readNICs().filter(n=>n.role==='business');
  for(const id of ['mirror_alias','ingress_alias','egress_alias']){
    const previous=$(id).value||networkConfig?.[id]||'';$(id).replaceChildren(option('','请选择业务网卡'));
    for(const nic of nics)$(id).append(option(nic.alias,nic.alias));
    $(id).value=previous;
  }
  $('mirror_alias').disabled=$('deployment_mode').value!=='bypass';
  for(const id of ['ingress_alias','egress_alias'])$(id).disabled=$('deployment_mode').value!=='inline';
}
function renderNICs(nics){
  $('nic-list').replaceChildren();
  for(const nic of nics){
    const row=element('tr'),alias=element('input');alias.value=nic.alias;alias.dataset.field='alias';alias.required=true;alias.pattern='[a-z][a-z0-9_-]{0,23}';alias.maxLength=24;alias.setAttribute('aria-label','系统网卡别名');
    const role=element('select');role.dataset.field='role';role.append(option('management','管理口'),option('business','业务口'));role.value=nic.role;role.setAttribute('aria-label','网卡用途');
    const binding=element('select');binding.dataset.field='physical_id';binding.setAttribute('aria-label','物理网卡绑定');binding.append(option('','未绑定'));
    for(const item of physicalNICs)binding.append(option(item.id,`${item.name} · ${item.mac||'无 MAC'} · ${item.status} · ${item.ipv4.join(', ')||'无 IPv4'}`));
    if(nic.physical_id&&!physicalNICs.some(p=>p.id===nic.physical_id))binding.append(option(nic.physical_id,`绑定已丢失：${nic.physical_id}`));
    binding.value=nic.physical_id;
    for(const field of [alias,role,binding]){const td=element('td');td.append(field);row.append(td);}
    alias.addEventListener('change',selectAliases);role.addEventListener('change',selectAliases);$('nic-list').append(row);
  }
  selectAliases();
}
async function loadSystem(){
  await Promise.all([loadPlatform(),loadLogging()]);
  const [value,status]=await Promise.all([api('/api/system'),api('/api/system/status')]);
  networkConfig=value;physicalNICs=status.adapters;
  for(const key of ['deployment_mode','nic_count','management_cidr'])$(key).value=value[key];
  renderNICs(value.interfaces);
  for(const key of ['mirror_alias','ingress_alias','egress_alias'])$(key).value=value[key];
  const modes={proxy:'反向代理',bypass:'镜像旁挂',inline:'透明串联'};
  $('network-status').textContent=`主机：${status.platform}${status.container?' / Docker':''} · 配置模式：${modes[value.deployment_mode]} · 数据平面：${value.deployment_mode==='proxy'?'使用 8300 反向代理':status.data_plane_running?'运行中（明文 HTTP）':status.data_plane_available?status.data_plane_autostart?'等待启动或启动失败，请检查容器日志':'未运行，需手动启动':'未运行（当前 Windows 不支持）'} · 管理 IP：${status.management_ip_applied?'已配置到物理网卡':'未应用'}`;
  let initStatus=$('initialization-status');
  if(!initStatus){initStatus=element('p');initStatus.id='initialization-status';$('network-status').after(initStatus);}
  const initial=status.initialization||{};
  const initNames={completed:'初始化完成',waiting_selection:'等待填写管理网卡',pending_ip:'等待应用管理 IP',error:'初始化失败',skipped_existing:'保留现有系统配置',skipped_changed:'已改为页面配置'};
  initStatus.textContent=`mgrnic.ini：${initNames[initial.state]||'尚未执行初始化'}。${initial.detail||''}${initial.last_error?' 最近错误：'+initial.last_error:''}`;
  if(initial.business){const b=initial.business;initStatus.textContent+=` 业务网卡：${b.state==='completed'?'已加载':b.state==='skipped_changed'?'保留页面配置':'未完成'}。${b.detail||''}${b.last_error?' 错误：'+b.last_error:''}`;}
  $('binding-status').replaceChildren();
  for(const item of status.interfaces)$('binding-status').append(element('p',`${item.alias}（${item.role==='management'?'管理口':'业务口'}） → ${item.physical?`${item.physical.name} / ${item.physical.status}`:item.binding_status==='missing'?'物理网卡丢失，请重新绑定':'未绑定'}`));
  $('apply-management').disabled=!status.privileged||!status.interfaces.some(n=>n.role==='management'&&n.binding_status==='bound');
  $('network-access').textContent=`预期管理入口：${status.management_url}；${status.management_listener_ip?'启动时监听管理 IP：'+status.management_listener_ip:'当前仅监听本机 127.0.0.1:8301'}。${status.privileged?'':'当前进程没有管理员权限，无法应用 IP。'}`;
}
$('resize-nics').addEventListener('click',run(async()=>{
  const count=Number($('nic_count').value);if(!Number.isInteger(count)||count<1||count>32)throw Error('网卡数量范围为 1～32。');
  const nics=readNICs();
  if(count<nics.length&&nics.slice(count).some(n=>n.physical_id||n.role==='management'))throw Error('请先解除待删除行的绑定，并将管理口保留在前面的行。');
  nics.splice(count);
  while(nics.length<count){let i=1;while(nics.some(n=>n.alias===`port${i}`))i++;nics.push({alias:`port${i}`,role:'business',physical_id:''});}
  renderNICs(nics);message('网卡数量已更新，请保存系统配置。');
}));
$('deployment_mode').addEventListener('change',selectAliases);
$('system-form').addEventListener('submit',run(async e=>{
  e.preventDefault();
  const value={...networkConfig,deployment_mode:$('deployment_mode').value,nic_count:Number($('nic_count').value),management_cidr:$('management_cidr').value.trim(),interfaces:readNICs()};
  for(const key of ['mirror_alias','ingress_alias','egress_alias'])value[key]=$(key).value||'';
  await api('/api/system',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
  await loadSystem();message('系统配置已保存。Docker 会按配置管理数据平面，管理 IP 需单独应用。请刷新查看运行状态。');
}));
$('refresh-system').addEventListener('click',run(loadSystem));
$('apply-management').addEventListener('click',run(async()=>{
  const button=$('apply-management');button.disabled=true;
  try{const result=await api('/api/system/apply-management',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});await loadSystem();message(result.detail);}finally{button.disabled=false;}
}));
let platformConfig=null;
function applyBrand(name){document.title=`${name} · 安全控制台`;$('platform-brand').textContent=name;$('platform-footer').textContent=name;}
async function loadPlatform(){
  const value=await api('/api/system/platform');
  platformConfig=value.config;
  applyBrand(value.config.platform_name);
  for(const key of ['platform_name','hostname','database_timeout','wal_autocheckpoint'])$(key).value=value.config[key];
  $('database-path').value=value.database.path;
  await loadDatabaseConfig();
  $('wal_autocheckpoint').disabled=value.database.engine!=='SQLite';
  $('sqlite-wal-field').hidden=value.database.engine!=='SQLite';
  $('platform-status').textContent=`当前主机名：${value.active_hostname} · ${value.hostname_pending?'主机名待重建容器生效':'主机名已生效'}`;
  $('database-size').textContent=`当前数据库大小：${(value.database.size_bytes/1048576).toFixed(2)} MB${value.database.engine==='SQLite'?'（不含 WAL）':''}`;
}
$('platform-form').addEventListener('submit',run(async e=>{
  e.preventDefault();
  if(!platformConfig)throw Error('配置尚未加载，请稍后再试。');
  await api('/api/system/platform',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...platformConfig,platform_name:$('platform_name').value.trim(),hostname:$('hostname').value.trim()})});
  await loadPlatform();message('平台配置已保存，主机名生效状态见配置下方。');
}));
$('database-runtime-form').addEventListener('submit',run(async e=>{
  e.preventDefault();if(!platformConfig)throw Error('配置尚未加载，请稍后再试。');
  await api('/api/system/platform',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...platformConfig,database_timeout:Number($('database_timeout').value),wal_autocheckpoint:Number($('wal_autocheckpoint').value)})});
  await loadPlatform();$('database-test-result').textContent='';message('数据库运行参数已保存并生效。');
}));
$('test-database').addEventListener('click',run(async()=>{
  const button=$('test-database');button.disabled=true;
  try{const result=await api('/api/system/database/test',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});$('database-test-result').textContent=result.engine==='PostgreSQL'?`${result.detail} · ${result.elapsed_ms} ms · SQL 超时 ${result.statement_timeout}`:`${result.detail} · ${result.elapsed_ms} ms · ${result.journal_mode.toUpperCase()} · 等待 ${result.busy_timeout_ms/1000} 秒 · 检查点 ${result.wal_autocheckpoint} 页`;}
  catch(error){$('database-test-result').textContent=error.message;throw error;}
  finally{button.disabled=false;}
}));
run(async()=>{await load();if(can('system'))await loadPlatform();})();
function showDatabaseFields(){
  const engine=$('database-engine').value,pq=engine==='postgresql',sqlite=engine==='sqlite';
  $('pq-config').hidden=!pq;$('sqlite-config').hidden=!sqlite;
  $('database-path-field').hidden=!sqlite||$('database-path').dataset.engine!=='sqlite';
  $('db-sqlite-path').disabled=!sqlite;
  $('pq-config').querySelectorAll('input,select').forEach(input=>{input.disabled=!pq;});
  for(const id of ['save-database-config','probe-database-config','initialize-database'])$(id).disabled=!engine;
}
let databaseProfiles={},databaseEditVersion=0;
for(const id of ['database-engine','db-sqlite-path','db-host','db-port','db-name','db-user','db-password','db-sslmode']){
  for(const event of ['input','change'])$(id).addEventListener(event,()=>{databaseEditVersion++;});
}
function selectedDatabase(){
  const engine=$('database-engine').value;
  if(engine==='sqlite')return {engine,sqlite_path:$('db-sqlite-path').value.trim()||'runtime/waf.sqlite3'};
  if(engine==='postgresql'){
    for(const [id,label] of [['db-host','PostgreSQL 主机'],['db-name','数据库名'],['db-user','用户名']]){
      const input=$(id);input.setCustomValidity(input.value.trim()?'':`请填写${label}`);
      if(!input.reportValidity()){input.focus();throw Error(`请填写${label}，切换数据库类型不会自动创建连接配置。`);}
    }
    return {engine,host:$('db-host').value.trim(),port:Number($('db-port').value)||5432,name:$('db-name').value.trim(),user:$('db-user').value.trim(),password:$('db-password').value,sslmode:$('db-sslmode').value};
  }
  throw Error('数据库配置尚未加载，请稍后重试。');
}
async function loadDatabaseConfig(){
  const version=databaseEditVersion;
  const state=await api('/api/system/database'),value=state.selected;
  if(version!==databaseEditVersion)return;
  databaseProfiles=state.profiles||{};
  $('database-engine').value=value.engine;$('database-engine').disabled=false;$('db-sqlite-path').value=value.sqlite_path;
  $('database-path').dataset.engine=state.active_engine;
  for(const key of ['host','port','name','user','sslmode'])$(`db-${key}`).value=value[key];
  $('db-password').value='';$('db-password').type='password';$('db-show-password').checked=false;revealedDatabasePassword=false;
  $('db-password').placeholder=value.password_set?'已保存密码；留空保留相同连接的密码':'请输入数据库密码';
  const active=state.active,connection=state.active_engine==='postgresql'?`${active.host}:${active.port}/${active.name}（用户：${active.user}）`:active.sqlite_path;
  $('database-config-status').textContent=`${state.environment==='development'?'本地独立开发环境':'当前服务'}（${location.host}） · 当前运行：${state.active_engine==='postgresql'?'PostgreSQL（PQ）':'SQLite'} · ${connection}。${state.pending?'下拉菜单显示待生效配置；当前存储尚未切换，完成停服迁移后启用。':'无待切换配置。'}`;
  $('discard-database-config').disabled=!state.pending;showDatabaseFields();
}
$('database-engine').addEventListener('change',()=>{
  const profile=databaseProfiles[$('database-engine').value];
  if(profile?.engine==='postgresql'&&!['db-host','db-name','db-user'].some(id=>$(id).value.trim())){
    for(const key of ['host','port','name','user','sslmode'])$(`db-${key}`).value=profile[key];
    $('db-password').placeholder=profile.password_set?'已保存密码；留空保留相同连接的密码':'请输入数据库密码';
  }
  showDatabaseFields();
});
for(const id of ['db-host','db-name','db-user'])$(id).addEventListener('input',()=>$(id).setCustomValidity(''));
let revealedDatabasePassword=false;
$('db-show-password').addEventListener('change',run(async()=>{
  const check=$('db-show-password'),input=$('db-password');
  if(!check.checked){input.type='password';if(revealedDatabasePassword)input.value='';revealedDatabasePassword=false;return;}
  check.disabled=true;
  try{
    if(!input.value){const result=await api('/api/system/database/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedDatabase())});if(!check.checked)return;input.value=result.password;revealedDatabasePassword=true;}
    input.type='text';
  }catch(error){check.checked=false;input.type='password';throw error;}
  finally{check.disabled=false;}
}));
for(const id of ['db-host','db-port','db-name','db-user','database-engine'])$(id).addEventListener('change',()=>{
  if(revealedDatabasePassword){$('db-password').value='';$('db-password').type='password';$('db-show-password').checked=false;revealedDatabasePassword=false;}
});
$('probe-database-config').addEventListener('click',run(async()=>{
  const result=await api('/api/system/database/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedDatabase())});message(`${result.detail}（${result.elapsed_ms} ms）`);
}));
$('initialize-database').addEventListener('click',run(async()=>{
  const button=$('initialize-database');button.disabled=true;$('database-initialize-result').textContent='正在初始化所选数据库…';
  try{
    const result=await api('/api/system/database/initialize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedDatabase())});
    $('database-initialize-result').textContent=result.detail;message('所选数据库初始化完成。');
  }catch(error){$('database-initialize-result').textContent=error.message;throw error;}
  finally{button.disabled=false;}
}));
$('save-database-config').addEventListener('click',run(async()=>{
  const result=await api('/api/system/database',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedDatabase())});await loadDatabaseConfig();message(result.detail);
}));
$('discard-database-config').addEventListener('click',run(async()=>{
  await api('/api/system/database/pending',{method:'DELETE',headers:{'Content-Type':'application/json'},body:'{}'});await loadDatabaseConfig();message('待生效数据库配置已取消。');
}));
function selectSystemTab(button,focus=false){
  document.querySelectorAll('[data-system-tab]').forEach(tab=>{const active=tab===button;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;});
  document.querySelectorAll('.system-sheet').forEach(panel=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});
  if(button.dataset.systemTab!=='database'){
    $('db-password').type='password';$('db-show-password').checked=false;
    if(revealedDatabasePassword)$('db-password').value='';revealedDatabasePassword=false;
  }
  if(focus)button.focus();
}
document.querySelectorAll('[data-system-tab]').forEach(button=>{
  button.addEventListener('click',()=>selectSystemTab(button));
  button.addEventListener('keydown',event=>{
    const tabs=[...document.querySelectorAll('[data-system-tab]')],index=tabs.indexOf(button);
    const next=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:-1;
    if(next>=0){event.preventDefault();selectSystemTab(tabs[next],true);}
  });
});

function selectSiteTab(button,focus=false){
  document.querySelectorAll('[data-site-tab]').forEach(tab=>{const active=tab===button;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;});
  document.querySelectorAll('.site-sheet').forEach(panel=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});
  if(button.dataset.siteTab!=='certificates'){$('certificate-password').type='password';$('show-certificate-password').checked=false;}
  if(focus)button.focus();
}
document.querySelectorAll('[data-site-tab]').forEach(button=>{
  button.addEventListener('click',()=>selectSiteTab(button));
  button.addEventListener('keydown',event=>{
    const tabs=[...document.querySelectorAll('[data-site-tab]')],index=tabs.indexOf(button);
    const next=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:-1;
    if(next>=0){event.preventDefault();selectSiteTab(tabs[next],true);}
  });
});

function selectRulesTab(button,focus=false){
  document.querySelectorAll('[data-rules-tab]').forEach(tab=>{const active=tab===button;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;});
  document.querySelectorAll('.rules-sheet').forEach(panel=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});
  if(focus)button.focus();
}
document.querySelectorAll('[data-rules-tab]').forEach(button=>{
  button.addEventListener('click',()=>selectRulesTab(button));
  button.addEventListener('keydown',event=>{
    const tabs=[...document.querySelectorAll('[data-rules-tab]')],index=tabs.indexOf(button);
    const next=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:-1;
    if(next>=0){event.preventDefault();selectRulesTab(tabs[next],true);}
  });
});

function showLogFields(){
  const disabled=!$('log-enabled').checked;
  for(const id of ['log-host','log-port','log-protocol','log-format','log-facility','log-template','test-logging'])$(id).disabled=disabled;
  $('log-template-field').hidden=$('log-format').value!=='custom';
  $('log-facility-field').hidden=$('log-format').value!=='syslog';
}
function selectedLogging(){return {enabled:$('log-enabled').checked,host:$('log-host').value.trim(),port:Number($('log-port').value),protocol:$('log-protocol').value,format:$('log-format').value,template:$('log-template').value,facility:Number($('log-facility').value)};}
async function loadLogging(){
  const value=await api('/api/system/logging');
  $('log-enabled').checked=value.config.enabled;
  for(const key of ['host','port','protocol','format','template','facility'])$(`log-${key}`).value=value.config[key];
  showLogFields();
  $('logging-status').textContent=`${value.config.enabled?'已启用':'未启用'} · 待发送 ${value.pending} 条 · 最近发送：${value.state.last_sent_at||'暂无'}${value.state.last_error?' · '+value.state.last_error:''}`;
}
$('log-format').addEventListener('change',showLogFields);
$('log-enabled').addEventListener('change',showLogFields);
showLogFields();
$('logging-form').addEventListener('submit',run(async e=>{
  e.preventDefault();await api('/api/system/logging',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedLogging())});
  await loadLogging();message('日志配置已保存并生效。');
}));
$('refresh-logging').addEventListener('click',run(loadLogging));
$('test-logging').addEventListener('click',run(async()=>{
  const result=await api('/api/system/logging/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selectedLogging())});
  $('logging-preview').textContent=result.preview;message(result.detail);
}));

let trafficPolicies={cc:[],ports:[]},trafficEditing={cc:'',ports:''};
function updateTrafficPolicyActions(section){
  for(const row of $(`${section}-list`).querySelectorAll('tr[data-rule-id]')){
    const rule=trafficPolicies[section].find(item=>item.id===row.dataset.ruleId);
    if(!rule)continue;
    const editing=trafficEditing[section]===rule.id;
    for(const button of row.querySelectorAll('button[data-policy-action]')){
      const action=button.dataset.policyAction;
      button.disabled=editing||(action==='delete'&&rule.enabled);
      button.title=editing?'正在编辑，请先保存或取消编辑':action==='delete'&&rule.enabled?'请先停用策略，再删除':'';
    }
  }
}
function showProtectionFields(){
  for(const section of ['cc','ports']){
    $(`${section}-fields`).disabled=!$(`${section}-enabled`).checked;
    const type=$(`${section}-target_type`).value;
    $(`${section}-target-field`).hidden=type==='all';
    $(`${section}-target`).required=type!=='all';
    $(`${section}-target`).placeholder=type==='ip'?'192.168.17.126':'www.example.com';
    if(type==='domain')$(`${section}-target`).setAttribute('list','cc-domain-options');else $(`${section}-target`).removeAttribute('list');
  }
  $('cc-target-help').textContent=$('cc-target_type').value==='ip'?'填写 WAF 业务入口的实际本地 IPv4 / IPv6 地址。':'填写受保护域名，支持单层通配符。';
}
function resetTrafficPolicy(section){
  trafficEditing[section]='';$(`${section}-form`).reset();
  $(`${section}-status`).textContent='新增策略：保存后加入列表，每类最多 100 条。';showProtectionFields();updateTrafficPolicyActions(section);
}
function editTrafficPolicy(section,rule){
  resetTrafficPolicy(section);trafficEditing[section]=rule.id;
  for(const [key,value] of Object.entries(rule)){
    const input=$(`${section}-${key}`);if(!input)continue;
    if(key==='enabled')input.checked=value;else input.value=Array.isArray(value)?value.join('\n'):(value??'');
  }
  $(`${section}-status`).textContent=`正在编辑：${rule.name}（${rule.id}），请保存或取消编辑后再操作该策略。`;showProtectionFields();updateTrafficPolicyActions(section);
}
async function loadTrafficProtection(){
  trafficPolicies=await api('/api/traffic-protection/rules');
  $('cc-domain-options').replaceChildren();for(const domain of config?.protected_domains||[])$('cc-domain-options').append(option(domain,domain));
  for(const section of ['cc','ports']){
    const list=$(`${section}-list`);list.replaceChildren();
    for(const rule of trafficPolicies[section]){
      const row=element('tr');row.dataset.ruleId=rule.id;
      const target=rule.target_type==='all'?'全部业务入口':`${rule.target_type==='domain'?'域名':'目标 IP'}：${rule.target}`;
      const scope=section==='ports'?` / ${rule.protocol.toUpperCase()} / ${rule.destination_port??'全部端口'}`:'';
      const limits=section==='cc'?`${rule.window_seconds} 秒 / ${rule.max_requests} 次 / 封禁 ${rule.ban_seconds} 秒`:`每 IP ${rule.max_concurrent_per_ip} / 总并发 ${rule.max_concurrent_total}`;
      row.append(element('td',rule.name),element('td',target+scope),element('td',`${rule.enabled?'启用':'停用'} / ${limits}`));
      const actions=element('td');actions.className='toolbar';
      for(const [label,handler] of [
        ['编辑',()=>editTrafficPolicy(section,rule)],
        [rule.enabled?'停用':'启用',run(async()=>{
          await api(`/api/traffic-protection/rules/${section}/${rule.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:rule.name,config:{...rule,enabled:!rule.enabled}})});
          await loadTrafficProtection();message('策略状态已更新。');
        })],
        ['删除',run(async()=>{
          if(!confirm(`确认删除策略“${rule.name}”？`))return;
          await api(`/api/traffic-protection/rules/${section}/${rule.id}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:'{}'});
          if(trafficEditing[section]===rule.id)resetTrafficPolicy(section);
          await loadTrafficProtection();message('策略已删除。');
        })]
      ]){const button=element('button',label);button.type='button';button.dataset.policyAction=label==='编辑'?'edit':label==='删除'?'delete':'toggle';button.addEventListener('click',handler);actions.append(button);}
      row.append(actions);list.append(row);
    }
    if(!trafficPolicies[section].length){const row=element('tr'),cell=element('td','暂无策略，请点击新增。');cell.colSpan=4;row.append(cell);list.append(row);}
    updateTrafficPolicyActions(section);
  }
  showProtectionFields();
}
for(const section of ['cc','ports']){
  $(`${section}-target_type`).addEventListener('change',showProtectionFields);
  $(`${section}-enabled`).addEventListener('change',showProtectionFields);
  for(const action of ['new','reset'])$(`${section}-${action}`).addEventListener('click',()=>{resetTrafficPolicy(section);$(`${section}-name`).focus();});
  $(`${section}-form`).addEventListener('submit',run(async event=>{
    event.preventDefault();const value={enabled:$(`${section}-enabled`).checked};
    const numeric=section==='cc'?['window_seconds','max_requests','ban_seconds']:['max_concurrent_per_ip','max_concurrent_total'];
    for(const key of numeric)value[key]=Number($(`${section}-${key}`).value);
    value.target_type=$(`${section}-target_type`).value;value.target=value.target_type==='all'?'':$(`${section}-target`).value.trim();
    if(section==='ports'){
      for(const key of ['allowed_sources','blocked_sources'])value[key]=$(`ports-${key}`).value.split(/[\n,，]+/).map(item=>item.trim()).filter(Boolean);
      value.protocol=$('ports-protocol').value;value.destination_port=$('ports-destination_port').value?Number($('ports-destination_port').value):null;
    }
    const id=trafficEditing[section],button=event.currentTarget.querySelector('button[type=submit]');button.disabled=true;
    try{
      await api(`/api/traffic-protection/rules/${section}${id?'/'+id:''}`,{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$(`${section}-name`).value.trim(),config:value})});
      resetTrafficPolicy(section);await loadTrafficProtection();message('策略已保存并立即生效。');
    }finally{button.disabled=false;}
  }));
}

let customRules=[],editingCustomRule='';
const customActions={block:'拦截 / 黑名单',allow:'放行 / 白名单',monitor:'仅记录'};
async function loadCustomRules(){
  customRules=await api('/api/custom-rules');$('custom-rule-list').replaceChildren();
  for(const rule of [...customRules].sort((a,b)=>a.priority-b.priority||a.id.localeCompare(b.id))){
    const row=element('tr'),state=!rule.enabled?'已停用':rule.expires_at&&new Date(rule.expires_at)<=new Date()?'已到期':'已启用';
    const conditions=[rule.source_ip&&`IP ${rule.source_ip}`,rule.domain&&`域名 ${rule.domain}`,rule.methods.length&&rule.methods.join(','),rule.path&&`路径 ${rule.path_match} ${rule.path}`,rule.keyword&&`URL 包含 ${rule.keyword}`].filter(Boolean).join('；')||'全部请求';
    row.append(element('td',`${rule.priority} · ${rule.name}（${rule.id}）`),element('td',`${customActions[rule.action]} · ${state}`),element('td',conditions),element('td',rule.expires_at?new Date(rule.expires_at).toLocaleString():'长期有效'));
    const actions=element('td');
    for(const [label,handler] of [['编辑',()=>editCustomRule(rule)], [rule.enabled?'停用':'启用',run(async()=>{
      const {id,...value}=rule;await api(`/api/custom-rules/${id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...value,enabled:!rule.enabled})});await loadCustomRules();message('规则状态已更新。');
    })], ['删除',run(async()=>{
      await api(`/api/custom-rules/${rule.id}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:'{}'});if(editingCustomRule===rule.id)resetCustomRule();await loadCustomRules();message('自定义规则已删除。');
    })]]){const button=element('button',label);button.type='button';button.addEventListener('click',handler);actions.append(button);}
    row.append(actions);row.dataset.ruleId=rule.id;$('custom-rule-list').append(row);
  }
  if(!customRules.length){const row=element('tr'),cell=element('td','暂无自定义规则，可新增紧急拦截、IP 黑名单或白名单。');cell.colSpan=5;row.append(cell);$('custom-rule-list').append(row);}
}
function resetCustomRule(){editingCustomRule='';$('custom-rule-form').reset();$('custom-rule-title').textContent='新增自定义防护规则';}
function editCustomRule(rule){
  resetCustomRule();editingCustomRule=rule.id;$('custom-rule-title').textContent=`编辑：${rule.name}（${rule.id}）`;
  for(const key of ['name','action','priority','source_ip','domain','path','path_match','keyword'])$(`custom-${key}`).value=rule[key];
  for(const key of ['enabled','case_sensitive','match_all'])$(`custom-${key}`).checked=rule[key];
  $('custom-methods').value=rule.methods.join(',');
  if(rule.expires_at){const date=new Date(rule.expires_at);$('custom-expires_at').value=new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);}
  $('custom-rule-form').scrollIntoView({block:'start'});
}
function quickCustom(action,name,priority){resetCustomRule();$('custom-action').value=action;$('custom-name').value=name;$('custom-priority').value=priority;$('custom-rule-form').scrollIntoView({block:'start'});$(action==='allow'||name==='IP 黑名单'?'custom-source_ip':'custom-domain').focus();}
$('new-custom-rule').addEventListener('click',()=>{resetCustomRule();$('custom-rule-form').scrollIntoView({block:'start'});$('custom-name').focus();});
$('quick-blacklist').addEventListener('click',()=>quickCustom('block','IP 黑名单',10));
$('quick-whitelist').addEventListener('click',()=>quickCustom('allow','IP 白名单',20));
$('quick-emergency').addEventListener('click',()=>quickCustom('block','紧急防护',1));
$('cancel-custom-edit').addEventListener('click',resetCustomRule);
$('custom-rule-form').addEventListener('submit',run(async event=>{
  event.preventDefault();
  const value={};
  for(const key of ['name','action','source_ip','domain','path','path_match','keyword'])value[key]=$(`custom-${key}`).value.trim();
  for(const key of ['enabled','case_sensitive','match_all'])value[key]=$(`custom-${key}`).checked;
  value.priority=Number($('custom-priority').value);value.methods=$('custom-methods').value.split(/[,，\s]+/).filter(Boolean);
  value.expires_at=$('custom-expires_at').value?new Date($('custom-expires_at').value).toISOString():null;
  const button=event.currentTarget.querySelector('button[type=submit]');button.disabled=true;
  try{await api(editingCustomRule?`/api/custom-rules/${editingCustomRule}`:'/api/custom-rules',{method:editingCustomRule?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});resetCustomRule();await loadCustomRules();message('自定义规则已保存并立即生效。');}
  finally{button.disabled=false;}
}));
