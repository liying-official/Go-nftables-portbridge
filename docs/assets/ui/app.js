'use strict';
const $=id=>document.getElementById(id);
const {t,translateAPIError}=window.PB_I18N;
let token='';try{token=sessionStorage.getItem('portbridge_demo_session')||'';}catch{}
let csrf='',rules=[],timer=null,sessionEpoch=0;
let polling=false;let statusRequest=null;
let lastStatus=null,lastTLS=null,view='overview',newToken='',confirmation=null;
const feedback={login:null,settings:null,rule:null,toast:null};
const ruleModal=new tabler.Modal($('ruleDialog'));
const confirmModal=new tabler.Modal($('confirmDialog'));
const toastView=new tabler.Toast($('toast'),{delay:2600});
const mobileNavigation=window.matchMedia?window.matchMedia('(max-width:991px)'):{matches:false,addEventListener(){}};

function saveSession(){try{if(token)sessionStorage.setItem('portbridge_demo_session',token);else sessionStorage.removeItem('portbridge_demo_session');}catch{}}
function setFeedback(slot,key,args={},error=''){feedback[slot]={key,args,error};renderFeedback();}
function localizedError(key,args={}){const error=new Error(t(key,args));error.messageKey=key;error.messageArgs=args;return error;}
function showError(slot,error){if(error.messageKey)setFeedback(slot,error.messageKey,error.messageArgs);else setFeedback(slot,'',{},error.message);if(slot==='toast')toastView.show();}
function renderFeedback(){for(const [slot,id] of Object.entries({login:'loginError',settings:'settingsMsg',rule:'ruleError',toast:'toastMessage'})){const value=feedback[slot];$(id).textContent=value?(value.error?translateAPIError(value.error):t(value.key,value.args)):'';}}
function setBusy(form,busy){form.dataset.busy=String(busy);for(const button of form.querySelectorAll('button[type=submit]'))button.disabled=busy;}
async function api(path,opts={}){
  const requestToken=token,epoch=sessionEpoch;
  const headers={...(opts.headers||{}),'Authorization':'Bearer '+requestToken};
  if(opts.method&&opts.method!=='GET')headers['X-PortBridge-CSRF']=csrf;
  if(opts.body)headers['Content-Type']='application/json';
  const response=await window.PB_DEMO.request(path,{...opts,headers});
  if(response.status===401){if(requestToken===token&&epoch===sessionEpoch){token='';sessionEpoch++;saveSession();showLogin();setFeedback('login','invalidToken');}throw localizedError('unauthorized');}
  if(response.status===204)return null;
  let data={};try{data=await response.json();}catch{}
  if(!response.ok)throw data.error?new Error(data.error):localizedError('requestFailed',{status:response.status});
  if(requestToken!==token||epoch!==sessionEpoch)throw localizedError('sessionChanged');
  return data;
}
function showTransportWarning(){const loopback=['localhost','127.0.0.1','::1','[::1]'].includes(location.hostname);$('insecureWarning').classList.toggle('hidden',location.protocol==='https:'||loopback);}
function stopTimer(){polling=false;clearTimeout(timer);timer=null;}
function startTimer(){stopTimer();polling=true;const poll=async()=>{await loadStatus();if(polling)timer=setTimeout(poll,500);};timer=setTimeout(poll,500);}
function clearManagementView(){
  csrf='';rules=[];lastStatus=null;lastTLS=null;newToken='';
  $('uptime').textContent=t('uptimeEmpty');for(const id of ['ruleCount','runningCount','activeTCP','activeUDP'])$(id).textContent='0';$('bytesUp').textContent='0 B';$('bytesDown').textContent='0 B';renderRules([]);
  for(const id of ['autoACL','whiteACL','bootstrapACL'])renderChips(id,[]);
  $('settingsForm').reset();for(const id of ['whitelist','dnsServers','tlsCertFile','tlsKeyFile'])$(id).value='';
  $('ruleForm').reset();$('ruleId').value='';ruleModal.hide();dismissConfirmation(false);
  $('tokenResult').textContent='';$('tokenResult').classList.add('hidden');toastView.hide();
  for(const key of Object.keys(feedback))feedback[key]=null;renderFeedback();renderTLS(null);syncStrictUI();closeNavigation();setView('overview');
}
function showLogin(){stopTimer();$('appShell').hidden=true;$('login').classList.remove('hidden');clearManagementView();}
function hideLogin(){$('login').classList.add('hidden');$('appShell').hidden=false;feedback.login=null;renderFeedback();}
async function bootstrap(){showTransportWarning();const epoch=sessionEpoch;if(token){try{await establishSession();if(epoch!==sessionEpoch)return;hideLogin();startTimer();}catch(error){if(epoch!==sessionEpoch)return;showLogin();showError('login',error);}}else showLogin();}
async function establishSession(){const result=await api('/api/bootstrap');csrf=result.csrf;await loadAll();}
async function loadAll(){await Promise.all([loadConfig(),loadStatus()]);}
async function loadConfig(){
  const requestToken=token,epoch=sessionEpoch;const cfg=await api('/api/config');if(!token||token!==requestToken)return;if(epoch!==sessionEpoch)return;
  rules=cfg.rules||[];$('autoLan').checked=cfg.web.auto_lan_acl;$('strictAllowlist').checked=!!cfg.web.strict_ip_allowlist;
  $('whitelist').value=(cfg.web.whitelist||[]).join('\n');$('dnsServers').value=(cfg.web.dns_servers||[]).join('\n');$('webPort').value=cfg.web.port;$('webIPv4').value=cfg.web.listen_ipv4;$('webIPv6').value=cfg.web.listen_ipv6;
  $('tlsCertFile').value=cfg.web.tls_cert_file||'';$('tlsKeyFile').value=cfg.web.tls_key_file||'';$('tlsMinVersion').value=cfg.web.tls_min_version==='1.3'?'1.3':'1.2';lastTLS=cfg.https;renderTLS(lastTLS);syncStrictUI();
}
async function loadStatus(){
  if(statusRequest)return statusRequest;
  const requestToken=token,epoch=sessionEpoch;
  statusRequest=(async()=>{try{const status=await api('/api/status');if(!token||token!==requestToken)return;if(epoch!==sessionEpoch)return;lastStatus=status;rules=status.rules.map(x=>x.rule);renderStatus(status);}catch(error){if(token===requestToken&&token&&epoch===sessionEpoch)console.error(error.message);}})();
  try{return await statusRequest;}finally{statusRequest=null;}
}
function renderStatus(status){
  $('uptime').textContent=t('uptime',{value:duration(status.uptime_seconds)});$('ruleCount').textContent=status.rules.length;$('runningCount').textContent=status.rules.filter(x=>x.stats.running).length;
  const sum=key=>status.rules.reduce((n,x)=>n+(x.stats[key]||0),0);$('activeTCP').textContent=sum('active_tcp');$('activeUDP').textContent=sum('active_udp_sessions');$('bytesUp').textContent=trafficSummary(status.rules,'bytes_up');$('bytesDown').textContent=trafficSummary(status.rules,'bytes_down');
  renderRules(status.rules);renderChips('autoACL',status.acl.auto);renderChips('whiteACL',status.acl.whitelist);renderChips('bootstrapACL',status.acl.bootstrap);
}
function icon(name){return `<svg class="icon" aria-hidden="true"><use href="assets/ui/tabler-icons.svg#${name}"></use></svg>`;}
function activityText(rule,stats,plane){
  if(plane==='nftables')return esc(t('kernelActivity'))+`<span class="sub">${esc(t('conntrackActivity'))}</span>`;
  const suffix=plane==='hybrid'?`<span class="sub">${esc(t('goActivityOnly'))}</span>`:'';
  const udp=`<span class="sub">${esc(t('udpActivity',{up:stats.udp_packets_up||0,down:stats.udp_packets_down||0,drops:stats.udp_drops||0}))}</span>`;
  if(rule.protocol==='both')return `TCP ${Number(stats.active_tcp)||0} / UDP ${Number(stats.active_udp_sessions)||0}<span class="sub">${esc(t('totalTCPUDP',{tcp:stats.total_tcp||0,udp:stats.total_udp_sessions||0}))}</span>${udp}${suffix}`;
  return `${Number(rule.protocol==='tcp'?stats.active_tcp:stats.active_udp_sessions)||0}<span class="sub">${esc(t('total',{value:rule.protocol==='tcp'?stats.total_tcp:stats.total_udp_sessions}))}</span>${rule.protocol==='udp'?udp:''}${suffix}`;
}
function renderRules(items){
  const body=$('rulesBody');body.textContent='';$('emptyRules').hidden=items.length>0;
  const cell=(label,html,cls='')=>`<td data-label="${esc(t(label))}"><div${cls?` class="${cls}"`:''}>${html}</div></td>`;
  for(const item of items){
    const r=item.rule,stats=item.stats,plane=item.data_plane||'go-proxy',row=document.createElement('tr');
    const state=stats.last_error?'error':stats.running?'running':'stopped';
    const status=`<span class="badge pb-status-${state}">${esc(t(state))}</span>`+(stats.last_error?`<span class="sub" title="${esc(translateAPIError(stats.last_error))}">${esc(short(translateAPIError(stats.last_error),45))}</span>`:'');
    row.innerHTML=cell('status',status)+cell('name',esc(r.name),'pb-rule-name')+cell('protocol',`<span class="badge">${esc(r.protocol==='both'?'TCP + UDP':r.protocol.toUpperCase())}</span>`)+cell('plane',`<span class="badge">${esc(r.data_plane==='go'?'GO':t('nftFirst'))}</span>`)+cell('listen',esc(endpoint(r.listen_host,r.listen_port,r.listen_port_end)),'pb-endpoint')+cell('target',esc(endpoint(r.target_host,r.target_port,r.target_port_end)),'pb-endpoint')+cell('activity',activityText(r,stats,plane))+cell('traffic',trafficText(item))+cell('actions',`<button type="button" class="btn btn-sm" data-edit="${esc(r.id)}" aria-label="${esc(t('edit'))}">${icon('pencil')}</button><button type="button" class="btn btn-sm" data-del="${esc(r.id)}" aria-label="${esc(t('remove'))}">${icon('trash')}</button>`,'pb-rule-actions');
    body.appendChild(row);
  }
  body.querySelectorAll('[data-edit]').forEach(button=>button.onclick=()=>openRule(button.dataset.edit));body.querySelectorAll('[data-del]').forEach(button=>button.onclick=()=>deleteRule(button.dataset.del));
}
function renderChips(id,items){const target=$(id);target.textContent='';if(!items?.length){target.textContent=t('none');return;}for(const value of items){const chip=document.createElement('span');chip.className='pb-chip';chip.textContent=value;target.appendChild(chip);}}
function syncStrictUI(){const strict=$('strictAllowlist').checked;if(strict)$('autoLan').checked=false;$('autoLan').disabled=strict;$('strictAllowlist').disabled=location.protocol!=='https:'&&!strict;}
function renderTLS(info){const cert=info?.certificate;$('selfSignedWarning').classList.toggle('hidden',!cert?.enabled||!cert.self_signed);$('certificateStatus').textContent=cert?.enabled?t(cert.self_signed?'certificateSelf':'certificateOther')+' SHA-256: '+cert.sha256+' · '+t('certificateExpiry',{date:new Date(cert.not_after).toLocaleString(window.PB_I18N.language())}):t('certificateNone');}
function renderNewToken(){$('tokenResult').textContent=newToken?t('newToken')+' '+newToken:'';$('tokenResult').classList.toggle('hidden',!newToken);}
function setView(next){if(!['overview','rules','access'].includes(next))return;const changed=view!==next;view=next;const key=next==='overview'?'dashboard':next;$('pageTitle').dataset.i18n=key;$('pageHint').dataset.i18n=key+'Hint';$('pageTitle').textContent=t(key);$('pageHint').textContent=t(key+'Hint');for(const panel of document.querySelectorAll('[data-page]'))panel.hidden=!panel.dataset.page.split(' ').includes(next);for(const link of document.querySelectorAll('.pb-nav [data-nav]')){link.classList.toggle('active',link.dataset.nav===next);if(link.dataset.nav===next)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');}closeNavigation();if(changed){document.documentElement.scrollTop=0;document.body.scrollTop=0;}}
function closeNavigation(){const wasOpen=document.body.classList.contains('pb-nav-open');document.body.classList.remove('pb-nav-open');$('navBackdrop').hidden=true;$('openNav').setAttribute('aria-expanded','false');$('sidebar').inert=mobileNavigation.matches;if(mobileNavigation.matches)$('sidebar').setAttribute('aria-hidden','true');else $('sidebar').removeAttribute('aria-hidden');if(wasOpen&&$('sidebar').contains(document.activeElement))$('openNav').focus();}
function askConfirmation(title,body,args={}){dismissConfirmation(false);return new Promise(resolve=>{confirmation={title,body,args,resolve};$('confirmTitle').textContent=t(title,args);$('confirmBody').textContent=t(body,args);confirmModal.show();});}
function dismissConfirmation(accepted){const pending=confirmation;confirmation=null;confirmModal.hide();if(pending)pending.resolve(accepted);}
function toast(key,args={},error=''){setFeedback('toast',key,args,error);toastView.show();}

const numericRuleFields={connectTimeout:['connect_timeout_seconds',10],tcpIdleTimeout:['tcp_idle_timeout_seconds',300],maxTcpConnections:['max_tcp_connections',2048],maxTcpConnectionsPerSource:['max_tcp_connections_per_source',256],udpTimeout:['udp_idle_timeout_seconds',60],maxUdpSessions:['max_udp_sessions',4096],maxUdpSessionsPerSource:['max_udp_sessions_per_source',512],udpNewSessionsPerSecond:['udp_new_sessions_per_second_per_source',1000],udpPacketsPerSecond:['udp_packets_per_second_per_source',100000],udpWorkers:['udp_workers',0],udpBatchSize:['udp_batch_size',64],udpPacketBufferSize:['udp_packet_buffer_size',2048],udpListenerBufferBytes:['udp_listener_buffer_bytes',4194304],udpSessionBufferBytes:['udp_session_buffer_bytes',65536]};
function openRule(id){
  const r=rules.find(x=>x.id===id);$('dialogTitle').dataset.i18n=r?'editRule':'addRule';$('dialogTitle').textContent=t(r?'editRule':'addRule');$('ruleId').value=r?.id||'';$('ruleName').value=r?.name||'';$('protocol').value=r?.protocol||'tcp';$('ruleDataPlane').value=r?.data_plane||'nftables';$('enabled').checked=r?.enabled??true;
  for(const [field,key,fallback] of [['listenHost','listen_host','*'],['listenPort','listen_port',''],['listenPortEnd','listen_port_end',''],['targetHost','target_host',''],['targetPort','target_port',''],['targetPortEnd','target_port_end','']])$(field).value=r?.[key]||fallback;
  $('allowPrivateTarget').checked=!!r?.allow_private_target;$('targetCIDRAllowlist').value=(r?.target_cidr_allowlist||[]).join('\n');for(const [field,[key,fallback]] of Object.entries(numericRuleFields))$(field).value=r?.[key]??fallback;
  feedback.rule=null;renderFeedback();ruleModal.show();
}
function closeRule(){ruleModal.hide();}
const lines=id=>$(id).value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
async function deleteRule(id){const r=rules.find(x=>x.id===id),epoch=sessionEpoch;if(!await askConfirmation('confirmDelete','confirmDeleteBody',{name:r?.name||id})||!token||epoch!==sessionEpoch)return;try{await api('/api/rules/'+encodeURIComponent(id),{method:'DELETE'});toast('ruleDeleted');await loadAll();}catch(error){if(token&&epoch===sessionEpoch)showError('toast',error);}}

$('loginForm').addEventListener('submit',async event=>{event.preventDefault();if(event.currentTarget.dataset.busy==='true')return;setBusy($('loginForm'),true);token=$('tokenInput').value.trim();sessionEpoch++;try{await establishSession();saveSession();$('tokenInput').value='';hideLogin();startTimer();}catch(error){token='';saveSession();showLogin();showError('login',error);}finally{setBusy($('loginForm'),false);}});
$('logoutBtn').onclick=()=>{token='';sessionEpoch++;saveSession();showLogin();};
$('strictAllowlist').addEventListener('change',syncStrictUI);
$('settingsForm').addEventListener('submit',async event=>{
  event.preventDefault();if(event.currentTarget.dataset.busy==='true')return;setBusy($('settingsForm'),true);feedback.settings=null;renderFeedback();const epoch=sessionEpoch;
  try{const result=await api('/api/settings',{method:'PUT',body:JSON.stringify({auto_lan_acl:$('autoLan').checked,strict_ip_allowlist:$('strictAllowlist').checked,allow_insecure_http:false,whitelist:lines('whitelist'),dns_servers:lines('dnsServers'),port:Number($('webPort').value),listen_ipv4:$('webIPv4').value.trim(),listen_ipv6:$('webIPv6').value.trim(),tls_cert_file:$('tlsCertFile').value.trim(),tls_key_file:$('tlsKeyFile').value.trim(),tls_min_version:$('tlsMinVersion').value})});setFeedback('settings',result.restart_required?'savedRestart':'saved');await loadAll();}catch(error){if(token&&epoch===sessionEpoch)showError('settings',error);}finally{setBusy($('settingsForm'),false);}
});
$('rotateTokenBtn').onclick=async()=>{const epoch=sessionEpoch;if(!await askConfirmation('confirmRotate','confirmRotateBody')||!token||epoch!==sessionEpoch)return;try{const result=await api('/api/token/rotate',{method:'POST'});token=result.token;newToken=result.token;sessionEpoch++;saveSession();renderNewToken();toast('tokenRotated');}catch(error){if(token&&epoch===sessionEpoch)showError('toast',error);}};
$('addRuleBtn').onclick=()=>openRule('');$('closeDialog').onclick=closeRule;$('cancelDialog').onclick=closeRule;
$('ruleForm').addEventListener('submit',async event=>{
  event.preventDefault();if(event.currentTarget.dataset.busy==='true')return;setBusy($('ruleForm'),true);const id=$('ruleId').value,epoch=sessionEpoch;
  const rule={name:$('ruleName').value.trim(),protocol:$('protocol').value,data_plane:$('ruleDataPlane').value,listen_host:$('listenHost').value.trim(),listen_port:Number($('listenPort').value),listen_port_end:Number($('listenPortEnd').value)||0,target_host:$('targetHost').value.trim(),target_port:Number($('targetPort').value),target_port_end:Number($('targetPortEnd').value)||0,enabled:$('enabled').checked,allow_private_target:$('allowPrivateTarget').checked,target_cidr_allowlist:lines('targetCIDRAllowlist')};
  for(const [field,[key]] of Object.entries(numericRuleFields))rule[key]=Number($(field).value);
  try{await api(id?'/api/rules/'+encodeURIComponent(id):'/api/rules',{method:id?'PUT':'POST',body:JSON.stringify(rule)});closeRule();toast(id?'ruleUpdated':'ruleCreated');await loadAll();}catch(error){if(token&&epoch===sessionEpoch)showError('rule',error);}finally{setBusy($('ruleForm'),false);}
});
for(const link of document.querySelectorAll('[data-nav]'))link.addEventListener('click',event=>{event.preventDefault();if(token)setView(link.dataset.nav);});
$('openNav').onclick=()=>{document.body.classList.add('pb-nav-open');$('sidebar').inert=false;$('sidebar').removeAttribute('aria-hidden');$('navBackdrop').hidden=false;$('openNav').setAttribute('aria-expanded','true');};$('closeNav').onclick=closeNavigation;$('navBackdrop').onclick=closeNavigation;mobileNavigation.addEventListener('change',closeNavigation);
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeNavigation();});
$('confirmAccept').onclick=()=>dismissConfirmation(true);$('confirmDialog').addEventListener('hidden.bs.modal',()=>{if(confirmation){const pending=confirmation;confirmation=null;pending.resolve(false);}});
document.addEventListener('portbridge:language',()=>{setView(view);if(lastStatus&&token)renderStatus(lastStatus);else $('uptime').textContent=t('uptimeEmpty');renderTLS(lastTLS);renderFeedback();renderNewToken();if(confirmation){$('confirmTitle').textContent=t(confirmation.title,confirmation.args);$('confirmBody').textContent=t(confirmation.body,confirmation.args);}});

function endpoint(host,port,end){const ports=end&&end!==port?`${port}-${end}`:`${port}`;return host.includes(':')?`[${host}]:${ports}`:`${host}:${ports}`;}
function duration(value){const seconds=Math.max(0,Number(value)||0),days=Math.floor(seconds/86400),hours=Math.floor(seconds%86400/3600),minutes=Math.floor(seconds%3600/60);return days?t('daysHours',{days,hours}):hours?t('hoursMinutes',{hours,minutes}):t('minutes',{minutes});}
function bytes(value){let n=Number(value)||0,index=0;const units=['B','KiB','MiB','GiB','TiB'];while(n>=1024&&index<units.length-1){n/=1024;index++;}return `${n.toFixed(index?1:0)} ${units[index]}`;}
function esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function short(value,length){return String(value).length>length?String(value).slice(0,length)+'…':String(value);}
function trafficSummary(items,key){const go=items.reduce((sum,item)=>sum+(item.traffic?.go?.[key]||0),0),nft=items.filter(item=>item.traffic?.nft_best_effort);const total=go+nft.reduce((sum,item)=>sum+(item.traffic.nft?.[key]||0),0);return (nft.length?'≈ ':'')+bytes(total)+(nft.some(item=>!item.traffic.nft?.available)?t('partial'):'');}
function trafficSeries(label,series){if(!series?.available)return `<span class="sub">${esc(label)}: ${esc(t('unavailable'))}</span>`;const rate=series.rate_ready?`${bytes(series.bytes_up_per_second)}/s ↑ / ${bytes(series.bytes_down_per_second)}/s ↓`:t('rateWarmup');return `<span class="sub">${esc(label)} ${esc(rate)}</span>`;}
function trafficText(item){const traffic=item.traffic||{},plane=item.data_plane||'go-proxy';let html=`<span class="sub">${esc(trafficSummary([item],'bytes_up'))} ↑ / ${esc(trafficSummary([item],'bytes_down'))} ↓</span>`;if(plane==='go-proxy'||plane==='hybrid')html+=trafficSeries('Go',traffic.go);if(plane==='nftables'||plane==='hybrid')html+=trafficSeries('nft',traffic.nft);return html;}
$('resetDemoBtn').onclick=async()=>{window.PB_DEMO.reset();await loadAll();toast('demoResetDone');};
closeNavigation();syncStrictUI();bootstrap().catch(error=>{showLogin();showError('login',error);});
