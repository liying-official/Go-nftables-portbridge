'use strict';
(() => {
  // Public UI gate only. This value is intentionally not a secret.
  const password = 'PortBridge';
  const csrf = 'public-demo-csrf-not-a-security-token';
  const copy = value => JSON.parse(JSON.stringify(value));
  const defaults = {
    connect_timeout_seconds:10,tcp_idle_timeout_seconds:300,max_tcp_connections:2048,max_tcp_connections_per_source:256,
    udp_idle_timeout_seconds:60,max_udp_sessions:4096,max_udp_sessions_per_source:512,udp_new_sessions_per_second_per_source:1000,
    udp_packets_per_second_per_source:100000,udp_workers:0,udp_batch_size:64,udp_packet_buffer_size:2048,
    udp_listener_buffer_bytes:4194304,udp_session_buffer_bytes:65536,listen_port_end:0,target_port_end:0,
    allow_private_target:false,target_cidr_allowlist:[]
  };
  const initial = [
    {id:'demo-web',name:'DEMO · Web TCP',protocol:'tcp',data_plane:'nftables',listen_host:'0.0.0.0',listen_port:8443,target_host:'192.0.2.20',target_port:443,enabled:true},
    {id:'demo-udp',name:'DEMO · UDP proxy',protocol:'udp',data_plane:'go',listen_host:'0.0.0.0',listen_port:27015,target_host:'198.51.100.30',target_port:27015,enabled:true},
    {id:'demo-dual',name:'DEMO · Dual stack',protocol:'both',data_plane:'nftables',listen_host:'*',listen_port:10080,target_host:'2001:db8::20',target_port:8080,enabled:true},
    {id:'demo-range',name:'DEMO · Port range',protocol:'both',data_plane:'go',listen_host:'127.0.0.1',listen_port:20000,listen_port_end:20009,target_host:'203.0.113.40',target_port:30000,target_port_end:30009,enabled:false}
  ];
  let rules, web, counters, lastSample, started, sequence;
  function reset() {
    rules=initial.map(rule=>({...copy(defaults),...rule}));
    web={port:9080,listen_ipv4:'127.0.0.1',listen_ipv6:'::1',auto_lan_acl:false,strict_ip_allowlist:true,allow_insecure_http:false,
      whitelist:['192.0.2.10/32'],tls_cert_file:'/demo/tls/fullchain.pem',tls_key_file:'/demo/tls/privkey.pem',tls_min_version:'1.3',dns_servers:[]};
    counters=new Map();started=performance.now();lastSample=started;sequence=0;
  }
  function plane(rule) {return !rule.enabled?'disabled':rule.data_plane==='go'?'go-proxy':rule.listen_host==='*'?'hybrid':'nftables';}
  function series(up,down,rateUp,rateDown,now,enabled) {
    return {bytes_up:Math.floor(up),bytes_down:Math.floor(down),packets_up:Math.floor(up/1100),packets_down:Math.floor(down/1100),
      bytes_up_per_second:enabled?rateUp:0,bytes_down_per_second:enabled?rateDown:0,packets_up_per_second:enabled?rateUp/1100:0,packets_down_per_second:enabled?rateDown/1100:0,
      sampled_at:now,interval_seconds:1,available:true,rate_ready:true};
  }
  function status() {
    const tick=performance.now(),elapsed=(tick-started)/1000,delta=tick-lastSample>=1000?(tick-lastSample)/1000:0;
    if(delta)lastSample=tick;
    const timestamp=new Date().toISOString();
    return {uptime_seconds:Math.floor(elapsed)+172800,acl:{auto:['127.0.0.0/8','::1/128'],whitelist:copy(web.whitelist),bootstrap:[],strict:web.strict_ip_allowlist},rules:rules.map((rule,index)=>{
      const active=rule.enabled,p=plane(rule),go=p==='go-proxy'||p==='hybrid',nft=p==='nftables'||p==='hybrid';
      let count=counters.get(rule.id);
      if(!count){count={goUp:go?2**28*(index+1):0,goDown:go?2**30*(index+1):0,nftUp:nft?2**30*(index+2):0,nftDown:nft?2**32*(index+2):0};counters.set(rule.id,count);}
      const rate=(index+1)*150000*(1+0.18*Math.sin(elapsed/3+index));
      const gu=go?rate:0,gd=go?rate*1.8:0,nu=nft?rate*3:0,nd=nft?rate*5:0;
      if(delta&&active){count.goUp+=gu*delta;count.goDown+=gd*delta;count.nftUp+=nu*delta;count.nftDown+=nd*delta;}
      return {rule:copy(rule),data_plane:p,go_running:go,kernel_state:nft?'active-verified':'inactive-verified',
        stats:{running:active,started_at:timestamp,active_tcp:active&&go&&rule.protocol!=='udp'?8+index:0,active_udp_sessions:active&&go&&rule.protocol!=='tcp'?24+index*3:0,
          total_tcp:active?1240+index*10:0,total_udp_sessions:active?328+index*5:0,tcp_rejected:0,bytes_up:Math.floor(count.goUp),bytes_down:Math.floor(count.goDown),
          udp_packets_up:rule.protocol==='tcp'?0:Math.floor(count.goUp/1100),udp_packets_down:rule.protocol==='tcp'?0:Math.floor(count.goDown/1100),udp_drops:0},
        traffic:{go:series(count.goUp,count.goDown,gu,gd,timestamp,active),nft:series(count.nftUp,count.nftDown,nu,nd,timestamp,active),
          nft_hooks:[],nft_hooks_available:nft,nft_hooks_sampled_at:timestamp,nft_best_effort:nft,nft_status:nft?'sampled':'not_applicable',counter_resets:0}};
    })};
  }
  const response=(code,data)=>new Response(code===204?null:JSON.stringify(data),{status:code,headers:{'Content-Type':'application/json'}});
  const fail=(code,key)=>response(code,{error:window.PB_I18N.t(key)});
  const port=value=>Number.isInteger(value)&&value>=1&&value<=65535;
  function validRule(rule) {
    const listenEnd=rule.listen_port_end||rule.listen_port,targetEnd=rule.target_port_end||rule.target_port;
    return typeof rule.name==='string'&&rule.name.trim()&&new TextEncoder().encode(rule.name.trim()).length<=80&&
      ['tcp','udp','both'].includes(rule.protocol)&&['go','nftables'].includes(rule.data_plane)&&
      typeof rule.listen_host==='string'&&rule.listen_host&&typeof rule.target_host==='string'&&rule.target_host&&rule.target_host.length<=253&&
      [rule.listen_port,listenEnd,rule.target_port,targetEnd].every(port)&&listenEnd>=rule.listen_port&&targetEnd>=rule.target_port&&
      listenEnd-rule.listen_port===targetEnd-rule.target_port&&listenEnd-rule.listen_port<4096&&typeof rule.enabled==='boolean';
  }
  async function request(path,options={}) {
    // Never fall back to fetch. Unknown paths and methods stay local and fail.
    const headers=new Headers(options.headers||{}),method=options.method||'GET';
    if(headers.get('Authorization')!=='Bearer '+password)return fail(401,'invalidToken');
    if(method!=='GET'&&headers.get('X-PortBridge-CSRF')!==csrf)return fail(403,'demoInvalidRequest');
    let body;
    if(options.body!==undefined){try{body=JSON.parse(options.body);}catch{return fail(400,'demoInvalidRequest');}}
    if(method==='GET'&&path==='/api/bootstrap')return response(200,{csrf,name:'PortBridge static demo'});
    if(method==='GET'&&path==='/api/config')return response(200,{web:copy(web),rules:copy(rules),https:{required:true,certificate:{enabled:true,self_signed:false,sha256:'0123456789abcdef'.repeat(4),not_after:'2036-01-01T00:00:00Z'}}});
    if(method==='GET'&&path==='/api/status')return response(200,status());
    if(method==='POST'&&path==='/api/token/rotate')return response(200,{token:password});
    if(method==='PUT'&&path==='/api/settings'){
      if(!body||!port(body.port)||!['1.2','1.3'].includes(body.tls_min_version)||!body.tls_cert_file||!body.tls_key_file||
         !Array.isArray(body.whitelist)||!Array.isArray(body.dns_servers)||body.allow_insecure_http||
         (body.strict_ip_allowlist&&(!body.whitelist.length||body.auto_lan_acl)))return fail(400,'demoInvalidSettings');
      web=copy(body);return response(200,{ok:true,restart_required:false});
    }
    if(method==='POST'&&path==='/api/rules'){
      if(rules.length>=100)return fail(400,'demoLimit');
      if(!body||!validRule(body))return fail(400,'demoInvalidRule');
      const rule={...copy(defaults),...copy(body),id:'demo-created-'+(++sequence)};rules.push(rule);return response(201,copy(rule));
    }
    if(typeof path==='string'&&path.startsWith('/api/rules/')){
      let id;try{id=decodeURIComponent(path.slice('/api/rules/'.length));}catch{return fail(400,'demoInvalidRequest');}
      const index=rules.findIndex(rule=>rule.id===id);
      if(index===-1)return fail(404,'demoInvalidRequest');
      if(method==='DELETE'){rules.splice(index,1);counters.delete(id);return response(204);}
      if(method==='PUT'){
        if(!body||!validRule(body))return fail(400,'demoInvalidRule');
        rules[index]={...copy(defaults),...copy(body),id};return response(200,copy(rules[index]));
      }
    }
    return fail(404,'demoInvalidRequest');
  }
  reset();
  window.PB_DEMO=Object.freeze({request,reset});
})();
