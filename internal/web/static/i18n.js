'use strict';
(() => {
  const messages = {
    'en-US': {
      title:'PortBridge · Port forwarding', language:'Language', dashboard:'Overview', rules:'Forwarding rules', access:'Access & security', navigation:'Navigation', menu:'Open navigation', close:'Close', administrator:'Administrator', logout:'Sign out', uptime:'Uptime {value}', uptimeEmpty:'Uptime —',
      signIn:'Sign in to PortBridge', signInHint:'Use the administrator token generated during installation.', adminToken:'Administrator token', enter:'Open dashboard', sessionOnly:'The token stays in this browser tab’s session. Sign out when you finish.',
      insecure:'This connection is not using HTTPS. Do not enter an administrator token over a public or untrusted network.',
      selfSigned:'This service uses a self-signed HTTPS certificate. Verify its SHA-256 fingerprint through a trusted channel before trusting it. You can replace it with your own certificate in access settings and restart the service.',
      dashboardHint:'Forwarding activity, at a glance.', rulesHint:'Choose nftables first or force Go for each rule. Cross-family traffic always uses Go.', accessHint:'Manage trusted sources, DNS and HTTPS without changing your forwarding rules.',
      ruleCount:'Rules', running:'Running', stopped:'Stopped', error:'Error', tcpConnections:'TCP connections', udpSessions:'UDP sessions', upload:'Observed upload', download:'Observed download',
      trafficNotice:'UI refresh interval: 500ms. Go counts payload; nft counts observed L3 traffic on a best-effort basis. Flowtable synchronization may lag and short flows may be missed; hook counters do not cover all fast-path traffic.',
      addRule:'Add rule', editRule:'Edit rule', noRules:'No forwarding rules yet.', noRulesHint:'Add your first rule to connect a listening port to its destination.', status:'Status', name:'Name', protocol:'Protocol', plane:'Data plane', listen:'Listener', target:'Destination', activity:'Activity', traffic:'Traffic', actions:'Actions', edit:'Edit', remove:'Delete', nftFirst:'nftables first',
      kernelActivity:'Kernel flowtable forwarding', conntrackActivity:'Connections managed by conntrack', goActivityOnly:'Connections and UDP activity cover Go paths only', totalTCPUDP:'Total TCP {tcp} / UDP {udp}', total:'Total {value}', udpActivity:'UDP packets {up} ↑ / {down} ↓ / dropped {drops}', unavailable:'Warming up or unavailable', rateWarmup:'Rate warming up', partial:' (partial)', none:'None',
      webAccess:'Web access control', directPeer:'Only the direct peer IP is trusted, never proxy headers.', autoLan:'Automatically allow local LAN interface subnets', strict:'Strict IP allowlist',
      httpsHint:'Installation and upgrades require HTTPS. Without a supplied certificate, a ten-year self-signed certificate is generated. Remote access also requires listener and allowlist configuration.',
      strictHint:'Strict mode allows only loopback and the manual allowlist, ignores automatic LAN and temporary startup grants, and requires native TLS. Set matching source restrictions in the host firewall.',
      whitelist:'Allowed IPs / CIDRs (one per line)', dns:'DNS servers (one per line; blank uses system DNS)', dnsHint:'Custom DNS uses ordinary UDP/TCP DNS. Use trusted resolvers; for encrypted DNS, configure a trusted local DoT/DoH stub and enter its address.',
      webPort:'Management port', webIPv4:'IPv4 listener', webIPv6:'IPv6 listener', tlsCert:'TLS certificate absolute path', tlsKey:'TLS private-key absolute path', tlsMin:'Minimum TLS version', tls12:'TLS 1.2 (default)', tls13:'TLS 1.3',
      tlsHint:'To replace a certificate, install the certificate and key on the server, save their absolute paths and restart the service. Renewal at the same paths also requires a restart. The certificate shown here is the one loaded by the running process.',
      saveAccess:'Save access settings', allowedNetworks:'Currently allowed networks', networksHint:'Interface address changes are refreshed periodically.', detected:'Automatic', manual:'Manual allowlist', temporary:'Temporary startup grants', rotate:'Rotate administrator token', rotateHint:'Rotation immediately invalidates the previous token.',
      certificateSelf:'The running process uses a self-signed certificate.', certificateOther:'The running process uses a non-self-signed certificate; clients validate trust.', certificateExpiry:'Expires {date}', certificateNone:'No HTTPS certificate loaded.', newToken:'New token (shown once):',
      ruleBasics:'Rule details', ruleName:'Rule name', ruleNamePlaceholder:'For example: IPv6 to IPv4 web service', enabled:'Enabled', forwardingHint:'nftables first uses flowtable for external same-family traffic and nftables NAT for local output; cross-family and loopback fallback use Go. GO forces the entire rule through the Go proxy.',
      listenAddress:'Listening address', listenStart:'Listening start port', listenEnd:'Listening end port (optional)', targetAddress:'Destination address', targetPlaceholder:'IPv4, IPv6 or hostname', targetStart:'Destination start port', targetEnd:'Destination end port (optional)', singlePort:'Blank for a single port', rangesHint:'Port ranges must have equal lengths, for example 10000–10099 → 20000–20099; at most 4096 ports.',
      targetSecurity:'Destination access', allowPrivate:'Allow local, private or link-local destinations (requires explicit CIDRs below)', targetCIDRs:'Allowed destination CIDRs (one per line)', rebindingHint:'Every DNS refresh validates all A/AAAA answers. Loopback, private, link-local, CGNAT, multicast and cloud metadata addresses are rejected unless explicitly permitted where supported.',
      limits:'Connection limits & timeouts', connectTimeout:'Connect timeout (seconds)', tcpIdle:'TCP idle timeout (seconds)', udpIdle:'UDP idle timeout (seconds)', maxTCP:'Maximum TCP connections', perSourceTCP:'TCP connections per source', maxUDP:'Maximum UDP sessions', perSourceUDP:'UDP sessions per source', newUDPRate:'New UDP sessions / second / source', udpPacketRate:'UDP packets / second / source',
      udpPerformance:'Go UDP performance', udpPerformanceHint:'Go UDP only. The worker budget is shared across the rule’s ports and address families; 0 selects automatically from GOMAXPROCS. Each listener requires at least one worker. Default batch: 64; packet buffer: 2048B.',
      workers:'Total UDP worker budget (0 = automatic)', batch:'Batch size', packetBuffer:'Packet buffer (bytes)', listenerBuffer:'Listener socket buffer (bytes)', sessionBuffer:'Session socket buffer (bytes)', cancel:'Cancel', saveRule:'Save rule', confirm:'Confirm', confirmDelete:'Delete this rule?', confirmDeleteBody:'Delete “{name}”? Its forwarding will stop.', confirmRotate:'Rotate the administrator token?', confirmRotateBody:'The current token will stop working immediately. Save the new token after rotation.',
      ruleCreated:'Rule created', ruleUpdated:'Rule updated', ruleDeleted:'Rule deleted', tokenRotated:'Administrator token rotated', saved:'Saved and applied.', savedRestart:'Saved. Security mode, TLS, listener or port changes require a service restart; the running process is unchanged until then.', invalidToken:'The token is invalid or has been rotated.', unauthorized:'Unauthorized', requestFailed:'Request failed ({status})', sessionChanged:'The session changed; sign in again if needed.', daysHours:'{days}d {hours}h', hoursMinutes:'{hours}h {minutes}m', minutes:'{minutes}m'
    },
    'zh-CN': {
      title:'PortBridge · 端口转发管理', language:'语言', dashboard:'运行概览', rules:'转发规则', access:'访问与安全', navigation:'导航', menu:'打开导航', close:'关闭', administrator:'管理员', logout:'退出', uptime:'运行时间 {value}', uptimeEmpty:'运行时间 —',
      signIn:'登录 PortBridge', signInHint:'请输入安装时生成的管理员令牌。', adminToken:'管理员令牌', enter:'进入管理页面', sessionOnly:'令牌仅保存在当前浏览器标签页会话中，使用完毕后请退出。',
      insecure:'当前连接未使用 HTTPS。公网或不可信网络上不要输入管理员令牌。',
      selfSigned:'当前服务使用自签 HTTPS 证书。请通过可信渠道核对 SHA-256 指纹后再建立信任；可在访问设置中替换正式证书并重启服务。',
      dashboardHint:'转发状态与流量，一目了然。', rulesHint:'每条规则可选择 nftables 优先或强制 Go；跨地址族始终由 Go 代理。', accessHint:'管理可信来源、DNS 与 HTTPS，不改变已有转发规则。',
      ruleCount:'规则', running:'运行中', stopped:'已停止', error:'错误', tcpConnections:'TCP 连接', udpSessions:'UDP 会话', upload:'已观测上行', download:'已观测下行',
      trafficNotice:'界面刷新频率500ms。Go 按有效载荷统计；nft 按已观测 L3 流量尽力统计。flowtable 同步可能延迟，短连接可能遗漏；hook 计数不含全部快速路径',
      addRule:'新增规则', editRule:'编辑规则', noRules:'还没有转发规则。', noRulesHint:'新增第一条规则，将监听端口连接到目标服务。', status:'状态', name:'名称', protocol:'协议', plane:'数据面', listen:'监听', target:'目标', activity:'活动', traffic:'流量', actions:'操作', edit:'编辑', remove:'删除', nftFirst:'nftables 优先',
      kernelActivity:'内核 flowtable 转发', conntrackActivity:'连接由 conntrack 管理', goActivityOnly:'连接与 UDP 活动仅计 Go 路径', totalTCPUDP:'累计 TCP {tcp} / UDP {udp}', total:'累计 {value}', udpActivity:'UDP 包 {up} ↑ / {down} ↓ / 丢弃 {drops}', unavailable:'采样中或不可用', rateWarmup:'速率预热中', partial:'（不完整）', none:'无',
      webAccess:'Web 访问控制', directPeer:'只按直接连接来源 IP 判断，不信任代理请求头。', autoLan:'自动授权本机局域网接口网段', strict:'严格 IP 白名单',
      httpsHint:'安装和升级强制 HTTPS。未提供证书时自动生成有效期 10 年的自签证书；远程访问仍需配置监听地址与白名单。',
      strictHint:'严格模式只允许回环地址和手动白名单，忽略自动 LAN 与启动参数临时授权，并强制原生 TLS。请在主机防火墙中设置相同来源限制。',
      whitelist:'白名单 IP / CIDR（每行一条）', dns:'DNS 服务器（每行一个，留空使用系统 DNS）', dnsHint:'自定义 DNS 使用普通 UDP/TCP DNS，请只填写可信解析器；需要加密 DNS 时，先配置受信的本地 DoT/DoH stub，再填写其地址。',
      webPort:'管理端口', webIPv4:'IPv4 监听', webIPv6:'IPv6 监听', tlsCert:'TLS 证书绝对路径', tlsKey:'TLS 私钥绝对路径', tlsMin:'TLS 最低版本', tls12:'TLS 1.2（默认）', tls13:'TLS 1.3',
      tlsHint:'替换证书时，将证书和私钥放到服务器，保存其绝对路径并重启服务；同路径续期也需重启。此处显示当前进程实际加载的证书。',
      saveAccess:'保存访问设置', allowedNetworks:'当前授权网段', networksHint:'网卡地址变化后会周期性刷新。', detected:'自动识别', manual:'手动白名单', temporary:'启动参数临时授权', rotate:'轮换管理员令牌', rotateHint:'轮换后，旧令牌将立即失效。',
      certificateSelf:'当前进程使用自签证书。', certificateOther:'当前进程使用非自签证书，信任状态由客户端验证。', certificateExpiry:'有效期至 {date}', certificateNone:'尚未加载 HTTPS 证书。', newToken:'新令牌（仅显示一次）：',
      ruleBasics:'规则信息', ruleName:'规则名称', ruleNamePlaceholder:'例如：Web IPv6 转 IPv4', enabled:'启用', forwardingHint:'nftables 优先：外部同族流量走 flowtable，本机 output 走 nftables NAT，跨族及回环回退走 Go；GO：整条规则强制使用 Go 代理。',
      listenAddress:'监听地址', listenStart:'监听起始端口', listenEnd:'监听结束端口（可选）', targetAddress:'目标地址', targetPlaceholder:'IPv4、IPv6 或域名', targetStart:'目标起始端口', targetEnd:'目标结束端口（可选）', singlePort:'单端口留空', rangesHint:'端口段必须等长，例如 10000–10099 → 20000–20099；最多 4096 个端口。',
      targetSecurity:'目标访问权限', allowPrivate:'允许本地、私有或链路本地目标（需下方 CIDR 明确授权）', targetCIDRs:'目标 CIDR 允许列表（每行一条）', rebindingHint:'每次 DNS 刷新都会重新校验全部 A/AAAA 结果。未在支持范围内明确授权时，拒绝回环、私网、链路本地、CGNAT、组播与云元数据地址。',
      limits:'连接限制与超时', connectTimeout:'连接超时（秒）', tcpIdle:'TCP 空闲超时（秒）', udpIdle:'UDP 空闲超时（秒）', maxTCP:'最大 TCP 连接数', perSourceTCP:'单来源 TCP 连接数', maxUDP:'最大 UDP 会话数', perSourceUDP:'单来源 UDP 会话数', newUDPRate:'单来源 UDP 新会话/秒', udpPacketRate:'单来源 UDP 包/秒',
      udpPerformance:'Go UDP 性能参数', udpPerformanceHint:'仅作用于 Go UDP。Worker 是整条规则共享的预算，按端口与地址族分摊；0 表示按 GOMAXPROCS 自动选择。每个监听 socket 至少 1 个 worker。默认 batch 64、单包缓冲 2048B。',
      workers:'UDP Worker 总预算（0=自动）', batch:'Batch Size', packetBuffer:'单包缓冲（字节）', listenerBuffer:'监听 socket 缓冲（字节）', sessionBuffer:'会话 socket 缓冲（字节）', cancel:'取消', saveRule:'保存规则', confirm:'确认', confirmDelete:'删除此规则？', confirmDeleteBody:'确定删除“{name}”吗？该规则的转发将停止。', confirmRotate:'轮换管理员令牌？', confirmRotateBody:'当前令牌将立即失效，轮换后请妥善保存新令牌。',
      ruleCreated:'规则已创建', ruleUpdated:'规则已更新', ruleDeleted:'规则已删除', tokenRotated:'管理员令牌已轮换', saved:'已保存并立即生效。', savedRestart:'已保存。安全模式、TLS、监听地址或端口变更需重启服务；重启前当前进程配置不变。', invalidToken:'令牌无效或已轮换。', unauthorized:'未授权', requestFailed:'请求失败（{status}）', sessionChanged:'会话已变更，必要时请重新登录。', daysHours:'{days}天 {hours}时', hoursMinutes:'{hours}时 {minutes}分', minutes:'{minutes}分'
    }
  };
  const apiErrors = {
    '认证请求过于频繁，请稍后重试':'Too many authentication requests; try again later', '管理员令牌无效':'Invalid administrator token', '跨站请求被拒绝':'Cross-site request rejected', 'CSRF 校验失败，请刷新页面':'CSRF validation failed; reload the page',
    'tls_min_version 仅支持 1.2 或 1.3':'tls_min_version only supports 1.2 or 1.3', '请先配置 TLS 并重启服务，再通过 HTTPS 启用严格 IP 白名单':'Configure TLS and restart first, then enable the strict IP allowlist over HTTPS', '严格 IP 白名单必须包含当前客户端地址':'The strict IP allowlist must include the current client address',
    'Content-Type 必须是 application/json':'Content-Type must be application/json', 'JSON 请求体不能超过 ':'JSON body must not exceed ', ' 字节':' bytes', 'JSON 格式错误: ':'Invalid JSON: ', '请求只能包含一个 JSON 对象':'The request must contain exactly one JSON object'
  };
  const supported = value => Object.hasOwn(messages,value);
  let current=document.documentElement.dataset.defaultLanguage||'en-US';
  try { const saved=localStorage.getItem('portbridge_language');if(supported(saved))current=saved; } catch {}
  if(!supported(current))current='en-US';
  function t(key,args={}) { return (messages[current][key]??messages['en-US'][key]??key).replace(/\{(\w+)\}/g,(_,name)=>String(args[name]??'')); }
  function apply(root=document) {
    for(const el of root.querySelectorAll('[data-i18n]'))el.textContent=t(el.dataset.i18n);
    for(const [attribute,data] of [['placeholder','i18nPlaceholder'],['aria-label','i18nAria'],['title','i18nTitle']])for(const el of root.querySelectorAll('[data-'+data.replace(/[A-Z]/g,c=>'-'+c.toLowerCase())+']'))el.setAttribute(attribute,t(el.dataset[data]));
    document.documentElement.lang=current;document.title=t('title');
    for(const button of document.querySelectorAll('[data-language]'))button.setAttribute('aria-pressed',String(button.dataset.language===current));
    for(const label of document.querySelectorAll('[data-current-language]'))label.textContent=current==='zh-CN'?'简体中文':'English';
  }
  function setLanguage(value) { if(!supported(value))return;current=value;try{localStorage.setItem('portbridge_language',value);}catch{}apply();document.dispatchEvent(new CustomEvent('portbridge:language')); }
  function translateAPIError(message) { let result=String(message??'');if(current==='en-US')for(const [original,translated] of Object.entries(apiErrors))result=result.replaceAll(original,translated);return result; }
  window.PB_I18N=Object.freeze({t,apply,setLanguage,translateAPIError,language:()=>current});
  apply();for(const button of document.querySelectorAll('[data-language]'))button.addEventListener('click',()=>setLanguage(button.dataset.language));
})();
