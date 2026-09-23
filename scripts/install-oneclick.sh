#!/usr/bin/env bash
# Interactive fresh-install bootstrap. No release private key is used here.
set +x
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PB_LANGUAGE=en-US
PB_WORK=''
PB_INSTALL_STARTED=0
PB_SIGNER='portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k'

pb_msg() {
  if [[ $PB_LANGUAGE == zh-CN ]]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi
}

pb_fail() { pb_msg "$1" "$2" >&2; return 1; }

pb_prompt() {
  if [[ $PB_LANGUAGE == zh-CN ]]; then printf '%s' "$2" >&3; else printf '%s' "$1" >&3; fi
  IFS= read -r "$3" <&3
}

pb_quiet() { "$@" >>"$PB_WORK/details.log" 2>&1; }

pb_python() {
  python3 - "$@" <<'PY'
import sys,json,ipaddress,pathlib,re,os,hashlib,tarfile,shutil,tempfile,socket,ssl,urllib.request
mode=sys.argv[1];args=sys.argv[2:]
def digest(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
if mode=='whitelist':
    raw=args[0]
    if len(raw)>65536:raise ValueError('allowlist too long')
    entries=re.split(r'[\s,]+',raw.strip());networks=set()
    for item in entries:
        if not item or '%' in item:raise ValueError('empty or scoped address')
        n=ipaddress.ip_network(item,strict=False)
        if n.prefixlen==0 or (n.version==6 and n.network_address.ipv4_mapped):raise ValueError('unsafe prefix')
        if n.network_address.is_multicast:raise ValueError('multicast source')
        networks.add(str(n))
    if not 1<=len(networks)<=1024:raise ValueError('allowlist count')
    print(json.dumps(sorted(networks)))
elif mode=='port':
    if not re.fullmatch(r'[0-9]{1,5}',args[0]) or not 1<=int(args[0])<=65535:raise ValueError('port range')
    port=int(args[0]);sockets=[]
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sockets.append(s);s.bind(('0.0.0.0',port))
        v6=False
        ipv6_flag=pathlib.Path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
        if ipv6_flag.exists() and ipv6_flag.read_text().strip()=='0':
            s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);sockets.append(s);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.bind(('::',port));v6=True
        print('yes' if v6 else 'no')
    finally:
        for s in sockets:s.close()
elif mode=='release':
    obj=json.loads(pathlib.Path(args[0]).read_text());arch,lang=args[1:]
    tag=obj.get('tag_name','')
    if obj.get('draft') or obj.get('prerelease') or not re.fullmatch(r'v\d+\.\d+\.\d+',tag):raise ValueError('stable release required')
    name=f'portbridge-{tag}-linux-{arch}-{lang}'
    for filename in (name+'.tar.gz','SHA256SUMS','SHA256SUMS.sig'):
        assets=[a for a in obj.get('assets',[]) if a.get('name')==filename and a.get('state')=='uploaded']
        expected=f'https://github.com/liying-official/Go-nftables-portbridge/releases/download/{tag}/{filename}'
        if len(assets)!=1 or assets[0].get('browser_download_url')!=expected:raise ValueError('missing or unexpected release asset')
    print(tag);print(name)
elif mode=='unpack':
    work=pathlib.Path(args[0]);name=args[1];archive=work/(name+'.tar.gz')
    rows=[]
    for line in (work/'SHA256SUMS').read_text().splitlines():
        match=re.fullmatch(r'([0-9a-f]{64}) [ *](.+)',line)
        if match and match[2]==archive.name:rows.append(match[1])
    if len(rows)!=1 or digest(archive)!=rows[0]:raise ValueError('archive digest mismatch')
    dest=work/'unpacked';dest.mkdir(mode=0o700)
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers();seen=set();total=0
        if len(members)>20000:raise ValueError('too many archive entries')
        for m in members:
            p=pathlib.PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or '\\' in m.name or not p.parts or p.parts[0]!=name:raise ValueError('unsafe archive path')
            if m.name in seen or not (m.isdir() or m.isfile()):raise ValueError('duplicate, linked or special archive member')
            seen.add(m.name);total+=m.size
            if total>536870912:raise ValueError('archive too large')
        for m in members:
            target=dest/pathlib.PurePosixPath(m.name)
            if m.isdir():target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(m) as inp,target.open('xb') as output:shutil.copyfileobj(inp,output)
            relative=target.relative_to(dest/name).as_posix()
            target.chmod(0o755 if relative.startswith('dist/') or relative.startswith('scripts/') and relative.endswith('.sh') else 0o644)
elif mode=='bundle':
    root=pathlib.Path(args[0]);version,arch=args[1:]
    manifest=json.loads((root/'release-bundle-manifest.json').read_text())
    if manifest.get('version')!=version or (root/'VERSION').read_text().strip()!=version:raise ValueError('version mismatch')
    if not re.fullmatch(r'[0-9a-f]{40}',manifest.get('source_revision','')):raise ValueError('revision missing')
    if not re.fullmatch(r'go\d+\.\d+\.\d+',manifest.get('release_toolchain','')):raise ValueError('toolchain missing')
    listing=root/'source-tree.sha256'
    if digest(listing)!=manifest.get('source_manifest_sha256'):raise ValueError('source manifest mismatch')
    seen=set()
    for line in listing.read_text().splitlines():
        m=re.fullmatch(r'([0-9a-f]{64})  (\./.+)',line)
        if not m:raise ValueError('source digest syntax')
        p=pathlib.PurePosixPath(m[2]);n=p.as_posix()
        if p.is_absolute() or '..' in p.parts or n in seen:raise ValueError('source path')
        seen.add(n)
        if digest(root/n)!=m[1]:raise ValueError('source file changed')
    expected={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and 'dist'!=p.relative_to(root).parts[0] and p.name not in ('source-tree.sha256','release-bundle-manifest.json','release-bundle-manifest.json.sig')}
    if seen!=expected:raise ValueError('incomplete source coverage')
    binary=root/'dist'/('go-nftables-portbridge-linux-'+arch)
    if digest(binary)!=manifest.get('binaries',{}).get(arch):raise ValueError('binary mismatch')
    with binary.open('rb') as f:header=f.read(20)
    if header[:5]!=b'\x7fELF\x02' or header[5]!=1 or int.from_bytes(header[18:20],'little')!={'amd64':62,'arm64':183}[arch]:raise ValueError('ELF architecture mismatch')
elif mode=='addresses':
    rows=json.loads(pathlib.Path(args[0]).read_text());v6=args[1]=='yes';addresses=set()
    for interface in rows:
        if 'UP' not in interface.get('flags',[]):continue
        for a in interface.get('addr_info',[]):
            if a.get('tentative') or a.get('dadfailed') or a.get('deprecated') or a.get('valid_life_time')==0 or set(a.get('flags',[]))&{'tentative','dadfailed','deprecated'}:continue
            ip=ipaddress.ip_address(a['local'])
            if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_loopback or (ip.version==6 and not v6):continue
            addresses.add(ip)
    print(json.dumps([str(ip) for ip in sorted(addresses,key=lambda x:(x.version,int(x)))]))
elif mode=='configure':
    path=pathlib.Path(args[0]);port=int(args[1]);whitelist=json.loads(args[2]);v6=args[3]=='yes'
    st=path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_nlink!=1:raise ValueError('unsafe configuration file')
    cfg=json.loads(path.read_text())
    if cfg.get('version')!=2 or cfg.get('rules')!=[]:raise ValueError('fresh schema-2 configuration required')
    if not cfg['web'].get('tls_cert_file') or not cfg['web'].get('tls_key_file'):raise ValueError('TLS must be prepared first')
    cfg['web'].update(port=port,listen_ipv4='0.0.0.0',listen_ipv6='::' if v6 else '',auto_lan_acl=False,strict_ip_allowlist=True,whitelist=whitelist,require_https=True,allow_insecure_http=False)
    fd,tmp=tempfile.mkstemp(prefix='.oneclick-',dir=path.parent)
    try:
        os.fchmod(fd,0o600);os.fchown(fd,st.st_uid,st.st_gid)
        with os.fdopen(fd,'w') as f:json.dump(cfg,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
elif mode=='health':
    cfg=json.loads(pathlib.Path(args[0]).read_text());token=pathlib.Path(args[1]).read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{64}',token) or hashlib.sha256(token.encode()).hexdigest()!=cfg['web']['admin_token_sha256']:raise ValueError('token mismatch')
    ctx=ssl.create_default_context(cafile=cfg['web']['tls_cert_file']);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    url='https://127.0.0.1:'+str(cfg['web']['port'])
    req=urllib.request.Request(url+'/api/config',headers={'Authorization':'Bearer '+token})
    with opener.open(req,timeout=5) as r:actual=json.load(r)
    if not actual['https']['required'] or not actual['https']['certificate']['self_signed'] or not actual['web']['strict_ip_allowlist'] or actual['web']['whitelist']!=cfg['web']['whitelist']:raise ValueError('HTTPS or allowlist not effective')
    print(actual['https']['certificate']['sha256'])
elif mode=='urls':
    for ip in json.loads(args[0]):
        address=ipaddress.ip_address(ip)
        if address.is_loopback or (address.version==6 and address.ipv4_mapped and address.ipv4_mapped.is_loopback):continue
        print('https://'+('['+ip+']' if ':' in ip else ip)+':'+args[1]+'/')
else:raise ValueError('unknown helper mode')
PY
}

pb_existing() {
  [[ -e /etc/portbridge || -L /etc/portbridge || -e /etc/portbridge-tls || -L /etc/portbridge-tls || -e /usr/local/bin/portbridge || -L /usr/local/bin/portbridge || -e /etc/systemd/system/portbridge.service ]] ||
    [[ $(systemctl show portbridge -p LoadState --value 2>/dev/null) != not-found ]]
}

# Invoked by EXIT; keep logs private on failures, never print raw diagnostics.
# shellcheck disable=SC2317
pb_exit() {
  local rc=$?
  if [[ -n $PB_WORK && -d $PB_WORK && ! -L $PB_WORK ]]; then
    if [[ $rc == 0 && $PB_WORK == /var/tmp/portbridge-oneclick.* ]]; then
      rm -rf -- "$PB_WORK"
    else
      pb_msg "Operation failed; private diagnostics: $PB_WORK/details.log" "操作失败；私有诊断日志：$PB_WORK/details.log" >&2
      if [[ $PB_INSTALL_STARTED == 1 ]]; then pb_msg 'Installation may be partially applied. Retain configuration and inspect the service; no automatic destructive rollback was performed.' '安装可能已部分执行。请保留配置并检查服务；脚本没有自动删除配置回滚。' >&2; fi
    fi
  fi
}

pb_main() {
  local check=0 option answer whitelist_raw whitelist port v6 metadata tag name base archive binary fp addresses previous_pid='' stable=0 pid i
  for option in "$@"; do
    case "$option" in
      --check) check=1 ;;
      --help|-h) printf '%s\n' 'Usage: sudo bash scripts/install-oneclick.sh [--check]' 'Fresh Debian/Ubuntu install only. --check verifies the latest release without installing or changing system configuration.'; return 0 ;;
      *) printf 'Unknown option: %s\n' "$option" >&2; return 2 ;;
    esac
  done
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then printf '%s\n' 'An interactive terminal is required. Download the script, then run it with Bash.' >&2; return 2; fi
  printf '%s\n' 'PortBridge one-click installer' 'Select language:' '  1) English' '  2) Simplified Chinese' >&3
  while :; do
    printf 'Language [1/2]: ' >&3; IFS= read -r answer <&3 || return 2
    case "$answer" in 1) PB_LANGUAGE=en-US; break ;; 2) PB_LANGUAGE=zh-CN; break ;; *) printf '%s\n' 'Please enter 1 or 2.' >&3 ;; esac
  done
  [[ -r /etc/os-release ]] || { pb_fail 'Cannot identify the operating system.' '无法识别操作系统。'; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || { pb_fail 'Only Debian and Ubuntu are supported.' '仅支持 Debian 和 Ubuntu。'; return 1; }
  case "$(uname -m)" in x86_64) PB_ARCH=amd64 ;; aarch64|arm64) PB_ARCH=arm64 ;; *) pb_fail 'Only amd64 and arm64 are supported.' '仅支持 amd64 和 arm64。'; return 1 ;; esac
  if [[ $check == 0 ]]; then
    [[ $EUID == 0 ]] || { pb_fail 'Run this installer with sudo or as root.' '请使用 sudo 或 root 运行安装。'; return 1; }
    [[ $(ps -p 1 -o comm= 2>/dev/null) == systemd ]] || { pb_fail 'systemd must be PID 1; enable systemd in WSL first.' 'systemd 必须为 PID 1；WSL 请先启用 systemd。'; return 1; }
    exec 9>/run/lock/portbridge-oneclick.lock
    flock -n 9 2>/dev/null || { pb_fail 'Cannot acquire the installation lock; check util-linux and other installers.' '无法获取安装锁，请检查 util-linux 或其他安装任务。'; return 1; }
    if pb_existing; then pb_fail 'Existing PortBridge files/service found. This fresh installer will not overwrite them; use the verified release upgrade procedure or --check.' '发现已有 PortBridge 文件或服务。本首次安装脚本不会覆盖，请使用已验签发布包升级流程或 --check。'; return 1; fi
  fi
  PB_WORK=$(mktemp -d /var/tmp/portbridge-oneclick.XXXXXX)
  trap pb_exit EXIT
  local missing=0 cmd
  for cmd in curl python3 ssh-keygen ip tar gzip sha256sum; do command -v "$cmd" >/dev/null || missing=1; done
  if [[ $check == 1 && $missing == 1 ]]; then pb_fail 'Check mode needs curl, python3, openssh-client, iproute2, tar/gzip and coreutils; it will not install dependencies.' '检查模式需要 curl、python3、openssh-client、iproute2、tar/gzip 和 coreutils，不会自动安装依赖。'; return 1; fi
  if [[ $check == 0 ]]; then
    pb_msg 'Preparing required Debian/Ubuntu packages (private output log).' '正在准备 Debian/Ubuntu 必需依赖（输出记录到私有日志）。'
    pb_quiet apt-get update
    pb_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl python3 openssh-client nftables conntrack iproute2 util-linux procps tar gzip
  fi
  pb_msg 'Enter the client IP/CIDR allowlist, separated by commas or spaces. A nonempty list is required; /0 is forbidden. Loopback recovery remains allowed. Management will listen on all available IPv4/IPv6 addresses, restricted by this allowlist; host/cloud firewalls are not modified.' '请输入客户端白名单 IP/CIDR，使用逗号或空格分隔。不能为空，禁止 /0；保留本机回环恢复通道。管理页面将监听可用 IPv4/IPv6 地址，并由严格白名单限制访问；脚本不会修改主机/云防火墙。'
  while :; do
    pb_prompt 'Allowed client IPs/CIDRs: ' '允许访问的客户端 IP/CIDR：' whitelist_raw || return 2
    if whitelist=$(pb_python whitelist "$whitelist_raw" 2>>"$PB_WORK/details.log"); then break; fi
    pb_msg 'Invalid allowlist. Enter IPs/CIDRs, without /0, multicast or IPv4-mapped IPv6.' '白名单无效。请输入 IP/CIDR，不允许 /0、多播或 IPv4 映射 IPv6。'
  done
  while :; do
    pb_prompt 'HTTPS management port [9080]: ' 'HTTPS 管理端口 [9080]：' port || return 2
    port=${port:-9080}
    if v6=$(pb_python port "$port" 2>>"$PB_WORK/details.log"); then break; fi
    pb_msg 'Invalid or occupied port. Choose another port between 1 and 65535.' '端口无效或已占用，请选择 1–65535 之间的其他端口。'
  done
  port=$((10#$port))
  ip -j address show up >"$PB_WORK/addresses.json"
  addresses=$(pb_python addresses "$PB_WORK/addresses.json" "$v6" 2>>"$PB_WORK/details.log")
  pb_msg 'Fetching and verifying the latest stable prebuilt release...' '正在获取并验证最新稳定版预编译发布包……'
  local curl_args=(-q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2)
  pb_quiet curl "${curl_args[@]}" -o "$PB_WORK/release.json" 'https://api.github.com/repos/liying-official/Go-nftables-portbridge/releases/latest'
  metadata=$(pb_python release "$PB_WORK/release.json" "$PB_ARCH" "$PB_LANGUAGE" 2>>"$PB_WORK/details.log")
  tag=${metadata%%$'\n'*};name=${metadata#*$'\n'};base="https://github.com/liying-official/Go-nftables-portbridge/releases/download/$tag"
  for archive in "$name.tar.gz" SHA256SUMS SHA256SUMS.sig; do
    pb_quiet curl "${curl_args[@]}" -H 'Cache-Control: no-cache' -o "$PB_WORK/$archive" "$base/$archive?oneclick=$(date +%s)"
  done
  printf '%s\n' "$PB_SIGNER" >"$PB_WORK/release-signers"
  pb_quiet ssh-keygen -Y verify -f "$PB_WORK/release-signers" -I portbridge-release-v2 -n portbridge-release -s "$PB_WORK/SHA256SUMS.sig" <"$PB_WORK/SHA256SUMS"
  pb_quiet pb_python unpack "$PB_WORK" "$name"
  local package="$PB_WORK/unpacked/$name"
  pb_quiet cmp "$PB_WORK/release-signers" "$package/packaging/release-signers"
  pb_quiet ssh-keygen -Y verify -f "$PB_WORK/release-signers" -I portbridge-release-v2 -n portbridge-release -s "$package/release-bundle-manifest.json.sig" <"$package/release-bundle-manifest.json"
  pb_quiet pb_python bundle "$package" "${tag#v}" "$PB_ARCH"
  binary="$package/dist/go-nftables-portbridge-linux-$PB_ARCH"
  [[ $("$binary" -version 2>>"$PB_WORK/details.log") == "${tag#v}" ]]
  pb_msg "Verified release: $tag / $PB_ARCH / $PB_LANGUAGE" "发布包验证通过：$tag / $PB_ARCH / $PB_LANGUAGE"
  pb_msg "Persistent allowlist: $whitelist" "持久白名单：$whitelist"
  pb_msg 'Planned management addresses (local-interface addresses, not a NAT/public-IP discovery result):' '计划管理地址（本机网卡地址，不代表 NAT 后公网地址）：'
  pb_python urls "$addresses" "$port"
  if [[ $check == 1 ]]; then pb_msg 'Check passed. Nothing was installed; no service/configuration was changed and no administrator token was read.' '检查通过。未执行安装，未修改服务或配置，也未读取管理员令牌。'; return 0; fi
  pb_msg 'A ten-year self-signed HTTPS certificate will be generated. Verify its fingerprint before trusting it; you can replace it later. The administrator token will be displayed after success: do not record/share this terminal.' '将生成十年有效的自签 HTTPS 证书。请核对指纹后建立信任，之后可自行替换。成功后会显示管理员令牌，请勿录屏或公开分享此终端。'
  pb_prompt 'Install now? [y/N]: ' '现在开始安装？[y/N]：' answer || return 2
  [[ $answer == y || $answer == Y ]] || { pb_msg 'Cancelled; no application installation performed.' '已取消，未执行程序安装。'; return 0; }
  if pb_existing; then pb_fail 'PortBridge appeared during preparation; refusing to overwrite it.' '准备期间出现了 PortBridge 文件或服务，拒绝覆盖。'; return 1; fi
  PB_INSTALL_STARTED=1
  pb_msg 'Installing verified binaries and preparing HTTPS without starting the service...' '正在安装已验证二进制并准备 HTTPS，暂不启动服务……'
  pb_quiet bash "$package/scripts/install.sh" --no-start
  pb_quiet pb_python configure /etc/portbridge/config.json "$port" "$whitelist" "$v6"
  pb_msg 'Starting the service with strict IP allowlisting...' '正在以严格 IP 白名单启动服务……'
  pb_quiet systemctl start portbridge
  for (( i=0; i<30; i++ )); do
    pid=$(systemctl show portbridge -p MainPID --value)
    if systemctl is-active --quiet portbridge && [[ $(systemctl show portbridge -p SubState --value) == running && $pid != 0 && $pid == "$previous_pid" ]]; then stable=$((stable+1)); else stable=0; fi
    previous_pid=$pid
    [[ $stable -ge 4 ]] && break
    sleep 1
  done
  [[ $stable -ge 4 && $(systemctl show portbridge -p Result --value) == success && $(systemctl show portbridge -p NRestarts --value) == 0 ]]
  fp=$(pb_python health /etc/portbridge/config.json /etc/portbridge/admin.token 2>>"$PB_WORK/details.log")
  ip -j address show up >"$PB_WORK/addresses.json"
  addresses=$(pb_python addresses "$PB_WORK/addresses.json" "$v6" 2>>"$PB_WORK/details.log")
  pb_msg 'Installation completed. Self-signed HTTPS is active; establish certificate trust before login.' '安装完成，当前使用自签 HTTPS；登录前请建立证书信任。'
  pb_msg "Certificate SHA-256: $fp" "证书 SHA-256：$fp"
  pb_msg 'Management URLs (reachability depends on routing, firewall and your source allowlist):' '管理页面地址（实际可达性取决于路由、防火墙和来源白名单）：'
  pb_python urls "$addresses" "$port"
  local token
  token=$(cat /etc/portbridge/admin.token)
  pb_msg "Administrator token: $token" "管理员令牌：$token"
  unset token
  pb_msg 'There are no forwarding rules yet. Add rules after login. This script does not change host/cloud firewalls or provide an automatic upgrade path.' '当前没有转发规则，请登录后添加。本脚本不会修改主机/云防火墙，也不提供自动覆盖升级。'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then pb_main "$@"; fi
