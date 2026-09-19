#!/usr/bin/env python3
"""Every link/address/route is created inside a fresh user/network namespace."""
import os,sys,pathlib,subprocess,time,signal,json
ROOT=pathlib.Path(__file__).resolve().parent
CLIENT=ROOT/'fixtures/udp_interface_client.py'
if not CLIENT.is_file(): raise SystemExit('BLOCKED: missing UDP interface client')
if len(sys.argv)<2 or sys.argv[1]!='--inside':
 parent=os.readlink('/proc/self/ns/net');env=os.environ.copy();env['PB_AUDIT_PARENT_NETNS']=parent
 raise SystemExit(subprocess.call(['unshare','-Urnm',sys.executable,__file__,'--inside',*sys.argv[1:]],env=env))
assert os.readlink('/proc/self/ns/net')!=os.environ['PB_AUDIT_PARENT_NETNS']
holders=[]
def run(*cmd):subprocess.run(cmd,check=True,timeout=5,stdout=subprocess.DEVNULL)
def peer(i,*cmd):run('/usr/bin/nsenter','--target',str(holders[i].pid),'--net','--',*cmd)
try:
 run('ip','link','set','lo','up')
 for i in range(2):
  p=subprocess.Popen(['unshare','-n','sleep','600']);holders.append(p)
  for _ in range(100):
   if os.readlink(f'/proc/{p.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
   time.sleep(.01)
  else:raise RuntimeError('peer namespace creation did not complete')
  run('ip','link','add',f'r{i}','type','veth','peer','name',f'c{i}')
  run('ip','link','set',f'c{i}','netns',str(p.pid))
  peer(i,'ip','link','set',f'c{i}','name','c0');peer(i,'ip','link','set','lo','up');peer(i,'ip','link','set','c0','up');run('ip','link','set',f'r{i}','up')
  run('ip','-6','addr','add','fe80::1/64','dev',f'r{i}','nodad');peer(i,'ip','-6','addr','add','fe80::2/64','dev','c0','nodad')
 run('ip','addr','add','192.0.2.1/24','dev','r0');peer(0,'ip','addr','add','192.0.2.2/24','dev','c0')
 run('ip','-6','addr','add','2001:db8:71::1/64','dev','r0','nodad');peer(0,'ip','-6','addr','add','2001:db8:71::2/64','dev','c0','nodad')
 run('ip','link','add','rAlt','type','veth','peer','name','cAlt');run('ip','link','set','cAlt','netns',str(holders[0].pid));run('ip','link','set','rAlt','up');peer(0,'ip','link','set','cAlt','up')
 run('ip','addr','add','198.18.0.1/30','dev','rAlt');peer(0,'ip','addr','add','198.18.0.2/30','dev','cAlt')
 run('ip','-6','addr','add','2001:db8:72::1/64','dev','rAlt','nodad');peer(0,'ip','-6','addr','add','2001:db8:72::2/64','dev','cAlt','nodad')
 peer(0,'ip','addr','add','198.51.100.2/32','dev','lo');peer(0,'ip','-6','addr','add','2001:db8:79::2/128','dev','lo','nodad')
 run('ip','route','add','198.51.100.2/32','via','198.18.0.2','dev','rAlt');run('ip','-6','route','add','2001:db8:79::2/128','via','2001:db8:72::2','dev','rAlt')
 # Only read reverse-path settings; the isolated namespace already inherits
 # permissive values here. Do not require an unnecessary procfs write.
 for key in ['all','default','r0','rAlt']:
  v=subprocess.check_output(['sysctl','-n',f'net.ipv4.conf.{key}.rp_filter'],text=True).strip()
  assert v in ('0','2'),('BLOCKED: strict rp_filter',key,v)
 for key in ['all','default','c0','cAlt']:
  v=subprocess.check_output(['/usr/bin/nsenter','--target',str(holders[0].pid),'--net','--','sysctl','-n',f'net.ipv4.conf.{key}.rp_filter'],text=True).strip()
  assert v in ('0','2'),('BLOCKED: peer strict rp_filter',key,v)
 def pending_ipv6():
  waiting=[]
  for label,prefix in [('router',[]),('peer0',['/usr/bin/nsenter','--target',str(holders[0].pid),'--net','--']),('peer1',['/usr/bin/nsenter','--target',str(holders[1].pid),'--net','--'])]:
   links=json.loads(subprocess.check_output(prefix+['ip','-j','-6','address','show'],text=True,timeout=3))
   for link in links:
    for address in link.get('addr_info',[]):
     flags=address.get('flags',[])
     assert not address.get('dadfailed') and 'dadfailed' not in flags,('BLOCKED: IPv6 DAD failed',label,link['ifname'])
     if address.get('tentative') or 'tentative' in flags:waiting.append((label,link['ifname'],address['local']))
  return waiting
 ready_start=time.monotonic();initial_pending=pending_ipv6();pending=initial_pending
 while pending and time.monotonic()-ready_start<5:
  time.sleep(.05);pending=pending_ipv6()
 assert not pending,('BLOCKED: IPv6 addresses remained tentative',pending)
 print('IPV6_ADDRESS_READINESS_VERIFIED',json.dumps({'initial_tentative':len(initial_pending),'waited_ms':round((time.monotonic()-ready_start)*1000),'payload_timeout_unchanged_seconds':2}),flush=True)
 env=os.environ.copy();env.update(PB_UDP_PEER0=str(holders[0].pid),PB_UDP_PEER1=str(holders[1].pid),PB_UDP_CLIENT=str(CLIENT),PB_AUDIT_PYTHON=sys.executable)
 print('ISOLATED_VETH_TOPOLOGY_READY',json.dumps({'server_netns':os.readlink('/proc/self/ns/net'),'peer_netns':[os.readlink(f'/proc/{p.pid}/ns/net') for p in holders]}),flush=True)
 # sys.argv[2:] begins with the compiled audit test binary.
 raise SystemExit(subprocess.run(sys.argv[2:],env=env,timeout=240).returncode)
finally:
 for p in holders:
  p.terminate()
 for p in holders:
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
