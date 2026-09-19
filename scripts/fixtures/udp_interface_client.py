"""Client for isolated audit-only UDP tests; validates reply address/interface."""
import socket,struct,sys,json
family,source,destination,port,sourceport,iface,expected_recv_iface,label=sys.argv[1:]
af=socket.AF_INET6 if family=='6' else socket.AF_INET
s=socket.socket(af,socket.SOCK_DGRAM);s.settimeout(2)
scope=socket.if_nametoindex(iface)
if af==socket.AF_INET6:
 s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_RECVPKTINFO,1)
 s.bind((source,int(sourceport),0,scope if source.startswith('fe80:') else 0))
 s.connect((destination,int(port),0,scope if destination.startswith('fe80:') else 0))
else:
 s.setsockopt(socket.IPPROTO_IP,8,1)
 s.bind((source,int(sourceport)));s.connect((destination,int(port)))
received=[]
for payload in [label.encode()+b'-first',b'',label.encode()+b'-tail']:
 s.send(payload);data,anc,flags,peer=s.recvmsg(2048,128)
 assert data==payload,(data,payload)
 assert peer[0].split('%')[0]==destination and peer[1]==int(port),(peer,destination,port)
 idx=None
 for lev,typ,value in anc:
  if af==socket.AF_INET and lev==socket.IPPROTO_IP and typ==8:idx=struct.unpack('=I',value[:4])[0]
  if af==socket.AF_INET6 and lev==socket.IPPROTO_IPV6 and typ==socket.IPV6_PKTINFO:idx=struct.unpack('=I',value[16:20])[0]
 assert idx==socket.if_nametoindex(expected_recv_iface),(idx,expected_recv_iface,anc)
 received.append({'bytes':len(data),'source':peer[0],'port':peer[1],'incoming_interface':socket.if_indextoname(idx)})
s.close();print(json.dumps({'result':'PASS','label':label,'replies':received}))
