//go:build linux

package proxy

import (
 "fmt"
 "net/netip"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "testing"
 "time"
)

func TestReview247UDPRealInterfaceScopeAndAsymmetry(t *testing.T) {
 parent:=os.Getenv("PB_AUDIT_PARENT_NETNS")
 current,err:=os.Readlink("/proc/self/ns/net")
 if parent=="" {t.Skip("requires verified audit-only veth namespace driver")}
 if err!=nil || current==parent {t.Fatal("not isolated from parent")}
 pids:=[]string{os.Getenv("PB_UDP_PEER0"),os.Getenv("PB_UDP_PEER1")}
 for _,pid:=range pids {
  if n,e:=strconv.Atoi(pid); e!=nil||n<=1 {t.Fatal("invalid peer PID")}
  peer,e:=os.Readlink("/proc/"+pid+"/ns/net")
  if e!=nil || peer==current || peer==parent {t.Fatal("peer namespace not isolated")}
 }
 python,script:=os.Getenv("PB_AUDIT_PYTHON"),os.Getenv("PB_UDP_CLIENT")
 if !strings.HasPrefix(python,"/")||!strings.HasPrefix(script,"/"){t.Fatal("absolute audit client paths required")}
 for _,workers:=range []int{1,4}{for _,target:=range []string{"127.0.0.1","::1"}{
  for _,mode:=range []string{"link-local-dual-scope","asymmetric-v4","asymmetric-v6"}{
   t.Run(fmt.Sprintf("workers-%d/target-%s/%s",workers,target,mode),func(t *testing.T){
    listen,family:="::","6";if mode=="asymmetric-v4"{listen,family="0.0.0.0","4"}
    r,port,seen:=startUDPRepair(t,listen,target,workers,64,100000,false)
    clients:=1;if mode=="link-local-dual-scope"{clients=2}
    for i:=0;i<clients;i++{
     source,dest,iface,incoming:="fe80::2","fe80::1","c0","c0"
     if mode=="asymmetric-v4"{source,dest,incoming="198.51.100.2","192.0.2.1","cAlt"}
     if mode=="asymmetric-v6"{source,dest,incoming="2001:db8:79::2","2001:db8:71::1","cAlt"}
     label:=fmt.Sprintf("peer%d",i)
     cmd:=exec.Command("/usr/bin/nsenter","--target",pids[i],"--net","--",python,script,family,source,dest,strconv.Itoa(port),"45321",iface,incoming,label)
     out,e:=cmd.CombinedOutput();t.Log(strings.TrimSpace(string(out)));if e!=nil{t.Fatalf("interface client: %v",e)}
    }
    targetPeers:=map[string]netip.AddrPort{}
    for i:=0;i<clients*3;i++ {
     var s udpRepairSeen
     select { case s=<-seen: case <-time.After(2*time.Second): t.Fatal("missing upstream observation") }
     if len(s.payload)>0 {
      label:=strings.SplitN(s.payload,"-",2)[0]
      if before,ok:=targetPeers[label];ok&&before!=s.peer{t.Fatal("one scope changed upstream session")}
      targetPeers[label]=s.peer
     }
    }
    if len(targetPeers)!=clients{t.Fatal("missing source group")}
    if clients==2 && targetPeers["peer0"]==targetPeers["peer1"]{t.Fatal("identical link-local address/port on separate interfaces merged")}
    assertUDPRepairReleased(t,r)
    s:=r.stats.snapshot()
    if s.UDPDrops!=0 || s.TotalUDPSessions!=uint64(clients) {t.Fatalf("scope/session/drop mismatch: %+v",s)}
    t.Logf("REAL_UDP_INTERFACES_VERIFIED mode=%s workers=%d target=%s independent_scopes=%d correct_reply_interface=true resources_released=true",mode,workers,target,clients)
   })
  }
 }}
}
