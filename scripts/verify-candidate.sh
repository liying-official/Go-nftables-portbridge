#!/usr/bin/env bash
# Source-candidate verification only. All nft/network mutations are isolated.
set -euo pipefail
umask 077
if [[ ${1:-} != --inside ]]; then
  [[ $EUID == 0 ]] || { echo "Run as root on an isolated evaluation host." >&2; exit 2; }
  GO_BIN=${1:-/usr/local/go/bin/go}
  export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor GOWORK=off GOENV=off
  [[ $GO_BIN == /* && -x $GO_BIN ]] || { echo "Supply an absolute Go 1.27.1 executable path." >&2; exit 2; }
  [[ $("$GO_BIN" version) == "go version go1.27.1 linux/amd64" ]] || { echo "This validation driver requires the supplied Go 1.27.1 linux/amd64 toolchain." >&2; exit 2; }
  for command in unshare ip nft conntrack mount sysctl setpriv python3 ssh-keygen; do
    command -v "$command" >/dev/null || { echo "Missing verification prerequisite: $command" >&2; exit 2; }
  done
  PB_VERIFY_PARENT=$(readlink /proc/self/ns/net)
  PB_VERIFY_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
  PB_VERIFY_OUT=$(mktemp -d /var/tmp/portbridge-verify.XXXXXX)
  export PB_VERIFY_PARENT PB_VERIFY_ROOT PB_VERIFY_OUT
  echo "Evidence and cache: $PB_VERIFY_OUT (retained for review; not a release artifact)"
  exec unshare --net /bin/bash "$0" --inside "$GO_BIN"
fi
GO_BIN=${2:?absolute Go path required}
[[ -n ${PB_VERIFY_PARENT:-} && $(readlink /proc/self/ns/net) != "$PB_VERIFY_PARENT" ]] || { echo "Refusing mutation outside a fresh network namespace." >&2; exit 2; }
ulimit -c 0
ip link set lo up
ip -6 addr add 2001:db8:55::1/128 dev lo nodad
ip -6 addr add 2001:db8:55::2/128 dev lo nodad
unset GOEXPERIMENT GOROOT GOOS GOARCH CGO_ENABLED GODEBUG
# Inherited audit/test switches are not evidence of a verified fixture.
for variable in $(compgen -e); do
  case "$variable" in
    PB_VERIFY_PARENT|PB_VERIFY_ROOT|PB_VERIFY_OUT) ;;
    PB_*|AUDIT_*) unset "$variable" ;;
  esac
done
unset PB_NFT_CONTROLLER_PEER PB_NFT_ROUTER_NS PB_NFT_ROUTER_MOUNT_NS PB_NFT_RECOVERY_CONFIG PB_NFT_TRAFFIC_CHILD PB_NFT_TRAFFIC_PARENT_NS PB_NFT_PARENT_MOUNT_NS PB_NFT_KERNEL_CHILD PB_NFT_PARENT_NS PB_REVIEW_CLEAN_NETNS PB_REVIEW_PARENT_NS PB_REVIEW_PROC_SUBSET PB_REVIEW_BOOT_BIND_COMPONENT
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor GOWORK=off GOENV=off LC_ALL=C GOMAXPROCS=4
export PB_REQUIRE_NFT=1 PB_V245_IPV6_MULTI=1
export GOCACHE="$PB_VERIFY_OUT/cache" GOMODCACHE="$PB_VERIFY_OUT/modcache" GOPATH="$PB_VERIFY_OUT/gopath" TMPDIR="$PB_VERIFY_OUT/temp" AUDIT_EVIDENCE="$PB_VERIFY_OUT/renderers"
export GOTMPDIR="$TMPDIR"
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH" "$GOTMPDIR" "$AUDIT_EVIDENCE"
cd -- "$PB_VERIFY_ROOT"
failed=0
gate() {
  local name=$1 rc=0; shift
  "$@" >"$PB_VERIFY_OUT/$name.stdout" 2>"$PB_VERIFY_OUT/$name.stderr" || rc=$?
  printf '%s\n' "$rc" >"$PB_VERIFY_OUT/$name.exit"
  printf '%s exit=%s\n' "$name" "$rc"
  [[ $rc == 0 ]] || failed=1
}
gate test-json "$GO_BIN" test -json ./... -count=1 -timeout=5m
gate race "$GO_BIN" test -race -json ./... -count=1 -timeout=5m
gate accept-independent "$GO_BIN" test -json ./internal/proxy -run '^TestReviewFixIndependent(EmptyHookPermitsB|LegalAcceptRulePermitsB|DropRuleIsNotBypassed|BootForeignAndCurrentRisk)$' -count=10 -timeout=3m
gate accept-strict "$GO_BIN" test -json ./internal/proxy -run '^TestNFTAcceptHook' -count=10 -timeout=3m
gate accept-race "$GO_BIN" test -race -json ./internal/proxy -run '^TestNFTAcceptHook' -count=3 -timeout=3m
gate transparent-original "$GO_BIN" test -json ./internal/proxy -run '^TestReview247(RemainingConditionalAcceptContract|IndependentMultiChainLifecycle)$' -count=10 -timeout=3m
gate transparent-strict "$GO_BIN" test -json ./internal/proxy -run '^TestNFTTransparentAccept' -count=10 -timeout=3m
gate transparent-race "$GO_BIN" test -race -json ./internal/proxy -run '^TestNFTTransparentAccept' -count=3 -timeout=3m
gate selective-unit "$GO_BIN" test -json ./internal/proxy -run '^TestNFTSelectiveACL' -count=1 -timeout=3m
gate selective-traffic "$GO_BIN" test -json ./internal/proxy -run '^TestNFTSelectiveTrafficIsolation$' -count=1 -timeout=4m
gate transparent-fuzz-list "$GO_BIN" test ./internal/proxy -list '^FuzzNFTTransparentAcceptProof$'
gate transparent-fuzz "$GO_BIN" test ./internal/proxy -run '^$' -fuzz '^FuzzNFTTransparentAcceptProof$' -fuzztime=30s -parallel=4 -timeout=2m
gate vet "$GO_BIN" vet ./...
gate build env CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags="-X main.version=$(cat VERSION)" -o "$PB_VERIFY_OUT/portbridge" ./cmd/portbridge
gate proxy-test-binary "$GO_BIN" test -c -o "$PB_VERIFY_OUT/proxy.test" ./internal/proxy
gate proxy-race-test-binary "$GO_BIN" test -race -c -o "$PB_VERIFY_OUT/proxy-race.test" ./internal/proxy
gate udp-interfaces "$GO_BIN" tool test2json -t -p portbridge/internal/proxy python3 ./scripts/run-udp-interfaces.py "$PB_VERIFY_OUT/proxy.test" -test.v -test.run '^TestReview247UDPRealInterfaceScopeAndAsymmetry$' -test.count=3 -test.timeout=3m
gate udp-interfaces-race "$GO_BIN" tool test2json -t -p portbridge/internal/proxy python3 ./scripts/run-udp-interfaces.py "$PB_VERIFY_OUT/proxy-race.test" -test.v -test.run '^TestReview247UDPRealInterfaceScopeAndAsymmetry$' -test.count=3 -test.timeout=3m
gate clean-go "$GO_BIN" tool test2json -t -p portbridge/internal/proxy ./scripts/test-clean-go-netns.sh "$PB_VERIFY_OUT/proxy.test" -test.v -test.run '^TestReviewClean' -test.count=10 -test.timeout=3m
gate proc-subset "$GO_BIN" tool test2json -t -p portbridge/internal/proxy ./scripts/test-recovery-proc-subset.sh "$PB_VERIFY_OUT/proxy.test" -test.v -test.run '^TestNFTRecoveryProcSubsetIdentity$' -test.count=1 -test.timeout=30s
gate boot-bind-component "$GO_BIN" tool test2json -t -p portbridge/internal/proxy ./scripts/test-recovery-boot-bind.sh "$PB_VERIFY_OUT/proxy.test" -test.v -test.run '^TestNFTRecoveryBootBindComponent$' -test.count=1 -test.timeout=30s
gate selection python3 - "$PB_VERIFY_OUT" <<'PY'
import collections,json,pathlib,sys
out=pathlib.Path(sys.argv[1]);counts=collections.Counter();roots=set();skips=set()
for line in (out/"test-json.stdout").read_text().splitlines():
    e=json.loads(line)
    if e.get("Test") and e["Action"] in ("pass","fail","skip"):
        counts[e["Action"]]+=1
        if e["Action"]=="pass":roots.add(e["Test"])
        if e["Action"]=="skip":skips.add(e["Test"])
required={"TestNFTTrafficIsolation","TestNFTKernelLifecycle","TestAuditRegressionZeroLengthUDP",
          "TestAuditRegressionTCPResetReleasesSession","TestAuditRegressionUDPWildcardReplyAddress",
          "TestReviewAdmissionConflictMustNotPreventRetirement","TestNFTIndependentStoreTableAndMemoryLoss",
          "TestReview246UnrelatedRuleNewAdmissionContract","TestReview246BootRolloverWithUnrelatedFirewall",
          "TestNFTEmptyHookRetirementMatrix","TestNFTBootScopeRejectsCurrentRiskWithoutDeletion",
          "TestReviewFixIndependentLegalAcceptRulePermitsB","TestNFTAcceptHookRetirementMatrix",
          "TestNFTAcceptHookProofSyntax","TestNFTAcceptHookMultiChainAndFamily",
          "TestNFTAcceptHookChangingSnapshots","TestNFTAcceptHookSuspendedRecordRevalidation",
          "TestNFTAcceptHookFailureRetry","TestNFTAcceptHookProofObjectLimit",
          "TestReview247RemainingConditionalAcceptContract","TestReview247IndependentMultiChainLifecycle"}
transparent={"TestNFTTransparentAccept"+suffix for suffix in ["RuleSyntax","MalformedAndSideEffects","BothBranches","MultiChainAndFamily","RetirementMatrix","SnapshotChanges","RecoveryAndFailures","Bounds"]}
required |= transparent
required |= {"TestNFTSelectiveACL"+suffix for suffix in ["NATAndDirections","UnknownAndSideEffects","UniversalPortDomain","PerRuleAndSameFamilyTransition","TwoSnapshots","FlowEntryIsOriginalTupleScoped","ProtocolAndBudgetBoundaries","ScopedPermissionIdentity"]}
required.add("TestNFTSelectiveTrafficIsolation")
required |= {"TestNFTFlowtableDeviceJSONShapes", "TestUDPTransientSendPressurePreservesSession", "TestUDPFatalSendErrorStillClosesSession"}
required.add("TestUDPBatchSyscallFailureSentinel")
separate={"TestReviewCleanForcedGoWithoutNFT","TestReviewCleanGoSocketMatrix","TestNFTRecoveryProcSubsetIdentity","TestNFTRecoveryBootBindComponent","TestReview247UDPRealInterfaceScopeAndAsymmetry"}
assert not counts["fail"] and skips <= separate and required <= roots,(counts,required-roots,skips-separate)
for label,expected,n in [("clean-go",{"TestReviewCleanForcedGoWithoutNFT","TestReviewCleanGoSocketMatrix"},10),("proc-subset",{"TestNFTRecoveryProcSubsetIdentity"},1),("boot-bind-component",{"TestNFTRecoveryBootBindComponent"},1)]:
    passed=collections.Counter(); bad=[]
    for line in (out/(label+".stdout")).read_text().splitlines():
        e=json.loads(line)
        if e.get("Test") and e["Action"]=="pass":passed[e["Test"]]+=1
        if e.get("Test") and e["Action"] in ("skip","fail"):bad.append(e)
    assert not bad and all(passed[name]==n for name in expected),(label,passed,bad)
independent={"TestReviewFixIndependent"+suffix for suffix in ["EmptyHookPermitsB","LegalAcceptRulePermitsB","DropRuleIsNotBypassed","BootForeignAndCurrentRisk"]}
strict={"TestNFTAcceptHook"+suffix for suffix in ["RetirementMatrix","ProofSyntax","MultiChainAndFamily","ChangingSnapshots","SuspendedRecordRevalidation","FailureRetry","ProofObjectLimit"]}
original={"TestReview247RemainingConditionalAcceptContract","TestReview247IndependentMultiChainLifecycle"}
interfaces={"TestReview247UDPRealInterfaceScopeAndAsymmetry"}
for label,expected,n in [("accept-independent",independent,10),("accept-strict",strict,10),("accept-race",strict,3),
                         ("transparent-original",original,10),("transparent-strict",transparent,10),("transparent-race",transparent,3),
                         ("udp-interfaces",interfaces,3),("udp-interfaces-race",interfaces,3)]:
    passed=collections.Counter();bad=[]
    for line in (out/(label+".stdout")).read_text().splitlines():
        e=json.loads(line)
        if e.get("Test") and e["Action"]=="pass":passed[e["Test"]]+=1
        if e.get("Test") and e["Action"] in ("fail","skip"):bad.append(e)
    assert not bad and all(passed[name]==n for name in expected),(label,passed,bad)
# Child traffic tests execute in a new topology and are captured in parent
# Output events. Require tuple/payload/OFFLOAD assertions' success markers, not
# just a passing parent with missing/skipped nested cases.
output="".join(json.loads(line).get("Output","") for line in (out/"test-json.stdout").read_text().splitlines())
import re
observed=set(re.findall(r"V247_ACCEPT_ONLY_NEW_B_VERIFIED family=(4|6) protocol=(tcp|udp) source_port=\d+ phase=single-accept software_offload=true",output))
assert observed=={(f,p) for f in ("4","6") for p in ("tcp","udp")},("missing real new-B/OFFLOAD evidence",observed)
for family in ("4","6"):
    assert "V247_DYNAMIC_POLICY_VERIFIED family="+family in output,("missing coordinated dynamic-policy coverage",family)
assert not re.search(r"--- SKIP: .*TestNFT(TrafficIsolation|KernelLifecycle)",output),"critical nested real-kernel test skipped"
conditional=set(re.findall(r"V248_TRANSPARENT_NEW_B_VERIFIED level=L3 family=(4|6) protocol=(tcp|udp) source_port=\d+ phase=(conditional-(?:match|miss|multi|multichain|restored)) payload_verified=true exact_tuple=true software_offload=true",output))
expected={(f,p,phase) for f in ("4","6") for p in ("tcp","udp") for phase in ("conditional-match","conditional-miss","conditional-multi","conditional-multichain","conditional-restored")}
assert conditional==expected,("missing true conditional match/miss/tuple/OFFLOAD coverage",expected-conditional)
assert "FuzzNFTTransparentAcceptProof" in (out/"transparent-fuzz-list.stdout").read_text().splitlines(),"fuzz target not selected"
fuzz=(out/"transparent-fuzz.stdout").read_text()+(out/"transparent-fuzz.stderr").read_text()
assert "PASS" in fuzz and "execs:" in fuzz and re.search(r"fuzz: elapsed: (?:3[0-9]|[4-9][0-9])s",fuzz),"finite fuzz did not execute for 30 seconds"
for label in ("udp-interfaces","udp-interfaces-race"):
    text="".join(json.loads(line).get("Output","") for line in (out/(label+".stdout")).read_text().splitlines())
    signatures=set(re.findall(r"REAL_UDP_INTERFACES_VERIFIED mode=(link-local-dual-scope|asymmetric-v4|asymmetric-v6) workers=(1|4) target=(127\.0\.0\.1|::1) independent_scopes=[12] correct_reply_interface=true resources_released=true",text))
    expected_udp={(mode,workers,target) for mode in ("link-local-dual-scope","asymmetric-v4","asymmetric-v6") for workers in ("1","4") for target in ("127.0.0.1","::1")}
    assert signatures==expected_udp,(label,"missing real interface payload assertions",expected_udp-signatures)
print(json.dumps({"events":counts,"required_selected":sorted(required),"accept_new_B_selected":sorted(observed),"conditional_new_B_selected":sorted(conditional),"release_approved":False},indent=2))
PY
echo "Review logs in $PB_VERIFY_OUT. Runtime validation is separate from release approval."
[[ $failed == 0 ]] || exit 1
echo "BLOCKED: v2.4.9 bounded selective-ACL support does not certify arbitrary stateful/side-effecting firewall policies, actual reboot or the complete original-user systemd unit. This unsigned candidate is not release-approved." >&2
exit 2
