#! /bin/sh
#
# Functional tests for dnsmasq, using shunit2.
#
# These start real dnsmasq processes and query them with dig, covering the
# ways dnsmasq is commonly deployed: a caching forwarder for a LAN, a
# local name server for hosts files and static records, a DNS sinkhole for
# ad blocking, split DNS with per-domain upstream servers and a TFTP server
# for network booting.
#
# Run with "make check-functional", or directly:
#
#   DNSMASQ=src/dnsmasq tests/functional/dnsmasq_test.sh
#
# Needs dig and shunit2; see lib.sh. Tests that need root (TFTP binds
# port 69) are skipped when not running as root.

# NAME_PORT and NAME_PID are assigned by start_dnsmasq with eval.
# shellcheck disable=SC2154

TOP=$(cd "$(dirname "$0")/../.." && pwd)
. "$TOP/tests/functional/lib.sh"

# An upstream server for the forwarding tests: another dnsmasq, which
# answers authoritatively for a few names.
start_upstream()
{
  cat > "$SCRATCH/upstream.conf" <<EOF
no-resolv
no-hosts
local=/example.test/
local-ttl=600
address=/www.example.test/192.0.2.10
address=/mail.example.test/192.0.2.25
address=/intranet.corp.test/10.1.1.1
txt-record=upstream.example.test,"from upstream"
EOF
  start_dnsmasq upstream
}

#
# Configuration handling
#

testSyntaxCheckAcceptsExampleConfig()
{
  out=$("$DNSMASQ" --test --conf-file="$TOP/dnsmasq.conf.example" 2>&1)
  assertEquals "exit status" 0 $?
  assert_contains "$out" "syntax check OK"
}

testSyntaxCheckRejectsBadConfig()
{
  printf 'no-resolv\naddres=/typo.test/1.2.3.4\n' > "$SCRATCH/bad.conf"
  out=$("$DNSMASQ" --test --conf-file="$SCRATCH/bad.conf" 2>&1)
  assertNotEquals "exit status" 0 $?
  assert_contains "error names the bad line" "$out" "line 2"

  printf 'address=/bad.test/999.1.1.1\n' > "$SCRATCH/bad2.conf"
  "$DNSMASQ" --test --conf-file="$SCRATCH/bad2.conf" >/dev/null 2>&1
  assertNotEquals "bad address rejected" 0 $?
}

testConfDirIsRead()
{
  mkdir "$SCRATCH/dnsmasq.d"
  echo 'address=/one.test/192.0.2.1' > "$SCRATCH/dnsmasq.d/one.conf"
  echo 'address=/two.test/192.0.2.2' > "$SCRATCH/dnsmasq.d/two.conf"
  # Not matching the suffix filter, so must be ignored.
  echo 'address=/three.test/192.0.2.3' > "$SCRATCH/dnsmasq.d/three.conf.bak"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
conf-dir=$SCRATCH/dnsmasq.d,*.conf
EOF
  start_dnsmasq main || return

  assertEquals "192.0.2.1" "$(query main one.test)"
  assertEquals "192.0.2.2" "$(query main two.test)"
  assertEquals "REFUSED" "$(rcode main three.test)"
}

#
# Local names: hosts files, static records, LAN domains
#

testHostsFile()
{
  cat > "$SCRATCH/hosts" <<EOF
# a comment
192.168.1.10  nas.lan nas
192.168.1.11  printer.lan printer
fd00::10      nas.lan nas
EOF
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
addn-hosts=$SCRATCH/hosts
EOF
  start_dnsmasq main || return

  assertEquals "A record" "192.168.1.10" "$(query main nas.lan A)"
  assertEquals "AAAA record" "fd00::10" "$(query main nas.lan AAAA)"
  assertEquals "alias" "192.168.1.11" "$(query main printer A)"
  assertEquals "reverse lookup" "nas.lan." "$(query main -x 192.168.1.10)"
  assertEquals "IPv6 reverse lookup" "nas.lan." "$(query main -x fd00::10)"
}

testSighupRereadsHostsFile()
{
  echo '192.168.1.20 old.lan' > "$SCRATCH/hosts"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
addn-hosts=$SCRATCH/hosts
EOF
  start_dnsmasq main || return
  assertEquals "192.168.1.20" "$(query main old.lan)"

  echo '192.168.1.21 new.lan' > "$SCRATCH/hosts"
  kill -HUP "$main_PID"
  tries=0
  while [ -z "$(query main new.lan)" ] && [ $tries -lt 20 ]; do
    sleep 0.1; tries=$((tries + 1))
  done

  assertEquals "new entry" "192.168.1.21" "$(query main new.lan)"
  assertEquals "old entry gone" "" "$(query main old.lan)"
  assertTrue "still running after SIGHUP" "kill -0 $main_PID"
}

testHostsDirIsWatched()
{
  has_feature inotify || { skip_test "built without inotify"; return; }
  mkdir "$SCRATCH/hosts.d"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
hostsdir=$SCRATCH/hosts.d
EOF
  start_dnsmasq main || return
  assertEquals "" "$(query main late.lan)"

  # Picked up via inotify, without a SIGHUP.
  echo '192.168.1.30 late.lan' > "$SCRATCH/hosts.d/late"
  tries=0
  while [ -z "$(query main late.lan)" ] && [ $tries -lt 30 ]; do
    sleep 0.1; tries=$((tries + 1))
  done
  assertEquals "192.168.1.30" "$(query main late.lan)"
}

testExpandHostsAndLocalDomain()
{
  echo '192.168.1.40 laptop' > "$SCRATCH/hosts"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
addn-hosts=$SCRATCH/hosts
domain=home.arpa
expand-hosts
local=/home.arpa/
EOF
  start_dnsmasq main || return

  assertEquals "bare name" "192.168.1.40" "$(query main laptop)"
  assertEquals "expanded name" "192.168.1.40" "$(query main laptop.home.arpa)"
  assertEquals "unknown local name" "NXDOMAIN" \
    "$(rcode main nosuch.home.arpa)"
}

testStaticRecords()
{
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
host-record=gw.lan,gw,192.168.1.1,fd00::1
cname=router.lan,gw.lan
mx-host=lan,mail.lan,10
srv-host=_ldap._tcp.lan,dc.lan,389,0,100
txt-record=lan,"v=spf1 -all"
ptr-record=_http._tcp.lan,"web._http._tcp.lan"
caa-record=lan,0,issue,"ca.example"
EOF
  start_dnsmasq main || return

  assertEquals "host-record A" "192.168.1.1" "$(query main gw.lan A)"
  assertEquals "host-record AAAA" "fd00::1" "$(query main gw.lan AAAA)"
  assertEquals "host-record PTR" "gw.lan." "$(query main -x 192.168.1.1)"
  assertEquals "CNAME" "gw.lan.
192.168.1.1" "$(query main router.lan A)"
  assertEquals "MX" "10 mail.lan." "$(query main lan MX)"
  assertEquals "SRV" "0 100 389 dc.lan." "$(query main _ldap._tcp.lan SRV)"
  assertEquals "TXT" '"v=spf1 -all"' "$(query main lan TXT)"
  assertEquals "PTR" "web._http._tcp.lan." "$(query main _http._tcp.lan PTR)"
  assertEquals "CAA" '0 issue "ca.example"' "$(query main lan CAA)"
}

#
# Blocking: address= used as a DNS sinkhole
#

testAddressBlocksDomainAndSubdomains()
{
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
address=/ads.test/0.0.0.0
address=/ads.test/::
address=/tracker.test/
address=/sinkhole.test/#
EOF
  start_dnsmasq main || return

  assertEquals "domain" "0.0.0.0" "$(query main ads.test A)"
  assertEquals "subdomain" "0.0.0.0" "$(query main deep.sub.ads.test A)"
  assertEquals "IPv6" "::" "$(query main x.ads.test AAAA)"
  assertEquals "different domain not matched" "REFUSED" \
    "$(rcode main notads.test A)"
  assertEquals "empty address gives NXDOMAIN" "NXDOMAIN" \
    "$(rcode main a.tracker.test A)"
  assertEquals "# gives null A" "0.0.0.0" "$(query main sinkhole.test A)"
  assertEquals "# gives null AAAA" "::" "$(query main sinkhole.test AAAA)"
}

#
# Forwarding and caching
#

testForwardsToUpstream()
{
  start_upstream || return
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
server=127.0.0.1#$upstream_PORT
EOF
  start_dnsmasq main || return

  assertEquals "192.0.2.10" "$(query main www.example.test)"
  assertEquals '"from upstream"' "$(query main upstream.example.test TXT)"
  assertEquals "over TCP" "192.0.2.25" "$(query main +tcp mail.example.test)"
  assertEquals "upstream NXDOMAIN passed through" "NXDOMAIN" \
    "$(rcode main nosuch.example.test)"
}

testResolvFileIsUsed()
{
  # resolv.conf can't give a port, so just check the servers are picked up.
  printf 'nameserver 192.0.2.53\nnameserver 192.0.2.54\n' \
    > "$SCRATCH/resolv.conf"
  cat > "$SCRATCH/main.conf" <<EOF
resolv-file=$SCRATCH/resolv.conf
no-hosts
EOF
  start_dnsmasq main || return

  assertEquals "resolv file read" 1 \
    "$(count_log main "reading $SCRATCH/resolv.conf")"
  assertEquals "first server" 1 "$(count_log main 'using nameserver 192.0.2.53#53')"
  assertEquals "second server" 1 "$(count_log main 'using nameserver 192.0.2.54#53')"
}

testCacheAnswersWhenUpstreamGone()
{
  start_upstream || return
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
server=127.0.0.1#$upstream_PORT
cache-size=1000
EOF
  start_dnsmasq main || return

  assertEquals "192.0.2.10" "$(query main www.example.test)"
  stop_dnsmasq upstream

  assertEquals "served from cache" "192.0.2.10" \
    "$(query main www.example.test)"
  assertEquals "cache hit logged" 1 \
    "$(count_log main 'cached www.example.test is 192.0.2.10')"
  # Not cached, so this now fails.
  assert_not_contains "uncached name" "$(query main mail.example.test)" \
    "192.0.2.25"
}

testNoCache()
{
  start_upstream || return
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
server=127.0.0.1#$upstream_PORT
cache-size=0
EOF
  start_dnsmasq main || return

  query main www.example.test >/dev/null
  query main www.example.test >/dev/null
  assertEquals "both queries forwarded" 2 \
    "$(count_log main 'forwarded www.example.test')"
}

testPerDomainServers()
{
  start_upstream || return
  # A second upstream that gives a different answer for everything.
  cat > "$SCRATCH/other.conf" <<EOF
no-resolv
no-hosts
address=/#/198.51.100.1
EOF
  start_dnsmasq other || return

  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
server=127.0.0.1#$other_PORT
server=/corp.test/127.0.0.1#$upstream_PORT
server=/internal.test/
EOF
  start_dnsmasq main || return

  assertEquals "split domain goes to its server" "10.1.1.1" \
    "$(query main intranet.corp.test)"
  assertEquals "everything else to default server" "198.51.100.1" \
    "$(query main www.example.test)"
  assertEquals "empty server= keeps domain local" "NXDOMAIN" \
    "$(rcode main host.internal.test)"
}

testDomainNeededAndBogusPriv()
{
  start_upstream || return
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
server=127.0.0.1#$upstream_PORT
domain-needed
bogus-priv
EOF
  start_dnsmasq main || return

  query main singlelabel >/dev/null
  query main -x 192.168.77.77 >/dev/null
  query main -x 10.9.9.9 >/dev/null
  assertEquals "nothing leaked upstream" 0 \
    "$(count_log upstream 'singlelabel\|in-addr\.arpa')"

  assertEquals "private PTR answered locally" "NXDOMAIN" \
    "$(rcode main -x 172.16.5.5)"
  # Public names are still forwarded.
  assertEquals "192.0.2.10" "$(query main www.example.test)"
}

testLocalTtl()
{
  echo '192.168.1.50 ttl.lan' > "$SCRATCH/hosts"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
addn-hosts=$SCRATCH/hosts
local-ttl=300
EOF
  start_dnsmasq main || return

  ttl=$($DIG @127.0.0.1 -p "$main_PORT" +noall +answer ttl.lan |
    awk '{print $2}')
  assertEquals "300" "$ttl"
}

#
# DNSSEC validation
#

# dnssec_refused [OPTION...]: start a daemon with --dnssec and OPTIONs,
# expecting it to refuse to start, and print what it said.
dnssec_refused()
{
  port=$((PORT_BASE + 50))
  out=$("$DNSMASQ" --no-resolv --no-hosts \
    --user="$(id -un)" --group="$(id -gn)" \
    --listen-address=127.0.0.1 --bind-interfaces --port="$port" \
    --pid-file="$SCRATCH/daemon.pid" --dnssec "$@" 2>&1)
  if [ $? -eq 0 ]; then
    fail "started with --dnssec $*"
    echo "daemon $(cat "$SCRATCH/daemon.pid")" >> "$SCRATCH/pids"
  fi
  echo "$out"
}

testDnssecConfigChecks()
{
  has_feature DNSSEC || { skip_test "built without DNSSEC"; return; }

  # Without a root trust anchor the validator could loop forever.
  assert_contains "$(dnssec_refused --conf-file=/dev/null)" \
    "no root trust anchor"
  assert_contains "$(dnssec_refused --conf-file=/dev/null \
                       --trust-anchor=example.test,1,8,2,00)" \
    "no root trust anchor"
  # Validation needs room in the cache for keys.
  assert_contains "$(dnssec_refused --conf-file="$TOP/trust-anchors.conf" \
                       --cache-size=50)" \
    "cannot reduce cache size"
}

testDnssecRejectsUnsignedUpstream()
{
  has_feature DNSSEC || { skip_test "built without DNSSEC"; return; }
  start_upstream || return
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
dnssec
conf-file=$TOP/trust-anchors.conf
server=127.0.0.1#$upstream_PORT
EOF
  start_dnsmasq main || return

  # The upstream signs nothing and knows nothing of the root zone, so
  # nothing can be proved secure or insecure.
  assertEquals "SERVFAIL" "$(rcode main www.example.test)"
  assertEquals "validation logged" 1 \
    "$(count_log main 'validation www.example.test is')"

  # Checking disabled: the client does its own validation.
  assertEquals "192.0.2.10" "$(query main +cd www.example.test)"
}

#
# Process lifecycle
#

testPidFileAndCleanShutdown()
{
  printf 'no-resolv\nno-hosts\n' > "$SCRATCH/main.conf"
  start_dnsmasq main || return

  assertEquals "pid file" "$main_PID" "$(cat "$SCRATCH/main.pid")"
  stop_dnsmasq main
  assertEquals "exit status after SIGTERM" 0 $?
  assert_contains "$(cat "$SCRATCH/main.log")" "exiting on receipt of SIGTERM"
}

testDaemonMode()
{
  port=$((PORT_BASE + 50))
  "$DNSMASQ" --conf-file=/dev/null --no-resolv --no-hosts \
    --user="$(id -un)" --group="$(id -gn)" \
    --listen-address=127.0.0.1 --bind-interfaces --port="$port" \
    --pid-file="$SCRATCH/daemon.pid" --address=/daemon.test/192.0.2.99
  assertEquals "launcher exit status" 0 $?

  pid=$(cat "$SCRATCH/daemon.pid")
  # Make sure tearDown cleans it up, even though we didn't start it.
  echo "daemon $pid" >> "$SCRATCH/pids"
  assertTrue "daemon running" "kill -0 $pid"
  assertEquals "192.0.2.99" \
    "$($DIG @127.0.0.1 -p "$port" +short +time=2 +tries=1 daemon.test)"
}

testLogsQueries()
{
  printf 'no-resolv\nno-hosts\naddress=/log.test/192.0.2.7\n' \
    > "$SCRATCH/main.conf"
  start_dnsmasq main || return
  query main log.test >/dev/null
  sleep 0.2

  assertEquals "query logged" 1 "$(count_log main 'query\[A\] log.test from 127.0.0.1')"
  assertEquals "reply logged" 1 "$(count_log main 'log.test is 192.0.2.7')"
}

#
# TFTP, as used for PXE boot. Port 69 is privileged.
#

# tftp_get FILE OUT: fetch FILE from the TFTP server on 127.0.0.1 into OUT,
# with curl if it supports TFTP, else the tftp-hpa client. Succeeds only
# if a non-empty file arrived.
tftp_get()
{
  rm -f "$2"
  if curl --version 2>/dev/null | grep -q tftp; then
    curl -s --path-as-is --max-time 10 -o "$2" "tftp://127.0.0.1/$1"
  else
    tftp 127.0.0.1 -m binary -c get "$1" "$2" >/dev/null 2>&1
  fi
  [ -s "$2" ]
}

testTftp()
{
  has_feature TFTP || { skip_test "built without TFTP"; return; }
  is_root || { skip_test "needs root to bind port 69"; return; }
  if ! curl --version 2>/dev/null | grep -q tftp &&
     ! command -v tftp >/dev/null 2>&1; then
    skip_test "needs curl with TFTP support, or tftp-hpa"
    return
  fi

  mkdir "$SCRATCH/tftp"
  head -c 70000 /dev/urandom > "$SCRATCH/tftp/pxelinux.0"
  cat > "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
enable-tftp
tftp-root=$SCRATCH/tftp
EOF
  start_dnsmasq main || return

  # More than 128 512-byte blocks, to get past the first few block numbers.
  tftp_get pxelinux.0 "$SCRATCH/got"
  assertTrue "transfer succeeded" $?
  assertEquals "file transferred intact" \
    "$(cksum < "$SCRATCH/tftp/pxelinux.0")" "$(cksum < "$SCRATCH/got" 2>&1)"

  tftp_get missing "$SCRATCH/missing"
  assertFalse "missing file is an error" $?
  tftp_get ../../../../etc/passwd "$SCRATCH/passwd"
  assertFalse "no escape from tftp-root" $?
}

run_suite "$@"
