#! /bin/sh
#
# Functional tests of dnsmasq's DBus interface, using shunit2.
#
# Each test starts its own private bus, configured as a system bus and
# pointed to by DBUS_SYSTEM_BUS_ADDRESS, then starts dnsmasq with
# --enable-dbus and drives it with dbus-send (and gdbus for SetServersEx,
# whose array of arrays dbus-send can't express). The tests check the
# effect of each method on the DNS answers given, and watch the signals
# sent with dbus-monitor.
#
# Run with "make check-functional", or directly:
#
#   DNSMASQ=src/dnsmasq tests/functional/dbus_test.sh
#
# Needs dig, shunit2 and dbus-daemon, dbus-send and dbus-monitor; see
# lib.sh. Every test is skipped if dnsmasq was built without DBus.
#
# --enable-dbus makes dnsmasq insist on CAP_NET_RAW, so the tests need
# root with that capability. Otherwise they run dnsmasq as root in a new
# user namespace (unshare -r), if the system allows that, and if not
# they are skipped.

# NAME_PORT and NAME_PID are assigned by start_dnsmasq with eval.
# shellcheck disable=SC2154

TOP=$(cd "$(dirname "$0")/../.." && pwd)
. "$TOP/tests/functional/lib.sh"

DBUS_PATH=/uk/org/thekelleys/dnsmasq
GDBUS=${GDBUS:-gdbus}

suiteSetUp()
{
  DBUS_SKIP=
  if ! has_feature DBus; then
    DBUS_SKIP="built without DBus"
    return
  fi
  for _tool in dbus-daemon dbus-send dbus-monitor; do
    if ! command -v $_tool >/dev/null 2>&1; then
      DBUS_SKIP="$_tool not found"
      return
    fi
  done

  # dnsmasq runs as it is if it can, else in a user namespace, through
  # a script; see start_dbus_dnsmasq.
  DBUS_WRAPPER=
  if is_root && has_net_raw; then
    return
  fi
  if ! has_net_raw unshare -r; then
    DBUS_SKIP="needs CAP_NET_RAW: root, or unshare -r to fake it"
    return
  fi
  DBUS_WRAPPER=$(mktemp "${TMPDIR:-/tmp}/dnsmasq-unshare.XXXXXX")
  # --no-daemon, as setgroups() is never allowed in the namespace, so
  # dnsmasq mustn't try to drop privileges.
  printf '#! /bin/sh\nexec unshare -r "%s" --no-daemon "$@"\n' \
    "$DNSMASQ" > "$DBUS_WRAPPER"
  chmod +x "$DBUS_WRAPPER"
}

# has_net_raw [COMMAND...]: true if a shell run by COMMAND has CAP_NET_RAW
# (bit 13). Containers may run as root without it, and some systems allow
# user namespaces but strip their capabilities.
has_net_raw()
{
  # shellcheck disable=SC2016
  _caps=$("$@" sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status' 2>/dev/null)
  [ -n "$_caps" ] && [ $((0x$_caps >> 13 & 1)) -eq 1 ]
}

oneTimeTearDown()
{
  if [ -n "${DBUS_WRAPPER:-}" ]; then
    rm -f "$DBUS_WRAPPER"
  fi
}

# need_dbus: true if the DBus tests can run, else skip the test. The
# need_ functions are used as "need_dbus || return 0", as shunit2 counts
# a non-zero return from a test as a failure.
need_dbus()
{
  [ -z "$DBUS_SKIP" ] && return 0
  skip_test "$DBUS_SKIP"
  return 1
}

# Every bus client and dnsmasq finds the private bus this way.
bus_env()
{
  DBUS_SYSTEM_BUS_ADDRESS="unix:path=$SCRATCH/bus"
  export DBUS_SYSTEM_BUS_ADDRESS
}

# start_bus: start a private system bus for this test, which lets anyone
# do anything. ANONYMOUS is allowed because in a user namespace dnsmasq
# claims to be uid 0, which EXTERNAL authentication would reject.
start_bus()
{
  bus_env
  cat > "$SCRATCH/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=$SCRATCH/bus</listen>
  <auth>EXTERNAL</auth>
  <auth>ANONYMOUS</auth>
  <allow_anonymous/>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow receive_sender="*"/>
    <allow eavesdrop="true"/>
  </policy>
</busconfig>
EOF
  dbus-daemon --config-file="$SCRATCH/bus.conf" --nofork \
    2> "$SCRATCH/bus.err" &
  echo "bus $!" >> "$SCRATCH/pids"

  _tries=0
  until [ -S "$SCRATCH/bus" ]; do
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 50 ]; then
      fail "dbus-daemon didn't start: $(cat "$SCRATCH/bus.err")"
      return 1
    fi
    sleep 0.1
  done
}

# start_dbus_dnsmasq NAME [OPTION...]: start_dnsmasq with --enable-dbus,
# unless an OPTION gives a service name with --enable-dbus=, which sets
# DBUS_NAME for dbus_call.
start_dbus_dnsmasq()
{
  _name=$1; shift
  DBUS_NAME=uk.org.thekelleys.dnsmasq
  _opt=--enable-dbus
  for _a in "$@"; do
    case $_a in
      --enable-dbus=*) DBUS_NAME=${_a#*=}; _opt= ;;
    esac
  done

  bus_env
  if [ -n "$DBUS_WRAPPER" ]; then
    _saved=$DNSMASQ
    DNSMASQ=$DBUS_WRAPPER
    start_dnsmasq "$_name" $_opt "$@"
    _status=$?
    DNSMASQ=$_saved
    return $_status
  fi
  start_dnsmasq "$_name" $_opt "$@"
}

# dbus_call METHOD [ARG...]: call a dnsmasq method with dbus-send, which
# prints the reply, or the error.
dbus_call()
{
  _method=$1; shift
  bus_env
  dbus-send --system --print-reply --reply-timeout=5000 \
    --dest="$DBUS_NAME" "$DBUS_PATH" "$DBUS_NAME.$_method" "$@" 2>&1
}

# gdbus_call METHOD [ARG...]: the same with gdbus, taking GVariant text.
gdbus_call()
{
  _method=$1; shift
  bus_env
  $GDBUS call --system --timeout=5 --dest "$DBUS_NAME" \
    --object-path "$DBUS_PATH" --method "$DBUS_NAME.$_method" "$@" 2>&1
}

need_gdbus()
{
  command -v "$GDBUS" >/dev/null 2>&1 && return 0
  skip_test "$GDBUS not found"
  return 1
}

# start_monitor: record all signals on the bus in monitor.out.
start_monitor()
{
  bus_env
  dbus-monitor --system "type='signal'" > "$SCRATCH/monitor.out" 2>&1 &
  echo "monitor $!" >> "$SCRATCH/pids"
  # It sees its own NameAcquired once it is listening.
  wait_for_file "$SCRATCH/monitor.out" "member=NameAcquired"
}

# wait_for_file FILE PATTERN: wait up to 5 seconds for PATTERN in FILE.
wait_for_file()
{
  _tries=0
  until grep -q -- "$2" "$1" 2>/dev/null; do
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 50 ]; then
      fail "<$2> never appeared in ${1##*/}"
      return 1
    fi
    sleep 0.1
  done
}

# signal_args MEMBER: print the string arguments of every MEMBER signal
# from dnsmasq so far, one signal per line, separated by spaces.
signal_args()
{
  awk -v m="interface=uk.org.thekelleys.dnsmasq; member=$1" '
    function flush() { if (n) print args; n = 0; args = "" }
    /^signal / { flush(); on = index($0, m) }
    on && /^ *string "/ {
      v = $0; sub(/^ *string "/, "", v); sub(/"$/, "", v)
      args = (n++ ? args " " : "") (v == "" ? "\"\"" : v)
    }
    END { flush() }' "$SCRATCH/monitor.out"
}

dnsmasq_version()
{
  "$DNSMASQ" --version | sed -n 's/^Dnsmasq version \(.*\)  Copyright.*/\1/p'
}

# bytes STRING: STRING as a comma separated list of byte values, for
# dbus-send's array:byte.
bytes()
{
  printf '%s' "$1" | od -An -tu1 | tr -s ' \n' ',,' | sed 's/^,//; s/,$//'
}

# metric NAME: the value of NAME from GetMetrics.
metric()
{
  dbus_call GetMetrics | awk -v k="\"$1\"" '$2 == k { getline; print $2 }'
}

# The upstream server for the forwarding tests: another dnsmasq, without
# DBus, which answers authoritatively for a few names.
start_upstream()
{
  cat > "$SCRATCH/upstream.conf" <<EOF
no-resolv
no-hosts
local=/example.test/
local=/corp.test/
address=/www.example.test/192.0.2.10
address=/www.example.test/2001:db8::10
address=/intranet.corp.test/10.1.1.1
ptr-record=1.1.1.10.in-addr.arpa,intranet.corp.test
srv-host=_ldap._tcp.example.test,dc.example.test,389
EOF
  start_dnsmasq upstream
}

# The DNS instance for the forwarding tests, with no servers of its own
# and no cache, so every query shows the current settings.
start_forwarder()
{
  start_bus || return
  start_dbus_dnsmasq main --no-resolv --no-hosts --cache-size=0 "$@"
}

#
# Connecting to the bus
#

testGetVersion()
{
  need_dbus || return 0
  start_forwarder || return

  out=$(dbus_call GetVersion)
  assert_contains "$out" "string \"$(dnsmasq_version)\""
  assertEquals "logged" 1 "$(count_log main 'connected to system bus')"
}

testUnknownMethod()
{
  need_dbus || return 0
  start_forwarder || return

  out=$(dbus_call NoSuchMethod)
  assert_contains "$out" "org.freedesktop.DBus.Error.UnknownMethod"
}

testIntrospect()
{
  need_dbus || return 0
  start_forwarder || return

  out=$(dbus-send --system --print-reply --dest="$DBUS_NAME" "$DBUS_PATH" \
          org.freedesktop.DBus.Introspectable.Introspect 2>&1)
  assert_contains "$out" '<interface name="uk.org.thekelleys.dnsmasq">'
  for m in GetVersion ClearCache SetServers SetServersEx SetDomainServers \
           GetMetrics GetServerMetrics ClearMetrics; do
    assert_contains "$out" "<method name=\"$m\">"
  done
}

testCustomServiceName()
{
  need_dbus || return 0
  start_bus || return
  start_dbus_dnsmasq main --no-resolv --enable-dbus=org.example.dns || return

  assert_contains "$(dbus_call GetVersion)" "string"
  out=$(dbus-send --system --print-reply --dest=org.example.dns "$DBUS_PATH" \
          org.freedesktop.DBus.Introspectable.Introspect 2>&1)
  assert_contains "$out" '<interface name="org.example.dns">'

  # Nothing answers to the default name.
  out=$(DBUS_NAME=uk.org.thekelleys.dnsmasq dbus_call GetVersion)
  assert_contains "$out" "ServiceUnknown"
}

testUpSignal()
{
  need_dbus || return 0
  start_bus || return
  start_monitor || return
  start_dbus_dnsmasq main --no-resolv || return

  wait_for_file "$SCRATCH/monitor.out" "member=Up"
  assert_contains "$(cat "$SCRATCH/monitor.out")" \
    "path=$DBUS_PATH; interface=uk.org.thekelleys.dnsmasq; member=Up"
}

testConnectsWhenBusStartsLater()
{
  need_dbus || return 0
  # No bus yet: dnsmasq carries on, and polls for one.
  start_dbus_dnsmasq main --no-resolv --address=/up.test/192.0.2.1 || return
  assertEquals "pending" 1 "$(count_log main 'bus connection pending')"
  assertEquals "answers without the bus" "192.0.2.1" "$(query main up.test)"

  start_bus || return
  start_monitor || return
  wait_for_file "$SCRATCH/main.log" "connected to system DBus"
  wait_for_file "$SCRATCH/monitor.out" "member=Up"
  assert_contains "$(dbus_call GetVersion)" "string"
}

testSurvivesBusExit()
{
  need_dbus || return 0
  start_forwarder --address=/up.test/192.0.2.1 || return

  kill "$(awk '$1 == "bus" { print $2 }' "$SCRATCH/pids")"
  sleep 0.5
  assertEquals "still answers" "192.0.2.1" "$(query main up.test)"
}

#
# Upstream servers
#

testConfiguredServersKept()
{
  need_dbus || return 0
  start_upstream || return
  echo "server=/corp.test/127.0.0.1#$upstream_PORT" > "$SCRATCH/main.conf"
  start_forwarder || return

  dbus_call SetDomainServers \
    array:string:"/example.test/127.0.0.1#$upstream_PORT" > /dev/null
  assertEquals "192.0.2.10" "$(query main www.example.test)"
  assertEquals "10.1.1.1" "$(query main intranet.corp.test)"

  dbus_call SetDomainServers array:string: > /dev/null
  assertEquals "REFUSED" "$(rcode main www.example.test)"
  assertEquals "from the config" "10.1.1.1" "$(query main intranet.corp.test)"
}

#
# Options
#

testSetFilterAAAA()
{
  need_dbus || return 0
  start_upstream || return
  start_forwarder --server="127.0.0.1#$upstream_PORT" || return

  assertEquals "2001:db8::10" "$(query main www.example.test AAAA)"

  dbus_call SetFilterAAAA boolean:true > /dev/null
  assertEquals "filtered" "" "$(query main www.example.test AAAA)"
  assertEquals "NODATA" "NOERROR" "$(rcode main www.example.test AAAA)"
  assertEquals "A untouched" "192.0.2.10" "$(query main www.example.test A)"

  dbus_call SetFilterA boolean:true > /dev/null
  assertEquals "A filtered" "" "$(query main www.example.test A)"

  dbus_call SetFilterAAAA boolean:false > /dev/null
  dbus_call SetFilterA boolean:false > /dev/null
  assertEquals "2001:db8::10" "$(query main www.example.test AAAA)"
  assertEquals "192.0.2.10" "$(query main www.example.test A)"

  out=$(dbus_call SetFilterA string:yes)
  assert_contains "$out" "Expected boolean argument"
}

testSetBogusPrivOption()
{
  need_dbus || return 0
  start_upstream || return
  start_forwarder --server="127.0.0.1#$upstream_PORT" || return

  assertEquals "intranet.corp.test." "$(query main -x 10.1.1.1)"

  dbus_call SetBogusPrivOption boolean:true > /dev/null
  assertEquals "not forwarded" "NXDOMAIN" "$(rcode main -x 10.1.1.1)"
  assertEquals "logged" 1 "$(count_log main 'Enabling --bogus-priv option from D-Bus')"

  dbus_call SetBogusPrivOption boolean:false > /dev/null
  assertEquals "intranet.corp.test." "$(query main -x 10.1.1.1)"
}

testSetFilterWin2KOption()
{
  need_dbus || return 0
  start_upstream || return
  start_forwarder --server="127.0.0.1#$upstream_PORT" || return

  assertEquals "0 0 389 dc.example.test." \
    "$(query main _ldap._tcp.example.test SRV)"

  dbus_call SetFilterWin2KOption boolean:true > /dev/null
  assertEquals "filtered" "" "$(query main _ldap._tcp.example.test SRV)"

  dbus_call SetFilterWin2KOption boolean:false > /dev/null
  assertEquals "0 0 389 dc.example.test." \
    "$(query main _ldap._tcp.example.test SRV)"
}

#
# Cache and metrics
#

testClearCache()
{
  need_dbus || return 0
  echo "192.0.2.1 host.test" > "$SCRATCH/hosts"
  start_bus || return
  start_dbus_dnsmasq main --no-resolv --no-hosts \
    --addn-hosts="$SCRATCH/hosts" || return

  assertEquals "192.0.2.1" "$(query main host.test)"
  echo "192.0.2.2 host.test" > "$SCRATCH/hosts"
  assertEquals "not reread yet" "192.0.2.1" "$(query main host.test)"

  dbus_call ClearCache > /dev/null
  assertEquals "192.0.2.2" "$(query main host.test)"
}

testMetrics()
{
  need_dbus || return 0
  start_upstream || return
  start_forwarder --server="127.0.0.1#$upstream_PORT" || return

  dbus_call ClearMetrics > /dev/null
  assertEquals "0" "$(metric dns_queries_forwarded)"
  for _ in 1 2 3; do
    query main www.example.test > /dev/null
  done
  assertEquals "3" "$(metric dns_queries_forwarded)"

  out=$(dbus_call GetServerMetrics)
  assert_contains "$out" 'string "127.0.0.1"'
  assert_contains "$out" "string \"$upstream_PORT\""
  queries=$(echo "$out" | awk '$2 == "\"queries\"" { getline; print $2 }')
  assertEquals '"3"' "$queries"

  dbus_call ClearMetrics > /dev/null
  assertEquals "0" "$(metric dns_queries_forwarded)"
}

testGetLoopServers()
{
  need_dbus || return 0
  has_feature loop-detect || { skip_test "built without loop-detect"; return; }

  # main forwards to loop, which forwards straight back.
  echo "server=127.0.0.1#$PORT_BASE" > "$SCRATCH/loop.conf"
  start_forwarder --dns-loop-detect || return
  start_dnsmasq loop --no-resolv --no-hosts || return

  out=$(dbus_call GetLoopServers)
  assert_not_contains "none yet" "$out" "string"

  dbus_call SetDomainServers array:string:"127.0.0.1#$loop_PORT" > /dev/null
  wait_for_file "$SCRATCH/main.log" "loop detected"
  out=$(dbus_call GetLoopServers)
  assert_contains "$out" 'string "127.0.0.1"'
}

#
# DHCP leases
#

# A DHCP server on unprivileged ports, for a range that matches no
# interface, so it never hands out leases itself.
start_dhcp()
{
  start_bus || return
  start_monitor || return
  start_dbus_dnsmasq main --no-resolv --no-hosts \
    --dhcp-range=192.0.2.100,192.0.2.200 \
    --dhcp-alternate-port=$((PORT_BASE + 100)),$((PORT_BASE + 101)) \
    --dhcp-leasefile="$SCRATCH/leases" --domain=lan.test
}

need_dhcp()
{
  has_feature DHCP && return 0
  skip_test "built without DHCP"
  return 1
}

# add_lease IP MAC HOSTNAME [CLID]
add_lease()
{
  dbus_call AddDhcpLease string:"$1" string:"$2" \
    array:byte:"$(bytes "$3")" array:byte:"${4:-1,0,35,69,103,137,171}" \
    uint32:3600 uint32:0 boolean:false
}

testAddDhcpLease()
{
  need_dbus || return 0
  need_dhcp || return 0
  start_dhcp || return

  out=$(add_lease 192.0.2.150 00:23:45:67:89:ab client)
  assert_not_contains "$out" "Error"
  assertEquals "192.0.2.150" "$(query main client.lan.test)"
  assertEquals "client.lan.test." "$(query main -x 192.0.2.150)"
  assert_contains "$(cat "$SCRATCH/leases")" \
    "00:23:45:67:89:ab 192.0.2.150 client 01:00:23:45:67:89:ab"

  wait_for_file "$SCRATCH/monitor.out" "member=DhcpLeaseAdded"
  assertEquals "192.0.2.150 00:23:45:67:89:ab client.lan.test" \
    "$(signal_args DhcpLeaseAdded)"

  # Again with a new name updates it.
  add_lease 192.0.2.150 00:23:45:67:89:ab renamed > /dev/null
  assertEquals "192.0.2.150" "$(query main renamed.lan.test)"
  assertEquals "old name gone" "" "$(query main client.lan.test)"
  wait_for_file "$SCRATCH/monitor.out" "member=DhcpLeaseUpdated"
  assertEquals "192.0.2.150 00:23:45:67:89:ab renamed.lan.test" \
    "$(signal_args DhcpLeaseUpdated)"
}

testDeleteDhcpLease()
{
  need_dbus || return 0
  need_dhcp || return 0
  start_dhcp || return

  add_lease 192.0.2.160 00:23:45:67:89:ab leaving > /dev/null
  assertEquals "192.0.2.160" "$(query main leaving.lan.test)"

  out=$(dbus_call DeleteDhcpLease string:192.0.2.160)
  assert_contains "$out" "boolean true"
  assertEquals "name removed" "" "$(query main leaving.lan.test)"
  assert_not_contains "$(cat "$SCRATCH/leases")" "192.0.2.160"
  wait_for_file "$SCRATCH/monitor.out" "member=DhcpLeaseDeleted"
  assert_contains "$(signal_args DhcpLeaseDeleted)" \
    "192.0.2.160 00:23:45:67:89:ab"

  out=$(dbus_call DeleteDhcpLease string:192.0.2.160)
  assert_contains "already gone" "$out" "boolean false"
  out=$(dbus_call DeleteDhcpLease string:nonsense)
  assert_contains "$out" "Invalid IP address 'nonsense'"
}

testAddDhcpLeaseWithoutDhcp()
{
  need_dbus || return 0
  need_dhcp || return 0
  start_forwarder || return

  out=$(add_lease 192.0.2.150 00:23:45:67:89:ab client)
  assert_contains "$out" "DHCPv4 not configured"
}

run_suite "$@"
