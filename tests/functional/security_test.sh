#! /bin/sh
#
# Functional tests of dnsmasq against hostile input, using shunit2.
#
# Covers malformed and abusive queries from clients (bad name compression,
# overlong names, lying section counts, broken EDNS0, responses sent as
# queries, TCP framing abuse, idle connection floods and random fuzzing),
# hostile upstream servers (spoofed replies, cache poisoning, DNS
# rebinding, malformed records, absurd TTLs) and hostile TFTP requests
# and hosts files.
#
# Each test checks dnsmasq's specific defence, and that the daemon is
# still alive and answering correctly afterwards. Built with
# -fsanitize=address,undefined, any sanitizer report also fails the test.
#
# Run with "make check-functional", or directly:
#
#   DNSMASQ=src/dnsmasq tests/functional/security_test.sh
#
# Needs dig, python3 and shunit2; see lib.sh. Crafted packets are made
# by dnstool.py. FUZZ_COUNT and FUZZ_SEED control the fuzzing test.

# NAME_PORT and NAME_PID are assigned by start_dnsmasq with eval.
# shellcheck disable=SC2154

TOP=$(cd "$(dirname "$0")/../.." && pwd)
. "$TOP/tests/functional/lib.sh"

PYTHON=${PYTHON:-python3}
DNSTOOL="$TOP/tests/functional/dnstool.py"

suiteSetUp()
{
  if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "$PYTHON not found; it's needed to craft packets." >&2
    exit 1
  fi
}

dnstool() { "$PYTHON" "$DNSTOOL" "$@"; }

# probe NAME SCENARIO [--tcp]: send one of dnstool's crafted queries.
probe()
{
  eval "_port=\$${1}_PORT"; shift
  dnstool probe "$_port" "$@"
}

# The instance under attack. It knows one name, so we can check that it
# still answers correctly afterwards.
start_target()
{
  cat >> "$SCRATCH/main.conf" <<EOF
no-resolv
no-hosts
address=/probe.test/192.0.2.1
EOF
  start_dnsmasq main
}

# assert_healthy [NAME]: the instance is running and answers correctly.
assert_healthy()
{
  _n=${1:-main}
  eval "_pid=\$${_n}_PID"
  assertTrue "$_n still running" "kill -0 $_pid"
  assertEquals "$_n still answers over UDP" "192.0.2.1" \
    "$(query "$_n" probe.test)"
  assertEquals "$_n still answers over TCP" "192.0.2.1" \
    "$(query "$_n" +tcp probe.test)"
}

# A malicious upstream server, answering according to the first label of
# the question (see dnstool.py). Every question it gets is logged.
start_evil_upstream()
{
  evil_PORT=$((PORT_BASE + _instances))
  _instances=$((_instances + 1))
  : > "$SCRATCH/evil.queries"
  # Not via dnstool(), so that $! is python's pid rather than a subshell's.
  "$PYTHON" "$DNSTOOL" upstream "$evil_PORT" "$SCRATCH/evil.queries" \
    2> "$SCRATCH/evil.err" &
  evil_PID=$!
  echo "evil $evil_PID" >> "$SCRATCH/pids"
  # Wait for it to bind.
  _tries=0
  until [ "$(dnstool probe "$evil_PORT" valid)" != noreply ]; do
    _tries=$((_tries + 1))
    if [ $_tries -ge 50 ]; then
      fail "fake upstream didn't start: $(cat "$SCRATCH/evil.err")"
      return 1
    fi
    sleep 0.1
  done
  echo "server=127.0.0.1#$evil_PORT" >> "$SCRATCH/main.conf"
}

# upstream_asked NAME: how many times the fake upstream was asked NAME.
upstream_asked()
{
  grep -c -x -F -- "$1" "$SCRATCH/evil.queries"
}

#
# Malformed queries from clients
#

testTruncatedAndMalformedQueriesAreDropped()
{
  start_target || return
  for p in empty short-header header-only qdcount-huge label-overrun \
           no-terminator extended-label missing-qtype; do
    for proto in "" --tcp; do
      assertEquals "$p $proto" "noreply" "$(probe main $p $proto)"
    done
  done
  assert_healthy
}

testCompressionPointerAttacks()
{
  start_target || return
  # A pointer to itself, a two-pointer loop, one past the end of the
  # packet and one into the header must not hang, crash or match a name.
  for p in pointer-self pointer-loop pointer-oob pointer-into-header; do
    for proto in "" --tcp; do
      r=$(probe main $p $proto)
      assert_contains "$p $proto: no answer" "$r noreply" "an=0"
    done
  done
  assert_healthy
}

testOverlongNameRejected()
{
  start_target || return
  # 5 labels of 63 octets is 320, over the 255 octet limit.
  assert_contains "$(probe main name-too-long)" "an=0"
  assert_healthy
}

testLyingSectionCounts()
{
  start_target || return
  assert_contains "65535 answers claimed" "$(probe main arcount-lies)" "an=0"
  assert_contains "two questions" "$(probe main qdcount-two)" "an=0"
  assert_contains "no questions" "$(probe main qdcount-zero)" "an=0"
  assert_healthy
}

testResponsesAreNotAnswered()
{
  start_target || return
  # Answering packets with QR set allows reflection loops between two
  # servers, or with a spoofed source address.
  assertEquals "UDP" "noreply" "$(probe main response-bit)"
  assertEquals "TCP" "noreply" "$(probe main response-bit --tcp)"
  assertEquals "no log entry" 0 "$(count_log main 'probe.test from')"
  assert_healthy
}

testUnknownOpcodeNotImplemented()
{
  start_target || return
  assertEquals "rcode=NOTIMP an=0" "$(probe main bad-opcode)"
  assert_healthy
}

testOversizedQueriesDropped()
{
  start_target || return
  assertEquals "trailing garbage" "noreply" "$(probe main trailing-garbage)"
  assertEquals "64k datagram" "noreply" "$(probe main max-udp)"
  assert_healthy
}

testMalformedEdns0()
{
  start_target || return
  # An OPT record overrunning the packet, an option overrunning the OPT
  # record, two OPT records and a 1 byte buffer size. Answering correctly
  # or refusing is fine; anything else isn't.
  for p in opt-overrun opt-bad-option opt-twice opt-tiny-payload; do
    r=$(probe main $p)
    case "$r" in
      noreply|*FORMERR*|*"a=192.0.2.1") ;;
      *) fail "$p: unexpected reply: $r" ;;
    esac
  done
  assert_healthy
}

testLabelTricksDoNotMatchLocalNames()
{
  start_evil_upstream || return
  start_target || return
  # A single label "probe.test", and "probe" "test\0evil", which reads as
  # probe.test if truncated at the NUL. Neither is the local probe.test.
  for p in dot-in-label nul-in-label; do
    assert_not_contains "$p" "$(probe main $p)" "a=192.0.2.1"
  done
  assert_healthy
}

testTcpFramingAbuse()
{
  start_target || return
  # Zero length, a length longer than what follows, the maximum length
  # with nothing behind it, and half a length field. dnsmasq should give
  # up on the connection, not wait or crash.
  for s in zero-length short-body huge-length half-length; do
    assertEquals "$s" "closed" "$(dnstool tcp "$main_PORT" $s)"
  done
  # A bad query followed by a good one on the same connection.
  assertNotEquals "pipelined" "timeout" \
    "$(dnstool tcp "$main_PORT" pipeline-bad-then-good)"
  assert_healthy
}

testIdleTcpConnectionFlood()
{
  start_target || return
  "$PYTHON" "$DNSTOOL" hold "$main_PORT" 200 4 > "$SCRATCH/hold.out" &
  hold=$!
  sleep 1.5

  # Each TCP connection takes a child process, and there's a limit, but
  # UDP is served by the main process and mustn't be held up.
  start=$(date +%s)
  assertEquals "UDP while flooded" "192.0.2.1" "$(query main probe.test)"
  assertTrue "UDP answered promptly" "[ $(($(date +%s) - start)) -le 1 ]"

  wait $hold
  assert_contains "connections were held" "$(cat "$SCRATCH/hold.out")" "open"
  # Once the attacker goes away, TCP recovers.
  tries=0
  until [ "$(query main +tcp probe.test)" = 192.0.2.1 ] || [ $tries -ge 10 ]; do
    sleep 0.5; tries=$((tries + 1))
  done
  assert_healthy
}

testFuzzedQueries()
{
  start_evil_upstream || return
  start_target || return
  count=${FUZZ_COUNT:-3000}
  seed=${FUZZ_SEED:-1}
  echo "  fuzzing with $count packets, seed $seed"
  dnstool fuzz "$main_PORT" "$count" "$seed" >/dev/null
  assertEquals "fuzzer exit status" 0 $?
  assert_healthy
}

#
# Hostile upstream servers
#

testSpoofedRepliesIgnored()
{
  start_evil_upstream || return
  start_target || return
  # Replies with the wrong ID, for a different question, without a
  # question, without QR set, with only a header, or random bytes. All
  # answer 1.2.3.4 if believed.
  for n in wrongid wrongq noquestion notaresponse headeronly garbage; do
    assert_not_contains "$n" \
      "$(query main +time=1 $n.evil.test 2>&1)" "1.2.3.4"
  done
  # And nothing was cached: asking again goes upstream again.
  query main +time=1 wrongid.evil.test >/dev/null 2>&1
  assertTrue "wrongid not cached" \
    "[ $(upstream_asked wrongid.evil.test) -ge 2 ]"
  assert_healthy
}

testCaseRandomisationDetectsSpoofing()
{
  echo "do-0x20-encode" > "$SCRATCH/main.conf"
  start_evil_upstream || return
  start_target || return
  assertEquals "honest reply accepted" "1.2.3.4" "$(query main good.evil.test)"
  # The upstream reply flips the case of the question, as a blind spoofer
  # who can't see the query would get it wrong.
  assert_not_contains "case mismatch rejected" \
    "$(query main +time=1 wrongcase.evil.test 2>&1)" "1.2.3.4"
  assert_healthy
}

testCachePoisoningByExtraRecords()
{
  start_evil_upstream || return
  start_target || return
  # The reply to inject.evil.test carries extra records claiming
  # victim.test and victim2.test are 6.6.6.6. That reply is relayed to
  # the client as it is, but the extra records mustn't be cached.
  assertEquals "1.2.3.4" "$(query main inject.evil.test | head -n 1)"
  assertNotEquals "answer section" "6.6.6.6" "$(query main victim.test)"
  assertNotEquals "additional section" "6.6.6.6" "$(query main victim2.test)"
  assertEquals "victim.test looked up upstream" 1 \
    "$(upstream_asked victim.test)"
  assertEquals "victim2.test looked up upstream" 1 \
    "$(upstream_asked victim2.test)"
  assert_healthy
}

testRebindProtection()
{
  echo "stop-dns-rebind" > "$SCRATCH/main.conf"
  start_evil_upstream || return
  start_target || return

  assertEquals "public address allowed" "1.2.3.4" \
    "$(query main good.evil.test)"
  assertEquals "RFC 1918" "" "$(query main private.evil.test)"
  assertEquals "loopback" "" "$(query main loopback.evil.test)"
  assertEquals "IPv4-mapped IPv6" "" "$(query main mapped.evil.test AAAA)"
  assertTrue "attack logged" \
    "[ $(count_log main 'possible DNS-rebind attack detected: private.evil.test') -ge 1 ]"
  assert_healthy
}

testRebindNotBlockedByDefault()
{
  # The counterpart of testRebindProtection, showing the fake upstream
  # really does send these addresses.
  start_evil_upstream || return
  start_target || return
  assertEquals "192.168.0.66" "$(query main private.evil.test)"
}

testBogusNxdomain()
{
  # Some upstreams answer for nonexistent names with an advertising
  # server's address; bogus-nxdomain turns that back into NXDOMAIN.
  echo "bogus-nxdomain=1.2.3.4" > "$SCRATCH/main.conf"
  start_evil_upstream || return
  start_target || return
  assertEquals "NXDOMAIN" "$(rcode main good.evil.test)"
  assert_healthy
}

testMalformedUpstreamRecords()
{
  start_evil_upstream || return
  start_target || return
  # An answer whose owner name is a compression loop, one whose rdata
  # overruns the packet and an A record cut short.
  for n in ptrloop rdoverrun rdshort; do
    r=$(rcode main $n.evil.test)
    assertNotEquals "$n not accepted" "NOERROR" "$r"
    assertNotEquals "$n answered" "" "$r"
  done
  # Claiming 500 answers when there is one, 4000 answers in an oversized
  # reply, a CNAME loop and a chain of 60 CNAMEs: no crash or hang.
  for n in ancountlies manyanswers cnameloop cnamechain; do
    assertNotEquals "$n answered" "" "$(rcode main $n.evil.test)"
  done
  assert_healthy
}

testMaxCacheTtlCapsHostileTtl()
{
  echo "max-cache-ttl=60" > "$SCRATCH/main.conf"
  start_evil_upstream || return
  start_target || return
  # The upstream says 0xffffffff seconds; it mustn't stay that long.
  query main hugettl.evil.test >/dev/null
  ttl=$($DIG @127.0.0.1 -p "$main_PORT" +noall +answer hugettl.evil.test |
    awk '{print $2}')
  assertTrue "cached TTL $ttl capped" "[ '$ttl' -le 60 ]"
  assert_healthy
}

#
# Hostile files and TFTP requests
#

testHostileHostsFile()
{
  {
    echo "192.0.2.50 good.lan"
    head -c 100000 /dev/zero | tr '\0' 'a'; echo " toolong.lan"
    echo "192.0.2.51 $(head -c 300 /dev/zero | tr '\0' 'b').lan"
    echo "999.1.1.1 badaddr.lan"
    echo "192.0.2.52"
    printf '192.0.2.53 nul\000name.lan\n'
    head -c 2000 /dev/urandom
    echo
    echo "192.0.2.54 alsogood.lan"
  } > "$SCRATCH/hosts"
  echo "addn-hosts=$SCRATCH/hosts" > "$SCRATCH/main.conf"
  start_target || return

  assertEquals "entry before junk" "192.0.2.50" "$(query main good.lan)"
  assertEquals "entry after junk" "192.0.2.54" "$(query main alsogood.lan)"
  assertEquals "bad address ignored" "" "$(query main badaddr.lan)"
  assert_healthy
}

testHostileConfigFileDoesNotCrash()
{
  {
    printf 'address=/'; head -c 100000 /dev/zero | tr '\0' 'a'
    echo '/192.0.2.1'
    printf 'server=/'; head -c 5000 /dev/zero | tr '\0' '/'; echo
    printf 'cname=%s\n' "$(head -c 3000 /dev/zero | tr '\0' 'c')"
    head -c 2000 /dev/urandom
  } > "$SCRATCH/bad.conf"
  "$DNSMASQ" --test --conf-file="$SCRATCH/bad.conf" >/dev/null 2>&1
  status=$?
  # Rejecting it is right; crashing (a signal, so status > 128) isn't.
  assertNotEquals "rejected" 0 $status
  assertTrue "exited normally, status $status" "[ $status -lt 128 ]"
}

testTftpHostileRequests()
{
  has_feature TFTP || { skip_test "built without TFTP"; return; }
  is_root || { skip_test "needs root to bind port 69"; return; }

  mkdir -p "$SCRATCH/tftp/x/..x"
  echo "boot image" > "$SCRATCH/tftp/pxelinux.0"
  # Just outside the TFTP root, so escaping it would really work.
  echo "secret" > "$SCRATCH/secret"
  cat > "$SCRATCH/main.conf" <<EOF
enable-tftp
tftp-root=$SCRATCH/tftp
EOF
  start_target || return

  assertEquals "control: legitimate read" "data" \
    "$(dnstool tftp read:pxelinux.0)"
  # "x/..x/../" is the case where a harmless "/..x" once hid a later
  # "/../" from the check.
  for f in ../secret x/../../secret x/..x/../../../secret; do
    assert_contains "$f refused" "$(dnstool tftp "read:$f")" \
      "Permission denied"
  done
  # Absolute paths are taken relative to the TFTP root.
  assert_contains "absolute path" "$(dnstool tftp absolute-path)" "not found"

  assert_contains "uploads refused" "$(dnstool tftp write-request)" "error"
  [ ! -e "$SCRATCH/tftp/upload" ]
  assertTrue "nothing written" $?
  # Malformed requests: an error or nothing, but not the file and not
  # a crash.
  for s in no-terminator no-mode bad-mode long-name bad-opcode empty; do
    assertNotEquals "$s" "data" "$(dnstool tftp $s)"
  done
  # An absurd block size option may be ignored; it just mustn't hurt.
  dnstool tftp bad-blksize >/dev/null
  assert_healthy
}

run_suite "$@"
