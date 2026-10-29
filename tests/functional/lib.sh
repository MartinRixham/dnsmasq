# Helpers and shunit2 hooks for the functional test suites, which source
# this and end by calling run_suite.
#
# Each test gets its own scratch directory and starts one or more dnsmasq
# instances listening on 127.0.0.1 on unprivileged ports, so the tests can
# run as an ordinary user and alongside any system resolver.
#
# shunit2 2.1.6 or later is needed. It is found on the PATH, in
# /usr/share/shunit2, or wherever SHUNIT2 points.

DNSMASQ=${DNSMASQ:-$TOP/src/dnsmasq}
DIG=${DIG:-dig}

# Base port; each instance started within a test takes the next one.
PORT_BASE=${PORT_BASE:-$((20000 + $$ % 20000))}

is_root() { [ "$(id -u)" -eq 0 ]; }

# has_feature NAME: true if dnsmasq was built with NAME, as listed in the
# compile time options of --version.
has_feature()
{
  "$DNSMASQ" --version | grep -q "options:.* $1\( \|\$\)"
}

# assert_contains [MESSAGE] HAYSTACK NEEDLE
# assert_not_contains [MESSAGE] HAYSTACK NEEDLE
#
# Like assertContains and assertNotContains, which only arrived in
# shunit2 2.1.8; built on assertTrue so 2.1.6 is enough.
assert_contains()
{
  [ $# -eq 3 ] && { _msg=$1; shift; } || _msg="expected <$1> to contain <$2>"
  case $1 in
    *"$2"*) assertTrue "$_msg" 0 ;;
    *)      assertTrue "$_msg" 1 ;;
  esac
}

assert_not_contains()
{
  [ $# -eq 3 ] && { _msg=$1; shift; } || _msg="expected <$1> not to contain <$2>"
  case $1 in
    *"$2"*) assertTrue "$_msg" 1 ;;
    *)      assertTrue "$_msg" 0 ;;
  esac
}

# skip_test REASON: skip the rest of the current test, counted as skipped.
skip_test()
{
  echo "  skipped: $1"
  startSkipping
  assertTrue "$1" true
}

# start_dnsmasq NAME [OPTION...]
#
# Start an instance in the foreground (in the background of this shell)
# reading NAME.conf from the scratch directory if it exists, followed by
# OPTIONs. Sets NAME_PORT and NAME_PID, and waits until it answers queries.
start_dnsmasq()
{
  _name=$1; shift
  _port=$((PORT_BASE + _instances))
  _instances=$((_instances + 1))
  _conf=$SCRATCH/$_name.conf
  [ -f "$_conf" ] || : > "$_conf"

  "$DNSMASQ" --keep-in-foreground \
    --conf-file="$_conf" \
    --user="$(id -un)" --group="$(id -gn)" \
    --pid-file="$SCRATCH/$_name.pid" \
    --log-facility="$SCRATCH/$_name.log" --log-queries=extra \
    --listen-address=127.0.0.1 --bind-interfaces --port="$_port" \
    "$@" 2> "$SCRATCH/$_name.err" &
  _pid=$!
  eval "${_name}_PORT=$_port ${_name}_PID=$_pid"
  echo "$_name $_pid" >> "$SCRATCH/pids"

  # dnsmasq answers version.bind in the CHAOS class itself, so this tells
  # us it is up without depending on any test data.
  _tries=0
  until $DIG @127.0.0.1 -p "$_port" +short +time=1 +tries=1 \
          version.bind CH TXT 2>/dev/null | grep -q dnsmasq; do
    if ! kill -0 "$_pid" 2>/dev/null; then
      fail "dnsmasq instance $_name exited during startup: $(cat "$SCRATCH/$_name.err")"
      return 1
    fi
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 100 ]; then
      fail "dnsmasq instance $_name did not answer on port $_port"
      return 1
    fi
    sleep 0.1
  done
}

# stop_dnsmasq NAME: SIGTERM an instance and wait for it to exit.
# Returns its exit status.
stop_dnsmasq()
{
  eval "_pid=\$${1}_PID"
  kill "$_pid" 2>/dev/null
  wait "$_pid"
}

stop_all()
{
  [ -f "$SCRATCH/pids" ] || return 0
  while read -r _name _pid; do
    kill "$_pid" 2>/dev/null || continue
    # A dnsmasq stuck in a loop never gets round to handling SIGTERM.
    _tries=0
    while kill -0 "$_pid" 2>/dev/null && [ $_tries -lt 50 ]; do
      sleep 0.1; _tries=$((_tries + 1))
    done
    if kill -9 "$_pid" 2>/dev/null; then
      fail "$_name ignored SIGTERM; killed it"
    fi
    wait "$_pid" 2>/dev/null
  done < "$SCRATCH/pids"
  rm -f "$SCRATCH/pids"
}

# query NAME [DIG-ARGS...]: query instance NAME, print the short answer.
query()
{
  eval "_port=\$${1}_PORT"; shift
  $DIG @127.0.0.1 -p "$_port" +short +time=2 +tries=1 "$@"
}

# rcode NAME [DIG-ARGS...]: print the response code (NOERROR, NXDOMAIN...).
rcode()
{
  eval "_port=\$${1}_PORT"; shift
  $DIG @127.0.0.1 -p "$_port" +time=2 +tries=1 "$@" |
    sed -n 's/.*status: \([A-Z]*\),.*/\1/p'
}

# count_log NAME PATTERN: number of lines in NAME's log matching PATTERN.
count_log()
{
  grep -c -- "$2" "$SCRATCH/$1.log" 2>/dev/null
}

# Dump logs to help diagnose a failing test.
dump_logs()
{
  for _f in "$SCRATCH"/*.log "$SCRATCH"/*.err; do
    [ -s "$_f" ] || continue
    echo "----- ${_f##*/} -----"
    cat "$_f"
  done
}

oneTimeSetUp()
{
  if [ ! -x "$DNSMASQ" ]; then
    echo "dnsmasq binary $DNSMASQ not found; build it first." >&2
    exit 1
  fi
  if ! command -v "$DIG" >/dev/null 2>&1; then
    echo "$DIG not found; install dig (bind-tools/dnsutils)." >&2
    exit 1
  fi
  if ! shunit2_at_least 2 1 6; then
    echo "shunit2 ${SHUNIT_VERSION:-(unknown version)} is too old, 2.1.6 or later is needed." >&2
    exit 1
  fi
  "$DNSMASQ" --version | head -n 2
  if command -v suiteSetUp >/dev/null; then
    suiteSetUp
  fi
}

setUp()
{
  SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/dnsmasq-test.XXXXXX")
  _instances=0
}

tearDown()
{
  stop_all
  # A sanitizer build reports to stderr but needn't exit, so look.
  for _f in "$SCRATCH"/*.err; do
    if grep -q -e 'Sanitizer' -e 'runtime error:' "$_f" 2>/dev/null; then
      fail "sanitizer report from ${_f##*/}"
    fi
  done
  # shunit2 has no public "did this test fail" hook; this variable has
  # been stable across 2.1.x.
  if [ "${__shunit_testSuccess:-0}" != "${SHUNIT_TRUE:-0}" ]; then
    dump_logs
  fi
  rm -rf "$SCRATCH"
}

# shunit2_at_least MAJOR MINOR PATCH: true if the shunit2 sourced is that
# version or later.
shunit2_at_least()
{
  # shellcheck disable=SC2046
  set -- "$@" $(echo "${SHUNIT_VERSION:-0}" | sed 's/[^0-9.].*//; s/\./ /g')
  [ "${4:-0}" -ne "$1" ] && { [ "${4:-0}" -gt "$1" ]; return; }
  [ "${5:-0}" -ne "$2" ] && { [ "${5:-0}" -gt "$2" ]; return; }
  [ "${6:-0}" -ge "$3" ]
}

# List the tests ourselves rather than leave it to shunit2, which finds
# them with egrep and xargs and, if either is missing, runs nothing and
# reports OK. suite() is honoured by every 2.1.x release.
suite()
{
  _tests=${_run_tests:-$(sed -n 's/^\(test[A-Za-z0-9_]*\)().*/\1/p' "$0")}
  if [ -z "$_tests" ]; then
    echo "no tests found in $0." >&2
    exit 1
  fi
  for _t in $_tests; do
    suite_addTest "$_t"
  done
}

# run_suite [-- TEST...]: find shunit2 and run the tests defined by the
# calling script, or just the named ones.
run_suite()
{
  [ "${1:-}" = "--" ] && shift
  _run_tests="$*"

  for _tool in awk sed grep cksum mktemp; do
    if ! command -v $_tool >/dev/null 2>&1; then
      echo "$_tool not found." >&2
      exit 1
    fi
  done

  if [ -n "${SHUNIT2:-}" ]; then
    :
  elif command -v shunit2 >/dev/null 2>&1; then
    SHUNIT2=$(command -v shunit2)
  elif [ -f /usr/share/shunit2/shunit2 ]; then
    SHUNIT2=/usr/share/shunit2/shunit2
  else
    echo "shunit2 not found; install it or set SHUNIT2." >&2
    exit 1
  fi
  # Leave no arguments for shunit2 to parse; suite() picks the tests.
  set --
  # shellcheck disable=SC1090
  . "$SHUNIT2"
}
