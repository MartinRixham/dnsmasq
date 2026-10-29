# Helpers for the functional tests. Sourced by dnsmasq_test.sh.
#
# Each test gets its own scratch directory and starts one or more dnsmasq
# instances listening on 127.0.0.1 on unprivileged ports, so the tests can
# run as an ordinary user and alongside any system resolver.

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
    kill "$_pid" 2>/dev/null && wait "$_pid" 2>/dev/null
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
