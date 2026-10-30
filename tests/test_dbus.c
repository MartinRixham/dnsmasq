/* dnsmasq is Copyright (c) 2026 Martin Rixham

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Tests for the DBus interface in dbus.c

   Method calls are built with libdbus and handed straight to
   message_handler(), with no bus involved. The test binary defines its
   own dbus_connection_send(), which the linker prefers to libdbus's, so
   replies and signals are captured here instead of being sent. */

#include "tests.h"

#ifdef HAVE_DBUS

#include <dbus/dbus.h>

DBusHandlerResult message_handler(DBusConnection *connection,
                                  DBusMessage *message, void *user_data);

#define MAX_SENT 8

static DBusMessage *sent[MAX_SENT];
static int nsent;

dbus_bool_t dbus_connection_send(DBusConnection *connection,
                                 DBusMessage *message,
                                 dbus_uint32_t *serial) {
  (void)connection;
  (void)serial;
  ck_assert_int_lt(nsent, MAX_SENT);
  sent[nsent++] = dbus_message_ref(message);
  return TRUE;
}

static void dbus_setup(void) {
  static const char *const args[] = {"--enable-dbus",
                                     "--server=192.0.2.53", NULL};

  test_daemon_init(args);
}

static DBusMessage *new_call(const char *method) {
  DBusMessage *msg = dbus_message_new_method_call(
      DNSMASQ_SERVICE, DNSMASQ_PATH, DNSMASQ_SERVICE, method);

  ck_assert_ptr_nonnull(msg);
  /* A reply needs a serial to refer to; normally the bus sets it. */
  dbus_message_set_serial(msg, 1);
  return msg;
}

/* Pass msg to the handler, consuming it, and return the one reply. */
static DBusMessage *dispatch(DBusMessage *msg) {
  ck_assert_int_eq(message_handler(NULL, msg, NULL),
                   DBUS_HANDLER_RESULT_HANDLED);
  dbus_message_unref(msg);
  ck_assert_int_eq(nsent, 1);
  nsent = 0;
  return sent[0];
}

static DBusMessage *call_empty(const char *method) {
  return dispatch(new_call(method));
}

static DBusMessage *call_bool(const char *method, dbus_bool_t val) {
  DBusMessage *msg = new_call(method);

  dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &val, DBUS_TYPE_INVALID);
  return dispatch(msg);
}

/* Call method with one array of strings, NULL-terminated. */
static DBusMessage *call_strings(const char *method, const char *const *strs) {
  DBusMessage *msg = new_call(method);
  DBusMessageIter iter, array;

  dbus_message_iter_init_append(msg, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                   DBUS_TYPE_STRING_AS_STRING, &array);
  for (; *strs; strs++)
    dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, strs);
  dbus_message_iter_close_container(&iter, &array);

  return dispatch(msg);
}

/* SetServersEx takes an array of arrays of strings. Each group is
   NULL-terminated, and an extra NULL ends the list. */
static DBusMessage *call_servers_ex(const char *const *groups) {
  DBusMessage *msg = new_call("SetServersEx");
  DBusMessageIter iter, outer, inner;

  dbus_message_iter_init_append(msg, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "as", &outer);
  while (*groups) {
    dbus_message_iter_open_container(&outer, DBUS_TYPE_ARRAY,
                                     DBUS_TYPE_STRING_AS_STRING, &inner);
    for (; *groups; groups++)
      dbus_message_iter_append_basic(&inner, DBUS_TYPE_STRING, groups);
    dbus_message_iter_close_container(&outer, &inner);
    groups++;
  }
  dbus_message_iter_close_container(&iter, &outer);

  return dispatch(msg);
}

static void assert_ok(DBusMessage *reply) {
  if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
    const char *text = "";

    dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &text,
                          DBUS_TYPE_INVALID);
    ck_abort_msg("unexpected error %s: %s", dbus_message_get_error_name(reply),
                 text);
  }
  ck_assert_int_eq(dbus_message_get_type(reply),
                   DBUS_MESSAGE_TYPE_METHOD_RETURN);
  ck_assert_int_eq(dbus_message_get_reply_serial(reply), 1);
  dbus_message_unref(reply);
}

/* Check reply is an InvalidArgs error whose text contains expect. */
static void assert_invalid_args(DBusMessage *reply, const char *expect) {
  const char *text = NULL;

  ck_assert_int_eq(dbus_message_get_type(reply), DBUS_MESSAGE_TYPE_ERROR);
  ck_assert_str_eq(dbus_message_get_error_name(reply),
                   DBUS_ERROR_INVALID_ARGS);
  ck_assert(dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &text,
                                  DBUS_TYPE_INVALID));
  ck_assert_msg(strstr(text, expect), "error <%s> does not contain <%s>", text,
                expect);
  dbus_message_unref(reply);
}

/* Find the upstream server for domain ("" for the default) at address
   addr, port port. */
static struct server *find_server(const char *domain, const char *addr,
                                  int port) {
  struct server *serv;
  char buf[ADDRSTRLEN];

  for (serv = daemon->servers; serv; serv = serv->next)
    if (hostname_isequal(serv->domain, domain) &&
        prettyprint_addr(&serv->addr, buf) == port && strcmp(buf, addr) == 0)
      return serv;

  return NULL;
}

static int count_servers(int flag) {
  struct server *serv;
  int count = 0;

  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->flags & flag)
      count++;

  return count;
}

static struct server *find_local(const char *domain) {
  struct server *serv;

  for (serv = daemon->local_domains; serv; serv = serv->next)
    if (hostname_isequal(serv->domain, domain))
      return serv;

  return NULL;
}

START_TEST(test_get_version) {
  DBusMessage *reply = call_empty("GetVersion");
  const char *version;

  ck_assert(dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &version,
                                  DBUS_TYPE_INVALID));
  ck_assert_str_eq(version, VERSION);
  dbus_message_unref(reply);
}
END_TEST

static void check_introspection(const char *name) {
  DBusMessage *msg = dbus_message_new_method_call(
      DNSMASQ_SERVICE, DNSMASQ_PATH, DBUS_INTERFACE_INTROSPECTABLE,
      "Introspect");
  DBusMessage *reply;
  const char *xml;
  char iface[256];

  dbus_message_set_serial(msg, 1);
  reply = dispatch(msg);
  ck_assert(dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &xml,
                                  DBUS_TYPE_INVALID));

  snprintf(iface, sizeof(iface), "<interface name=\"%s\">", name);
  ck_assert_ptr_nonnull(strstr(xml, iface));
  ck_assert_ptr_nonnull(strstr(xml, "<node name=\"" DNSMASQ_PATH "\">"));
  ck_assert_ptr_nonnull(strstr(xml, "<method name=\"SetServersEx\">"));
  ck_assert_ptr_nonnull(strstr(xml, "</node>"));
#ifdef HAVE_DHCP
  ck_assert_ptr_nonnull(strstr(xml, "<method name=\"AddDhcpLease\">"));
#else
  ck_assert_ptr_null(strstr(xml, "AddDhcpLease"));
#endif
  dbus_message_unref(reply);
}

START_TEST(test_introspect) { check_introspection(DNSMASQ_SERVICE); }
END_TEST

START_TEST(test_introspect_custom_name) {
  static const char *const args[] = {"--enable-dbus=org.example.dns", NULL};

  test_daemon_init(args);
  check_introspection("org.example.dns");
}
END_TEST

START_TEST(test_unknown_method) {
  DBusMessage *msg = new_call("NoSuchMethod");

  /* Left to libdbus, which replies UnknownMethod. */
  ck_assert_int_eq(message_handler(NULL, msg, NULL),
                   DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
  ck_assert_int_eq(nsent, 0);
  dbus_message_unref(msg);
}
END_TEST

/*
 * SetServers: flat arguments, IPv4 as UINT32 and IPv6 as 16 BYTEs, each
 * followed by any number of domains.
 */

static void append_ipv4(DBusMessage *msg, const char *addr) {
  struct in_addr a;
  dbus_uint32_t u;

  ck_assert_int_eq(inet_pton(AF_INET, addr, &a), 1);
  /* The interface wants the address as a number: 192.0.2.1 is 0xc0000201. */
  u = ntohl(a.s_addr);
  dbus_message_append_args(msg, DBUS_TYPE_UINT32, &u, DBUS_TYPE_INVALID);
}

static void append_ipv6(DBusMessage *msg, const char *addr, int nbytes) {
  unsigned char a[16];
  int i;

  ck_assert_int_eq(inet_pton(AF_INET6, addr, a), 1);
  for (i = 0; i < nbytes; i++)
    dbus_message_append_args(msg, DBUS_TYPE_BYTE, &a[i], DBUS_TYPE_INVALID);
}

static void append_string(DBusMessage *msg, const char *s) {
  dbus_message_append_args(msg, DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID);
}

START_TEST(test_set_servers) {
  DBusMessage *msg = new_call("SetServers");
  struct server *serv;

  append_ipv4(msg, "192.0.2.1");
  append_ipv4(msg, "192.0.2.2");
  append_string(msg, "one.test");
  append_string(msg, "two.test");
  append_ipv6(msg, "2001:db8::1", 16);
  append_string(msg, "six.test");
  assert_ok(dispatch(msg));

  serv = find_server("", "192.0.2.1", NAMESERVER_PORT);
  ck_assert_ptr_nonnull(serv);
  ck_assert(serv->flags & SERV_FROM_DBUS);
  ck_assert_ptr_nonnull(find_server("one.test", "192.0.2.2", NAMESERVER_PORT));
  ck_assert_ptr_nonnull(find_server("two.test", "192.0.2.2", NAMESERVER_PORT));
  ck_assert_ptr_nonnull(
      find_server("six.test", "2001:db8::1", NAMESERVER_PORT));
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 4);

  /* The server from the command line is untouched. */
  serv = find_server("", "192.0.2.53", NAMESERVER_PORT);
  ck_assert_ptr_nonnull(serv);
  ck_assert(!(serv->flags & SERV_FROM_DBUS));
}
END_TEST

START_TEST(test_set_servers_local) {
  DBusMessage *msg = new_call("SetServers");

  /* 0.0.0.0 means answer locally, like --local. */
  append_ipv4(msg, "0.0.0.0");
  append_string(msg, "local.test");
  assert_ok(dispatch(msg));

  ck_assert_ptr_nonnull(find_local("local.test"));
  ck_assert(find_local("local.test")->flags & SERV_FROM_DBUS);
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 0);

  /* And is replaced like any other. */
  msg = new_call("SetServers");
  append_ipv4(msg, "192.0.2.1");
  assert_ok(dispatch(msg));
  ck_assert_ptr_null(find_local("local.test"));
}
END_TEST

START_TEST(test_set_servers_replaces) {
  DBusMessage *msg = new_call("SetServers");

  append_ipv4(msg, "192.0.2.1");
  append_string(msg, "one.test");
  assert_ok(dispatch(msg));

  msg = new_call("SetServers");
  append_ipv4(msg, "192.0.2.9");
  append_string(msg, "nine.test");
  assert_ok(dispatch(msg));

  ck_assert_ptr_null(find_server("one.test", "192.0.2.1", NAMESERVER_PORT));
  ck_assert_ptr_nonnull(find_server("nine.test", "192.0.2.9", NAMESERVER_PORT));
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 1);

  /* No arguments is an error, so can't be used to remove them all. */
  assert_invalid_args(call_empty("SetServers"), "Failed to initialize");
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 1);
  ck_assert_ptr_nonnull(find_server("", "192.0.2.53", NAMESERVER_PORT));
}
END_TEST

START_TEST(test_set_servers_short_ipv6) {
  DBusMessage *msg = new_call("SetServers");

  /* 15 bytes isn't an address: it and its domain are skipped, and
     parsing carries on with the next address. */
  append_ipv6(msg, "2001:db8::1", 15);
  append_string(msg, "short.test");
  append_ipv4(msg, "192.0.2.3");
  append_string(msg, "three.test");
  assert_ok(dispatch(msg));

  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 1);
  ck_assert_ptr_nonnull(
      find_server("three.test", "192.0.2.3", NAMESERVER_PORT));
}
END_TEST

START_TEST(test_set_servers_stops_at_other_types) {
  DBusMessage *msg = new_call("SetServers");
  dbus_int32_t junk = 42;

  append_ipv4(msg, "192.0.2.4");
  dbus_message_append_args(msg, DBUS_TYPE_INT32, &junk, DBUS_TYPE_INVALID);
  append_ipv4(msg, "192.0.2.5");
  assert_ok(dispatch(msg));

  ck_assert_ptr_nonnull(find_server("", "192.0.2.4", NAMESERVER_PORT));
  ck_assert_ptr_null(find_server("", "192.0.2.5", NAMESERVER_PORT));
}
END_TEST

/*
 * SetServersEx: an array of arrays of strings, address first.
 */

START_TEST(test_set_servers_ex) {
  static const char *const groups[] = {
      "192.0.2.1#5353", "one.test", "two.test", NULL,
      "2001:db8::2",    NULL,
      "0.0.0.0",        "local.test", NULL,
      NULL};

  assert_ok(call_servers_ex(groups));

  ck_assert_ptr_nonnull(find_server("one.test", "192.0.2.1", 5353));
  ck_assert_ptr_nonnull(find_server("two.test", "192.0.2.1", 5353));
  ck_assert_ptr_nonnull(find_server("", "2001:db8::2", NAMESERVER_PORT));

  /* 0.0.0.0 means answer locally, like --local. */
  ck_assert_ptr_nonnull(find_local("local.test"));
  ck_assert(find_local("local.test")->flags & SERV_FROM_DBUS);
}
END_TEST

START_TEST(test_set_servers_ex_wrong_type) {
  static const char *const strs[] = {"192.0.2.1", NULL};

  /* "as" where "aas" is expected. */
  DBusMessage *msg = new_call("SetServersEx");
  DBusMessageIter iter, array;

  dbus_message_iter_init_append(msg, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                   DBUS_TYPE_STRING_AS_STRING, &array);
  dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &strs[0]);
  dbus_message_iter_close_container(&iter, &array);
  assert_invalid_args(dispatch(msg), "Expected array of string arrays");

  assert_invalid_args(call_empty("SetServersEx"), "Failed to initialize");
}
END_TEST

START_TEST(test_set_servers_ex_bad_groups) {
  static const char *const empty[] = {NULL, NULL};
  static const char *const blank[] = {"", "x.test", NULL, NULL};
  static const char *const bad[] = {"192.0.2.1", NULL, "192.0.2.2#99999",
                                    "bad.test", NULL, NULL};

  /* An empty inner array: built by hand, as call_servers_ex() can't
     express one. */
  DBusMessage *msg = new_call("SetServersEx");
  DBusMessageIter iter, outer, inner;

  dbus_message_iter_init_append(msg, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "as", &outer);
  dbus_message_iter_open_container(&outer, DBUS_TYPE_ARRAY,
                                   DBUS_TYPE_STRING_AS_STRING, &inner);
  dbus_message_iter_close_container(&outer, &inner);
  dbus_message_iter_close_container(&iter, &outer);
  assert_invalid_args(dispatch(msg), "Expected IP address");

  /* An empty outer array is fine, and removes all DBus servers. */
  assert_ok(call_servers_ex(empty));
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 0);

  assert_invalid_args(call_servers_ex(blank), "Empty IP address");
  assert_invalid_args(call_servers_ex(bad),
                      "Invalid IP address '192.0.2.2#99999': bad port");

  /* The command line server survives all of that. */
  ck_assert_ptr_nonnull(find_server("", "192.0.2.53", NAMESERVER_PORT));
}
END_TEST

/*
 * SetDomainServers: an array of strings in the format of --server.
 */

START_TEST(test_set_domain_servers) {
  static const char *const strs[] = {"/one.test/two.test/192.0.2.1#5353",
                                     "192.0.2.2", "/local.test/",
                                     "/v6.test/2001:db8::3", NULL};

  assert_ok(call_strings("SetDomainServers", strs));

  ck_assert_ptr_nonnull(find_server("one.test", "192.0.2.1", 5353));
  ck_assert_ptr_nonnull(find_server("two.test", "192.0.2.1", 5353));
  ck_assert_ptr_nonnull(find_server("", "192.0.2.2", NAMESERVER_PORT));
  ck_assert_ptr_nonnull(find_server("v6.test", "2001:db8::3", NAMESERVER_PORT));
  ck_assert_ptr_nonnull(find_local("local.test"));
  ck_assert_int_eq(count_servers(SERV_FROM_DBUS), 4);
}
END_TEST

START_TEST(test_set_domain_servers_errors) {
  static const char *const empty[] = {"", NULL};
  static const char *const no_leading[] = {"one.test/192.0.2.1", NULL};
  static const char *const no_domain[] = {"/192.0.2.1", NULL};
  static const char *const bad_port[] = {"/one.test/192.0.2.1#port", NULL};
  static const char *const later_bad[] = {"192.0.2.1", "/x.test/192.0.2.2#0x35",
                                          NULL};

  assert_invalid_args(call_strings("SetDomainServers", empty), "Empty string");
  assert_invalid_args(call_strings("SetDomainServers", no_leading),
                      "No domain terminator");
  assert_invalid_args(call_strings("SetDomainServers", no_domain),
                      "No domain terminator");
  assert_invalid_args(call_strings("SetDomainServers", bad_port),
                      "Invalid IP address '192.0.2.1#port': bad port");
  assert_invalid_args(call_strings("SetDomainServers", later_bad),
                      "Invalid IP address '192.0.2.2#0x35': bad port");

  ck_assert_ptr_nonnull(find_server("", "192.0.2.53", NAMESERVER_PORT));
}
END_TEST

/*
 * Options.
 */

START_TEST(test_bool_options) {
  static const struct {
    const char *method;
    int opt;
  } opts[] = {{"SetFilterWin2KOption", OPT_FILTER},
              {"SetBogusPrivOption", OPT_BOGUSPRIV},
              {"SetLocaliseQueriesOption", OPT_LOCALISE}};
  unsigned int i;

  for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
    ck_assert(!option_bool(opts[i].opt));
    assert_ok(call_bool(opts[i].method, TRUE));
    ck_assert_msg(option_bool(opts[i].opt), "%s didn't set", opts[i].method);
    assert_ok(call_bool(opts[i].method, FALSE));
    ck_assert_msg(!option_bool(opts[i].opt), "%s didn't reset",
                  opts[i].method);
  }
}
END_TEST

START_TEST(test_bool_option_wrong_type) {
  DBusMessage *msg = new_call("SetBogusPrivOption");
  dbus_uint32_t one = 1;

  dbus_message_append_args(msg, DBUS_TYPE_UINT32, &one, DBUS_TYPE_INVALID);
  assert_invalid_args(dispatch(msg), "Expected boolean argument");
  ck_assert(!option_bool(OPT_BOGUSPRIV));

  assert_invalid_args(call_empty("SetFilterAAAA"), "Expected boolean argument");
}
END_TEST

static int filter_rr_count(unsigned short rr) {
  struct rrlist *r;
  int count = 0;

  for (r = daemon->filter_rr; r; r = r->next)
    if (r->rr == rr)
      count++;

  return count;
}

START_TEST(test_filter_rr) {
  assert_ok(call_bool("SetFilterAAAA", TRUE));
  ck_assert_int_eq(filter_rr_count(T_AAAA), 1);
  ck_assert_int_eq(filter_rr_count(T_A), 0);

  /* Repeating it reuses the one list entry. */
  assert_ok(call_bool("SetFilterAAAA", TRUE));
  ck_assert_int_eq(filter_rr_count(T_AAAA), 1);

  assert_ok(call_bool("SetFilterA", TRUE));
  ck_assert_int_eq(filter_rr_count(T_A), 1);

  assert_ok(call_bool("SetFilterAAAA", FALSE));
  ck_assert_int_eq(filter_rr_count(T_AAAA), 0);
  ck_assert_int_eq(filter_rr_count(T_A), 1);
}
END_TEST

/*
 * Metrics.
 */

/* Look up key in an a{su} or a{ss} reply, as a string. Returns NULL if
   absent. */
static const char *dict_get(DBusMessageIter *array, const char *key,
                            char *buf, size_t bufsz) {
  DBusMessageIter dict;

  ck_assert_int_eq(dbus_message_iter_get_arg_type(array),
                   DBUS_TYPE_DICT_ENTRY);
  do {
    const char *k;

    dbus_message_iter_recurse(array, &dict);
    dbus_message_iter_get_basic(&dict, &k);
    dbus_message_iter_next(&dict);
    if (strcmp(k, key) == 0) {
      if (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_UINT32) {
        dbus_uint32_t u;

        dbus_message_iter_get_basic(&dict, &u);
        snprintf(buf, bufsz, "%u", u);
      } else {
        const char *s;

        dbus_message_iter_get_basic(&dict, &s);
        snprintf(buf, bufsz, "%s", s);
      }
      return buf;
    }
  } while (dbus_message_iter_next(array));

  return NULL;
}

static const char *get_metric(const char *key, char *buf, size_t bufsz) {
  DBusMessage *reply = call_empty("GetMetrics");
  DBusMessageIter iter, array;
  const char *val;

  ck_assert_str_eq(dbus_message_get_signature(reply), "a{su}");
  dbus_message_iter_init(reply, &iter);
  dbus_message_iter_recurse(&iter, &array);
  val = dict_get(&array, key, buf, bufsz);
  dbus_message_unref(reply);

  return val;
}

START_TEST(test_metrics) {
  const char *name = get_metric_name(METRIC_DNS_QUERIES_FORWARDED);
  char buf[32];

  daemon->metrics[METRIC_DNS_QUERIES_FORWARDED] = 42;
  ck_assert_str_eq(get_metric(name, buf, sizeof(buf)), "42");
  ck_assert_ptr_null(get_metric("no_such_metric", buf, sizeof(buf)));

  assert_ok(call_empty("ClearMetrics"));
  ck_assert_str_eq(get_metric(name, buf, sizeof(buf)), "0");
}
END_TEST

START_TEST(test_server_metrics) {
  static const char *const strs[] = {"/one.test/two.test/192.0.2.1#5353",
                                     NULL};
  DBusMessage *reply;
  DBusMessageIter iter, servers, dict;
  struct server *serv;
  char buf[64];
  int count = 0, seen = 0;

  assert_ok(call_strings("SetDomainServers", strs));
  find_server("one.test", "192.0.2.1", 5353)->queries = 3;
  find_server("two.test", "192.0.2.1", 5353)->queries = 4;
  serv = find_server("", "192.0.2.53", NAMESERVER_PORT);
  serv->queries = 5;
  serv->nxdomain_replies = 1;

  reply = call_empty("GetServerMetrics");
  ck_assert_str_eq(dbus_message_get_signature(reply), "aa{ss}");
  dbus_message_iter_init(reply, &iter);
  dbus_message_iter_recurse(&iter, &servers);

  /* One entry per address, so the two domains are summed. */
  do {
    const char *addr;

    dbus_message_iter_recurse(&servers, &dict);
    addr = dict_get(&dict, "address", buf, sizeof(buf));
    ck_assert_ptr_nonnull(addr);
    count++;

    if (strcmp(addr, "192.0.2.1") == 0) {
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "port", buf, sizeof(buf)), "5353");
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "queries", buf, sizeof(buf)), "7");
      seen |= 1;
    } else if (strcmp(addr, "192.0.2.53") == 0) {
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "port", buf, sizeof(buf)), "53");
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "queries", buf, sizeof(buf)), "5");
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "nxdomain", buf, sizeof(buf)), "1");
      dbus_message_iter_recurse(&servers, &dict);
      ck_assert_str_eq(dict_get(&dict, "failed_queries", buf, sizeof(buf)),
                       "0");
      seen |= 2;
    }
  } while (dbus_message_iter_next(&servers));

  ck_assert_int_eq(seen, 3);
  ck_assert_int_eq(count, 2);
  dbus_message_unref(reply);
}
END_TEST

#ifdef HAVE_LOOP
START_TEST(test_loop_servers) {
  DBusMessage *reply;
  DBusMessageIter iter, array;
  const char *addr;

  reply = call_empty("GetLoopServers");
  ck_assert_str_eq(dbus_message_get_signature(reply), "as");
  dbus_message_iter_init(reply, &iter);
  dbus_message_iter_recurse(&iter, &array);
  ck_assert_int_eq(dbus_message_iter_get_arg_type(&array), DBUS_TYPE_INVALID);
  dbus_message_unref(reply);

  find_server("", "192.0.2.53", NAMESERVER_PORT)->flags |= SERV_LOOP;
  reply = call_empty("GetLoopServers");
  dbus_message_iter_init(reply, &iter);
  dbus_message_iter_recurse(&iter, &array);
  dbus_message_iter_get_basic(&array, &addr);
  ck_assert_str_eq(addr, "192.0.2.53");
  ck_assert(!dbus_message_iter_next(&array));
  dbus_message_unref(reply);
}
END_TEST
#endif

START_TEST(test_clear_cache) {
  union all_addr addr;
  time_t now = dnsmasq_time();

  inet_pton(AF_INET, "192.0.2.10", &addr.addr4);
  cache_start_insert();
  cache_insert("cached.test", &addr, C_IN, now, 600, F_IPV4 | F_FORWARD);
  cache_end_insert();
  ck_assert_ptr_nonnull(cache_find_by_name(NULL, "cached.test", now, F_IPV4));

  assert_ok(call_empty("ClearCache"));
  ck_assert_ptr_null(cache_find_by_name(NULL, "cached.test", now, F_IPV4));
}
END_TEST

#ifdef HAVE_DHCP

/*
 * DHCP leases.
 */

static void dhcp_setup(void) {
  static const char *const args[] = {
      "--enable-dbus", "--dhcp-range=192.0.2.100,192.0.2.200",
      "--domain=lan.test", "--leasefile-ro", NULL};

  test_daemon_init(args);
  /* With --leasefile-ro and no script, there's no lease file. */
  lease_init(dnsmasq_time());
#ifdef HAVE_DHCP6
  daemon->doing_dhcp6 = 1;
#endif
}

static DBusMessage *new_lease_call(const char *ip, const char *mac,
                                   const char *hostname, int hostname_len,
                                   const unsigned char *clid, int clid_len,
                                   dbus_uint32_t expires, dbus_uint32_t iaid,
                                   dbus_bool_t temporary) {
  DBusMessage *msg = new_call("AddDhcpLease");

  ck_assert(dbus_message_append_args(
      msg, DBUS_TYPE_STRING, &ip, DBUS_TYPE_STRING, &mac, DBUS_TYPE_ARRAY,
      DBUS_TYPE_BYTE, &hostname, hostname_len, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
      &clid, clid_len, DBUS_TYPE_UINT32, &expires, DBUS_TYPE_UINT32, &iaid,
      DBUS_TYPE_BOOLEAN, &temporary, DBUS_TYPE_INVALID));

  return msg;
}

static DBusMessage *add_lease(const char *ip, const char *mac,
                              const char *hostname) {
  static const unsigned char clid[] = {1, 0, 0x23, 0x45, 0x67, 0x89, 0xab};

  return dispatch(new_lease_call(ip, mac, hostname, strlen(hostname), clid,
                                 sizeof(clid), 3600, 0, FALSE));
}

static struct dhcp_lease *find_lease4(const char *ip) {
  struct in_addr addr;

  ck_assert_int_eq(inet_pton(AF_INET, ip, &addr), 1);
  return lease_find_by_addr(addr);
}

static dbus_bool_t del_lease(const char *ip) {
  DBusMessage *msg = new_call("DeleteDhcpLease"), *reply;
  dbus_bool_t ret;

  append_string(msg, ip);
  reply = dispatch(msg);
  ck_assert(dbus_message_get_args(reply, NULL, DBUS_TYPE_BOOLEAN, &ret,
                                  DBUS_TYPE_INVALID));
  dbus_message_unref(reply);

  return ret;
}

START_TEST(test_add_lease) {
  static const unsigned char mac[] = {0x00, 0x23, 0x45, 0x67, 0x89, 0xab};
  struct dhcp_lease *lease;
  time_t now = dnsmasq_time();

  assert_ok(add_lease("192.0.2.150", "00:23:45:67:89:ab", "client"));

  lease = find_lease4("192.0.2.150");
  ck_assert_ptr_nonnull(lease);
  ck_assert_int_eq(lease->hwaddr_type, ARPHRD_ETHER);
  ck_assert_int_eq(lease->hwaddr_len, sizeof(mac));
  ck_assert_mem_eq(lease->hwaddr, mac, sizeof(mac));
  ck_assert_int_eq(lease->clid_len, 7);
  ck_assert_str_eq(lease->hostname, "client");
  ck_assert_str_eq(lease->fqdn, "client.lan.test");
  ck_assert(lease->expires >= now + 3600 && lease->expires <= now + 3601);

  /* And the name is in DNS. */
  ck_assert_ptr_nonnull(
      cache_find_by_name(NULL, "client.lan.test", now, F_IPV4));

  /* The same address again updates the lease. */
  assert_ok(add_lease("192.0.2.150", "00:23:45:67:89:ac", "renamed"));
  ck_assert_ptr_eq(find_lease4("192.0.2.150"), lease);
  ck_assert_int_eq(lease->hwaddr[5], 0xac);
  ck_assert_str_eq(lease->hostname, "renamed");
}
END_TEST

START_TEST(test_add_lease_no_hostname) {
  struct dhcp_lease *lease;

  assert_ok(add_lease("192.0.2.151", "00:23:45:67:89:ab", ""));
  lease = find_lease4("192.0.2.151");
  ck_assert_ptr_nonnull(lease);
  ck_assert_ptr_null(lease->hostname);
}
END_TEST

START_TEST(test_add_lease_hostname_not_terminated) {
  static const unsigned char clid[] = {1, 2, 3};
  struct dhcp_lease *lease;

  /* The hostname arrives as a byte array, with no terminating NUL. With
     a length which is a multiple of four, the bytes after it in the
     message are the length of the clid array. */
  assert_ok(dispatch(new_lease_call("192.0.2.152", "00:23:45:67:89:ab",
                                    "four", 4, clid, sizeof(clid), 3600, 0,
                                    FALSE)));
  lease = find_lease4("192.0.2.152");
  ck_assert_ptr_nonnull(lease);
  ck_assert_str_eq(lease->hostname, "four");

  /* A single trailing NUL is allowed. */
  assert_ok(dispatch(new_lease_call("192.0.2.153", "00:23:45:67:89:ab",
                                    "nul", 4, clid, sizeof(clid), 3600, 0,
                                    FALSE)));
  ck_assert_str_eq(find_lease4("192.0.2.153")->hostname, "nul");
}
END_TEST

START_TEST(test_add_lease_dhcp_off) {
  /* dbus_setup(), so no DHCP. */
  assert_invalid_args(add_lease("192.0.2.150", "00:23:45:67:89:ab", "x"),
                      "DHCPv4 not configured");
#ifdef HAVE_DHCP6
  assert_invalid_args(add_lease("2001:db8::10", "00:23:45:67:89:ab", "x"),
                      "DHCPv6 not configured");
#endif
}
END_TEST

#ifdef HAVE_DHCP6
START_TEST(test_add_lease6) {
  static const unsigned char duid[] = {0, 3, 0, 1, 0, 0x23, 0x45, 0x67, 0x89,
                                       0xab};
  struct in6_addr addr;
  struct dhcp_lease *lease;

  assert_ok(dispatch(new_lease_call("2001:db8::10", "00:23:45:67:89:ab",
                                    "six", 3, duid, sizeof(duid), 3600,
                                    203569230, TRUE)));

  inet_pton(AF_INET6, "2001:db8::10", &addr);
  lease = lease6_find_by_addr(&addr, 128, 0);
  ck_assert_ptr_nonnull(lease);
  ck_assert(lease->flags & LEASE_TA);
  ck_assert_uint_eq(lease->iaid, 203569230);
  ck_assert_int_eq(lease->clid_len, sizeof(duid));
  ck_assert_mem_eq(lease->clid, duid, sizeof(duid));

  ck_assert(del_lease("2001:db8::10"));
  ck_assert_ptr_null(lease6_find_by_addr(&addr, 128, 0));
}
END_TEST
#endif

START_TEST(test_delete_lease) {
  DBusMessage *msg;

  assert_ok(add_lease("192.0.2.170", "00:23:45:67:89:ab", "gone"));
  ck_assert_ptr_nonnull(find_lease4("192.0.2.170"));

  ck_assert(del_lease("192.0.2.170"));
  ck_assert_ptr_null(find_lease4("192.0.2.170"));
  ck_assert(!del_lease("192.0.2.170"));

  msg = new_call("DeleteDhcpLease");
  append_string(msg, "nonsense");
  assert_invalid_args(dispatch(msg), "Invalid IP address 'nonsense'");

  assert_invalid_args(call_empty("DeleteDhcpLease"), "Failed to initialize");
}
END_TEST

/* Check the one message sent was signal name with the given args. */
static void assert_signal(const char *name, const char *ip, const char *mac,
                          const char *hostname) {
  DBusMessage *sig;
  const char *a, *m, *h;

  ck_assert_int_eq(nsent, 1);
  sig = sent[0];
  nsent = 0;

  ck_assert(dbus_message_is_signal(sig, DNSMASQ_SERVICE, name));
  ck_assert_str_eq(dbus_message_get_path(sig), DNSMASQ_PATH);
  ck_assert(dbus_message_get_args(sig, NULL, DBUS_TYPE_STRING, &a,
                                  DBUS_TYPE_STRING, &m, DBUS_TYPE_STRING, &h,
                                  DBUS_TYPE_INVALID));
  ck_assert_str_eq(a, ip);
  ck_assert_str_eq(m, mac);
  ck_assert_str_eq(h, hostname);
  dbus_message_unref(sig);
}

START_TEST(test_lease_signals) {
  struct dhcp_lease *lease;

  /* Without a connection, nothing is sent. */
  assert_ok(add_lease("192.0.2.180", "00:23:45:67:89:ab", "sig"));
  lease = find_lease4("192.0.2.180");
  emit_dbus_signal(ACTION_ADD, lease, lease->hostname);
  ck_assert_int_eq(nsent, 0);

  /* Any non-NULL pointer will do, as dbus_connection_send() is ours. */
  daemon->dbus = &nsent;

  emit_dbus_signal(ACTION_ADD, lease, lease->hostname);
  assert_signal("DhcpLeaseAdded", "192.0.2.180", "00:23:45:67:89:ab", "sig");

  emit_dbus_signal(ACTION_OLD, lease, lease->fqdn);
  assert_signal("DhcpLeaseUpdated", "192.0.2.180", "00:23:45:67:89:ab",
                "sig.lan.test");

  emit_dbus_signal(ACTION_DEL, lease, NULL);
  assert_signal("DhcpLeaseDeleted", "192.0.2.180", "00:23:45:67:89:ab", "");

  /* Other actions aren't signalled. */
  emit_dbus_signal(ACTION_ARP, lease, NULL);
  ck_assert_int_eq(nsent, 0);
}
END_TEST

#endif /* HAVE_DHCP */

#endif /* HAVE_DBUS */

Suite *dbus_suite(void) {
  Suite *s = suite_create("dbus");
#ifdef HAVE_DBUS
  TCase *tc = tcase_create("methods");

  tcase_add_checked_fixture(tc, dbus_setup, NULL);
  tcase_add_test(tc, test_get_version);
  tcase_add_test(tc, test_introspect);
  tcase_add_test(tc, test_unknown_method);
  tcase_add_test(tc, test_bool_options);
  tcase_add_test(tc, test_bool_option_wrong_type);
  tcase_add_test(tc, test_filter_rr);
  tcase_add_test(tc, test_metrics);
  tcase_add_test(tc, test_server_metrics);
#ifdef HAVE_LOOP
  tcase_add_test(tc, test_loop_servers);
#endif
  tcase_add_test(tc, test_clear_cache);
#ifdef HAVE_DHCP
  tcase_add_test(tc, test_add_lease_dhcp_off);
#endif
  suite_add_tcase(s, tc);

  /* No fixture: it sets its own --enable-dbus. */
  tc = tcase_create("name");
  tcase_add_test(tc, test_introspect_custom_name);
  suite_add_tcase(s, tc);

  tc = tcase_create("servers");
  tcase_add_checked_fixture(tc, dbus_setup, NULL);
  tcase_add_test(tc, test_set_servers);
  tcase_add_test(tc, test_set_servers_local);
  tcase_add_test(tc, test_set_servers_replaces);
  tcase_add_test(tc, test_set_servers_short_ipv6);
  tcase_add_test(tc, test_set_servers_stops_at_other_types);
  tcase_add_test(tc, test_set_servers_ex);
  tcase_add_test(tc, test_set_servers_ex_wrong_type);
  tcase_add_test(tc, test_set_servers_ex_bad_groups);
  tcase_add_test(tc, test_set_domain_servers);
  tcase_add_test(tc, test_set_domain_servers_errors);
  suite_add_tcase(s, tc);

#ifdef HAVE_DHCP
  tc = tcase_create("leases");
  tcase_add_checked_fixture(tc, dhcp_setup, NULL);
  tcase_add_test(tc, test_add_lease);
  tcase_add_test(tc, test_add_lease_no_hostname);
  tcase_add_test(tc, test_add_lease_hostname_not_terminated);
#ifdef HAVE_DHCP6
  tcase_add_test(tc, test_add_lease6);
#endif
  tcase_add_test(tc, test_delete_lease);
  tcase_add_test(tc, test_lease_signals);
  suite_add_tcase(s, tc);
#endif
#endif

  return s;
}
