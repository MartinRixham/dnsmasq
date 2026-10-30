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

/* Tests for upstream server management in domain-match.c */

#include "tests.h"

static void domain_match_setup(void) { test_daemon_init(NULL); }

START_TEST(test_reuse_moves_to_tail) {
  struct server *a, *b;

  mark_servers(SERV_FROM_DBUS);
  ck_assert(
      add_update_server(SERV_FROM_DBUS, NULL, NULL, NULL, "a.example", NULL));
  a = daemon->servers_tail;
  ck_assert(
      add_update_server(SERV_FROM_DBUS, NULL, NULL, NULL, "b.example", NULL));
  b = daemon->servers_tail;
  cleanup_servers();

  /* Reloaded in the other order: both records are reused, and the list
     follows the new order, since that's the order servers are tried in
     with --strict-order. */
  mark_servers(SERV_FROM_DBUS);
  ck_assert(
      add_update_server(SERV_FROM_DBUS, NULL, NULL, NULL, "b.example", NULL));
  ck_assert(
      add_update_server(SERV_FROM_DBUS, NULL, NULL, NULL, "a.example", NULL));
  cleanup_servers();

  ck_assert_ptr_eq(daemon->servers, b);
  ck_assert_ptr_eq(b->next, a);
  ck_assert_ptr_null(a->next);
  ck_assert_ptr_eq(daemon->servers_tail, a);
  ck_assert_int_eq(a->flags & SERV_MARK, 0);
  ck_assert_int_eq(b->flags & SERV_MARK, 0);
}
END_TEST

START_TEST(test_cleanup_frees_marked) {
  struct server *keep;

  mark_servers(0);
  ck_assert(add_update_server(0, NULL, NULL, NULL, NULL, NULL));
  keep = daemon->servers_tail;
  ck_assert(add_update_server(SERV_FROM_DBUS, NULL, NULL, NULL, "corp.example",
                              NULL));

  /* A reload with no DBus servers drops the DBus one only. */
  mark_servers(SERV_FROM_DBUS);
  cleanup_servers();

  ck_assert_ptr_eq(daemon->servers, keep);
  ck_assert_ptr_null(keep->next);
  ck_assert_ptr_eq(daemon->servers_tail, keep);
}
END_TEST

START_TEST(test_mark_frees_local_domains) {
  mark_servers(0);
  ck_assert(add_update_server(SERV_LITERAL_ADDRESS, NULL, NULL, NULL,
                              "keep.example", NULL));
  ck_assert(add_update_server(SERV_LITERAL_ADDRESS | SERV_FROM_DBUS, NULL, NULL,
                              NULL, "drop.example", NULL));

  /* Local domains aren't reused, but deleted as soon as they're marked. */
  mark_servers(SERV_FROM_DBUS);

  ck_assert_ptr_nonnull(daemon->local_domains);
  ck_assert_str_eq(daemon->local_domains->domain, "keep.example");
  ck_assert_ptr_null(daemon->local_domains->next);
}
END_TEST

START_TEST(test_add_domain_forms) {
  struct server *serv;

  mark_servers(0);

  /* .domain is the same as domain. */
  ck_assert(add_update_server(0, NULL, NULL, NULL, "..example.com", NULL));
  serv = daemon->servers_tail;
  ck_assert_str_eq(serv->domain, "example.com");
  ck_assert_int_eq(serv->domain_len, strlen("example.com"));
  ck_assert_int_eq(serv->flags & SERV_WILDCARD, 0);

  ck_assert(add_update_server(0, NULL, NULL, NULL, "*example.com", NULL));
  serv = daemon->servers_tail;
  ck_assert_str_eq(serv->domain, "example.com");
  ck_assert(serv->flags & SERV_WILDCARD);

  /* A lone * matches everything, so isn't a wildcard. */
  ck_assert(add_update_server(0, NULL, NULL, NULL, "*", NULL));
  serv = daemon->servers_tail;
  ck_assert_str_eq(serv->domain, "");
  ck_assert_int_eq(serv->domain_len, 0);
  ck_assert_int_eq(serv->flags & SERV_WILDCARD, 0);

  ck_assert(add_update_server(0, NULL, NULL, NULL, NULL, NULL));
  serv = daemon->servers_tail;
  ck_assert_str_eq(serv->domain, "");
  ck_assert_int_eq(serv->tcpfd, -1);

  ck_assert_ptr_null(daemon->local_domains);
}
END_TEST

START_TEST(test_add_local_address) {
  union all_addr addr;
  struct serv_addr4 *serv;
  struct server *upstream = daemon->servers;

  ck_assert_int_eq(inet_pton(AF_INET, "192.0.2.99", &addr.addr4), 1);
  ck_assert(add_update_server(SERV_LITERAL_ADDRESS | SERV_4ADDR, NULL, NULL,
                              NULL, "ads.example", &addr));

  /* On the local_domains chain, not with the upstream servers. */
  ck_assert_ptr_eq(daemon->servers, upstream);
  serv = (struct serv_addr4 *)daemon->local_domains;
  ck_assert_ptr_nonnull(serv);
  ck_assert_str_eq(serv->domain, "ads.example");
  ck_assert_int_eq(serv->flags, SERV_LITERAL_ADDRESS | SERV_4ADDR);
  ck_assert_uint_eq(serv->addr.s_addr, addr.addr4.s_addr);
}
END_TEST

/* Domain lookups. Each test sets up its own servers. */

/* Look up name, returning the first server record of the match. */
static struct server *lookup(const char *name, int flags) {
  char qname[MAXDNAME];
  int first, last;

  safe_strncpy(qname, name, sizeof(qname));
  if (!lookup_domain(qname, flags, &first, &last))
    return NULL;

  ck_assert_int_lt(first, last);
  return daemon->serverarray[first];
}

/* The address of the upstream server name is sent to, or NULL. */
static const char *lookup_ip(const char *name, int flags) {
  struct server *serv = lookup(name, flags);

  if (!serv)
    return NULL;
  ck_assert_int_eq(serv->flags & (SERV_LITERAL_ADDRESS | SERV_USE_RESOLV), 0);
  return inet_ntoa(serv->addr.in.sin_addr);
}

START_TEST(test_lookup_wildcard) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/*wild.example/192.0.2.2",
                                     "--server=/exact.example/192.0.2.3", NULL};

  test_daemon_init(args);
  ck_assert(daemon->server_has_wildcard);

  ck_assert_str_eq(lookup_ip("wild.example", 0), "192.0.2.2");
  ck_assert_str_eq(lookup_ip("www.wild.example", 0), "192.0.2.2");
  ck_assert_str_eq(lookup_ip("foowild.example", 0), "192.0.2.2");

  /* Searching one character at a time for the wildcard mustn't let
     ordinary domains match other than at a label boundary. */
  ck_assert_str_eq(lookup_ip("www.exact.example", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("fooexact.example", 0), "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_wildcard_and_exact) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/*example.com/192.0.2.2",
                                     "--server=/example.com/192.0.2.3", NULL};

  test_daemon_init(args);

  /* Where both match, the ordinary domain wins. */
  ck_assert_str_eq(lookup_ip("example.com", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("www.example.com", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("wwwexample.com", 0), "192.0.2.2");
}
END_TEST

START_TEST(test_lookup_nodots) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=//192.0.2.9",
                                     "--server=/lan/192.0.2.10", NULL};
  struct server *serv;

  test_daemon_init(args);

  serv = lookup("host", 0);
  ck_assert_ptr_nonnull(serv);
  ck_assert(serv->flags & SERV_FOR_NODOTS);
  ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "192.0.2.9");

  ck_assert_str_eq(lookup_ip("host.example", 0), "192.0.2.1");

  /* A server for the name itself takes precedence. */
  ck_assert_str_eq(lookup_ip("lan", 0), "192.0.2.10");

  /* DNSSEC queries aren't sent to servers for dotless names. */
  ck_assert_str_eq(lookup_ip("host", F_DNSSECOK), "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_ds) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/example.com/192.0.2.2", NULL};

  test_daemon_init(args);

  /* The DS record for a zone is in its parent. */
  ck_assert_str_eq(lookup_ip("example.com", 0), "192.0.2.2");
  ck_assert_str_eq(lookup_ip("example.com", F_DS), "192.0.2.1");
  ck_assert_str_eq(lookup_ip("sub.example.com", F_DS), "192.0.2.2");
  ck_assert_str_eq(lookup_ip("com", F_DS), "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_domainsrv) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/corp.example/192.0.2.2",
                                     "--local=/lan/", NULL};

  test_daemon_init(args);

  ck_assert_str_eq(lookup_ip("x.corp.example", F_DOMAINSRV), "192.0.2.2");
  ck_assert_ptr_null(lookup("www.example.org", F_DOMAINSRV));
  ck_assert_ptr_null(lookup("printer.lan", F_DOMAINSRV));
}
END_TEST

START_TEST(test_lookup_server_only) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--address=/ads.example/192.0.2.99",
                                     "--local=/lan/", NULL};

  test_daemon_init(args);

  ck_assert(lookup("x.ads.example", F_IPV4)->flags & SERV_LITERAL_ADDRESS);
  ck_assert(lookup("printer.lan", 0)->flags & SERV_LITERAL_ADDRESS);

  /* F_SERVER skips local answers. */
  ck_assert_str_eq(lookup_ip("x.ads.example", F_IPV4 | F_SERVER), "192.0.2.1");
  ck_assert_str_eq(lookup_ip("printer.lan", F_SERVER), "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_config) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--address=/ads.example/192.0.2.99",
                                     "--local=/lan/", NULL};
  struct server *serv;

  test_daemon_init(args);

  /* F_CONFIG finds only names with a configured address. */
  serv = lookup("x.ads.example", F_CONFIG);
  ck_assert_ptr_nonnull(serv);
  ck_assert(serv->flags & SERV_4ADDR);

  ck_assert_ptr_null(lookup("printer.lan", F_CONFIG));
  ck_assert_ptr_null(lookup("www.example.org", F_CONFIG));
}
END_TEST

START_TEST(test_lookup_use_standard) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/example/192.0.2.5",
                                     "--server=/corp.example/#", NULL};

  test_daemon_init(args);

  /* # sends the subdomain to the default servers, not those for the
     enclosing domain. */
  ck_assert_str_eq(lookup_ip("x.corp.example", 0), "192.0.2.1");
  ck_assert_str_eq(lookup_ip("x.other.example", 0), "192.0.2.5");
}
END_TEST

START_TEST(test_lookup_use_standard_none) {
  static const char *const args[] = {"--server=/corp.example/#", NULL};

  test_daemon_init(args);

  ck_assert_ptr_null(lookup("x.corp.example", 0));
}
END_TEST

START_TEST(test_local_answer_types) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--address=/v4.example/192.0.2.99",
                                     "--address=/nodata.example/192.0.2.98",
                                     "--local=/nodata.example/",
                                     "--address=/zero.example/#",
                                     NULL};
  int first, last;
  char name[MAXDNAME];
  time_t now = dnsmasq_time();

  test_daemon_init(args);

  strcpy(name, "v4.example");
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV4);

  /* With only an IPv4 address, other types are forwarded... */
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), 0);
  ck_assert_str_eq(inet_ntoa(daemon->serverarray[first]->addr.in.sin_addr),
                   "192.0.2.1");

  /* ...unless --local is given too, when the answer is NODATA. */
  strcpy(name, "nodata.example");
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_NOERR);
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV4);

  /* # gives zeros for both. */
  strcpy(name, "zero.example");
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV4 | F_IPV6);
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV4 | F_IPV6);
}
END_TEST

START_TEST(test_lookup_no_servers) {
  test_daemon_init(NULL);
  ck_assert_int_eq(daemon->serverarraysz, 0);
  ck_assert_ptr_null(lookup("www.example.org", 0));
}
END_TEST

/* Only for a domain: other names have nowhere to go. */
START_TEST(test_lookup_no_default_server) {
  static const char *const args[] = {"--server=/corp.example/192.0.2.2", NULL};

  test_daemon_init(args);
  ck_assert_str_eq(lookup_ip("x.corp.example", 0), "192.0.2.2");
  ck_assert_ptr_null(lookup("www.example.org", 0));
  ck_assert_ptr_null(lookup("", 0));
}
END_TEST

START_TEST(test_lookup_longest_match) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/example.com/192.0.2.2",
                                     "--server=/sub.example.com/192.0.2.3",
                                     "--server=/.dot.example/192.0.2.4", NULL};

  test_daemon_init(args);
  ck_assert(!daemon->server_has_wildcard);

  ck_assert_str_eq(lookup_ip("a.sub.example.com", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("sub.example.com", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("other.example.com", 0), "192.0.2.2");
  ck_assert_str_eq(lookup_ip("example.com", 0), "192.0.2.2");

  /* Only at a label boundary. */
  ck_assert_str_eq(lookup_ip("notexample.com", 0), "192.0.2.1");
  ck_assert_str_eq(lookup_ip("com", 0), "192.0.2.1");

  /* Case doesn't matter, and a leading . in the config is ignored. */
  ck_assert_str_eq(lookup_ip("WWW.Sub.Example.COM", 0), "192.0.2.3");
  ck_assert_str_eq(lookup_ip("x.dot.example", 0), "192.0.2.4");
}
END_TEST

START_TEST(test_lookup_address_all) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/corp.example/192.0.2.2",
                                     "--address=/#/192.0.2.99", NULL};
  struct server *serv;

  test_daemon_init(args);

  /* # matches every name, but a more specific server still wins. */
  serv = lookup("www.example.org", F_IPV4);
  ck_assert_ptr_nonnull(serv);
  ck_assert(serv->flags & SERV_4ADDR);
  ck_assert_str_eq(lookup_ip("x.corp.example", F_IPV4), "192.0.2.2");

  /* Other types, and F_SERVER, go to the default server. */
  ck_assert_str_eq(lookup_ip("www.example.org", F_IPV6), "192.0.2.1");
  ck_assert_str_eq(lookup_ip("www.example.org", F_IPV4 | F_SERVER),
                   "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_wildcard_address) {
  static const char *const args[] = {
      "--server=192.0.2.1", "--address=/*ads.example/192.0.2.99", NULL};
  struct server *serv;

  test_daemon_init(args);

  /* Wildcards on the local_domains chain count too. */
  ck_assert(daemon->server_has_wildcard);

  serv = lookup("fooads.example", F_IPV4);
  ck_assert_ptr_nonnull(serv);
  ck_assert(serv->flags & SERV_4ADDR);
  ck_assert(lookup("x.ads.example", F_IPV4)->flags & SERV_4ADDR);
  ck_assert_str_eq(lookup_ip("foo.example", F_IPV4), "192.0.2.1");
}
END_TEST

#ifdef HAVE_LOOP
START_TEST(test_lookup_skips_loop) {
  static const char *const args[] = {"--server=192.0.2.1", "--server=192.0.2.2",
                                     NULL};
  int first, last;
  char name[] = "www.example.org";

  test_daemon_init(args);
  ck_assert(lookup_domain(name, 0, &first, &last));
  ck_assert_int_eq(last - first, 2);

  /* A server found to loop is left out of the array. */
  daemon->serverarray[first]->flags |= SERV_LOOP;
  build_server_array();

  ck_assert_int_eq(daemon->serverarraysz, 1);
  ck_assert(lookup_domain(name, 0, &first, &last));
  ck_assert_int_eq(last - first, 1);
  ck_assert_str_eq(inet_ntoa(daemon->serverarray[first]->addr.in.sin_addr),
                   "192.0.2.2");
}
END_TEST
#endif

START_TEST(test_local_nxdomain) {
  static const char *const args[] = {"--server=192.0.2.1", "--local=/lan/",
                                     "--txt-record=printer.lan,hello", NULL};
  struct dns_header *header;
  char name[MAXDNAME];
  size_t qlen, len;
  int first, last, flags;
  time_t now = dnsmasq_time();

  test_daemon_init(args);
  header = (struct dns_header *)daemon->packet;

  /* --local names are NXDOMAIN, unless something else is configured for
     them, when the answer is NODATA. */
  strcpy(name, "host.lan");
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_NXDOMAIN);
  strcpy(name, "printer.lan");
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_NOERR);

  strcpy(name, "host.lan");
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, name, T_A);
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  flags = is_local_answer(now, first, name);
  len = make_local_answer(flags, F_IPV4, qlen, header, name,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_eq(len, qlen);
  ck_assert_int_eq(RCODE(header), NXDOMAIN);
  ck_assert_uint_eq(ntohs(header->ancount), 0);
}
END_TEST

START_TEST(test_local_answer_ipv6) {
  static const char *const args[] = {
      "--server=192.0.2.1", "--address=/v6.example/2001:db8::1",
      "--address=/both.example/192.0.2.7",
      "--address=/both.example/2001:db8::7", NULL};
  struct dns_header *header;
  struct in6_addr expect;
  char name[MAXDNAME];
  size_t qlen, len;
  int first, last, flags;
  time_t now = dnsmasq_time();

  test_daemon_init(args);
  header = (struct dns_header *)daemon->packet;

  strcpy(name, "v6.example");
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV6);
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(now, first, name), 0);

  /* With both, each type gets its own. */
  strcpy(name, "both.example");
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  ck_assert_int_eq(last - first, 1);
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV4);
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  ck_assert_int_eq(last - first, 1);
  ck_assert_int_eq(is_local_answer(now, first, name), F_IPV6);

  /* The AAAA record's data is the last thing in the reply. */
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, name, T_AAAA);
  flags = is_local_answer(now, first, name);
  len = make_local_answer(flags, F_IPV6, qlen, header, name,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_eq(len, qlen + 12 + IN6ADDRSZ);
  ck_assert_int_eq(RCODE(header), NOERROR);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
  ck_assert_int_eq(inet_pton(AF_INET6, "2001:db8::7", &expect), 1);
  ck_assert_mem_eq((unsigned char *)header + len - IN6ADDRSZ, &expect,
                   IN6ADDRSZ);
}
END_TEST

START_TEST(test_make_local_answer_zeros) {
  static const char *const args[] = {"--address=/zero.example/#", NULL};
  static const unsigned char zeros[IN6ADDRSZ];
  struct dns_header *header;
  char name[] = "zero.example";
  size_t qlen, len;
  int first, last, flags;

  test_daemon_init(args);
  header = (struct dns_header *)daemon->packet;

  memset(daemon->packet, 0xff, daemon->packet_buff_sz);
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, name, T_A);
  ck_assert(lookup_domain(name, F_IPV4, &first, &last));
  flags = is_local_answer(dnsmasq_time(), first, name);
  len = make_local_answer(flags, F_IPV4, qlen, header, name,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_eq(len, qlen + 12 + INADDRSZ);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
  ck_assert_mem_eq((unsigned char *)header + len - INADDRSZ, zeros, INADDRSZ);

  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, name, T_AAAA);
  ck_assert(lookup_domain(name, F_IPV6, &first, &last));
  flags = is_local_answer(dnsmasq_time(), first, name);
  len = make_local_answer(flags, F_IPV6, qlen, header, name,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_eq(len, qlen + 12 + IN6ADDRSZ);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
  ck_assert_mem_eq((unsigned char *)header + len - IN6ADDRSZ, zeros, IN6ADDRSZ);
}
END_TEST

static void multi_address_setup(void) {
  static const char *const args[] = {"--address=/multi.example/192.0.2.7",
                                     "--address=/multi.example/192.0.2.8",
                                     NULL};

  test_daemon_init(args);
}

START_TEST(test_make_local_answer_multi) {
  struct dns_header *header;
  char qname[] = "multi.example";
  size_t qlen, len;
  int first, last, flags;

  multi_address_setup();
  header = (struct dns_header *)daemon->packet;
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, qname, T_A);

  ck_assert(lookup_domain(qname, F_IPV4, &first, &last));
  ck_assert_int_eq(last - first, 2);
  flags = is_local_answer(dnsmasq_time(), first, qname);
  len = make_local_answer(flags, F_IPV4, qlen, header, qname,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_gt(len, qlen);
  ck_assert_int_eq(RCODE(header), NOERROR);
  ck_assert_uint_eq(ntohs(header->ancount), 2);
}
END_TEST

START_TEST(test_make_local_answer_truncated) {
  struct dns_header *header;
  char qname[] = "multi.example";
  size_t qlen, len;
  int first, last, flags;

  multi_address_setup();
  header = (struct dns_header *)daemon->packet;
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, qname, T_A);

  /* No room for any answers: the reply has just the question, with TC. */
  ck_assert(lookup_domain(qname, F_IPV4, &first, &last));
  flags = is_local_answer(dnsmasq_time(), first, qname);
  len = make_local_answer(flags, F_IPV4, qlen, header, qname, qlen + 4, first,
                          last, EDE_UNSET);

  ck_assert_uint_eq(len, qlen);
  ck_assert(header->hb3 & HB3_TC);
  ck_assert_uint_eq(ntohs(header->ancount), 0);
}
END_TEST

static void group_setup(void) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/corp.example/192.0.2.2",
                                     "--server=/corp.example/192.0.2.3", NULL};

  test_daemon_init(args);
}

START_TEST(test_server_group) {
  int first, last, i;
  char name[] = "x.corp.example";

  group_setup();

  /* All servers for the domain are returned, in configured order. */
  ck_assert(lookup_domain(name, 0, &first, &last));
  ck_assert_int_eq(last - first, 2);
  ck_assert_str_eq(inet_ntoa(daemon->serverarray[first]->addr.in.sin_addr),
                   "192.0.2.2");
  ck_assert_str_eq(inet_ntoa(daemon->serverarray[first + 1]->addr.in.sin_addr),
                   "192.0.2.3");
  ck_assert(server_samegroup(daemon->serverarray[first],
                             daemon->serverarray[first + 1]));

  for (i = 0; i < daemon->serverarraysz; i++)
    ck_assert_int_eq(daemon->serverarray[i]->arrayposn, i);
}
END_TEST

START_TEST(test_server_group_distinct) {
  struct server *corp, *dflt;

  group_setup();

  corp = lookup("x.corp.example", 0);
  dflt = lookup("www.example.org", 0);
  ck_assert_ptr_nonnull(corp);
  ck_assert_ptr_nonnull(dflt);
  ck_assert(!server_samegroup(corp, dflt));
}
END_TEST

#ifdef HAVE_DNSSEC
START_TEST(test_dnssec_server) {
  int first, last, index;
  struct server *second, *dflt;
  char keyname[] = "corp.example";

  group_setup();
  second = daemon->serverarray[lookup("x.corp.example", 0)->arrayposn + 1];
  dflt = lookup("www.example.org", 0);

  /* Keep to the server the original query went to, if it can answer. */
  index = dnssec_server(second, keyname, 0, &first, &last);
  ck_assert_ptr_eq(daemon->serverarray[index], second);
  ck_assert_int_eq(last - first, 2);

  /* Otherwise, the first one that can. */
  index = dnssec_server(dflt, keyname, 0, &first, &last);
  ck_assert_int_eq(index, first);
  ck_assert_str_eq(daemon->serverarray[index]->domain, "corp.example");

  /* The DS record comes from the parent's servers. */
  index = dnssec_server(second, keyname, 1, &first, &last);
  ck_assert_ptr_eq(daemon->serverarray[index], dflt);
}
END_TEST
#endif

Suite *domain_match_suite(void) {
  Suite *s = suite_create("domain-match");
  TCase *tc = tcase_create("servers");
  TCase *tc_lookup = tcase_create("lookup");

  tcase_add_checked_fixture(tc, domain_match_setup, NULL);
  tcase_add_test(tc, test_reuse_moves_to_tail);
  tcase_add_test(tc, test_cleanup_frees_marked);
  tcase_add_test(tc, test_mark_frees_local_domains);
  tcase_add_test(tc, test_add_domain_forms);
  tcase_add_test(tc, test_add_local_address);
  suite_add_tcase(s, tc);

  /* No fixture: each test has its own servers. */
  tcase_add_test(tc_lookup, test_lookup_wildcard);
  tcase_add_test(tc_lookup, test_lookup_wildcard_and_exact);
  tcase_add_test(tc_lookup, test_lookup_nodots);
  tcase_add_test(tc_lookup, test_lookup_ds);
  tcase_add_test(tc_lookup, test_lookup_domainsrv);
  tcase_add_test(tc_lookup, test_lookup_server_only);
  tcase_add_test(tc_lookup, test_lookup_config);
  tcase_add_test(tc_lookup, test_lookup_use_standard);
  tcase_add_test(tc_lookup, test_lookup_use_standard_none);
  tcase_add_test(tc_lookup, test_lookup_no_servers);
  tcase_add_test(tc_lookup, test_lookup_no_default_server);
  tcase_add_test(tc_lookup, test_lookup_longest_match);
  tcase_add_test(tc_lookup, test_lookup_address_all);
  tcase_add_test(tc_lookup, test_lookup_wildcard_address);
#ifdef HAVE_LOOP
  tcase_add_test(tc_lookup, test_lookup_skips_loop);
#endif
  tcase_add_test(tc_lookup, test_local_answer_types);
  tcase_add_test(tc_lookup, test_local_nxdomain);
  tcase_add_test(tc_lookup, test_local_answer_ipv6);
  tcase_add_test(tc_lookup, test_make_local_answer_zeros);
  tcase_add_test(tc_lookup, test_make_local_answer_multi);
  tcase_add_test(tc_lookup, test_make_local_answer_truncated);
  tcase_add_test(tc_lookup, test_server_group);
  tcase_add_test(tc_lookup, test_server_group_distinct);
#ifdef HAVE_DNSSEC
  tcase_add_test(tc_lookup, test_dnssec_server);
#endif
  suite_add_tcase(s, tc_lookup);

  return s;
}
