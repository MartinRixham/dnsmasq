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

/* Tests for command-line parsing in option.c, and for the server
   selection in domain-match.c that the parsed options drive. */

#include "tests.h"

START_TEST(test_defaults) {
  test_daemon_init(NULL);

  ck_assert_int_eq(daemon->cachesize, CACHESIZ);
  ck_assert_int_eq(daemon->port, NAMESERVER_PORT);
  ck_assert_int_eq(daemon->edns_pktsz, EDNS_PKTSZ);
  ck_assert(option_bool(OPT_NO_RESOLV));
  ck_assert(option_bool(OPT_NO_HOSTS));
  ck_assert(!option_bool(OPT_BOGUSPRIV));
  ck_assert_ptr_null(daemon->servers);
}
END_TEST

START_TEST(test_scalar_options) {
  static const char *const args[] = {"--cache-size=500",
                                     "--port=5353",
                                     "--local-ttl=60",
                                     "--min-cache-ttl=30",
                                     "--max-cache-ttl=3600",
                                     "--edns-packet-max=1232",
                                     NULL};
  test_daemon_init(args);

  ck_assert_int_eq(daemon->cachesize, 500);
  ck_assert_int_eq(daemon->port, 5353);
  ck_assert_uint_eq(daemon->local_ttl, 60);
  ck_assert_uint_eq(daemon->min_cache_ttl, 30);
  ck_assert_uint_eq(daemon->max_cache_ttl, 3600);
  ck_assert_int_eq(daemon->edns_pktsz, 1232);
}
END_TEST

START_TEST(test_bool_options) {
  static const char *const args[] = {"--bogus-priv", "--domain-needed", "-f",
                                     NULL};
  test_daemon_init(args);

  ck_assert(option_bool(OPT_BOGUSPRIV));
  ck_assert(option_bool(OPT_NODOTS_LOCAL));
  ck_assert(option_bool(OPT_FILTER));
}
END_TEST

START_TEST(test_server_option) {
  static const char *const args[] = {"--server=10.0.0.1",
                                     "--server=192.0.2.53#5353", NULL};
  struct server *serv;
  int count = 0;

  test_daemon_init(args);

  for (serv = daemon->servers; serv; serv = serv->next) {
    count++;
    ck_assert_int_eq(serv->addr.sa.sa_family, AF_INET);
    if (ntohs(serv->addr.in.sin_port) == 5353)
      ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "192.0.2.53");
    else {
      ck_assert_int_eq(ntohs(serv->addr.in.sin_port), NAMESERVER_PORT);
      ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "10.0.0.1");
    }
  }
  ck_assert_int_eq(count, 2);
}
END_TEST

START_TEST(test_bad_option_value) {
  static const char *const args[] = {"--cache-size=lots", NULL};

  test_daemon_init(args); /* exits */
}
END_TEST

START_TEST(test_bad_server) {
  static const char *const args[] = {"--server=not-an-address", NULL};

  test_daemon_init(args); /* exits */
}
END_TEST

START_TEST(test_unknown_option) {
  static const char *const args[] = {"--no-such-option", NULL};

  test_daemon_init(args); /* exits */
}
END_TEST

/* Server selection. */

static void servers_setup(void) {
  static const char *const args[] = {"--server=192.0.2.1",
                                     "--server=/corp.example/10.0.0.1",
                                     "--server=/sub.corp.example/10.0.0.2",
                                     "--address=/ads.example/0.0.0.0",
                                     "--address=/v6.example/2001:db8::99",
                                     "--address=/blocked.example/",
                                     "--local=/lan/",
                                     NULL};
  test_daemon_init(args);
}

static struct server *lookup(char *qname, int flags) {
  int first, last;

  if (!lookup_domain(qname, flags, &first, &last))
    return NULL;

  ck_assert_int_le(first, last);
  return daemon->serverarray[first];
}

START_TEST(test_lookup_default_server) {
  struct server *serv = lookup("www.example.org", F_IPV4);

  ck_assert_ptr_nonnull(serv);
  ck_assert_int_eq(serv->domain_len, 0);
  ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "192.0.2.1");
}
END_TEST

START_TEST(test_lookup_domain_server) {
  struct server *serv = lookup("host.corp.example", F_IPV4);

  ck_assert_ptr_nonnull(serv);
  ck_assert_str_eq(serv->domain, "corp.example");
  ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "10.0.0.1");

  /* The bare domain matches too. */
  serv = lookup("corp.example", F_IPV4);
  ck_assert_ptr_nonnull(serv);
  ck_assert_str_eq(serv->domain, "corp.example");

  /* Not a label boundary, so goes to the default server. */
  serv = lookup("notcorp.example", F_IPV4);
  ck_assert_ptr_nonnull(serv);
  ck_assert_int_eq(serv->domain_len, 0);
}
END_TEST

START_TEST(test_lookup_longest_match) {
  struct server *serv = lookup("a.b.sub.corp.example", F_IPV4);

  ck_assert_ptr_nonnull(serv);
  ck_assert_str_eq(serv->domain, "sub.corp.example");
  ck_assert_str_eq(inet_ntoa(serv->addr.in.sin_addr), "10.0.0.2");
}
END_TEST

START_TEST(test_lookup_address) {
  int first, last;
  struct server *serv;

  ck_assert(lookup_domain("tracker.ads.example", F_IPV4, &first, &last));
  serv = daemon->serverarray[first];
  ck_assert_str_eq(serv->domain, "ads.example");
  ck_assert(serv->flags & SERV_LITERAL_ADDRESS);
  ck_assert_int_eq(
      is_local_answer(dnsmasq_time(), first, "tracker.ads.example"), F_IPV4);
  ck_assert_uint_eq(((struct serv_addr4 *)serv)->addr.s_addr,
                    htonl(INADDR_ANY));

  ck_assert(lookup_domain("x.v6.example", F_IPV6, &first, &last));
  ck_assert_int_eq(is_local_answer(dnsmasq_time(), first, "x.v6.example"),
                   F_IPV6);
}
END_TEST

START_TEST(test_lookup_nxdomain) {
  int first, last;

  ck_assert(lookup_domain("blocked.example", F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(dnsmasq_time(), first, "blocked.example"),
                   F_NXDOMAIN);

  ck_assert(lookup_domain("printer.lan", F_IPV4, &first, &last));
  ck_assert_int_eq(is_local_answer(dnsmasq_time(), first, "printer.lan"),
                   F_NXDOMAIN);
}
END_TEST

START_TEST(test_make_local_answer) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  char qname[] = "tracker.ads.example";
  size_t len =
      test_make_query(daemon->packet, daemon->packet_buff_sz, qname, T_A);
  int first, last, flags;

  ck_assert(lookup_domain(qname, F_IPV4, &first, &last));
  flags = is_local_answer(dnsmasq_time(), first, qname);
  len = make_local_answer(flags, F_IPV4, len, header, qname,
                          daemon->packet_buff_sz, first, last, EDE_UNSET);

  ck_assert_uint_gt(len, 0);
  ck_assert(header->hb3 & HB3_QR);
  ck_assert_int_eq(RCODE(header), NOERROR);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
  ck_assert_mem_eq((unsigned char *)daemon->packet + len - INADDRSZ, "\0\0\0\0",
                   INADDRSZ);
}
END_TEST

START_TEST(test_no_servers) {
  int first, last;

  test_daemon_init(NULL);
  ck_assert_int_eq(daemon->serverarraysz, 0);
  ck_assert_int_eq(lookup_domain("www.example.org", F_IPV4, &first, &last), 0);
}
END_TEST

Suite *option_suite(void) {
  Suite *s = suite_create("options");
  TCase *tc_parse = tcase_create("parse");
  TCase *tc_lookup = tcase_create("lookup_domain");

  tcase_add_test(tc_parse, test_defaults);
  tcase_add_test(tc_parse, test_scalar_options);
  tcase_add_test(tc_parse, test_bool_options);
  tcase_add_test(tc_parse, test_server_option);
  tcase_add_exit_test(tc_parse, test_bad_option_value, EC_BADCONF);
  tcase_add_exit_test(tc_parse, test_bad_server, EC_BADCONF);
  tcase_add_exit_test(tc_parse, test_unknown_option, EC_BADCONF);
  suite_add_tcase(s, tc_parse);

  tcase_add_checked_fixture(tc_lookup, servers_setup, NULL);
  tcase_add_test(tc_lookup, test_lookup_default_server);
  tcase_add_test(tc_lookup, test_lookup_domain_server);
  tcase_add_test(tc_lookup, test_lookup_longest_match);
  tcase_add_test(tc_lookup, test_lookup_address);
  tcase_add_test(tc_lookup, test_lookup_nxdomain);
  tcase_add_test(tc_lookup, test_make_local_answer);
  suite_add_tcase(s, tc_lookup);

  /* Doesn't use the fixture. */
  tcase_add_test(tc_parse, test_no_servers);

  return s;
}
