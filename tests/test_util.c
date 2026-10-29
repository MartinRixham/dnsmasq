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

/* Tests for util.c */

#include "tests.h"

/* Names are writable: the code under test strips a trailing period in place. */

START_TEST(test_legal_hostname) {
  char good1[] = "host", good2[] = "my-host_1.example.com", good3[] = "host.";
  char bad1[] = "bad host", bad2[] = "-leadingdash", bad3[] = "";

  ck_assert_int_ne(legal_hostname(good1), 0);
  ck_assert_int_ne(legal_hostname(good2), 0);
  ck_assert_int_ne(legal_hostname(good3), 0);
  ck_assert_str_eq(good3, "host");
  ck_assert_int_eq(legal_hostname(bad1), 0);
  ck_assert_int_eq(legal_hostname(bad2), 0);
  ck_assert_int_eq(legal_hostname(bad3), 0);
}
END_TEST

START_TEST(test_canonicalise) {
  int nomem = 0;
  char in[] = "Host.Example.COM.", ctrl[] = "bad\tname", label[80];
  char *out;

  test_daemon_init(NULL); /* allocation logging consults daemon */
  out = canonicalise(in, &nomem);

  ck_assert_ptr_nonnull(out);
  ck_assert_int_eq(nomem, 0);
  ck_assert(hostname_isequal(out, "host.example.com"));
  free(out);

  ck_assert_ptr_null(canonicalise(ctrl, &nomem));
  ck_assert_int_eq(nomem, 0);

  /* Labels are limited to 63 octets. */
  memset(label, 'a', 64);
  strcpy(label + 64, ".com");
  ck_assert_ptr_null(canonicalise(label, &nomem));
  label[63] = '.';
  ck_assert_ptr_nonnull(canonicalise(label, &nomem));
}
END_TEST

START_TEST(test_hostname_compare) {
  ck_assert(hostname_isequal("Example.COM", "example.com"));
  ck_assert(!hostname_isequal("example.com", "example.org"));
  ck_assert(!hostname_isequal("example.com", "example.co"));
  ck_assert_int_lt(hostname_order("a.example", "b.example"), 0);
  ck_assert_int_gt(hostname_order("B.example", "a.example"), 0);
}
END_TEST

START_TEST(test_hostname_issubdomain) {
  ck_assert_int_eq(hostname_issubdomain("example.com", "example.com"), 2);
  /* Is the second argument equal to or a subdomain of the first? */
  ck_assert_int_eq(hostname_issubdomain("example.com", "www.EXAMPLE.com"), 1);
  ck_assert_int_eq(hostname_issubdomain("example.com", "wwwexample.com"), 0);
  ck_assert_int_eq(hostname_issubdomain("www.example.com", "example.com"), 0);
}
END_TEST

START_TEST(test_do_rfc1035_name) {
  unsigned char buf[64];
  unsigned char *end =
      do_rfc1035_name(buf, "www.example.com", buf + sizeof(buf));
  static const unsigned char expect[] = "\3www\7example\3com";

  ck_assert_ptr_nonnull(end);
  /* do_rfc1035_name() does not write the terminating root label. */
  ck_assert_int_eq(end - buf, sizeof(expect) - 1);
  ck_assert_mem_eq(buf, expect, sizeof(expect) - 1);

  /* Not enough space. */
  ck_assert_ptr_null(do_rfc1035_name(buf, "www.example.com", buf + 5));
}
END_TEST

START_TEST(test_parse_hex_mac) {
  char in[] = "00:1a:2B:3c:4d:5E";
  unsigned char out[6];
  static const unsigned char expect[] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
  unsigned int mask = 0;
  int mac_type = 0;

  test_daemon_init(NULL); /* allocation logging consults daemon */
  ck_assert_int_eq(parse_hex(in, out, sizeof(out), &mask, &mac_type), 6);
  ck_assert_mem_eq(out, expect, 6);
  ck_assert_uint_eq(mask, 0);
  ck_assert_str_eq(print_mac(out, 6), "00:1a:2b:3c:4d:5e");
}
END_TEST

START_TEST(test_parse_hex_wildcard) {
  char in[] = "00:11:*:33";
  unsigned char out[4];
  unsigned char other[] = {0x00, 0x11, 0xff, 0x33};
  unsigned int mask = 0;

  ck_assert_int_eq(parse_hex(in, out, sizeof(out), &mask, NULL), 4);
  ck_assert_uint_ne(mask, 0);
  /* Non-zero (count of compared bytes + 1) on match. */
  ck_assert_int_ne(memcmp_masked(out, other, 4, mask), 0);
  other[3] = 0x34;
  ck_assert_int_eq(memcmp_masked(out, other, 4, mask), 0);
}
END_TEST

START_TEST(test_parse_hex_bad) {
  char in[] = "00:zz";
  unsigned char out[4];

  ck_assert_int_eq(parse_hex(in, out, sizeof(out), NULL, NULL), -1);
}
END_TEST

START_TEST(test_ipv6_net) {
  struct in6_addr a, b;

  inet_pton(AF_INET6, "2001:db8:1::10", &a);
  inet_pton(AF_INET6, "2001:db8:1::ffff", &b);
  ck_assert(is_same_net6(&a, &b, 64));

  inet_pton(AF_INET6, "2001:db8:2::10", &b);
  ck_assert(!is_same_net6(&a, &b, 64));
  ck_assert(is_same_net6(&a, &b, 32));

  ck_assert_uint_eq(addr6part(&a), 0x10);
  setaddr6part(&a, 0xdeadbeefULL);
  ck_assert_uint_eq(addr6part(&a), 0xdeadbeefULL);
  inet_pton(AF_INET6, "2001:db8:1::dead:beef", &b);
  ck_assert_mem_eq(&a, &b, sizeof(a));
}
END_TEST

START_TEST(test_sockaddr_isequal) {
  union mysockaddr s1, s2;

  memset(&s1, 0, sizeof(s1));
  s1.in.sin_family = AF_INET;
  s1.in.sin_port = htons(53);
  inet_pton(AF_INET, "10.0.0.1", &s1.in.sin_addr);
  s2 = s1;

  ck_assert(sockaddr_isequal(&s1, &s2));
  s2.in.sin_port = htons(5353);
  ck_assert(!sockaddr_isequal(&s1, &s2));
  ck_assert_int_eq(sa_len(&s1), sizeof(struct sockaddr_in));
}
END_TEST

START_TEST(test_wildcard_match) {
  ck_assert(wildcard_match("eth*", "eth0"));
  ck_assert(wildcard_match("eth0", "eth0"));
  ck_assert(!wildcard_match("eth*", "wlan0"));
  ck_assert(!wildcard_match("eth0", "eth01"));
  ck_assert(wildcard_matchn("eth*", "eth0:1", 4));
}
END_TEST

START_TEST(test_prettyprint_time) {
  char buf[64];

  prettyprint_time(buf, 0xffffffff);
  ck_assert_str_eq(buf, "infinite");
  prettyprint_time(buf, 90061);
  ck_assert_str_eq(buf, "1d1h1m1s");
  prettyprint_time(buf, 3600);
  ck_assert_str_eq(buf, "1h");
}
END_TEST

START_TEST(test_rr_on_list) {
  struct rrlist mx = {T_MX, NULL};
  struct rrlist list = {T_A, &mx};

  ck_assert(rr_on_list(&list, T_A));
  ck_assert(rr_on_list(&list, T_MX));
  ck_assert(!rr_on_list(&list, T_AAAA));
  ck_assert(!rr_on_list(NULL, T_A));
}
END_TEST

Suite *util_suite(void) {
  Suite *s = suite_create("util");
  TCase *tc_names = tcase_create("names");
  TCase *tc_hex = tcase_create("hex");
  TCase *tc_addr = tcase_create("addresses");
  TCase *tc_misc = tcase_create("misc");

  tcase_add_test(tc_names, test_legal_hostname);
  tcase_add_test(tc_names, test_canonicalise);
  tcase_add_test(tc_names, test_hostname_compare);
  tcase_add_test(tc_names, test_hostname_issubdomain);
  tcase_add_test(tc_names, test_do_rfc1035_name);
  suite_add_tcase(s, tc_names);

  tcase_add_test(tc_hex, test_parse_hex_mac);
  tcase_add_test(tc_hex, test_parse_hex_wildcard);
  tcase_add_test(tc_hex, test_parse_hex_bad);
  suite_add_tcase(s, tc_hex);

  tcase_add_test(tc_addr, test_ipv6_net);
  tcase_add_test(tc_addr, test_sockaddr_isequal);
  suite_add_tcase(s, tc_addr);

  tcase_add_test(tc_misc, test_wildcard_match);
  tcase_add_test(tc_misc, test_prettyprint_time);
  tcase_add_test(tc_misc, test_rr_on_list);
  suite_add_tcase(s, tc_misc);

  return s;
}
