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

/* Tests for DNS packet parsing and construction in rfc1035.c */

#include "tests.h"

static unsigned char packet[PACKETSZ];
static char name[MAXDNAME * 2];

START_TEST(test_extract_name) {
  size_t len = test_make_query(packet, sizeof(packet), "www.example.com", T_A);
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = (unsigned char *)(header + 1);

  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_EXTRACT, 4),
                   1);
  ck_assert_str_eq(name, "www.example.com");
  /* p is left just after the name, at the qtype. */
  ck_assert_int_eq(p - packet, len - 4);
}
END_TEST

START_TEST(test_extract_name_compressed) {
  size_t len = test_make_query(packet, sizeof(packet), "www.example.com", T_A);
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = packet + len;
  /* "mail" + pointer to "example.com" inside the question. */
  unsigned short ptr = 0xc000 | (sizeof(struct dns_header) + 4);

  *p++ = 4;
  memcpy(p, "mail", 4);
  p += 4;
  PUTSHORT(ptr, p);
  len = p - packet;

  p = packet + len - 7;
  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_EXTRACT, 0),
                   1);
  ck_assert_str_eq(name, "mail.example.com");
  /* After a jump, p is left after the pointer, not after the target. */
  ck_assert_ptr_eq(p, packet + len);
}
END_TEST

START_TEST(test_extract_name_pointer_loop) {
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = (unsigned char *)(header + 1);
  unsigned short self = 0xc000 | sizeof(struct dns_header);

  memset(packet, 0, sizeof(packet));
  PUTSHORT(self, p);

  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(
      extract_name(header, p + 2 - packet, &p, name, EXTR_NAME_EXTRACT, 0), 0);
}
END_TEST

START_TEST(test_extract_name_truncated) {
  size_t len = test_make_query(packet, sizeof(packet), "www.example.com", T_A);
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = (unsigned char *)(header + 1);

  /* Cut off in the middle of "example". */
  ck_assert_int_eq(extract_name(header, sizeof(struct dns_header) + 7, &p, name,
                                EXTR_NAME_EXTRACT, 0),
                   0);

  /* Whole name present, but not the 4 bytes of type and class that follow. */
  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(
      extract_name(header, len - 2, &p, name, EXTR_NAME_EXTRACT, 4), 0);
}
END_TEST

START_TEST(test_extract_name_reserved_label) {
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = (unsigned char *)(header + 1);

  memset(packet, 0, sizeof(packet));
  p[0] = 0x40; /* extended label type: not supported */

  ck_assert_int_eq(
      extract_name(header, sizeof(packet), &p, name, EXTR_NAME_EXTRACT, 0), 0);
}
END_TEST

START_TEST(test_extract_name_escapes) {
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p = (unsigned char *)(header + 1);
  static const char expect[] = {'a', NAME_ESCAPE, '.' + 1, 'b', '.', 'c', 0};

  memset(packet, 0, sizeof(packet));
  memcpy(p, "\3a.b\1c", 7);

  ck_assert_int_eq(
      extract_name(header, sizeof(packet), &p, name, EXTR_NAME_EXTRACT, 0), 1);
  ck_assert_str_eq(name, expect);
}
END_TEST

START_TEST(test_extract_name_compare) {
  size_t len = test_make_query(packet, sizeof(packet), "WWW.Example.com", T_A);
  struct dns_header *header = (struct dns_header *)packet;
  unsigned char *p;

  strcpy(name, "www.example.com");
  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_COMPARE, 4),
                   1);

  /* Case-sensitive comparison reports a case-only difference as 3. */
  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_NOCASE, 4), 3);

  strcpy(name, "www.example.org");
  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_COMPARE, 4),
                   2);

  strcpy(name, "example.com");
  p = (unsigned char *)(header + 1);
  ck_assert_int_eq(extract_name(header, len, &p, name, EXTR_NAME_COMPARE, 4),
                   2);
}
END_TEST

START_TEST(test_skip_questions) {
  size_t len = test_make_query(packet, sizeof(packet), "www.example.com", T_A);
  struct dns_header *header = (struct dns_header *)packet;

  ck_assert_ptr_eq(skip_questions(header, len), packet + len);
  ck_assert_ptr_null(skip_questions(header, len - 1));
}
END_TEST

START_TEST(test_extract_request) {
  struct dns_header *header = (struct dns_header *)packet;
  unsigned short type, class;
  size_t len;

  len = test_make_query(packet, sizeof(packet), "host.example", T_A);
  ck_assert_uint_eq(extract_request(header, len, name, &type, &class), F_IPV4);
  ck_assert_str_eq(name, "host.example");
  ck_assert_uint_eq(type, T_A);
  ck_assert_uint_eq(class, C_IN);

  len = test_make_query(packet, sizeof(packet), "host.example", T_AAAA);
  ck_assert_uint_eq(extract_request(header, len, name, &type, NULL), F_IPV6);

  len = test_make_query(packet, sizeof(packet), "host.example", T_MX);
  ck_assert_uint_eq(extract_request(header, len, name, &type, NULL), F_QUERY);
  ck_assert_uint_eq(type, T_MX);

  len = test_make_query(packet, sizeof(packet), "host.example", T_DS);
  ck_assert_uint_eq(extract_request(header, len, name, NULL, NULL),
                    F_DNSSECOK | F_DS);
}
END_TEST

START_TEST(test_extract_request_bad) {
  struct dns_header *header = (struct dns_header *)packet;
  size_t len = test_make_query(packet, sizeof(packet), "host.example", T_A);

  header->qdcount = htons(2);
  ck_assert_uint_eq(extract_request(header, len, name, NULL, NULL), 0);
  ck_assert_str_eq(name, "");

  header->qdcount = htons(1);
  header->ancount = htons(1);
  ck_assert_uint_eq(extract_request(header, len, name, NULL, NULL), 0);

  header->ancount = 0;
  ck_assert_uint_eq(extract_request(header, len - 3, name, NULL, NULL), 0);
}
END_TEST

START_TEST(test_setup_reply) {
  struct dns_header *header = (struct dns_header *)packet;

  test_make_query(packet, sizeof(packet), "host.example", T_A);
  header->hb3 |= HB3_AA | HB3_TC;
  header->hb4 |= HB4_AD;

  setup_reply(header, F_NXDOMAIN, EDE_UNSET);

  ck_assert(header->hb3 & HB3_QR);
  ck_assert(header->hb3 & HB3_RD);
  ck_assert(!(header->hb3 & (HB3_AA | HB3_TC)));
  ck_assert(header->hb4 & HB4_RA);
  ck_assert(!(header->hb4 & HB4_AD));
  ck_assert_int_eq(RCODE(header), NXDOMAIN);
  ck_assert_uint_eq(ntohs(header->ancount), 0);
}
END_TEST

START_TEST(test_add_resource_record) {
  struct dns_header *header = (struct dns_header *)packet;
  size_t len = test_make_query(packet, sizeof(packet), "host.example", T_A);
  unsigned char *p = packet + len;
  struct in_addr addr;
  int trunc = 0, ttl, rdlen, type, class;

  inet_pton(AF_INET, "192.0.2.1", &addr);
  ck_assert(add_resource_record(header, (char *)packet + sizeof(packet), &trunc,
                                sizeof(struct dns_header), &p, 300, NULL, T_A,
                                C_IN, "4", &addr));
  ck_assert_int_eq(trunc, 0);
  ck_assert_int_eq(p - packet, len + 2 + RRFIXEDSZ + INADDRSZ);

  /* Name is a compression pointer back to the question. */
  p = packet + len;
  ck_assert_int_eq(extract_name(header, sizeof(packet), &p, name,
                                EXTR_NAME_EXTRACT, RRFIXEDSZ),
                   1);
  ck_assert_str_eq(name, "host.example");
  GETSHORT(type, p);
  GETSHORT(class, p);
  GETLONG(ttl, p);
  GETSHORT(rdlen, p);
  ck_assert_int_eq(type, T_A);
  ck_assert_int_eq(class, C_IN);
  ck_assert_int_eq(ttl, 300);
  ck_assert_int_eq(rdlen, INADDRSZ);
  ck_assert_mem_eq(p, &addr, INADDRSZ);
}
END_TEST

START_TEST(test_add_resource_record_truncated) {
  struct dns_header *header = (struct dns_header *)packet;
  size_t len = test_make_query(packet, sizeof(packet), "host.example", T_A);
  unsigned char *p = packet + len;
  struct in_addr addr;
  int trunc = 0;

  inet_pton(AF_INET, "192.0.2.1", &addr);
  ck_assert(!add_resource_record(header, (char *)packet + len + 8, &trunc,
                                 sizeof(struct dns_header), &p, 300, NULL, T_A,
                                 C_IN, "4", &addr));
  ck_assert_int_eq(trunc, 1);
}
END_TEST

START_TEST(test_in_arpa_name_2_addr) {
  union all_addr addr, expect;
  char v4[] = "4.3.2.192.in-addr.arpa";
  char v6[] = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2."
              "ip6.arpa";
  char bad[] = "www.example.com";

  ck_assert_int_eq(in_arpa_name_2_addr(v4, &addr), F_IPV4);
  inet_pton(AF_INET, "192.2.3.4", &expect.addr4);
  ck_assert_mem_eq(&addr.addr4, &expect.addr4, sizeof(struct in_addr));

  ck_assert_int_eq(in_arpa_name_2_addr(v6, &addr), F_IPV6);
  inet_pton(AF_INET6, "2001:db8::1", &expect.addr6);
  ck_assert_mem_eq(&addr.addr6, &expect.addr6, sizeof(struct in6_addr));

  ck_assert_int_eq(in_arpa_name_2_addr(bad, &addr), 0);
}
END_TEST

START_TEST(test_private_net) {
  struct in_addr a;
  struct in6_addr a6;

  inet_pton(AF_INET, "10.1.2.3", &a);
  ck_assert(private_net(a, 0));
  inet_pton(AF_INET, "192.168.0.1", &a);
  ck_assert(private_net(a, 0));
  inet_pton(AF_INET, "127.0.0.1", &a);
  ck_assert(!private_net(a, 0));
  ck_assert(private_net(a, 1));
  inet_pton(AF_INET, "8.8.8.8", &a);
  ck_assert(!private_net(a, 1));

  inet_pton(AF_INET6, "fd00::1", &a6);
  ck_assert(private_net6(&a6, 0));
  inet_pton(AF_INET6, "::ffff:10.0.0.1", &a6);
  ck_assert(private_net6(&a6, 0));
  inet_pton(AF_INET6, "2001:4860::8888", &a6);
  ck_assert(!private_net6(&a6, 1));
}
END_TEST

/* answer_request() against records configured on the command line. */

static void host_record_setup(void) {
  static const char *const args[] = {
      "--host-record=host.test,192.0.2.5,2001:db8::5", "--filter-rr=TXT",
      "--mx-host=test,mail.test,10", NULL};

  test_daemon_init(args);
  cache_reload();
}

static int filtered;

static size_t do_answer(const char *qname, unsigned short type) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len =
      test_make_query(daemon->packet, daemon->packet_buff_sz, qname, type);
  struct in_addr local, mask;

  inet_pton(AF_INET, "127.0.0.1", &local);
  inet_pton(AF_INET, "255.0.0.0", &mask);

  return answer_request(header, (char *)daemon->packet + daemon->packet_buff_sz,
                        len, local, mask, dnsmasq_time(), 0, 0, 0, NULL,
                        &filtered);
}

START_TEST(test_answer_request_a) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len = do_answer("host.test", T_A);
  struct in_addr expect;

  ck_assert_uint_gt(len, 0);
  ck_assert(header->hb3 & HB3_QR);
  ck_assert(header->hb3 & HB3_AA);
  ck_assert_int_eq(RCODE(header), NOERROR);
  ck_assert_uint_eq(ntohs(header->ancount), 1);

  inet_pton(AF_INET, "192.0.2.5", &expect);
  ck_assert_mem_eq((unsigned char *)daemon->packet + len - INADDRSZ, &expect,
                   INADDRSZ);
}
END_TEST

START_TEST(test_answer_request_aaaa) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len = do_answer("HOST.test", T_AAAA);
  struct in6_addr expect;

  ck_assert_uint_gt(len, 0);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
  inet_pton(AF_INET6, "2001:db8::5", &expect);
  ck_assert_mem_eq((unsigned char *)daemon->packet + len - IN6ADDRSZ, &expect,
                   IN6ADDRSZ);
}
END_TEST

START_TEST(test_answer_request_ptr) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len = do_answer("5.2.0.192.in-addr.arpa", T_PTR);
  unsigned char *p;

  ck_assert_uint_gt(len, 0);
  ck_assert_uint_eq(ntohs(header->ancount), 1);

  p = skip_questions(header, len);
  ck_assert_ptr_nonnull(p);
  p = skip_name(p, header, len, RRFIXEDSZ);
  ck_assert_ptr_nonnull(p);
  p += RRFIXEDSZ;
  ck_assert_int_eq(extract_name(header, len, &p, daemon->workspacename,
                                EXTR_NAME_EXTRACT, 0),
                   1);
  ck_assert_str_eq(daemon->workspacename, "host.test");
}
END_TEST

START_TEST(test_answer_request_mx) {
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len = do_answer("test", T_MX);

  ck_assert_uint_gt(len, 0);
  ck_assert_uint_eq(ntohs(header->ancount), 1);
}
END_TEST

START_TEST(test_answer_request_unknown) {
  /* Nothing local for this name: must be forwarded, so no answer. */
  ck_assert_uint_eq(do_answer("elsewhere.example", T_A), 0);
  ck_assert_uint_eq(do_answer("elsewhere.example", T_TXT), 0);
  ck_assert_int_eq(filtered, 0);
}
END_TEST

START_TEST(test_answer_request_nodata) {
  /* A filtered type for a name we have other records for: NODATA
     without going upstream. */
  struct dns_header *header = (struct dns_header *)daemon->packet;
  size_t len = do_answer("host.test", T_TXT);

  ck_assert_uint_gt(len, 0);
  ck_assert_int_eq(filtered, 1);
  ck_assert_int_eq(RCODE(header), NOERROR);
  ck_assert_uint_eq(ntohs(header->ancount), 0);
}
END_TEST

Suite *rfc1035_suite(void) {
  Suite *s = suite_create("rfc1035");
  TCase *tc_parse = tcase_create("parse");
  TCase *tc_build = tcase_create("build");
  TCase *tc_answer = tcase_create("answer_request");

  tcase_add_test(tc_parse, test_extract_name);
  tcase_add_test(tc_parse, test_extract_name_compressed);
  tcase_add_test(tc_parse, test_extract_name_pointer_loop);
  tcase_add_test(tc_parse, test_extract_name_truncated);
  tcase_add_test(tc_parse, test_extract_name_reserved_label);
  tcase_add_test(tc_parse, test_extract_name_escapes);
  tcase_add_test(tc_parse, test_extract_name_compare);
  tcase_add_test(tc_parse, test_skip_questions);
  tcase_add_test(tc_parse, test_extract_request);
  tcase_add_test(tc_parse, test_extract_request_bad);
  tcase_add_test(tc_parse, test_in_arpa_name_2_addr);
  tcase_add_test(tc_parse, test_private_net);
  suite_add_tcase(s, tc_parse);

  tcase_add_test(tc_build, test_setup_reply);
  tcase_add_test(tc_build, test_add_resource_record);
  tcase_add_test(tc_build, test_add_resource_record_truncated);
  suite_add_tcase(s, tc_build);

  tcase_add_checked_fixture(tc_answer, host_record_setup, NULL);
  tcase_add_test(tc_answer, test_answer_request_a);
  tcase_add_test(tc_answer, test_answer_request_aaaa);
  tcase_add_test(tc_answer, test_answer_request_ptr);
  tcase_add_test(tc_answer, test_answer_request_mx);
  tcase_add_test(tc_answer, test_answer_request_unknown);
  tcase_add_test(tc_answer, test_answer_request_nodata);
  suite_add_tcase(s, tc_answer);

  return s;
}
