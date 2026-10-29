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

/* Tests for EDNS0 pseudoheader handling in edns0.c */

#include "tests.h"

static struct dns_header *header;
static size_t limit;
static size_t qlen;

static void edns0_setup(void) {
  test_daemon_init(NULL);
  header = (struct dns_header *)daemon->packet;
  limit = daemon->packet_buff_sz;
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz,
                         "www.example.com", T_A);
}

/* Return the OPT RR's flags field, and its rdata via *data and *rdlen. */
static unsigned short opt_flags(size_t plen, unsigned char **data,
                                unsigned short *rdlen) {
  unsigned char *p, *udp;
  unsigned short udpsz, rcode, flags, len;
  size_t optlen;

  p = find_pseudoheader(header, plen, &optlen, &udp, NULL, NULL);
  ck_assert_ptr_nonnull(p);
  ck_assert_uint_eq(*p, 0); /* root name */

  GETSHORT(udpsz, udp);
  GETSHORT(rcode, udp);
  GETSHORT(flags, udp);
  GETSHORT(len, udp);
  ck_assert_uint_eq(udpsz, daemon->edns_pktsz);
  ck_assert_uint_eq(rcode, 0);
  ck_assert_uint_eq(optlen, 1 + RRFIXEDSZ + len);

  if (data)
    *data = udp;
  if (rdlen)
    *rdlen = len;

  return flags;
}

START_TEST(test_no_pseudoheader) {
  ck_assert_ptr_null(find_pseudoheader(header, qlen, NULL, NULL, NULL, NULL));
}
END_TEST

START_TEST(test_add_pseudoheader) {
  size_t plen = add_pseudoheader(header, qlen, limit, 0, NULL, 0, 0, 0);
  unsigned short rdlen;

  ck_assert_uint_eq(plen, qlen + 1 + RRFIXEDSZ);
  ck_assert_uint_eq(ntohs(header->arcount), 1);
  ck_assert_uint_eq(opt_flags(plen, NULL, &rdlen), 0);
  ck_assert_uint_eq(rdlen, 0);
}
END_TEST

START_TEST(test_add_do_bit) {
  size_t plen = add_do_bit(header, qlen, limit);

  ck_assert_uint_eq(ntohs(header->arcount), 1);
  ck_assert_uint_eq(opt_flags(plen, NULL, NULL), 0x8000);

  /* Idempotent on a packet that already has a pseudoheader. */
  ck_assert_uint_eq(add_do_bit(header, plen, limit), plen);
  ck_assert_uint_eq(ntohs(header->arcount), 1);
}
END_TEST

START_TEST(test_add_option) {
  unsigned char opt[] = {1, 2, 3, 4}, *data;
  unsigned short rdlen, code, len;
  size_t plen = add_pseudoheader(header, qlen, limit, EDNS0_OPTION_NOMDEVICEID,
                                 opt, sizeof(opt), 0, 0);

  opt_flags(plen, &data, &rdlen);
  ck_assert_uint_eq(rdlen, 4 + sizeof(opt));
  GETSHORT(code, data);
  GETSHORT(len, data);
  ck_assert_uint_eq(code, EDNS0_OPTION_NOMDEVICEID);
  ck_assert_uint_eq(len, sizeof(opt));
  ck_assert_mem_eq(data, opt, sizeof(opt));
}
END_TEST

START_TEST(test_replace_option) {
  unsigned char opt1[] = {1, 2, 3, 4}, opt2[] = {9, 8}, *data;
  unsigned short rdlen, code, len;
  size_t plen = add_pseudoheader(header, qlen, limit, EDNS0_OPTION_NOMDEVICEID,
                                 opt1, sizeof(opt1), 0, 0);

  /* replace == 0 leaves an existing option alone. */
  ck_assert_uint_eq(add_pseudoheader(header, plen, limit,
                                     EDNS0_OPTION_NOMDEVICEID, opt2,
                                     sizeof(opt2), 0, 0),
                    plen);
  opt_flags(plen, &data, &rdlen);
  ck_assert_mem_eq(data + 4, opt1, sizeof(opt1));

  /* replace == 1 swaps it. */
  plen = add_pseudoheader(header, plen, limit, EDNS0_OPTION_NOMDEVICEID, opt2,
                          sizeof(opt2), 0, 1);
  ck_assert_uint_eq(ntohs(header->arcount), 1);
  opt_flags(plen, &data, &rdlen);
  ck_assert_uint_eq(rdlen, 4 + sizeof(opt2));
  GETSHORT(code, data);
  GETSHORT(len, data);
  ck_assert_uint_eq(code, EDNS0_OPTION_NOMDEVICEID);
  ck_assert_uint_eq(len, sizeof(opt2));
  ck_assert_mem_eq(data, opt2, sizeof(opt2));
}
END_TEST

START_TEST(test_signed_packet_untouched) {
  size_t plen;

  /* A TKEY query is signed: must not be modified. */
  qlen = test_make_query(daemon->packet, daemon->packet_buff_sz, "key.example",
                         T_TKEY);
  plen = add_pseudoheader(header, qlen, limit, 0, NULL, 0, 1, 0);
  ck_assert_uint_eq(plen, qlen);
  ck_assert_uint_eq(ntohs(header->arcount), 0);
}
END_TEST

START_TEST(test_pseudoheader_no_room) {
  ck_assert_uint_eq(add_pseudoheader(header, qlen, qlen + 2, 0, NULL, 0, 1, 0),
                    qlen);
  ck_assert_uint_eq(ntohs(header->arcount), 0);
}
END_TEST

Suite *edns0_suite(void) {
  Suite *s = suite_create("edns0");
  TCase *tc = tcase_create("pseudoheader");

  tcase_add_checked_fixture(tc, edns0_setup, NULL);
  tcase_add_test(tc, test_no_pseudoheader);
  tcase_add_test(tc, test_add_pseudoheader);
  tcase_add_test(tc, test_add_do_bit);
  tcase_add_test(tc, test_add_option);
  tcase_add_test(tc, test_replace_option);
  tcase_add_test(tc, test_signed_packet_untouched);
  tcase_add_test(tc, test_pseudoheader_no_room);
  suite_add_tcase(s, tc);

  return s;
}
