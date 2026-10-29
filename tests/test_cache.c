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

/* Tests for the DNS cache in cache.c */

#include "tests.h"

#define NOW 1000000

static void cache_setup(void) {
  static const char *const args[] = {"--cache-size=10", NULL};

  test_daemon_init(args);
}

static struct crec *insert_a(char *name, const char *ip, unsigned long ttl) {
  union all_addr addr;
  struct crec *crec;

  ck_assert_int_eq(inet_pton(AF_INET, ip, &addr.addr4), 1);
  cache_start_insert();
  crec = cache_insert(name, &addr, C_IN, NOW, ttl, F_IPV4 | F_FORWARD);
  cache_end_insert();

  return crec;
}

START_TEST(test_insert_find_by_name) {
  struct crec *crec;
  struct in_addr expect;

  ck_assert_ptr_nonnull(insert_a("www.example.com", "192.0.2.10", 300));

  crec = cache_find_by_name(NULL, "WWW.example.com", NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert_str_eq(cache_get_name(crec), "www.example.com");
  inet_pton(AF_INET, "192.0.2.10", &expect);
  ck_assert_mem_eq(&crec->addr.addr4, &expect, sizeof(expect));
  ck_assert_int_eq(crec->ttd, NOW + 300);

  /* Wrong type, or different name. */
  ck_assert_ptr_null(cache_find_by_name(NULL, "www.example.com", NOW, F_IPV6));
  ck_assert_ptr_null(cache_find_by_name(NULL, "example.com", NOW, F_IPV4));
}
END_TEST

START_TEST(test_find_by_addr) {
  union all_addr addr;
  struct crec *crec;

  /* PTR answers are cached as F_REVERSE entries keyed on the address. */
  inet_pton(AF_INET, "192.0.2.11", &addr.addr4);
  cache_start_insert();
  ck_assert_ptr_nonnull(cache_insert("host.example.com", &addr, C_IN, NOW, 300,
                                     F_IPV4 | F_REVERSE));
  cache_end_insert();

  crec = cache_find_by_addr(NULL, &addr, NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert_str_eq(cache_get_name(crec), "host.example.com");

  inet_pton(AF_INET, "192.0.2.12", &addr.addr4);
  ck_assert_ptr_null(cache_find_by_addr(NULL, &addr, NOW, F_IPV4));

  /* Plain forward entries are not found by address. */
  insert_a("fwd.example.com", "192.0.2.12", 300);
  ck_assert_ptr_null(cache_find_by_addr(NULL, &addr, NOW, F_IPV4));
}
END_TEST

START_TEST(test_multiple_addresses) {
  struct crec *crec = NULL;
  union all_addr addr;
  int count = 0;

  cache_start_insert();
  inet_pton(AF_INET, "192.0.2.1", &addr.addr4);
  cache_insert("multi.example", &addr, C_IN, NOW, 300, F_IPV4 | F_FORWARD);
  inet_pton(AF_INET, "192.0.2.2", &addr.addr4);
  cache_insert("multi.example", &addr, C_IN, NOW, 300, F_IPV4 | F_FORWARD);
  inet_pton(AF_INET6, "2001:db8::1", &addr.addr6);
  cache_insert("multi.example", &addr, C_IN, NOW, 300, F_IPV6 | F_FORWARD);
  cache_end_insert();

  while ((crec = cache_find_by_name(crec, "multi.example", NOW, F_IPV4))) {
    ck_assert(crec->flags & F_IPV4);
    count++;
  }
  ck_assert_int_eq(count, 2);

  crec = cache_find_by_name(NULL, "multi.example", NOW, F_IPV6);
  ck_assert_ptr_nonnull(crec);
  ck_assert_mem_eq(&crec->addr.addr6, &addr.addr6, sizeof(addr.addr6));
}
END_TEST

START_TEST(test_expiry) {
  insert_a("short.example", "192.0.2.20", 10);

  ck_assert_ptr_nonnull(
      cache_find_by_name(NULL, "short.example", NOW + 9, F_IPV4));
  ck_assert_ptr_null(
      cache_find_by_name(NULL, "short.example", NOW + 11, F_IPV4));
}
END_TEST

START_TEST(test_negative_entry) {
  struct crec *crec;

  cache_start_insert();
  ck_assert_ptr_nonnull(cache_insert("missing.example", NULL, C_IN, NOW, 60,
                                     F_IPV4 | F_NEG | F_NXDOMAIN | F_FORWARD));
  cache_end_insert();

  crec = cache_find_by_name(NULL, "missing.example", NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert(crec->flags & F_NEG);
  ck_assert(crec->flags & F_NXDOMAIN);
}
END_TEST

START_TEST(test_ttl_clamping) {
  static const char *const args[] = {"--min-cache-ttl=100",
                                     "--max-cache-ttl=1000", NULL};
  struct crec *crec;

  test_daemon_init(args);

  insert_a("low.example", "192.0.2.30", 5);
  insert_a("high.example", "192.0.2.31", 86400);

  crec = cache_find_by_name(NULL, "low.example", NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert_int_eq(crec->ttd, NOW + 100);

  crec = cache_find_by_name(NULL, "high.example", NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert_int_eq(crec->ttd, NOW + 1000);
}
END_TEST

START_TEST(test_eviction) {
  char name[32];
  int i, found = 0;

  /* Twice the cache size: the oldest live entries make way for new ones. */
  for (i = 0; i < 20; i++) {
    sprintf(name, "host%d.example", i);
    ck_assert_ptr_nonnull(insert_a(name, "192.0.2.40", 300));
  }

  for (i = 0; i < 20; i++) {
    sprintf(name, "host%d.example", i);
    if (cache_find_by_name(NULL, name, NOW, F_IPV4))
      found++;
  }

  ck_assert_int_eq(found, 10);
  ck_assert_ptr_nonnull(
      cache_find_by_name(NULL, "host19.example", NOW, F_IPV4));
  ck_assert_ptr_null(cache_find_by_name(NULL, "host0.example", NOW, F_IPV4));
}
END_TEST

START_TEST(test_reload_config_records) {
  static const char *const args[] = {"--host-record=router.lan,192.168.1.1",
                                     "--cname=gw.lan,router.lan", NULL};
  struct crec *crec;

  test_daemon_init(args);
  insert_a("www.example.com", "192.0.2.10", 300);
  cache_reload();

  crec = cache_find_by_name(NULL, "router.lan", NOW, F_IPV4);
  ck_assert_ptr_nonnull(crec);
  ck_assert(crec->flags & F_CONFIG);
  ck_assert(crec->flags & F_IMMORTAL);

  crec = cache_find_by_name(NULL, "gw.lan", NOW, F_CNAME);
  ck_assert_ptr_nonnull(crec);
  ck_assert(crec->flags & F_CNAME);
  ck_assert_str_eq(cache_get_cname_target(crec), "router.lan");

  /* Reload discards records learned from upstream. */
  ck_assert_ptr_null(cache_find_by_name(NULL, "www.example.com", NOW, F_IPV4));
}
END_TEST

START_TEST(test_blockdata) {
  char data[300], out[300];
  struct blockdata *block;
  int i;

  for (i = 0; i < (int)sizeof(data); i++)
    data[i] = i;

  /* Spans several blocks. */
  block = blockdata_alloc(data, sizeof(data));
  ck_assert_ptr_nonnull(block);
  ck_assert_ptr_eq(blockdata_retrieve(block, sizeof(data), out), out);
  ck_assert_mem_eq(out, data, sizeof(data));
  blockdata_free(block);
}
END_TEST

Suite *cache_suite(void) {
  Suite *s = suite_create("cache");
  TCase *tc = tcase_create("cache");
  TCase *tc_config = tcase_create("config");

  tcase_add_checked_fixture(tc, cache_setup, NULL);
  tcase_add_test(tc, test_insert_find_by_name);
  tcase_add_test(tc, test_find_by_addr);
  tcase_add_test(tc, test_multiple_addresses);
  tcase_add_test(tc, test_expiry);
  tcase_add_test(tc, test_negative_entry);
  tcase_add_test(tc, test_eviction);
  tcase_add_test(tc, test_blockdata);
  suite_add_tcase(s, tc);

  /* These set up the daemon with their own options. */
  tcase_add_test(tc_config, test_ttl_clamping);
  tcase_add_test(tc_config, test_reload_config_records);
  suite_add_tcase(s, tc_config);

  return s;
}
