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

/* Test runner and shared helpers. Each test runs in its own forked
   process (check's default), so the global daemon state set up by
   test_daemon_init() never leaks between tests. */

#include "tests.h"

void test_daemon_init(const char *const *extra) {
  char *argv[64];
  int argc = 0;

  argv[argc++] = "dnsmasq";
  argv[argc++] = "--conf-file=/dev/null";
  argv[argc++] = "--no-resolv";
  argv[argc++] = "--no-hosts";

  for (; extra && *extra; extra++) {
    ck_assert_int_lt(argc, 63);
    argv[argc++] = (char *)*extra;
  }
  argv[argc] = NULL;

  /* glibc: optind == 0 forces getopt to fully reinitialise. */
  optind = 0;

  rand_init();
  read_opts(argc, argv, "");

  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  daemon->pipe_to_parent = -1;

  cache_init();
  blockdata_init();
  build_server_array();
}

size_t test_make_query(void *buf, size_t bufsz, const char *name,
                       unsigned short type) {
  struct dns_header *header = (struct dns_header *)buf;
  unsigned char *start = buf, *p = (unsigned char *)(header + 1);
  const char *label = name;

  memset(buf, 0, bufsz);
  header->id = htons(0x1234);
  header->hb3 = HB3_RD;
  header->qdcount = htons(1);

  while (*label) {
    const char *dot = strchr(label, '.');
    size_t len = dot ? (size_t)(dot - label) : strlen(label);

    ck_assert_uint_lt((size_t)(p - start) + len + 1, bufsz);
    *p++ = len;
    memcpy(p, label, len);
    p += len;
    label += len;
    if (*label == '.')
      label++;
  }
  *p++ = 0;

  PUTSHORT(type, p);
  PUTSHORT(C_IN, p);

  return p - start;
}

int main(void) {
  SRunner *sr = srunner_create(util_suite());
  int failed;

  srunner_add_suite(sr, rfc1035_suite());
  srunner_add_suite(sr, option_suite());
  srunner_add_suite(sr, cache_suite());
  srunner_add_suite(sr, edns0_suite());
  srunner_add_suite(sr, dbus_suite());
  srunner_add_suite(sr, domain_match_suite());
  srunner_add_suite(sr, dnssec_suite());

  srunner_run_all(sr, CK_NORMAL);
  failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
