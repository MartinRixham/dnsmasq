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

/* Shared declarations for the check(3) based unit tests. */

#ifndef DNSMASQ_TESTS_H
#define DNSMASQ_TESTS_H

#include "dnsmasq.h"
#include <check.h>

Suite *util_suite(void);
Suite *rfc1035_suite(void);
Suite *option_suite(void);
Suite *cache_suite(void);
Suite *edns0_suite(void);
Suite *dbus_suite(void);

/* Run read_opts() on a minimal command line (no config file, no
   resolv.conf, no /etc/hosts) plus the NULL-terminated extra args, then
   do the subset of main()'s initialisation the DNS code relies on. */
void test_daemon_init(const char *const *extra);

/* Build a single-question query for name/type into buf, independently of
   the code under test. Returns the packet length. */
size_t test_make_query(void *buf, size_t bufsz, const char *name,
                       unsigned short type);

#endif
