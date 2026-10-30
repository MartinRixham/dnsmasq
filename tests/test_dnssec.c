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

/* Tests for DNSSEC validation in dnssec.c and crypto.c

   Replies are signed here at run time with nettle, using fixed keys for
   the root zone and for "example", so a test can build any reply, good
   or bad, and check what the validator makes of it. The root key's DS is
   passed to the daemon with --trust-anchor, as trust-anchors.conf does.
   The validation tests run once with Ed25519 keys and once with ECDSA
   P-256 keys. */

#include "tests.h"

#ifdef HAVE_DNSSEC

#include <nettle/bignum.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecc.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/sha2.h>

#define TTL 3600
#define SIG_SIZE 64 /* Both Ed25519 and P-256 */

enum section { AN, NS };

struct key {
  const char *zone; /* "" for the root */
  int algo, keytag;
  unsigned char priv[32];
  struct ecc_scalar scalar; /* ECDSA only */
  unsigned char dnskey[4 + 64];
  size_t dnskey_len;
  unsigned char ds[4 + SHA256_DIGEST_SIZE];
};

struct rr {
  const unsigned char *data;
  size_t len;
};

static struct key root, example;
static time_t now;
static int counter;

static struct dns_header *header;
static unsigned char *end;      /* end of the reply built so far */
static unsigned char *last_sig; /* signature of the last RRSIG added */

static const unsigned char a1[] = {192, 0, 2, 1}, a2[] = {192, 0, 2, 2};

/* NSEC type bitmaps, window 0. */
static const unsigned char map_a[] = {0, 6, 0x40, 0, 0, 0, 0, 0x03};
static const unsigned char map_a_aaaa[] = {0, 6, 0x40, 0, 0, 0x08, 0, 0x03};
static const unsigned char map_ns[] = {0, 6, 0x20, 0, 0, 0, 0, 0x03};

static int count_labels(const char *name) {
  int n = *name ? 1 : 0;

  for (; *name; name++)
    if (*name == '.')
      n++;

  return n;
}

static unsigned char *put_name(unsigned char *p, const char *name) {
  while (*name) {
    const char *dot = strchr(name, '.');
    size_t len = dot ? (size_t)(dot - name) : strlen(name);

    *p++ = len;
    memcpy(p, name, len);
    p += len;
    name += len;
    if (*name == '.')
      name++;
  }
  *p++ = 0;

  return p;
}

/* RFC 4034 appendix B, independently of dnskey_keytag(). */
static int keytag(const unsigned char *rdata, size_t len) {
  unsigned long ac = 0;
  size_t i;

  for (i = 0; i < len; i++)
    ac += (i & 1) ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xffff;

  return ac & 0xffff;
}

static void sha256(const unsigned char *data, size_t len, unsigned char *out) {
  struct sha256_ctx ctx;

  nettle_sha256.init(&ctx);
  nettle_sha256.update(&ctx, len, data);
  nettle_digest_wrapper(&nettle_sha256, &ctx, SHA256_DIGEST_SIZE, out);
}

static void export_fixed(const mpz_t v, unsigned char *buf, size_t len) {
  size_t n = (mpz_sizeinbase(v, 2) + 7) / 8;

  ck_assert_uint_le(n, len);
  memset(buf, 0, len);
  mpz_export(buf + len - n, NULL, 1, 1, 0, 0, v);
}

static void test_random(void *ctx, size_t len, uint8_t *dst) {
  (void)ctx;
  while (len--)
    *dst++ = rand16();
}

/* Make a key for zone from a fixed private key derived from seed, with
   its DNSKEY rdata, key tag and SHA-256 DS rdata. */
static void make_key(struct key *k, const char *zone, int algo,
                     unsigned char seed) {
  unsigned char wire[MAXDNAME + sizeof(k->dnskey)], *p = k->dnskey, *q;
  int i;

  k->zone = zone;
  k->algo = algo;
  for (i = 0; i < 32; i++)
    k->priv[i] = seed + i;

  PUTSHORT(257, p); /* zone key, SEP */
  *p++ = 3;
  *p++ = algo;

  if (algo == 15) {
    ed25519_sha512_public_key(p, k->priv);
    p += ED25519_KEY_SIZE;
  } else {
    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_point pub;
    mpz_t d, x, y;

    mpz_init(d);
    mpz_init(x);
    mpz_init(y);
    mpz_import(d, 32, 1, 1, 0, 0, k->priv);
    ecc_scalar_init(&k->scalar, curve);
    ck_assert(ecc_scalar_set(&k->scalar, d));
    ecc_point_init(&pub, curve);
    ecc_point_mul_g(&pub, &k->scalar);
    ecc_point_get(&pub, x, y);
    export_fixed(x, p, 32);
    export_fixed(y, p + 32, 32);
    p += 64;
  }

  k->dnskey_len = p - k->dnskey;
  k->keytag = keytag(k->dnskey, k->dnskey_len);

  p = put_name(wire, zone);
  memcpy(p, k->dnskey, k->dnskey_len);
  p += k->dnskey_len;

  q = k->ds;
  PUTSHORT(k->keytag, q);
  *q++ = algo;
  *q++ = 2; /* SHA-256 */
  sha256(wire, p - wire, q);
}

static void sign(const struct key *k, const unsigned char *data, size_t len,
                 unsigned char *sig) {
  if (k->algo == 15)
    ed25519_sha512_sign(k->dnskey + 4, k->priv, len, data, sig);
  else {
    unsigned char digest[SHA256_DIGEST_SIZE];
    struct dsa_signature s;

    sha256(data, len, digest);
    dsa_signature_init(&s);
    ecdsa_sign(&k->scalar, NULL, test_random, sizeof(digest), digest, &s);
    export_fixed(s.r, sig, 32);
    export_fixed(s.s, sig + 32, 32);
    dsa_signature_clear(&s);
  }
}

static void reply_start(const char *qname, unsigned short qtype, int rcode) {
  header = (struct dns_header *)daemon->packet;
  memset(header, 0, sizeof(*header));
  header->id = htons(0x1234);
  header->hb3 = HB3_QR | HB3_RD;
  header->hb4 = HB4_RA | rcode;
  header->qdcount = htons(1);

  end = put_name((unsigned char *)(header + 1), qname);
  PUTSHORT(qtype, end);
  PUTSHORT(C_IN, end);
}

static size_t reply_len(void) { return end - (unsigned char *)header; }

static void add_rr(enum section section, const char *owner, unsigned short type,
                   const unsigned char *rdata, size_t rdlen) {
  ck_assert_uint_lt(reply_len() + MAXDNAME + RRFIXEDSZ + rdlen,
                    daemon->packet_buff_sz);

  end = put_name(end, owner);
  PUTSHORT(type, end);
  PUTSHORT(C_IN, end);
  PUTLONG(TTL, end);
  PUTSHORT(rdlen, end);
  memcpy(end, rdata, rdlen);
  end += rdlen;

  if (section == AN) {
    ck_assert_uint_eq(ntohs(header->nscount), 0);
    header->ancount = htons(ntohs(header->ancount) + 1);
  } else
    header->nscount = htons(ntohs(header->nscount) + 1);
}

/* Add an RRSIG made by k over the RRset (owner, type) whose rdata are
   rrs, which must be in canonical order. labels less than the number in
   owner makes it a signature over the wildcard. */
static void add_rrsig_full(enum section section, const struct key *k,
                           const char *owner, unsigned short type,
                           const struct rr *rrs, int n, int labels,
                           u32 inception, u32 expiration) {
  unsigned char rdata[MAXDNAME + 18 + SIG_SIZE], *p = rdata;
  unsigned char data[2048], *q;
  char signed_owner[MAXDNAME];
  int i;

  PUTSHORT(type, p);
  *p++ = k->algo;
  *p++ = labels;
  PUTLONG(TTL, p);
  PUTLONG(expiration, p);
  PUTLONG(inception, p);
  PUTSHORT(k->keytag, p);
  p = put_name(p, k->zone);

  if (labels < count_labels(owner)) {
    const char *s = owner;

    for (i = count_labels(owner) - labels; i != 0; i--)
      s = strchr(s, '.') + 1;
    snprintf(signed_owner, sizeof(signed_owner), "*.%s", s);
  } else
    snprintf(signed_owner, sizeof(signed_owner), "%s", owner);

  memcpy(data, rdata, p - rdata);
  q = data + (p - rdata);
  for (i = 0; i < n; i++) {
    ck_assert_uint_lt((size_t)(q - data) + MAXDNAME + 10 + rrs[i].len,
                      sizeof(data));
    q = put_name(q, signed_owner);
    PUTSHORT(type, q);
    PUTSHORT(C_IN, q);
    PUTLONG(TTL, q);
    PUTSHORT(rrs[i].len, q);
    memcpy(q, rrs[i].data, rrs[i].len);
    q += rrs[i].len;
  }

  sign(k, data, q - data, p);
  add_rr(section, owner, T_RRSIG, rdata, p + SIG_SIZE - rdata);
  last_sig = end - SIG_SIZE;
}

static void add_rrsig(enum section section, const struct key *k,
                      const char *owner, unsigned short type,
                      const struct rr *rrs, int n) {
  add_rrsig_full(section, k, owner, type, rrs, n, count_labels(owner),
                 now - 3600, now + 86400);
}

static void add_signed(enum section section, const struct key *k,
                       const char *owner, unsigned short type,
                       const unsigned char *rdata, size_t rdlen) {
  struct rr rr = {rdata, rdlen};

  add_rr(section, owner, type, rdata, rdlen);
  add_rrsig(section, k, owner, type, &rr, 1);
}

static void add_nsec(const struct key *k, const char *owner, const char *next,
                     const unsigned char *map, size_t maplen) {
  unsigned char rdata[MAXDNAME + 34], *p = put_name(rdata, next);

  memcpy(p, map, maplen);
  add_signed(NS, k, owner, T_NSEC, rdata, p + maplen - rdata);
}

/* An OPT RR with the DO bit, as in replies to the validator's queries. */
static void add_opt(void) {
  ck_assert_uint_lt(reply_len() + 1 + RRFIXEDSZ, daemon->packet_buff_sz);
  *end++ = 0;
  PUTSHORT(T_OPT, end);
  PUTSHORT(1232, end);
  PUTLONG(0x8000, end);
  PUTSHORT(0, end);
  header->arcount = htons(ntohs(header->arcount) + 1);
}

static int validate_by_ds(void) {
  return dnssec_validate_by_ds(now, header, reply_len(), daemon->namebuff,
                               daemon->keyname, C_IN, &counter);
}

static int validate_ds(void) {
  return dnssec_validate_ds(now, header, reply_len(), daemon->namebuff,
                            daemon->keyname, C_IN, &counter);
}

static int validate_reply(int check_unsigned, int *neganswer) {
  int class;

  return dnssec_validate_reply(now, header, reply_len(), daemon->namebuff,
                               daemon->keyname, &class, check_unsigned,
                               neganswer, NULL, NULL, NULL, &counter);
}

/* Validate and cache the DNSKEY RRset of k's zone. */
static void load_key(const struct key *k) {
  reply_start(k->zone, T_DNSKEY, NOERROR);
  add_signed(AN, k, k->zone, T_DNSKEY, k->dnskey, k->dnskey_len);
  ck_assert_int_eq(validate_by_ds(), STAT_OK);
}

/* Validate and cache child's DS, signed by parent. */
static void load_ds(const struct key *parent, const struct key *child) {
  reply_start(child->zone, T_DS, NOERROR);
  add_signed(AN, parent, child->zone, T_DS, child->ds, sizeof(child->ds));
  ck_assert_int_eq(validate_ds(), STAT_OK);
}

/* Validate and cache proof from the root zone that there's no DS for
   name, with an NSEC whose type bitmap is map. With an NS in map, name is
   an unsigned delegation, otherwise it's in the root zone. */
static void deny_ds(const char *name, const char *next,
                    const unsigned char *map, size_t maplen) {
  reply_start(name, T_DS, NOERROR);
  add_nsec(&root, name, next, map, maplen);
  ck_assert_int_eq(validate_ds(), STAT_OK);
}

static void dnssec_setup(int algo) {
  char anchor[200], *p;
  const char *args[] = {"--dnssec", anchor, NULL};
  size_t i;

  make_key(&root, "", algo, 0x01);
  make_key(&example, "example", algo, 0x41);

  p = anchor + sprintf(anchor, "--trust-anchor=.,%d,%d,2,", root.keytag, algo);
  for (i = 4; i < sizeof(root.ds); i++)
    p += sprintf(p, "%02X", root.ds[i]);

  test_daemon_init(args);
  /* As main() does for --dnssec. */
  daemon->keyname = safe_malloc(MAXDNAMESTR + 1);
  daemon->cname = safe_malloc(MAXDNAMESTR + 1);
  /* Puts the trust anchor in the cache. */
  cache_reload();

  now = time(NULL);
  counter = daemon->limit[LIMIT_CRYPTO];
}

static void ed25519_setup(void) { dnssec_setup(15); }

static void crypto_setup(void) { test_daemon_init(NULL); }

static void ecdsa_setup(void) { dnssec_setup(13); }

/* DNSKEY RRsets, validated against DS records. */

START_TEST(test_dnskey_validated_by_trust_anchor) {
  struct crec *crec;

  load_key(&root);

  crec = cache_find_by_name(NULL, "", now, F_DNSKEY);
  ck_assert_ptr_nonnull(crec);
  ck_assert_int_eq(crec->addr.key.algo, root.algo);
  ck_assert_int_eq(crec->addr.key.keytag, root.keytag);
  ck_assert_int_eq(crec->addr.key.keylen, root.dnskey_len - 4);
}
END_TEST

START_TEST(test_dnskey_bad_signature) {
  reply_start("", T_DNSKEY, NOERROR);
  add_signed(AN, &root, "", T_DNSKEY, root.dnskey, root.dnskey_len);
  last_sig[10] ^= 1;

  ck_assert_int_eq(validate_by_ds(), STAT_BOGUS);
  ck_assert_ptr_null(cache_find_by_name(NULL, "", now, F_DNSKEY));
}
END_TEST

START_TEST(test_dnskey_unsigned) {
  reply_start("", T_DNSKEY, NOERROR);
  add_rr(AN, "", T_DNSKEY, root.dnskey, root.dnskey_len);

  ck_assert_int_eq(validate_by_ds(), STAT_BOGUS | DNSSEC_FAIL_NOSIG);
  ck_assert_ptr_null(cache_find_by_name(NULL, "", now, F_DNSKEY));
}
END_TEST

/* A self-signed root key that doesn't match the trust anchor. */
START_TEST(test_dnskey_not_trust_anchor) {
  struct key rogue;

  make_key(&rogue, "", root.algo, 0x81);
  reply_start("", T_DNSKEY, NOERROR);
  add_signed(AN, &rogue, "", T_DNSKEY, rogue.dnskey, rogue.dnskey_len);

  ck_assert(STAT_ISEQUAL(validate_by_ds(), STAT_BOGUS));
  ck_assert_ptr_null(cache_find_by_name(NULL, "", now, F_DNSKEY));
}
END_TEST

START_TEST(test_dnskey_not_zone_key) {
  int rc;

  reply_start("", T_DNSKEY, NOERROR);
  root.dnskey[0] = 0;
  add_signed(AN, &root, "", T_DNSKEY, root.dnskey, root.dnskey_len);

  rc = validate_by_ds();
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert(rc & DNSSEC_FAIL_NOZONE);
  ck_assert_int_eq(errflags_to_ede(rc), EDE_NO_ZONEKEY);
}
END_TEST

START_TEST(test_dnskey_need_ds) {
  reply_start("example", T_DNSKEY, NOERROR);
  add_signed(AN, &example, "example", T_DNSKEY, example.dnskey,
             example.dnskey_len);

  ck_assert_int_eq(validate_by_ds(), STAT_NEED_DS);
  ck_assert_str_eq(daemon->keyname, "example");
}
END_TEST

/* Answers, validated with cached keys. */

START_TEST(test_answer_secure) {
  int neganswer = -1;

  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_signed(AN, &root, "test", T_A, a1, sizeof(a1));

  ck_assert_int_eq(validate_reply(1, &neganswer), STAT_SECURE);
  ck_assert_int_eq(neganswer, 0);
  ck_assert_uint_eq(daemon->rr_status[0], TTL);
}
END_TEST

/* The RRset must be put in canonical order before checking the sig. */
START_TEST(test_answer_canonical_order) {
  const struct rr rrs[] = {{a1, sizeof(a1)}, {a2, sizeof(a2)}};

  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a2, sizeof(a2));
  add_rr(AN, "test", T_A, a1, sizeof(a1));
  add_rrsig(AN, &root, "test", T_A, rrs, 2);

  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);
  ck_assert_uint_ne(daemon->rr_status[0], 0);
  ck_assert_uint_ne(daemon->rr_status[1], 0);
}
END_TEST

/* Name compression and case don't change the signed data. */
START_TEST(test_answer_compressed_name) {
  unsigned char *p;

  load_key(&root);
  reply_start("TeSt", T_A, NOERROR);
  add_signed(AN, &root, "test", T_A, a1, sizeof(a1));

  /* Point the A record's owner at the question. */
  p = (unsigned char *)(header + 1) + 6 + 4;
  ck_assert_mem_eq(p, "\4test\0", 6);
  p[0] = 0xc0;
  p[1] = sizeof(struct dns_header);
  memmove(p + 2, p + 6, end - (p + 6));
  end -= 4;
  last_sig -= 4;

  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);
}
END_TEST

START_TEST(test_answer_tampered) {
  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_signed(AN, &root, "test", T_A, a1, sizeof(a1));
  /* The last byte of the address. */
  ((unsigned char *)(header + 1))[6 + 4 + 6 + RRFIXEDSZ + 3] ^= 1;

  ck_assert(STAT_ISEQUAL(validate_reply(1, NULL), STAT_BOGUS));
}
END_TEST

/* Is the name in a zone of its own, perhaps unsigned? */
START_TEST(test_answer_unsigned_need_ds) {
  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a1, sizeof(a1));

  ck_assert_int_eq(validate_reply(1, NULL), STAT_NEED_DS);
  ck_assert_str_eq(daemon->keyname, "test");
}
END_TEST

START_TEST(test_answer_unsigned) {
  int rc;

  load_key(&root);
  deny_ds("test", "zz", map_a, sizeof(map_a));
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a1, sizeof(a1));

  rc = validate_reply(1, NULL);
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert(rc & DNSSEC_FAIL_NOSIG);
  ck_assert_uint_eq(daemon->rr_status[0], 0);
}
END_TEST

START_TEST(test_answer_need_key) {
  reply_start("test", T_A, NOERROR);
  add_signed(AN, &root, "test", T_A, a1, sizeof(a1));

  ck_assert_int_eq(validate_reply(1, NULL), STAT_NEED_KEY);
  ck_assert_str_eq(daemon->keyname, "");
}
END_TEST

/* A signature by a zone that doesn't enclose the name doesn't count, even
   if it's valid. */
START_TEST(test_answer_signer_not_parent) {
  int rc;

  load_key(&root);
  deny_ds("test", "zz", map_a, sizeof(map_a));
  load_ds(&root, &example);
  load_key(&example);
  reply_start("test", T_A, NOERROR);
  add_signed(AN, &example, "test", T_A, a1, sizeof(a1));

  rc = validate_reply(1, NULL);
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert(rc & DNSSEC_FAIL_NOSIG);
}
END_TEST

START_TEST(test_answer_sig_expired) {
  struct rr rr = {a1, sizeof(a1)};
  int rc;

  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a1, sizeof(a1));
  add_rrsig_full(AN, &root, "test", T_A, &rr, 1, 1, now - 7200, now - 60);

  rc = validate_reply(1, NULL);
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert_int_eq(errflags_to_ede(rc), EDE_SIG_EXP);

  /* --dnssec-no-timecheck, before the time is known to be right. */
  daemon->dnssec_no_time_check = 1;
  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);
}
END_TEST

START_TEST(test_answer_sig_not_yet_valid) {
  struct rr rr = {a1, sizeof(a1)};
  int rc;

  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a1, sizeof(a1));
  add_rrsig_full(AN, &root, "test", T_A, &rr, 1, 1, now + 3600, now + 7200);

  rc = validate_reply(1, NULL);
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert_int_eq(errflags_to_ede(rc), EDE_SIG_NYV);
}
END_TEST

/* A signature mustn't be trusted for longer than it's valid. */
START_TEST(test_answer_ttl_capped_by_sig) {
  struct rr rr = {a1, sizeof(a1)};

  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_rr(AN, "test", T_A, a1, sizeof(a1));
  add_rrsig_full(AN, &root, "test", T_A, &rr, 1, 1, now - 3600, now + 100);

  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);
  ck_assert_uint_gt(daemon->rr_status[0], 0);
  ck_assert_uint_le(daemon->rr_status[0], 100);
}
END_TEST

START_TEST(test_answer_crypto_limit) {
  load_key(&root);
  reply_start("test", T_A, NOERROR);
  add_signed(AN, &root, "test", T_A, a1, sizeof(a1));

  counter = 0;
  ck_assert_int_eq(validate_reply(1, NULL), STAT_ABANDONED);
}
END_TEST

START_TEST(test_answer_servfail) {
  int rc;

  reply_start("test", T_A, SERVFAIL);

  rc = validate_reply(1, NULL);
  ck_assert_int_eq(rc, STAT_BOGUS | DNSSEC_FAIL_UPSTREAM);
  ck_assert_int_eq(errflags_to_ede(rc), EDE_US_SERVFAIL);
}
END_TEST

/* Delegations. */

START_TEST(test_secure_delegation) {
  struct crec *crec;

  load_key(&root);
  load_ds(&root, &example);

  crec = cache_find_by_name(NULL, "example", now, F_DS);
  ck_assert_ptr_nonnull(crec);
  ck_assert(!(crec->flags & F_NEG));
  ck_assert_int_eq(crec->addr.ds.keytag, example.keytag);
  ck_assert_int_eq(crec->addr.ds.algo, example.algo);
  ck_assert_int_eq(crec->addr.ds.digest, 2);

  load_key(&example);
  reply_start("www.example", T_A, NOERROR);
  add_signed(AN, &example, "www.example", T_A, a1, sizeof(a1));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);
}
END_TEST

START_TEST(test_ds_bad_signature) {
  load_key(&root);
  reply_start("example", T_DS, NOERROR);
  add_signed(AN, &root, "example", T_DS, example.ds, sizeof(example.ds));
  last_sig[0] ^= 0x80;

  ck_assert(STAT_ISEQUAL(validate_ds(), STAT_BOGUS));
  ck_assert_ptr_null(cache_find_by_name(NULL, "example", now, F_DS));
}
END_TEST

/* The child's key, validated by a DS for some other key. */
START_TEST(test_dnskey_not_matching_ds) {
  struct key other;

  make_key(&other, "example", example.algo, 0x81);
  load_key(&root);
  load_ds(&root, &other);

  reply_start("example", T_DNSKEY, NOERROR);
  add_signed(AN, &example, "example", T_DNSKEY, example.dnskey,
             example.dnskey_len);
  ck_assert(STAT_ISEQUAL(validate_by_ds(), STAT_BOGUS));
}
END_TEST

/* A signed NSEC proves there's no DS at a zone cut: everything below is
   unsigned. */
START_TEST(test_insecure_delegation) {
  struct crec *crec;

  load_key(&root);
  deny_ds("insecure", "test", map_ns, sizeof(map_ns));

  crec = cache_find_by_name(NULL, "insecure", now, F_DS);
  ck_assert_ptr_nonnull(crec);
  ck_assert(crec->flags & F_NEG);
  ck_assert(crec->flags & F_DNSSECOK); /* there is an NS */

  reply_start("www.insecure", T_A, NOERROR);
  add_rr(AN, "www.insecure", T_A, a1, sizeof(a1));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_INSECURE);
}
END_TEST

/* Without an NS there's no zone cut, so no proof that what's below is
   unsigned. */
START_TEST(test_no_ds_not_zone_cut) {
  load_key(&root);
  deny_ds("notzone", "test", map_a, sizeof(map_a));

  reply_start("www.notzone", T_A, NOERROR);
  add_rr(AN, "www.notzone", T_A, a1, sizeof(a1));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_NEED_DS);
  ck_assert_str_eq(daemon->keyname, "www.notzone");
}
END_TEST

/* An unsigned answer to a DS query mustn't be taken as proof of an
   unsigned zone. */
START_TEST(test_ds_unsigned_denial) {
  int rc;

  load_key(&root);
  reply_start("example", T_DS, NOERROR);
  add_rr(NS, "example", T_NSEC,
         (const unsigned char *)"\4test\0\0\6\x20\0\0\0\0\3", 14);

  rc = validate_ds();
  ck_assert(STAT_ISEQUAL(rc, STAT_BOGUS));
  ck_assert_ptr_null(cache_find_by_name(NULL, "example", now, F_DS));
}
END_TEST

/* Denial of existence. */

START_TEST(test_nodata_proof) {
  int neganswer = 0;

  load_key(&root);
  reply_start("test", T_AAAA, NOERROR);
  add_nsec(&root, "test", "zz", map_a, sizeof(map_a));

  ck_assert_int_eq(validate_reply(1, &neganswer), STAT_SECURE);
  ck_assert_int_eq(neganswer, 1);
}
END_TEST

START_TEST(test_nodata_type_in_bitmap) {
  load_key(&root);
  deny_ds("test", "zz", map_a, sizeof(map_a));
  reply_start("test", T_AAAA, NOERROR);
  add_nsec(&root, "test", "zz", map_a_aaaa, sizeof(map_a_aaaa));

  ck_assert_int_eq(validate_reply(1, NULL), STAT_BOGUS | DNSSEC_FAIL_NONSEC);
}
END_TEST

START_TEST(test_nodata_no_nsec) {
  load_key(&root);
  deny_ds("test", "zz", map_a, sizeof(map_a));
  reply_start("test", T_AAAA, NOERROR);
  add_opt();

  ck_assert_int_eq(validate_reply(1, NULL), STAT_BOGUS | DNSSEC_FAIL_NONSEC);
}
END_TEST

START_TEST(test_nxdomain_proof) {
  int neganswer = 0;

  load_key(&root);
  reply_start("bb", T_A, NXDOMAIN);
  add_nsec(&root, "aa", "cc", map_a, sizeof(map_a));

  ck_assert_int_eq(validate_reply(1, &neganswer), STAT_SECURE);
  ck_assert_int_eq(neganswer, 1);

  /* An NSEC that doesn't cover the name: unless the name turns out to be
     in an unsigned zone, that's bogus. */
  reply_start("dd", T_A, NXDOMAIN);
  add_nsec(&root, "aa", "cc", map_a, sizeof(map_a));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_NEED_DS);
  ck_assert_str_eq(daemon->keyname, "dd");
}
END_TEST

/* An answer synthesised from a wildcard needs proof that the name itself
   doesn't exist, or a wildcard answer could be replayed over a real one. */
START_TEST(test_wildcard_answer) {
  struct rr rr = {a1, sizeof(a1)};

  load_key(&root);
  reply_start("a.test", T_A, NOERROR);
  add_rr(AN, "a.test", T_A, a1, sizeof(a1));
  add_rrsig_full(AN, &root, "a.test", T_A, &rr, 1, 1, now - 3600, now + 86400);
  ck_assert_int_eq(validate_reply(1, NULL), STAT_BOGUS | DNSSEC_FAIL_NONSEC);

  add_nsec(&root, "test", "b.test", map_a, sizeof(map_a));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_SECURE);

  /* An NSEC showing the name exists doesn't do. */
  reply_start("a.test", T_A, NOERROR);
  add_rr(AN, "a.test", T_A, a1, sizeof(a1));
  add_rrsig_full(AN, &root, "a.test", T_A, &rr, 1, 1, now - 3600, now + 86400);
  add_nsec(&root, "a.test", "b.test", map_a, sizeof(map_a));
  ck_assert_int_eq(validate_reply(1, NULL), STAT_BOGUS | DNSSEC_FAIL_NONSEC);
}
END_TEST

START_TEST(test_unsigned_nsec) {
  load_key(&root);
  reply_start("test", T_AAAA, NOERROR);
  add_rr(NS, "test", T_NSEC, (const unsigned char *)"\2zz\0\0\6\x40\0\0\0\0\3",
         12);

  ck_assert_int_eq(validate_reply(1, NULL), STAT_BOGUS | DNSSEC_FAIL_NOSIG);
}
END_TEST

/* Validation helpers that need no keys. */

/* The 2017 root KSK, which trust-anchors.conf has as
   .,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
 */
static const unsigned char root_ksk[] =
    "\x01\x01\x03\x08"
    "\x03\x01\x00\x01\xac\xff\xb4\x09\xbc\xc9\x39\xf8\x31\xf7\xa1\xe5"
    "\xec\x88\xf7\xa5\x92\x55\xec\x53\x04\x0b\xe4\x32\x02\x73\x90\xa4"
    "\xce\x89\x6d\x6f\x90\x86\xf3\xc5\xe1\x77\xfb\xfe\x11\x81\x63\xaa"
    "\xec\x7a\xf1\x46\x2c\x47\x94\x59\x44\xc4\xe2\xc0\x26\xbe\x5e\x98"
    "\xbb\xcd\xed\x25\x97\x82\x72\xe1\xe3\xe0\x79\xc5\x09\x4d\x57\x3f"
    "\x0e\x83\xc9\x2f\x02\xb3\x2d\x35\x13\xb1\x55\x0b\x82\x69\x29\xc8"
    "\x0d\xd0\xf9\x2c\xac\x96\x6d\x17\x76\x9f\xd5\x86\x7b\x64\x7c\x3f"
    "\x38\x02\x9a\xbd\xc4\x81\x52\xeb\x8f\x20\x71\x59\xec\xc5\xd2\x32"
    "\xc7\xc1\x53\x7c\x79\xf4\xb7\xac\x28\xff\x11\x68\x2f\x21\x68\x1b"
    "\xf6\xd6\xab\xa5\x55\x03\x2b\xf6\xf9\xf0\x36\xbe\xb2\xaa\xa5\xb3"
    "\x77\x8d\x6e\xeb\xfb\xa6\xbf\x9e\xa1\x91\xbe\x4a\xb0\xca\xea\x75"
    "\x9e\x2f\x77\x3a\x1f\x90\x29\xc7\x3e\xcb\x8d\x57\x35\xb9\x32\x1d"
    "\xb0\x85\xf1\xb8\xe2\xd8\x03\x8f\xe2\x94\x19\x92\x54\x8c\xee\x0d"
    "\x67\xdd\x45\x47\xe1\x1d\xd6\x3a\xf9\xc9\xfc\x1c\x54\x66\xfb\x68"
    "\x4c\xf0\x09\xd7\x19\x7c\x2c\xf7\x9e\x79\x2a\xb5\x01\xe6\xa8\xa1"
    "\xca\x51\x9a\xf2\xcb\x9b\x5f\x63\x67\xe9\x4c\x0d\x47\x50\x24\x51"
    "\x35\x7b\xe1\xb5";

static const unsigned char root_ksk_ds[] =
    "\xe0\x6d\x44\xb8\x0b\x8f\x1d\x39\xa9\x5c\x0b\x0d\x7c\x65\xd0\x84"
    "\x58\xe8\x80\x40\x9b\xbc\x68\x34\x57\x10\x42\x37\xc7\xf8\xec\x8d";

START_TEST(test_root_ksk) {
  const struct nettle_hash *hash = hash_find(ds_digest_name(2));
  unsigned char *digest;
  void *ctx;

  ck_assert_uint_eq(sizeof(root_ksk) - 1, 4 + 260);
  ck_assert_int_eq(dnskey_keytag(8, 257, (unsigned char *)root_ksk + 4, 260),
                   20326);

  ck_assert_ptr_nonnull(hash);
  ck_assert_uint_eq(hash->digest_size, sizeof(root_ksk_ds) - 1);
  ck_assert(hash_init(hash, &ctx, &digest));
  hash->update(ctx, 1, (const uint8_t *)""); /* root name */
  hash->update(ctx, sizeof(root_ksk) - 1, root_ksk);
  nettle_digest_wrapper(hash, ctx, hash->digest_size, digest);
  ck_assert_mem_eq(digest, root_ksk_ds, hash->digest_size);
}
END_TEST

/* RSA/MD5 keys have their own, older, key tag. */
START_TEST(test_keytag_rsamd5) {
  unsigned char key[] = {1, 2, 3, 4, 0x12, 0x34, 5, 6};

  ck_assert_int_eq(dnskey_keytag(1, 257, key, sizeof(key)), 0x1234);
}
END_TEST

START_TEST(test_supported_algorithms) {
  static const int supported[] = {5, 7, 8, 10, 13, 14, 15};
  static const int unsupported[] = {0, 1, 2, 3, 4, 6, 9, 11, 252, 253, 254};
  size_t i;

  for (i = 0; i < sizeof(supported) / sizeof(supported[0]); i++)
    ck_assert_msg(hash_find(algo_digest_name(supported[i])), "algorithm %d",
                  supported[i]);
  for (i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++)
    ck_assert_msg(!algo_digest_name(unsupported[i]), "algorithm %d",
                  unsupported[i]);

  ck_assert_ptr_nonnull(hash_find(ds_digest_name(1)));
  ck_assert_ptr_nonnull(hash_find(ds_digest_name(2)));
  ck_assert_ptr_nonnull(hash_find(ds_digest_name(4)));
  ck_assert_ptr_null(ds_digest_name(0));
  ck_assert_ptr_null(ds_digest_name(5));

  ck_assert_ptr_nonnull(hash_find(nsec3_digest_name(1)));
  ck_assert_ptr_null(nsec3_digest_name(2));

  ck_assert_ptr_null(hash_find(NULL));
  ck_assert_ptr_null(hash_find("no-such-hash"));
}
END_TEST

START_TEST(test_errflags_to_ede) {
  ck_assert_int_eq(errflags_to_ede(0), EDE_UNSET);
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_NOSIG), EDE_NO_RRSIG);
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_NONSEC), EDE_NO_NSEC);
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_NOKEY), EDE_NO_DNSKEY);
  /* Most specific first. */
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_UPSTREAM | DNSSEC_FAIL_NYV),
                   EDE_US_SERVFAIL);
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_EXP | DNSSEC_FAIL_NOKEYSUP |
                                   DNSSEC_FAIL_NOKEY),
                   EDE_SIG_EXP);
  ck_assert_int_eq(errflags_to_ede(DNSSEC_FAIL_NOKEY | DNSSEC_FAIL_NOSIG),
                   EDE_NO_DNSKEY);
}
END_TEST

static void check_generated_query(int cd) {
  struct dns_header *h = (struct dns_header *)daemon->packet;
  unsigned char *p, *udp;
  unsigned short type, class, flags;
  size_t len;

  len = dnssec_generate_query(h, daemon->packet_buff_sz, (char *)"Example.com",
                              C_IN, 0x4321, T_DS);

  ck_assert_uint_eq(ntohs(h->id), 0x4321);
  ck_assert_uint_eq(ntohs(h->qdcount), 1);
  ck_assert_uint_eq(ntohs(h->ancount), 0);
  ck_assert_uint_eq(ntohs(h->nscount), 0);
  ck_assert(h->hb3 & HB3_RD);
  ck_assert(!(h->hb3 & HB3_QR));
  ck_assert_int_eq(!!(h->hb4 & HB4_CD), cd);

  p = (unsigned char *)(h + 1);
  ck_assert_mem_eq(p, "\7Example\3com\0", 13);
  p += 13;
  GETSHORT(type, p);
  GETSHORT(class, p);
  ck_assert_uint_eq(type, T_DS);
  ck_assert_uint_eq(class, C_IN);

  /* With the DO bit. */
  ck_assert_ptr_nonnull(find_pseudoheader(h, len, NULL, &udp, NULL, NULL));
  udp += 4;
  GETSHORT(flags, udp);
  ck_assert_uint_eq(flags, 0x8000);
}

START_TEST(test_generate_query) { check_generated_query(0); }
END_TEST

START_TEST(test_generate_query_debug) {
  static const char *const args[] = {"--dnssec-debug", NULL};

  test_daemon_init(args);
  check_generated_query(1);
}
END_TEST

START_TEST(test_trust_anchor_option) {
  static const char *const args[] = {
      "--trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D084"
      "58E880409BBC683457104237C7F8EC8D",
      "--trust-anchor=example.com,CH,12345,13,2,AB cd 01", NULL};
  struct ds_config *ds;

  test_daemon_init(args);

  /* Most recent first. */
  ds = daemon->ds;
  ck_assert_ptr_nonnull(ds);
  ck_assert_str_eq(ds->name, "example.com");
  ck_assert_int_eq(ds->class, C_CHAOS);
  ck_assert_int_eq(ds->keytag, 12345);
  ck_assert_int_eq(ds->algo, 13);
  ck_assert_int_eq(ds->digest_type, 2);
  ck_assert_int_eq(ds->digestlen, 3);
  ck_assert_mem_eq(ds->digest, "\xab\xcd\x01", 3);

  ds = ds->next;
  ck_assert_ptr_nonnull(ds);
  ck_assert_str_eq(ds->name, "");
  ck_assert_int_eq(ds->class, C_IN);
  ck_assert_int_eq(ds->keytag, 20326);
  ck_assert_int_eq(ds->algo, 8);
  ck_assert_int_eq(ds->digest_type, 2);
  ck_assert_int_eq(ds->digestlen, sizeof(root_ksk_ds) - 1);
  ck_assert_mem_eq(ds->digest, root_ksk_ds, sizeof(root_ksk_ds) - 1);
  ck_assert_ptr_null(ds->next);
}
END_TEST

START_TEST(test_trust_anchor_bad_hex) {
  static const char *const args[] = {"--trust-anchor=.,20326,8,2,E06DXX", NULL};

  test_daemon_init(args);
}
END_TEST

START_TEST(test_trust_anchor_bad_keytag) {
  static const char *const args[] = {"--trust-anchor=.,70000,8,2,E06D", NULL};

  test_daemon_init(args);
}
END_TEST

static void add_validation_tests(TCase *tc) {
  tcase_add_test(tc, test_dnskey_validated_by_trust_anchor);
  tcase_add_test(tc, test_dnskey_bad_signature);
  tcase_add_test(tc, test_dnskey_unsigned);
  tcase_add_test(tc, test_dnskey_not_trust_anchor);
  tcase_add_test(tc, test_dnskey_not_zone_key);
  tcase_add_test(tc, test_dnskey_need_ds);
  tcase_add_test(tc, test_answer_secure);
  tcase_add_test(tc, test_answer_canonical_order);
  tcase_add_test(tc, test_answer_compressed_name);
  tcase_add_test(tc, test_answer_tampered);
  tcase_add_test(tc, test_answer_unsigned_need_ds);
  tcase_add_test(tc, test_answer_unsigned);
  tcase_add_test(tc, test_answer_need_key);
  tcase_add_test(tc, test_answer_signer_not_parent);
  tcase_add_test(tc, test_answer_sig_expired);
  tcase_add_test(tc, test_answer_sig_not_yet_valid);
  tcase_add_test(tc, test_answer_ttl_capped_by_sig);
  tcase_add_test(tc, test_answer_crypto_limit);
  tcase_add_test(tc, test_answer_servfail);
  tcase_add_test(tc, test_secure_delegation);
  tcase_add_test(tc, test_ds_bad_signature);
  tcase_add_test(tc, test_dnskey_not_matching_ds);
  tcase_add_test(tc, test_insecure_delegation);
  tcase_add_test(tc, test_no_ds_not_zone_cut);
  tcase_add_test(tc, test_ds_unsigned_denial);
  tcase_add_test(tc, test_nodata_proof);
  tcase_add_test(tc, test_nodata_type_in_bitmap);
  tcase_add_test(tc, test_nodata_no_nsec);
  tcase_add_test(tc, test_nxdomain_proof);
  tcase_add_test(tc, test_wildcard_answer);
  tcase_add_test(tc, test_unsigned_nsec);
}

#endif /* HAVE_DNSSEC */

Suite *dnssec_suite(void) {
  Suite *s = suite_create("dnssec");
#ifdef HAVE_DNSSEC
  TCase *tc = tcase_create("ed25519");

  tcase_add_checked_fixture(tc, ed25519_setup, NULL);
  add_validation_tests(tc);
  suite_add_tcase(s, tc);

  tc = tcase_create("ecdsa");
  tcase_add_checked_fixture(tc, ecdsa_setup, NULL);
  add_validation_tests(tc);
  suite_add_tcase(s, tc);

  tc = tcase_create("crypto");
  tcase_add_checked_fixture(tc, crypto_setup, NULL);
  tcase_add_test(tc, test_root_ksk);
  tcase_add_test(tc, test_keytag_rsamd5);
  tcase_add_test(tc, test_supported_algorithms);
  tcase_add_test(tc, test_errflags_to_ede);
  tcase_add_test(tc, test_generate_query);
  suite_add_tcase(s, tc);

  tc = tcase_create("options");
  tcase_add_test(tc, test_generate_query_debug);
  tcase_add_test(tc, test_trust_anchor_option);
  tcase_add_exit_test(tc, test_trust_anchor_bad_hex, EC_BADCONF);
  tcase_add_exit_test(tc, test_trust_anchor_bad_keytag, EC_BADCONF);
  suite_add_tcase(s, tc);
#endif

  return s;
}
