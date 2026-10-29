"""Send malformed DNS and TFTP traffic, or act as a malicious upstream.

Used by security_test.sh. Standard library only, so that it runs on any
distribution's python3 (3.6 or later).

  dnstool.py probe PORT SCENARIO [--tcp]
      Send one crafted query to 127.0.0.1#PORT and print "noreply", or
      "rcode=NAME an=COUNT" describing the reply.

  dnstool.py fuzz PORT COUNT SEED
      Send COUNT random and mutated queries over UDP, and a few over TCP.
      Replies are not checked; the caller checks dnsmasq survived.

  dnstool.py tcp PORT SCENARIO
      Misbehave on a TCP connection; print "closed" or "reply".

  dnstool.py hold PORT COUNT SECONDS
      Open COUNT TCP connections, send nothing, and keep them open.

  dnstool.py upstream PORT LOGFILE
      Serve as a malicious upstream on 127.0.0.1#PORT. How it answers
      depends on the first label of the question; see UPSTREAM below.
      Each question received is appended to LOGFILE.

  dnstool.py tftp SCENARIO
      Send a malformed TFTP request to 127.0.0.1#69 and print the error
      message, or "noreply" or "data". SCENARIO "read:FILE" requests FILE.
"""

import random
import socket
import struct
import sys
import time

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def header(qid=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def name(n):
    out = b""
    for label in n.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def question(n, qtype=1, qclass=1):
    return name(n) + struct.pack("!HH", qtype, qclass)


def rr(owner, rtype, rdata, ttl=300, rclass=1, rdlen=None):
    if rdlen is None:
        rdlen = len(rdata)
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, rdlen) + rdata


def opt_rr(payload=1232, rdlen=0, rdata=b""):
    return b"\0" + struct.pack("!HHIH", 41, payload, 0, rdlen) + rdata


A = lambda ip: socket.inet_aton(ip)
# A public address, so --stop-dns-rebind accepts it. (The documentation
# ranges count as private.)
GOOD = "1.2.3.4"
QPTR = b"\xc0\x0c"  # Compression pointer to the question name.

# Crafted client queries. All of them are bad, apart from "valid".
PROBES = {
    "valid": header() + question("probe.test"),
    "empty": b"",
    "short-header": header()[:7],
    "header-only": header(),
    "qdcount-huge": header(qd=0xffff) + question("probe.test"),
    "qdcount-zero": header(qd=0),
    "qdcount-two": header(qd=2) + question("a.test") + question("b.test"),
    "label-overrun": header() + b"\x3fshort",
    "no-terminator": header() + b"\x05probe\x04test",
    "pointer-self": header() + b"\xc0\x0c\x00\x01\x00\x01",
    "pointer-loop": header() + b"\x01a\xc0\x0e\x00\x01\x00\x01",
    "pointer-oob": header() + b"\xc0\xff\x00\x01\x00\x01",
    "pointer-into-header": header() + b"\xc0\x02\x00\x01\x00\x01",
    "extended-label": header() + b"\x41abc\x00\x00\x01\x00\x01",
    "name-too-long": header() +
        b"".join(b"\x3f" + b"a" * 63 for _ in range(5)) + b"\0\0\1\0\1",
    "missing-qtype": header() + name("probe.test"),
    # A single label "probe.test", which mustn't be confused with the
    # two-label name.
    "dot-in-label": header() + b"\x0aprobe.test\x00\x00\x01\x00\x01",
    # "probe" "test\0evil", which is "probe.test" if truncated at the NUL.
    "nul-in-label": header() + b"\x05probe\x09test\x00evil\x00\x00\x01\x00\x01",
    "response-bit": header(flags=0x8100) + question("probe.test"),
    "bad-opcode": header(flags=0x7900) + question("probe.test"),
    "opt-overrun": header(ar=1) + question("probe.test") +
        opt_rr(rdlen=0xffff),
    "opt-bad-option": header(ar=1) + question("probe.test") +
        opt_rr(rdlen=4, rdata=struct.pack("!HH", 8, 0xfff0)),
    "opt-twice": header(ar=2) + question("probe.test") + opt_rr() + opt_rr(),
    "opt-tiny-payload": header(ar=1) + question("probe.test") +
        opt_rr(payload=1),
    "arcount-lies": header(an=0xffff, ns=0xffff, ar=0xffff) +
        question("probe.test"),
    "trailing-garbage": header() + question("probe.test") + b"\xff" * 2000,
    "max-udp": header() + question("probe.test") + b"\0" * 65000,
}


def skip_name(pkt, pos):
    while True:
        n = pkt[pos]
        if n & 0xc0 == 0xc0:
            return pos + 2
        if n == 0:
            return pos + 1
        pos += n + 1


def first_a(pkt):
    """The first A record in the answer section, or None."""
    try:
        qd, an = struct.unpack("!HH", pkt[4:8])
        pos = 12
        for _ in range(qd):
            pos = skip_name(pkt, pos) + 4
        for _ in range(an):
            pos = skip_name(pkt, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", pkt[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(pkt[pos:pos + 4])
            pos += rdlen
    except (IndexError, struct.error):
        pass
    return None


def describe(reply):
    if reply is None:
        return "noreply"
    if len(reply) < 12:
        return "short-reply"
    flags, an = struct.unpack("!HH", reply[2:4] + reply[6:8])
    out = "rcode=%s an=%d" % (RCODES.get(flags & 0xf, flags & 0xf), an)
    a = first_a(reply)
    return out + (" a=" + a if a else "")


def udp_exchange(port, data, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(data, ("127.0.0.1", port))
        return s.recv(65535)
    except socket.timeout:
        return None
    finally:
        s.close()


def tcp_exchange(port, data, timeout=2.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(struct.pack("!H", len(data)) + data)
        hdr = s.recv(2)
        if len(hdr) < 2:
            return None
        want = struct.unpack("!H", hdr)[0]
        buf = b""
        while len(buf) < want:
            chunk = s.recv(want - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf
    except (socket.timeout, ConnectionError):
        return None
    finally:
        s.close()


def cmd_probe(port, scenario, tcp=False):
    data = PROBES[scenario]
    if tcp:
        print(describe(tcp_exchange(port, data)))
    else:
        print(describe(udp_exchange(port, data)))


def mutate(rng, pkt):
    pkt = bytearray(pkt)
    for _ in range(rng.randint(1, 8)):
        op = rng.randint(0, 3)
        if op == 0 and pkt:
            pkt[rng.randrange(len(pkt))] = rng.randrange(256)
        elif op == 1 and pkt:
            del pkt[rng.randrange(len(pkt)):]
        elif op == 2:
            pos = rng.randint(0, len(pkt))
            pkt[pos:pos] = bytes(rng.randrange(256)
                                 for _ in range(rng.randint(1, 16)))
        else:
            # Compression pointers are the classic trouble spot.
            pos = rng.randint(12, max(12, len(pkt)))
            pkt[pos:pos] = bytes([0xc0, rng.randrange(256)])
    return bytes(pkt)


def cmd_fuzz(port, count, seed):
    rng = random.Random(seed)
    seeds = [p for p in PROBES.values() if len(p) < 4096]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        if rng.random() < 0.1:
            pkt = bytes(rng.randrange(256) for _ in range(rng.randint(0, 600)))
        else:
            pkt = mutate(rng, rng.choice(seeds))
        if i % 100 == 0:
            try:
                tcp_exchange(port, pkt, timeout=0.5)
            except OSError:
                pass
        else:
            s.sendto(pkt, ("127.0.0.1", port))
        if i % 50 == 0:
            time.sleep(0.01)  # Don't just overflow the socket buffer.
    s.close()
    print("sent %d" % count)


def cmd_tcp(port, scenario):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
    except OSError as e:
        print("connect failed: %s" % e)
        return
    try:
        if scenario == "zero-length":
            s.sendall(b"\0\0")
        elif scenario == "short-body":
            s.sendall(b"\0\x64" + PROBES["valid"])
            s.shutdown(socket.SHUT_WR)
        elif scenario == "huge-length":
            s.sendall(b"\xff\xff" + PROBES["valid"])
            s.shutdown(socket.SHUT_WR)
        elif scenario == "half-length":
            s.sendall(b"\0")
            s.shutdown(socket.SHUT_WR)
        elif scenario == "pipeline-bad-then-good":
            bad = PROBES["pointer-loop"]
            good = PROBES["valid"]
            s.sendall(struct.pack("!H", len(bad)) + bad +
                      struct.pack("!H", len(good)) + good)
        try:
            data = s.recv(65535)
        except socket.timeout:
            print("timeout")
            return
        print("reply" if data else "closed")
    finally:
        s.close()


def cmd_hold(port, count, seconds):
    socks = []
    for _ in range(count):
        try:
            socks.append(socket.create_connection(("127.0.0.1", port),
                                                  timeout=2))
        except OSError:
            break
    print("open %d" % len(socks))
    sys.stdout.flush()
    time.sleep(seconds)
    for s in socks:
        s.close()


#
# Malicious upstream.
#

def parse_question(pkt):
    """Return (qname, raw question bytes) from a query."""
    pos, labels = 12, []
    while pkt[pos]:
        n = pkt[pos]
        labels.append(pkt[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += n + 1
    return ".".join(labels), pkt[12:pos + 5]


def upstream_reply(pkt, rng):
    qid = struct.unpack("!H", pkt[:2])[0]
    qname, rawq = parse_question(pkt)
    first = qname.split(".")[0].lower()
    ok = 0x8180  # QR, RD, RA, NOERROR

    def answer(*records, flags=ok, an=None, ar=0, extra=b"", qd=rawq,
               rid=qid):
        an = len(records) if an is None else an
        return header(rid, flags, 1 if qd else 0, an, 0, ar) + qd + \
            b"".join(records) + extra

    good = rr(QPTR, 1, A(GOOD))

    if first == "wrongid":
        return answer(good, rid=qid ^ 0xffff)
    if first == "wrongq":
        return answer(good, qd=question("other.test"))
    if first == "wrongcase":
        return answer(good, qd=rawq.lower() if rawq != rawq.lower()
                      else rawq.upper())
    if first == "noquestion":
        return answer(good, qd=b"")
    if first == "inject":
        # Unrelated records in the answer and additional sections, the
        # classic Kaminsky-style cache poisoning attempt.
        return answer(good, rr(name("victim.test"), 1, A("6.6.6.6")),
                      ar=1, extra=rr(name("victim2.test"), 1, A("6.6.6.6")))
    if first == "private":
        return answer(rr(QPTR, 1, A("192.168.0.66")))
    if first == "loopback":
        return answer(rr(QPTR, 1, A("127.0.0.1")))
    if first == "mapped":
        return answer(rr(QPTR, 28, socket.inet_pton(
            socket.AF_INET6, "::ffff:10.0.0.1")))
    if first == "ptrloop":
        # Answer owner name is a compression pointer to itself.
        here = 12 + len(rawq)
        return answer(rr(struct.pack("!H", 0xc000 | here), 1,
                         A(GOOD)))
    if first == "rdoverrun":
        return answer(rr(QPTR, 1, A(GOOD), rdlen=0xffff))
    if first == "rdshort":
        return answer(rr(QPTR, 1, b"\xcb\x00", rdlen=4))
    if first == "badalen":
        return answer(rr(QPTR, 1, b"\xcb\x00\x71\x01\x01\x01"))
    if first == "ancountlies":
        return answer(good, an=500)
    if first == "cnameloop":
        a, b = name("loop-a." + qname), name("loop-b." + qname)
        return answer(rr(QPTR, 5, a), rr(a, 5, b), rr(b, 5, a))
    if first == "cnamechain":
        recs, prev = [], QPTR
        for i in range(60):
            nxt = name("c%d.%s" % (i, qname))
            recs.append(rr(prev, 5, nxt))
            prev = nxt
        recs.append(rr(prev, 1, A(GOOD)))
        return answer(*recs)
    if first == "hugettl":
        return answer(rr(QPTR, 1, A(GOOD), ttl=0xffffffff))
    if first == "manyanswers":
        return answer(*[rr(QPTR, 1, A("1.2.3.%d" % (i % 250 + 1)))
                        for i in range(4000)])
    if first == "garbage":
        return struct.pack("!H", qid) + bytes(
            rng.randrange(256) for _ in range(rng.randint(0, 600)))
    if first == "headeronly":
        return header(qid, ok, 0, 0, 0, 0)
    if first == "notaresponse":
        return answer(good, flags=0x0100)
    return answer(good)


def cmd_upstream(port, logfile):
    rng = random.Random(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    log = open(logfile, "a")
    while True:
        pkt, addr = s.recvfrom(65535)
        try:
            qname, _ = parse_question(pkt)
        except (IndexError, UnicodeError):
            continue
        log.write(qname.lower() + "\n")
        log.flush()
        reply = upstream_reply(pkt, rng)
        # Oversized replies go out anyway; a real attacker isn't bound
        # by the requester's EDNS buffer size.
        s.sendto(reply[:65507], addr)


#
# TFTP.
#

def cmd_tftp(scenario):
    if scenario.startswith("read:"):
        # Read request for an arbitrary filename.
        pkts = {scenario: b"\0\1" + scenario[5:].encode() + b"\0octet\0"}
    else:
        pkts = {}
    pkts.update({
        "absolute-path": b"\0\1/etc/passwd\0octet\0",
        "dotdot": b"\0\1../../../../../../etc/passwd\0octet\0",
        "no-terminator": b"\0\1pxelinux.0",
        "no-mode": b"\0\1pxelinux.0\0",
        "bad-mode": b"\0\1pxelinux.0\0nonsense\0",
        "long-name": b"\0\1" + b"a" * 1400 + b"\0octet\0",
        "bad-opcode": b"\0\x09pxelinux.0\0octet\0",
        "write-request": b"\0\2upload\0octet\0",
        "bad-blksize": b"\0\1pxelinux.0\0octet\0blksize\0" +
            b"9" * 40 + b"\0",
        "empty": b"",
    })
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    s.sendto(pkts[scenario], ("127.0.0.1", 69))
    try:
        reply = s.recv(65535)
    except socket.timeout:
        print("noreply")
        return
    op = struct.unpack("!H", reply[:2])[0]
    if op == 5:
        print("error: " + reply[4:].rstrip(b"\0").decode("ascii", "replace"))
    else:
        print("data")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "probe":
        cmd_probe(int(args[0]), args[1], "--tcp" in args)
    elif cmd == "fuzz":
        cmd_fuzz(int(args[0]), int(args[1]), int(args[2]))
    elif cmd == "tcp":
        cmd_tcp(int(args[0]), args[1])
    elif cmd == "hold":
        cmd_hold(int(args[0]), int(args[1]), float(args[2]))
    elif cmd == "upstream":
        cmd_upstream(int(args[0]), args[1])
    elif cmd == "tftp":
        cmd_tftp(args[0])
    else:
        sys.exit("unknown command " + cmd)


if __name__ == "__main__":
    main()
