# Independent MSE (BitTorrent protocol encryption) responder written from the spec,
# used to check torrentide's initiator. Accepts one connection, prints what happened.
import hashlib, os, socket, sys
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
def h(*p): return hashlib.sha1(b"".join(p)).digest()
class RC4:
    def __init__(s, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
        s.S, s.i, s.j = S, 0, 0
        s.crypt(bytes(1024))
    def crypt(s, data):
        out = bytearray(); S = s.S
        for b in data:
            s.i = (s.i + 1) & 255; s.j = (s.j + S[s.i]) & 255; S[s.i], S[s.j] = S[s.j], S[s.i]
            out.append(b ^ S[(S[s.i] + S[s.j]) & 255])
        return bytes(out)
def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise EOFError("closed")
        b += d
    return b
infohash = bytes.fromhex(sys.argv[2])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(1); print("listening", flush=True)
c, _ = srv.accept(); c.settimeout(10)
ya = int.from_bytes(recv_exact(c, 96), "big")
y = int.from_bytes(os.urandom(20), "big")
c.sendall(pow(2, y, P).to_bytes(96, "big") + os.urandom(7))
S = pow(ya, y, P).to_bytes(96, "big")
req1 = h(b"req1", S)
buf = b""
while req1 not in buf:
    buf += c.recv(4096)
    if len(buf) > 700: print("FAIL: req1 not found"); sys.exit(1)
buf = buf[buf.index(req1) + 20:]
buf += recv_exact(c, max(0, 20 - len(buf)))
x = bytes(a ^ b for a, b in zip(buf[:20], h(b"req3", S)))
assert x == h(b"req2", infohash), "FAIL: req2/req3 mismatch"
buf = buf[20:]
dec = RC4(h(b"keyA", S, infohash)); enc = RC4(h(b"keyB", S, infohash))
buf += recv_exact(c, max(0, 14 - len(buf)))
head = dec.crypt(buf[:14]); buf = buf[14:]
assert head[:8] == bytes(8), "FAIL: VC mismatch %r" % head[:8]
provide = int.from_bytes(head[8:12], "big"); padc = int.from_bytes(head[12:14], "big")
buf += recv_exact(c, max(0, padc + 2 - len(buf)))
dec.crypt(buf[:padc]); ialen = int.from_bytes(dec.crypt(buf[padc:padc+2]), "big"); buf = buf[padc+2:]
print("provide", provide, "ia_len", ialen, flush=True)
c.sendall(enc.crypt(bytes(8) + (2).to_bytes(4, "big") + (3).to_bytes(2, "big") + b"xyz"))
buf += recv_exact(c, max(0, ialen + 68 - len(buf)))
hs = dec.crypt(buf[ialen:ialen+68])
print("handshake ok" if hs[1:20] == b"BitTorrent protocol" and hs[28:48] == infohash else "FAIL: bad handshake %r" % hs[:20], flush=True)
c.sendall(enc.crypt(hs[:20] + bytes(8) + infohash + os.urandom(20)))
print("PASS", flush=True)
