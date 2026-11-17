"""Secure Chat Demo (SC1) - DEMO EDUKASI, bukan untuk produksi.

Key confirmation: implisit, yaitu tag AES-GCM valid pada pesan data pertama.

Handshake: X25519 (ephemeral) + Ed25519 (tanda tangan identitas)
Derivasi kunci: HKDF-SHA256 dengan transcript hash
Enkripsi pesan: AES-256-GCM dengan hash ratchet (counter)
"""
import hashlib
import hmac as _stdlib_hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUITE = b"X25519+Ed25519+AES256GCM"


# ---------- Utilitas ----------
def enc(*parts: bytes) -> bytes:
    """Encoding tak-ambigu: setiap bagian diawali panjang 2 byte."""
    for p in parts:
        if len(p) > 0xFFFF:
            raise ValueError("bagian terlalu panjang")
    return b"".join(len(p).to_bytes(2, "big") + p for p in parts)


def raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def hmac32(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# ---------- Pesan handshake ----------
def hello_msg(id_a, id_b, epk_a, n_a):
    return enc(b"SC1-HELLO", SUITE, id_a, id_b, epk_a, n_a)


def reply_msg(id_b, id_a, epk_b, n_b, m1):
    return enc(b"SC1-REPLY", SUITE, id_b, id_a, epk_b, n_b, hashlib.sha256(m1).digest())


def derive_keys(z, n_a, n_b, transcript):
    th = hashlib.sha256(transcript).digest()

    def kdf(label):
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=n_a + n_b, info=label + th
        ).derive(z)

    return {
        "a2b": kdf(b"SC1 A->B"),
        "b2a": kdf(b"SC1 B->A"),
        "sid": th,
    }


# ---------- Handshake ----------
def a_start(ik_sk_a, id_a, id_b):
    esk_a = X25519PrivateKey.generate()
    epk_a, n_a = raw(esk_a.public_key()), os.urandom(16)
    m1 = hello_msg(id_a, id_b, epk_a, n_a)
    return esk_a, (id_a, id_b, epk_a, n_a, ik_sk_a.sign(m1))


def b_respond(ik_sk_b, ik_pk_a, id_b, hello, seen_nonces=None):
    id_a, id_b_in, epk_a, n_a, sig1 = hello
    if id_b_in != id_b:  # sengaja bukan assert (assert hilang dengan python -O)
        raise ValueError("identitas penerima tidak cocok")
    m1 = hello_msg(id_a, id_b, epk_a, n_a)
    ik_pk_a.verify(sig1, m1)
    # n_A dicatat hanya SETELAH tanda tangan valid, agar cache tidak bisa dibanjiri nonce sampah
    if seen_nonces is not None:
        if n_a in seen_nonces:
            raise ValueError("hello replay: n_A sudah pernah dilihat")
        seen_nonces.add(n_a)
    esk_b = X25519PrivateKey.generate()
    epk_b, n_b = raw(esk_b.public_key()), os.urandom(16)
    m2 = reply_msg(id_b, id_a, epk_b, n_b, m1)
    z = esk_b.exchange(X25519PublicKey.from_public_bytes(epk_a))
    return derive_keys(z, n_a, n_b, m1 + m2), (epk_b, n_b, ik_sk_b.sign(m2))


def a_finish(ik_pk_b, esk_a, id_a, id_b, hello, reply):
    _, _, epk_a, n_a, _ = hello
    epk_b, n_b, sig2 = reply
    m1 = hello_msg(id_a, id_b, epk_a, n_a)
    m2 = reply_msg(id_b, id_a, epk_b, n_b, m1)
    ik_pk_b.verify(sig2, m2)
    z = esk_a.exchange(X25519PublicKey.from_public_bytes(epk_b))
    return derive_keys(z, n_a, n_b, m1 + m2)


# ---------- Enkripsi pesan ----------
class Chain:
    def __init__(self, ck, sid, id_from, id_to):
        self.ck, self.n = ck, 0
        self.sid, self.id_from, self.id_to = sid, id_from, id_to

    def _aad(self, n):
        return enc(self.sid, self.id_from, self.id_to, n.to_bytes(8, "big"))

    def _advance(self):
        self.ck = hmac32(self.ck, b"\x02")
        self.n += 1

    def seal(self, plaintext):
        n, mk = self.n, hmac32(self.ck, b"\x01")
        ct = AESGCM(mk).encrypt(n.to_bytes(12, "big"), plaintext, self._aad(n))
        self._advance()
        return n, ct

    def open(self, n, ct):
        if n != self.n:
            raise ValueError("counter tidak sesuai (replay/reorder)")
        mk = hmac32(self.ck, b"\x01")
        pt = AESGCM(mk).decrypt(n.to_bytes(12, "big"), ct, self._aad(n))
        self._advance()  # hanya maju jika tag valid
        return pt


def safety_number(pk_a: bytes, pk_b: bytes) -> str:
    """60 digit (12 kelompok x 5 digit), urutan kunci tidak berpengaruh."""
    h = hashlib.sha512(b"SC1-SAFETY" + b"".join(sorted([pk_a, pk_b]))).digest()
    chunks = [int.from_bytes(h[i : i + 5], "big") % 100000 for i in range(0, 60, 5)]
    return " ".join(f"{c:05d}" for c in chunks)


# ---------- Demo ----------
def demo_handshake():
    print("== Handshake & pesan ==")
    ik_a, ik_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    esk_a, hello = a_start(ik_a, b"alice", b"bob")
    keys_b, reply = b_respond(ik_b, ik_a.public_key(), b"bob", hello)
    keys_a = a_finish(ik_b.public_key(), esk_a, b"alice", b"bob", hello, reply)
    assert keys_a == keys_b
    print("handshake sukses (key confirmation = tag valid pada pesan data pertama)")

    send = Chain(keys_a["a2b"], keys_a["sid"], b"alice", b"bob")
    recv = Chain(keys_b["a2b"], keys_b["sid"], b"alice", b"bob")
    n, ct = send.seal(b"halo bob")
    print(recv.open(n, ct))
    n2, ct2 = send.seal(b"pesan 2")
    print(recv.open(n2, ct2))

    try:
        recv.open(n, ct)
    except ValueError as e:
        print("replay ditolak:", e)

    seen = set()
    b_respond(ik_b, ik_a.public_key(), b"bob", hello, seen)
    try:
        b_respond(ik_b, ik_a.public_key(), b"bob", hello, seen)  # M1 lama dikirim ulang
    except ValueError as e:
        print("replay handshake ditolak:", e)

    mitm = X25519PrivateKey.generate()
    bad = (hello[0], hello[1], raw(mitm.public_key()), hello[3], hello[4])
    try:
        b_respond(ik_b, ik_a.public_key(), b"bob", bad)
    except Exception as e:
        print("MITM ditolak:", type(e).__name__)

    n3, ct3 = send.seal(b"pesan 3")
    tampered = bytes([ct3[0] ^ 1]) + ct3[1:]
    try:
        recv.open(n3, tampered)
    except InvalidTag:
        print("ciphertext diubah -> InvalidTag (ditolak)")
    print(recv.open(n3, ct3), "(paket asli masih diterima)")

    print("safety number:", safety_number(raw(ik_a.public_key()), raw(ik_b.public_key())))

    print("\n== Batas jaminan: IK palsu yang dipercaya ==")
    eve_ik = Ed25519PrivateKey.generate()
    _, hello_e = a_start(eve_ik, b"alice", b"bob")
    b_respond(ik_b, eve_ik.public_key(), b"bob", hello_e)
    print("Bob mem-pin IK Eve -> handshake sukses (tanpa verifikasi safety number)")
    same = safety_number(raw(ik_a.public_key()), raw(ik_b.public_key())) == safety_number(
        raw(eve_ik.public_key()), raw(ik_b.public_key())
    )
    print("safety number sama dengan yang asli:", same)


def experiments():
    print("\n== HKDF: pemisahan konteks ==")
    master = os.urandom(32)

    def derive(info):
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"demo-salt", info=info
        ).derive(master)

    k_chat, k_pay, k_chat2 = derive(b"app/chat/v1"), derive(b"app/payment/v1"), derive(b"app/chat/v1")
    print("konteks beda -> kunci beda:", k_chat != k_pay, "| input sama -> kunci sama:", k_chat == k_chat2)

    print("\n== X25519: shared secret sama ==")
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    print("secret_a == secret_b:", a.exchange(b.public_key()) == b.exchange(a.public_key()))

    print("\n== AES-GCM: kunci salah, ciphertext diubah, AAD beda ==")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"pesan", b"aad-1")
    print("kunci benar:", AESGCM(key).decrypt(nonce, ct, b"aad-1"))
    cases = [
        ("kunci salah", lambda: AESGCM(AESGCM.generate_key(256)).decrypt(nonce, ct, b"aad-1")),
        ("ciphertext diubah", lambda: AESGCM(key).decrypt(nonce, bytes([ct[0] ^ 1]) + ct[1:], b"aad-1")),
        ("AAD beda", lambda: AESGCM(key).decrypt(nonce, ct, b"aad-2")),
    ]
    for name, fn in cases:
        try:
            fn()
            print(name, "-> LOLOS (tidak seharusnya)")
        except InvalidTag:
            print(name, "-> InvalidTag")

    print("\n== Forward secrecy (dua sesi, IK tetap) ==")
    ik_a, ik_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    sess = []
    for _ in range(2):
        esk, h = a_start(ik_a, b"alice", b"bob")
        kb, r = b_respond(ik_b, ik_a.public_key(), b"bob", h)
        ka = a_finish(ik_b.public_key(), esk, b"alice", b"bob", h, r)
        assert ka == kb
        sess.append(ka)
    print("K1 != K2:", sess[0]["a2b"] != sess[1]["a2b"], "| session id beda:", sess[0]["sid"] != sess[1]["sid"])

    print("\n== Zeroization: batasan Python ==")
    buf = bytearray(os.urandom(16))
    for i in range(len(buf)):
        buf[i] = 0
    print("bytearray ditimpa:", all(x == 0 for x in buf))
    secret = os.urandom(16)
    alias = secret
    del secret
    print("setelah del, alias masih memegang bytes:", len(alias) == 16)


def main():
    demo_handshake()
    experiments()


if __name__ == "__main__":
    main()
