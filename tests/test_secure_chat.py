import os
import sys

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import secure_chat_demo as sc


def handshake():
    ik_a, ik_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    esk_a, hello = sc.a_start(ik_a, b"alice", b"bob")
    keys_b, reply = sc.b_respond(ik_b, ik_a.public_key(), b"bob", hello)
    keys_a = sc.a_finish(ik_b.public_key(), esk_a, b"alice", b"bob", hello, reply)
    return ik_a, ik_b, hello, keys_a, keys_b


def chains(keys_a, keys_b):
    return (
        sc.Chain(keys_a["a2b"], keys_a["sid"], b"alice", b"bob"),
        sc.Chain(keys_b["a2b"], keys_b["sid"], b"alice", b"bob"),
    )


def test_keys_match():
    *_, keys_a, keys_b = handshake()
    assert keys_a == keys_b
    assert set(keys_a) == {"a2b", "b2a", "sid"}


def test_hello_replay_rejected_by_nonce_cache():
    ik_a, ik_b, hello, *_ = handshake()
    seen = set()
    sc.b_respond(ik_b, ik_a.public_key(), b"bob", hello, seen)
    with pytest.raises(ValueError):
        sc.b_respond(ik_b, ik_a.public_key(), b"bob", hello, seen)


def test_replayed_hello_attacker_cannot_send_valid_message():
    # tanpa cache sekalipun: Eve tidak punya esk_A, jadi tidak bisa membuat tag valid
    ik_a, ik_b, hello, *_ = handshake()
    keys_b2, _ = sc.b_respond(ik_b, ik_a.public_key(), b"bob", hello)
    recv = sc.Chain(keys_b2["a2b"], keys_b2["sid"], b"alice", b"bob")
    with pytest.raises(InvalidTag):
        recv.open(0, os.urandom(32))


def test_bad_nonce_hello_not_cached():
    ik_a, ik_b, hello, *_ = handshake()
    seen = set()
    bad = (hello[0], hello[1], hello[2], os.urandom(16), hello[4])  # tanda tangan tidak cocok
    with pytest.raises(InvalidSignature):
        sc.b_respond(ik_b, ik_a.public_key(), b"bob", bad, seen)
    assert seen == set()


def test_roundtrip_and_replay():
    *_, keys_a, keys_b = handshake()
    send, recv = chains(keys_a, keys_b)
    n, ct = send.seal(b"halo")
    assert recv.open(n, ct) == b"halo"
    with pytest.raises(ValueError):
        recv.open(n, ct)


def test_tamper_does_not_advance():
    *_, keys_a, keys_b = handshake()
    send, recv = chains(keys_a, keys_b)
    n, ct = send.seal(b"x")
    with pytest.raises(InvalidTag):
        recv.open(n, bytes([ct[0] ^ 1]) + ct[1:])
    assert recv.open(n, ct) == b"x"


def test_mitm_epk_rejected():
    ik_a, ik_b, hello, *_ = handshake()
    bad = (hello[0], hello[1], sc.raw(X25519PrivateKey.generate().public_key()), hello[3], hello[4])
    with pytest.raises(InvalidSignature):
        sc.b_respond(ik_b, ik_a.public_key(), b"bob", bad)


def test_wrong_recipient_rejected():
    ik_a, ik_b, hello, *_ = handshake()
    with pytest.raises(ValueError):
        sc.b_respond(ik_b, ik_a.public_key(), b"carol", hello)


def test_safety_number_format_and_symmetry():
    a, b = os.urandom(32), os.urandom(32)
    s = sc.safety_number(a, b)
    assert s == sc.safety_number(b, a)
    groups = s.split(" ")
    assert len(groups) == 12 and all(len(g) == 5 and g.isdigit() for g in groups)
