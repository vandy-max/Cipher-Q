"""Focused cryptographic tests for the simple direct-message path."""
import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.routers.direct_messages import _aad, _unwrap_dek, _wrap_dek
from security.keyring import Keyring


def _doc_for(message_id, sender_id, recipient_id, created, expires, kid, dek, kr):
    sender_nonce, sender_wrapped = _wrap_dek(kr, kid, message_id, sender_id, dek)
    recipient_nonce, recipient_wrapped = _wrap_dek(kr, kid, message_id, recipient_id, dek)
    return {
        "_id": message_id, "sender_user_id": sender_id, "recipient_user_id": recipient_id,
        "created_ts": created, "expires_ts": expires, "kid": kid,
        "sender_wrap_nonce": sender_nonce, "sender_wrapped_dek": sender_wrapped,
        "recipient_wrap_nonce": recipient_nonce, "recipient_wrapped_dek": recipient_wrapped,
    }


def test_sender_and_recipient_can_unwrap_the_same_message_dek():
    kr = Keyring({1: os.urandom(32)}, 1)
    dek = os.urandom(32)
    doc = _doc_for("msg_test_123", 10, 20, 1000, 2000, 1, dek, kr)
    assert _unwrap_dek(kr, doc, 10) == dek
    assert _unwrap_dek(kr, doc, 20) == dek


def test_nonparticipant_cannot_unwrap_message_dek():
    kr = Keyring({1: os.urandom(32)}, 1)
    dek = os.urandom(32)
    doc = _doc_for("msg_test_456", 10, 20, 1000, 2000, 1, dek, kr)
    with pytest.raises(Exception):
        _unwrap_dek(kr, doc, 30)


def test_message_ciphertext_is_bound_to_sender_recipient_and_expiry():
    kr = Keyring({1: os.urandom(32)}, 1)
    dek = os.urandom(32)
    aad = _aad("msg_test_789", 10, 20, 1000, 2000, 1)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, b"hello", aad)
    assert AESGCM(dek).decrypt(nonce, ciphertext, aad) == b"hello"
    with pytest.raises(InvalidTag):
        AESGCM(dek).decrypt(nonce, ciphertext, _aad("msg_test_789", 10, 21, 1000, 2000, 1))
    with pytest.raises(InvalidTag):
        AESGCM(dek).decrypt(nonce, ciphertext, _aad("msg_test_789", 10, 20, 1000, 3000, 1))
