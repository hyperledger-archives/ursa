from indy_crypto import bls

import pytest


@pytest.fixture
def generator() -> bytes:
    gen = bls.create_generator()

    assert type(gen) is bytes
    assert len(gen) > 0

    return gen


@pytest.fixture
def keys1(generator) -> (bytes, bytes):
    sign_key, ver_key = bls.generate_keys(generator, None)

    assert type(sign_key) is bytes
    assert len(sign_key) > 0

    assert type(sign_key) is bytes
    assert len(sign_key) > 0

    return sign_key, ver_key


@pytest.fixture
def keys2(generator) -> (bytes, bytes):
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4,
                  5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8,
                  9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8])
    sign_key, ver_key = bls.generate_keys(generator, seed)

    assert type(sign_key) is bytes
    assert len(sign_key) > 0

    assert type(sign_key) is bytes
    assert len(sign_key) > 0

    return sign_key, ver_key


@pytest.fixture
def message() -> bytes:
    return bytes([1, 2, 3, 4, 5])


@pytest.fixture
def signature1(message, keys1) -> bytes:
    sign_key, ver_key = keys1
    return bls.sign(message, sign_key)


@pytest.fixture
def signature2(message, keys2) -> bytes:
    sign_key, ver_key = keys2
    return bls.sign(message, sign_key)


@pytest.fixture
def multi_sig(signature1, signature2) -> bytes:
    return bls.create_multi_signature([signature1, signature2])
