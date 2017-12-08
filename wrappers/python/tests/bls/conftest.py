from indy_crypto.bls import Bls, Generator, SignKey, VerKey, Signature, MultiSignature

import pytest


@pytest.fixture
def generator() -> Generator:
    gen = Generator.new()

    assert type(gen) is Generator
    assert gen.c_instance is not None
    return gen


@pytest.fixture
def sign_key1() -> SignKey:
    sign_key = SignKey.new(None)

    assert type(sign_key) is SignKey
    assert sign_key.c_instance is not None
    return sign_key


@pytest.fixture
def sign_key2() -> SignKey:
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                  11, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                  21, 2, 3, 4, 5, 6, 7, 8, 9, 10, 31, 32])
    sign_key = SignKey.new(seed)

    assert type(sign_key) is SignKey
    assert sign_key.c_instance is not None
    return sign_key


@pytest.fixture
def ver_key1(generator: Generator, sign_key1: SignKey) -> VerKey:
    ver_key = VerKey.new(generator, sign_key1)

    assert type(ver_key) is VerKey
    assert ver_key.c_instance is not None
    return ver_key


@pytest.fixture
def ver_key2(generator: Generator, sign_key2: SignKey) -> VerKey:
    ver_key = VerKey.new(generator, sign_key2)

    assert type(ver_key) is VerKey
    assert ver_key.c_instance is not None
    return ver_key


@pytest.fixture
def message() -> bytes:
    return bytes([1, 2, 3, 4, 5])


@pytest.fixture
def signature1(message: bytes, sign_key1: SignKey) -> Signature:
    signature = Bls.sign(message, sign_key1)

    assert type(signature) is Signature
    assert signature.c_instance is not None
    return signature


@pytest.fixture
def signature2(message: bytes, sign_key2: SignKey) -> Signature:
    signature = Bls.sign(message, sign_key2)

    assert type(signature) is Signature
    assert signature.c_instance is not None
    return signature


@pytest.fixture
def multi_sig(signature1: Signature, signature2: Signature) -> MultiSignature:
    multi_sig = MultiSignature.new([signature1, signature2])

    assert type(multi_sig) is MultiSignature
    assert multi_sig.c_instance is not None
    return multi_sig
