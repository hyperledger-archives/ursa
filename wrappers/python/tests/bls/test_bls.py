from indy_crypto.bls import Bls, Generator, SignKey, VerKey, Signature, MultiSignature


def test_sign(signature1: Signature):
    assert signature1 is not None


def test_sign_for_seed(signature2: Signature):
    assert signature2 is not None


def test_sign_pop(signature_pop: Signature):
    assert signature_pop is not None


def test_verify(generator: Generator, message: bytes, ver_key1: VerKey, signature1: Signature):
    valid = Bls.verify(signature1, message, ver_key1, generator)
    assert valid


def test_verify_pop(generator: Generator, message: bytes, ver_key1: VerKey, signature_pop: Signature):
    valid = Bls.verify_pop(signature_pop, message, ver_key1, generator)
    assert valid


def test_verify_for_seed(generator: Generator, message: bytes, ver_key2: VerKey, signature2: Signature):
    valid = Bls.verify(signature2, message, ver_key2, generator)
    assert valid


def test_verify__multi_sig_works(generator: Generator, message: bytes, multi_sig: MultiSignature,
                                 ver_key1: VerKey, ver_key2: VerKey):
    valid = Bls.verify_multi_sig(multi_sig, message, [ver_key1, ver_key2], generator)
    assert valid


def test_verify_multi_sig_works_for_invalid_signature(generator, message):
    sign_key1 = SignKey.new(None)
    ver_key1 = VerKey.new(generator, sign_key1)

    sign_key2 = SignKey.new(None)
    ver_key2 = VerKey.new(generator, SignKey.new(None))

    signature1 = Bls.sign(message, sign_key1)
    signature2 = Bls.sign(message, sign_key2)
    multi_signature_invalid = MultiSignature.new([signature1, signature2])

    valid = Bls.verify_multi_sig(multi_signature_invalid, message, [ver_key1, ver_key2], generator)
    assert not valid
