from indy_crypto import bls


def test_verify_works(generator, message, keys1, keys2, signature1, signature2):
    _, ver_key = keys1
    valid = bls.verify(signature1, message, ver_key, generator)
    assert valid

    _, ver_key = keys2
    valid = bls.verify(signature2, message, ver_key, generator)
    assert valid
