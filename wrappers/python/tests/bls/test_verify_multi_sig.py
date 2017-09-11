from indy_crypto import bls


def test_verify__multi_sig_works(generator, message, multi_sig, keys1, keys2):
    _, ver_key1 = keys1
    _, ver_key2 = keys2

    valid = bls.verify_multi_sig(multi_sig, message, [ver_key1, ver_key2], generator)
    assert valid
