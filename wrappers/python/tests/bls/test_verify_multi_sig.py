from indy_crypto import bls


def test_verify__multi_sig_works(generator, message, multi_sig, keys1, keys2):
    _, ver_key1 = keys1
    _, ver_key2 = keys2

    valid = bls.verify_multi_sig(multi_sig, message, [ver_key1, ver_key2], generator)
    assert valid


def test_verify_multi_sig_works_for_invalid_signature():
    message = bytes([1, 2, 3, 4, 5])

    gen = bls.create_generator()

    sk1, pk1 = bls.generate_keys(gen, None)
    _, pk2 = bls.generate_keys(gen, None)
    sk2, _ = bls.generate_keys(gen, None)

    pks = [
        pk1, pk2
    ]

    signature1 = bls.sign(message, sk1)
    signature2 = bls.sign(message, sk2)

    signatures = [
        signature1,
        signature2
    ]

    multi_signature_invalud = bls.create_multi_signature(signatures)
    valid = bls.verify_multi_sig(multi_signature_invalud, message, pks, gen)
    assert not valid
