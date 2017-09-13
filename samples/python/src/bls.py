from indy_crypto import bls


def demo():
    # Create generator
    generator = bls.create_generator()

    # Create first keys pair
    sign_key1, ver_key1 = bls.generate_keys(generator, None)

    # Create second keys pair based on seed
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4,
                  5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8,
                  9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8])
    sign_key2, ver_key2 = bls.generate_keys(generator, seed)

    # Sample message
    message = bytes([1, 2, 3, 4, 5])

    # Sign message with first sing key
    signature1 = bls.sign(message, sign_key1)

    # Verify first signature with first ver key
    valid = bls.verify(signature1, message, ver_key1, generator)
    assert valid

    # Sign message with second sing key
    signature2 = bls.sign(message, sign_key2)

    # Verify second signature with second ver key
    valid = bls.verify(signature2, message, ver_key2, generator)
    assert valid

    # Create multi signature
    multi_sig = bls.create_multi_signature([signature1, signature2])

    # Verify multi signature
    valid = bls.verify_multi_sig(multi_sig, message, [ver_key1, ver_key2], generator)
    assert valid
