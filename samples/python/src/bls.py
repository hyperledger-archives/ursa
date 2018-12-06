from indy_crypto.bls import Bls, Generator, VerKey, SignKey, Signature, MultiSignature


def demo():
    # Create generator
    generator = Generator.new()

    # Create first key pair
    sign_key1 = SignKey.new(None)
    ver_key1 = VerKey.new(generator, sign_key1)

    # Create second keys pair based on seed
    seed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4,
                  5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8,
                  9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8])
    sign_key2 = SignKey.new(seed)
    ver_key2 = VerKey.new(generator, sign_key2)

    # Sample message
    message = bytes([1, 2, 3, 4, 5])

    # Sign message with first sing key
    signature1 = Bls.sign(message, sign_key1)

    # Verify first signature with first ver key
    valid = Bls.verify(signature1, message, ver_key1, generator)
    assert valid

    # Sign message with second sing key
    signature2 = Bls.sign(message, sign_key2)

    # Verify second signature with second ver key
    valid = Bls.verify(signature2, message, ver_key2, generator)
    assert valid

    # Create multi signature
    multi_sig = MultiSignature.new([signature1, signature2])

    # Verify multi signature
    valid = Bls.verify_multi_sig(multi_sig, message, [ver_key1, ver_key2], generator)
    assert valid
