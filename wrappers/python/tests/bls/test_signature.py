from indy_crypto.bls import Signature


def test_new(signature1: Signature):
    assert signature1 is not None


def test_new_for_seed(signature2: Signature):
    assert signature2 is not None


def test_as_bytes(signature1: Signature):
    xbytes = signature1.as_bytes()
    assert len(xbytes) > 0


def test_from_bytes(signature1: Signature):
    xbytes = signature1.as_bytes()

    signature12 = Signature.from_bytes(xbytes)
    assert type(signature12) is Signature

    xbytes2 = signature12.as_bytes()
    assert xbytes == xbytes2
