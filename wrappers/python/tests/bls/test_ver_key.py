from indy_crypto.bls import VerKey


def test_new(ver_key1: VerKey):
    assert ver_key1 is not None


def test_new_for_seed(ver_key2: VerKey):
    assert ver_key2 is not None


def test_as_bytes(ver_key1: VerKey):
    xbytes = ver_key1.as_bytes()
    assert len(xbytes) > 0


def test_from_bytes(ver_key1: VerKey):
    xbytes = ver_key1.as_bytes()

    ver_key12 = VerKey.from_bytes(xbytes)
    assert type(ver_key12) is VerKey

    xbytes2 = ver_key12.as_bytes()
    assert xbytes == xbytes2
