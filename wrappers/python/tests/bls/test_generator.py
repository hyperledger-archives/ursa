from indy_crypto.bls import Generator


def test_new(generator: Generator):
    assert generator is not None


def test_as_bytes(generator):
    xbytes = generator.as_bytes()
    assert len(xbytes) > 0


def test_from_bytes(generator):
    xbytes = generator.as_bytes()

    generator2 = Generator.from_bytes(xbytes)
    assert type(generator2) is Generator

    xbytes2 = generator2.as_bytes()
    assert xbytes == xbytes2
