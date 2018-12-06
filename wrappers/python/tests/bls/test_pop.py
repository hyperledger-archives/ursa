from indy_crypto.bls import ProofOfPossession


def test_new(pop: ProofOfPossession):
    assert pop is not None


def test_as_bytes(pop: ProofOfPossession):
    xbytes = pop.as_bytes()
    assert len(xbytes) > 0


def test_from_bytes(pop: ProofOfPossession):
    xbytes = pop.as_bytes()

    pop2 = ProofOfPossession.from_bytes(xbytes)
    assert type(pop2) is ProofOfPossession

    xbytes2 = pop2.as_bytes()
    assert xbytes == xbytes2
