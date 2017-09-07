import logging
from ctypes import *

from .lib import do_call


def create_generator() -> bytes:
    """
    TODO: FIXME: Comment!!!

    :return: Random BLS generator.
    """

    logger = logging.getLogger(__name__)
    logger.debug("create_generator: >>>")

    generator_p = POINTER(POINTER(c_ubyte))
    generator_len_p = POINTER(c_uint32)

    do_call('indy_crypto_bls_create_generator', generator_p, generator_len_p)

    res = bytes(generator_p.contents[:generator_len_p.contents])
    do_call('indy_crypto_bls_free', generator_p.contents)

    logger.debug("create_generator: <<< res: %r", res)
    return res
