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

    gen = POINTER(c_ubyte)()
    gen_len = c_size_t(0)

    do_call('indy_crypto_bls_create_generator', byref(gen), byref(gen_len))

    logger.debug("%r %r", gen, gen_len)

    res = bytes(gen[:gen_len.value])
    do_call('indy_crypto_bls_free_array', gen, gen_len)

    logger.debug("create_generator: <<< %r", res)
    return res
