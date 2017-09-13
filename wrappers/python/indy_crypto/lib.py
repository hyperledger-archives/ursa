import logging
import sys
from ctypes import *

from .error import ErrorCode, IndyCryptoError


def do_call(name: str, *args):
    logger = logging.getLogger(__name__)
    logger.debug("do_call: >>> name: %r, args: %r", name, args)

    err = getattr(_cdll(), name)(*args)

    logger.debug("do_call: Function %r returned err: %r", name, err)

    if err != ErrorCode.Success:
        raise IndyCryptoError(ErrorCode(err))


def _cdll() -> CDLL:
    if not hasattr(_cdll, "cdll"):
        _cdll.cdll = _load_cdll()

    return _cdll.cdll


def _load_cdll() -> CDLL:
    logger = logging.getLogger(__name__)
    logger.debug("_load_cdll: >>>")

    lib_prefix_mapping = {"darwin": "lib", "linux": "lib", "linux2": "lib", "win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "linux": ".so", "linux2": ".so", "win32": ".dll"}

    os_name = sys.platform
    logger.debug("_load_cdll: Detected OS name: %s", os_name)

    try:
        libindy_prefix = lib_prefix_mapping[os_name]
        libindy_suffix = lib_suffix_mapping[os_name]
    except KeyError:
        logger.error("_load_cdll: OS isn't supported: %s", os_name)
        raise OSError("OS isn't supported: %s", os_name)

    lib_name = "{0}indy_crypto{1}".format(libindy_prefix, libindy_suffix)
    logger.debug("_load_cdll: Resolved libindy name is: %s", lib_name)

    try:
        res = CDLL(lib_name)

        logger.debug("_load_cdll: Init Indy Crypto logger")
        getattr(res, "indy_crypto_init_logger")()

        logger.debug("_load_cdll: <<< res: %s", res)
        return res
    except OSError as e:
        logger.error("_load_cdll: Can't load libindy-crypto: %s", e)
        raise e
