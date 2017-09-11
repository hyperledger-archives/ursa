import logging
from ctypes import *
from typing import Optional

from .lib import do_call


def create_generator() -> bytes:
    """
    :return: BLS generator.
    """

    logger = logging.getLogger(__name__)
    logger.debug("create_generator: >>>")

    gen = POINTER(c_ubyte)()
    gen_len = c_size_t()

    do_call('indy_crypto_bls_create_generator', byref(gen), byref(gen_len))
    res = bytes(gen[:gen_len.value])

    do_call('indy_crypto_bls_free_array', gen, gen_len)

    logger.debug("create_generator: <<< res: %r", res)
    return res


def generate_keys(gen: bytes, seed: Optional[bytes]) -> (bytes, bytes):
    """
    :return: (Sign key, Verification Key).
    """

    logger = logging.getLogger(__name__)
    logger.debug("generate_keys: >>> gen: %r, seed: %r", gen, seed)

    sign_key = POINTER(c_ubyte)()
    sign_key_len = c_size_t()

    ver_key = POINTER(c_ubyte)()
    ver_key_len = c_size_t()

    do_call('indy_crypto_bls_generate_keys',
            gen, len(gen),
            seed, len(seed) if seed is not None else 0,
            byref(sign_key), byref(sign_key_len),
            byref(ver_key), byref(ver_key_len))

    res = (bytes(sign_key[:sign_key_len.value]), bytes(ver_key[:ver_key_len.value]))

    do_call('indy_crypto_bls_free_array', sign_key, sign_key_len)
    do_call('indy_crypto_bls_free_array', ver_key, ver_key_len)

    logger.debug("generate_keys: <<< res: %r", res)
    return res


def sign(message: bytes, sign_key: bytes) -> bytes:
    """
    :return: Signature.
    """

    logger = logging.getLogger(__name__)
    logger.debug("sign: >>> message: %r, sign_key: %r", message, sign_key)

    signature = POINTER(c_ubyte)()
    signature_len = c_size_t()

    do_call('indy_crypto_bls_sign',
            message, len(message),
            sign_key, len(sign_key),
            byref(signature), byref(signature_len))

    res = bytes(signature[:signature_len.value])

    do_call('indy_crypto_bls_free_array', signature, signature_len)

    logger.debug("sign: <<< res: %r", res)
    return res


def create_multi_signature(signatures: [bytes]) -> bytes:
    """
    :return: Multi signature.
    """

    logger = logging.getLogger(__name__)
    logger.debug("create_multi_signature: >>> signatures: %r", signatures)

    # noinspection PyCallingNonCallable,PyTypeChecker
    signature_lens = (c_size_t * len(signatures))()
    # noinspection PyCallingNonCallable
    signatures_arr = (POINTER(c_ubyte) * len(signatures))()

    for i in range(len(signatures)):
        signature_lens[i] = c_size_t(len(signatures[i]))

        # noinspection PyCallingNonCallable,PyTypeChecker
        signature_buf = (c_ubyte * len(signatures[i]))()
        signature_buf.value = signatures[i]
        signatures_arr[i] = signature_buf

    multi_sig = POINTER(c_ubyte)()
    multi_sig_len = c_size_t()

    do_call('indy_crypto_bls_create_multi_signature',
            byref(signatures_arr), byref(signature_lens), len(signatures),
            byref(multi_sig), byref(multi_sig_len))

    res = bytes(multi_sig[:multi_sig_len.value])

    do_call('indy_crypto_bls_free_array', multi_sig, multi_sig_len)

    logger.debug("create_multi_signature: <<< res: %r", res)
    return res


def verify(signature: bytes, message: bytes, ver_key: bytes, gen: bytes) -> bool:
    """
    :return: true if signature valid.
    """

    logger = logging.getLogger(__name__)
    logger.debug("verify: >>> signature: %r, message: %r, ver_key: %r, gen: %r", signature, message, ver_key, gen)

    valid = c_bool()

    do_call('indy_crypto_bsl_verify',
            signature, len(signature),
            message, len(message),
            ver_key, len(ver_key),
            gen, len(gen),
            byref(valid))

    res = valid
    logger.debug("verify: <<< res: %r", res)
    return res


def verify_multi_sig(multi_sig: bytes, message: bytes, ver_keys: [bytes], gen: bytes) -> bool:
    """
    :return: true if multi signature valid.
    """

    logger = logging.getLogger(__name__)
    logger.debug("verify_multi_sig: >>> multi_sig: %r, message: %r, ver_keys: %r, gen: %r",
                 multi_sig, message, ver_keys, gen)

    # noinspection PyCallingNonCallable,PyCallingNonCallable,PyTypeChecker
    ver_keys_lens = (c_size_t * len(ver_keys))()
    # noinspection PyCallingNonCallable
    ver_keys_arr = (POINTER(c_ubyte) * len(ver_keys))()

    for i in range(len(ver_keys)):
        ver_keys_lens[i] = c_size_t(len(ver_keys[i]))

        # noinspection PyCallingNonCallable,PyCallingNonCallable,PyTypeChecker
        ver_key_buf = (c_ubyte * len(ver_keys[i]))()
        ver_key_buf.value = ver_keys[i]
        ver_keys_arr[i] = ver_key_buf

    valid = c_bool()

    do_call('indy_crypto_bls_verify_multi_sig',
            multi_sig, len(multi_sig),
            message, len(message),
            byref(ver_keys_arr), byref(ver_keys_lens), len(ver_keys),
            gen, len(gen),
            byref(valid))

    res = valid
    logger.debug("verify_multi_sig: <<< res: %r", res)
    return res
