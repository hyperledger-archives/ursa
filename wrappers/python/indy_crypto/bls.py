from ctypes import c_void_p
from logging import getLogger
from .lib import do_call

class Bls_Generator:
    """
    BLS class that includes the standard Bohen, Lynn, Shacham signature scheme.
    """

    def __init__(self, c_instance):
        logger = getLogger(__name__)
        logger.debug("BlsEntity.__init__: >>> self: %r, instance: %r", self, c_instance)

        self.c_instance = c_instance



    def new(self):
        logger = getLogger(__name__)
        logger.debug("Generator::new: >>>")


        do_call()


