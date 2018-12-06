Indy Crypto API Reference
=========================
.. js:module:: indycrypto
  
.. js:function:: blsGenerator()

  Creates and returns random generator point that satisfies BLS algorithm requirements.
  
  :returns: A Generator.
  
.. js:function:: blsGeneratorAsBytes(generator)

  Returns BLS generator point bytes representation.
  
  :param generator: The generator.
  :returns: A byte array.
  
.. js:function:: blsGeneratorFromBytes(bytes)

  Creates and returns generator point from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsGeneratorAsBytes.
  :returns: A Generator.
  
.. js:function:: blsSignKey([seed])

  Creates and returns random (with optional seed) BLS sign key algorithm requirements.
  
  :param seed: A seed as an array of bytes (length 32).
  :returns: A SignKey.
  
.. js:function:: blsSignKeyAsBytes(signKey)

  Returns BLS sign key bytes representation.
  
  :param signKey: A SignKey.
  :returns: A byte array.
  
.. js:function:: blsSignKeyFromBytes(bytes)

  Creates and returns BLS sign key from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsSignKeyAsBytes.
  :returns: A SignKey.
  
.. js:function:: blsVerKey(generator, signKey)

  Creates and returns BLS ver key that corresponds to sign key.
  
  :param generator: A Generator.
  :param signKey: A SignKey.
  :returns: A VerKey.
  
.. js:function:: blsVerKeyAsBytes(verKey)

  Returns BLS verification key bytes representation.
  
  :param verKey: A VerKey.
  :returns: A byte array.
  
.. js:function:: blsVerKeyFromBytes(bytes)

  Creates and returns BLS verification key from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsVerKeyAsBytes.
  :returns: A VerKey.
  
.. js:function:: blsProofOfPossession(verKey, signKey)

  Creates and returns BLS proof of possession that corresponds to ver key.
  
  :param verKey: A VerKey.
  :param signKey: A SignKey.
  :returns: A ProofOfPossession.
  
.. js:function:: blsProofOfPossessionAsBytes(proofOfPossession)

  Returns BLS proof of possession to bytes representation.
  
  :param proofOfPossession: A ProofOfPossession.
  :returns: A byte array.
  
.. js:function:: blsProofOfPossessionFromBytes(bytes)

  Creates and returns BLS proof of possession from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsProofOfPossessionAsBytes.
  :returns: A ProofOfPossession.
  
.. js:function:: blsSignatureAsBytes(signature)

  Returns BLS signature to bytes representation.
  
  :param signature: A Signature.
  :returns: A byte array.
  
.. js:function:: blsSignatureFromBytes(bytes)

  Creates and returns BLS signature from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsSignatureAsBytes.
  :returns: A Signature.
  
.. js:function:: blsMultiSignature(signatures)

  Creates and returns multi signature for provided list of signatures.
  
  :param signatures: An array of signatures.
  :returns: A MultiSignature.
  
.. js:function:: blsMultiSignatureAsBytes(multiSignature)

  Returns BLS multi signature bytes representation.
  
  :param multiSignature: A MultiSignature.
  :returns: A byte array.
  
.. js:function:: blsMultiSignatureFromBytes(bytes)

  Creates and returns BLS multi signature from bytes representation.
  
  :param bytes: An array of bytes, as returned by blsMultiSignatureAsBytes.
  :returns: A MultiSignature.
  
.. js:function:: blsSign(message, signKey)

  Signs the message and returns signature.
  
  :param string message: The message to sign.
  :param signKey: A SignKey.
  :returns: A Signature.
  
.. js:function:: blsVerify(signature, message, verKey, generator)

  Verifies the message signature and returns true if signature valid or false otherwise.
  
  :param signature: Signature to verify.
  :param string message: Message to verify.
  :param verKey: A VerKey.
  :param generator: A Generator.
  :returns: boolean.
  
.. js:function:: blsVerifyProofOfPossession(proofOfPossession, verKey, generator)

  Verifies the proof of possession and returns true if signature valid or false otherwise.
  
  :param proofOfPossession: Proof of possession.
  :param verKey: A VerKey.
  :param generator: A Generator.
  :returns: boolean.
  
.. js:function:: blsVerifyMultiSig(multiSig, message, verKeys, generator)

  Verifies the message multi signature and returns true if signature valid or false otherwise.
  
  :param multiSig: MultiSignature to verify.
  :param string message: Message to verify.
  :param verKeys: An array of VerKeys.
  :param generator: A Generator.
  :returns: boolean.