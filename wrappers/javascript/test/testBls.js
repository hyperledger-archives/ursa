const test = require('ava')

const indyCrypto = require('../')

const constructMacro = (t, typeName, ...args) => {
  const factory = indyCrypto[`bls${typeName}`]
  t.false(factory == null, `No function by the name of bls${typeName}`)
  const obj = factory(...args)
  
  t.false(obj == null)
}

constructMacro.title = (_, typeName) => {
  return `BLS ${typeName}`
}

const asBytesMacro = (t, typeName, ...args) => {
  const factory = indyCrypto[`bls${typeName}`]
  const obj = factory(...args)
  
  const bytes = indyCrypto[`bls${typeName}AsBytes`](obj)
  t.notDeepEqual(bytes.toString(), '')
}

asBytesMacro.title = (_, typeName) => {
  return `BLS ${typeName} as bytes`
}

const fromBytesMacro = (t, typeName, ...args) => {
  const factory = indyCrypto[`bls${typeName}`]
  const refObj = factory(...args)
  const refBytes = indyCrypto[`bls${typeName}AsBytes`](refObj)
  
  const gotObj = indyCrypto[`bls${typeName}FromBytes`](refBytes)
  const gotBytes = indyCrypto[`bls${typeName}AsBytes`](gotObj)
  t.deepEqual(gotBytes, refBytes)
}

fromBytesMacro.title = (_, typeName) => {
  return `BLS ${typeName} from bytes`
}

test([constructMacro, asBytesMacro, fromBytesMacro,], 'Generator')

test([constructMacro, asBytesMacro, fromBytesMacro,], 'SignKey')

test([constructMacro, asBytesMacro, fromBytesMacro,], 'VerKey', indyCrypto.blsGenerator(),
  indyCrypto.blsSignKey())
  
test([constructMacro, asBytesMacro, fromBytesMacro,], 'ProofOfPossession',
  indyCrypto.blsVerKey(indyCrypto.blsGenerator(), indyCrypto.blsSignKey()),
  indyCrypto.blsSignKey())
  
test('blsSign', (t) => {
  const signature = indyCrypto.blsSign('12345', indyCrypto.blsSignKey())
  
  t.true(signature != null)
  
  const signatureBytes = indyCrypto.blsSignatureAsBytes(signature)
  t.true(signatureBytes.length > 0)
  const signatureFromBytes = indyCrypto.blsSignatureFromBytes(signatureBytes)
  
  t.deepEqual(indyCrypto.blsSignatureAsBytes(signatureFromBytes), signatureBytes)
})

test('blsMultiSignature', (t) => {
  const signature1 = indyCrypto.blsSign('12345', indyCrypto.blsSignKey())
  const signature2 = indyCrypto.blsSign('12345', indyCrypto.blsSignKey())
  const multiSignature = indyCrypto.blsMultiSignature([signature1, signature2,])
  
  t.true(multiSignature != null)
  
  const bytes = indyCrypto.blsMultiSignatureAsBytes(multiSignature)
  const fromBytes = indyCrypto.blsMultiSignatureFromBytes(bytes)
  
  t.deepEqual(indyCrypto.blsMultiSignatureAsBytes(fromBytes), bytes)
})

test('blsVerify', (t) => {
  const message = '12345'
  const signKey = indyCrypto.blsSignKey()
  const generator = indyCrypto.blsGenerator()
  const verKey = indyCrypto.blsVerKey(generator, signKey)
  const signature = indyCrypto.blsSign(message, signKey)
  
  const verified = indyCrypto.blsVerify(signature, message, verKey, generator)
  
  t.true(verified)
})

test('blsVerify incorrect message', (t) => {
  const message = '12345'
  const signKey = indyCrypto.blsSignKey()
  const generator = indyCrypto.blsGenerator()
  const verKey = indyCrypto.blsVerKey(generator, signKey)
  const signature = indyCrypto.blsSign(message, signKey)
  
  const verified = indyCrypto.blsVerify(signature, '1234', verKey, generator)
  
  t.false(verified)
})

test('blsVerifyProofOfPossession', (t) => {
  const message = '12345'
  const signKey = indyCrypto.blsSignKey()
  const generator = indyCrypto.blsGenerator()
  const verKey = indyCrypto.blsVerKey(generator, signKey)
  const proofOfPossession = indyCrypto.blsProofOfPossession(verKey, signKey)
  
  const verified = indyCrypto.blsVerifyProofOfPossession(proofOfPossession, verKey, generator)
  
  t.true(verified)
})

test('blsVerifyProofOfPossession wrong key', (t) => {
  const message = '12345'
  const signKey = indyCrypto.blsSignKey()
  const generator = indyCrypto.blsGenerator()
  const verKey = indyCrypto.blsVerKey(generator, signKey)
  const proofOfPossession = indyCrypto.blsProofOfPossession(verKey, signKey)
  
  const verified = indyCrypto.blsVerifyProofOfPossession(proofOfPossession, indyCrypto.blsVerKey(
    generator, indyCrypto.blsSignKey()), generator)
  
  t.false(verified)
})

test('blsVerifyMultiSig', (t) => {
  const message = '12345'
  const signKey1 = indyCrypto.blsSignKey()
  const signKey2 = indyCrypto.blsSignKey()
  const signature1 = indyCrypto.blsSign(message, signKey1)
  const signature2 = indyCrypto.blsSign(message, signKey2)
  const generator = indyCrypto.blsGenerator()
  const verKeys = [
    indyCrypto.blsVerKey(generator, signKey1), indyCrypto.blsVerKey(generator, signKey2),
]
  const multiSignature = indyCrypto.blsMultiSignature([signature1, signature2,])
  
  const verified = indyCrypto.blsVerifyMultiSig(multiSignature, message, verKeys, generator)
  
  t.true(verified)
})

test('blsVerifyMultiSig incorrect message', (t) => {
  const message = '12345'
  const signKey1 = indyCrypto.blsSignKey()
  const signKey2 = indyCrypto.blsSignKey()
  const signature1 = indyCrypto.blsSign(message, signKey1)
  const signature2 = indyCrypto.blsSign(message, signKey2)
  const generator = indyCrypto.blsGenerator()
  const verKeys = [
    indyCrypto.blsVerKey(generator, signKey1), indyCrypto.blsVerKey(generator, signKey2),
]
  const multiSignature = indyCrypto.blsMultiSignature([signature1, signature2,])
  
  const verified = indyCrypto.blsVerifyMultiSig(multiSignature, '1234', verKeys, generator)
  
  t.false(verified)
})