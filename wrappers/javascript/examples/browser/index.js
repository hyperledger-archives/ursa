import Promise from 'bluebird'
import range from 'ramda/src/range'
import reduce from 'ramda/src/reduce'

const main = async () => {
  const outputElem = document.getElementById('output-area')
  outputElem.innerHTML = `Computing`
  
  let count = 0
  
  const updateProgress = () => {
    let dots = reduce((acc) => {
      return acc + '.'
    }, '', range(0, count))
    
    outputElem.innerHTML = `Computing${dots}`
    timeoutHandle = setTimeout(updateProgress, 500)
    count = (count + 1) % 4
  }
  
  let timeoutHandle = setTimeout(updateProgress, 500)
  
  await Promise.delay(5000)
  clearTimeout(timeoutHandle)
  
  const indyCrypto = await import('../..')
  
  const message = '12345'
  const signKey = indyCrypto.blsSignKey()
  const generator = indyCrypto.blsGenerator()
  const verKey = indyCrypto.blsVerKey(generator, signKey)
  const signature = indyCrypto.blsSign(message, signKey)
  
  const verified = indyCrypto.blsVerify(signature, message, verKey, generator)
  if (verified) {
    outputElem.innerHTML = `<em>Message successfully verified! :)<em>`
  } else {
    outputElem.innerHTML = `<em>Message could not be verified! :(<em>`
  }
}

main()
  .catch((error) => {
    console.error(`An unexpected error occurred:`, error)
  })

