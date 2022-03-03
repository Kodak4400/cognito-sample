import Log from '@dazn/lambda-powertools-logger'
import { CognitoJwtVerifier } from 'aws-jwt-verify'
import { CloudFrontRequestHandler } from 'aws-lambda'

export const handler: CloudFrontRequestHandler = async (event, context, callback) => {
  Log.info('Start Auth')
  const userPoolId = process.env.USER_POOL_ID ? process.env.USER_POOL_ID : ''
  const tokenUse = 'id'
  const clientId = process.env.CLIENT_ID ? process.env.CLIENT_ID : ''

  const verifier = CognitoJwtVerifier.create({
    userPoolId,
    tokenUse,
    clientId,
  })

  const request = event.Records[0].cf.request

  Log.info('headers', request)
  try {
    for (const cookie of request.headers['cookie']) {
      const values = cookie.value.split(';')
      for (const value of values) {
        if (value.split('idToken=')[1]) {
          Log.info(value.split('idToken=')[1])
          const payload = await verifier.verify(value.split('idToken=')[1])
          Log.info('Token is valid. Payload:', payload)
          callback(null, request)
          return undefined
        }
      }
    }
    throw new Error('Token not valid!')
  } catch (error: unknown) {
    // 認証NG
    request.uri = '/404.html'
    callback(null, request)
    return undefined
  }
}
