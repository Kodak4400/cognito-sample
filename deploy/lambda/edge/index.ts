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
  for (const cookie of request.headers['cookie']) {
    if (cookie.key === 'cookie') {
      // 認証OK
      try {
        const cookies = cookie.value.split(';')
        for (const c of cookies) {
          if (c.split('idToken=')[1]) {
            Log.info(c.split('idToken=')[1])
            const payload = await verifier.verify(c.split('idToken=')[1])
            Log.info('Token is valid. Payload:', payload)
            callback(null, request)
            return null
          }
        }
      } catch {
        Log.info('Token not valid!')
      }
    }
  }

  // 認証NG
  callback(null, {
    status: '401',
    statusDescription: 'Unauthorized',
    body: '<h1>401 Unauthorized</h1>',
  })
}
