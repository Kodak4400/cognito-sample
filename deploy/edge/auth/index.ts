import Log from '@dazn/lambda-powertools-logger'
import { CloudFrontRequestHandler } from 'aws-lambda'

export const handler: CloudFrontRequestHandler = async (event, context, callback) => {
  Log.info('Start Auth')
  return null
}
