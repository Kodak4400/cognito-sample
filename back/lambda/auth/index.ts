import Log from '@dazn/lambda-powertools-logger'
import { APIGatewayProxyHandlerV2 } from 'aws-lambda'
import httpResponseBuilder from '../modules/HttpResponseBuilder'
import Cookie from './cookie'
import SignIn from './signin'
import SignUp from './signup'

export const handler: APIGatewayProxyHandlerV2 = async event => {
  try {
    Log.info('Received event:', { event })

    switch (event.routeKey) {
      case 'POST /api/signin':
        return await new SignIn().handler(event)
      case 'POST /api/signup':
        return await new SignUp().handler(event)
      case 'POST /api/cookie':
        return await new Cookie().handler(event)
      default:
        return await httpResponseBuilder(400, {
          message: 'No route.',
        })
    }
  } catch (error: unknown) {
    if (error instanceof Error) {
      Log.error('Error occurred:', error)
      return await httpResponseBuilder(400, {
        message: error.message,
      })
    }
    return await httpResponseBuilder(500, {
      message: 'Internal Server Error',
    })
  }
}
