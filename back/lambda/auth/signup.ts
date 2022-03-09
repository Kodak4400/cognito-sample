import Log from '@dazn/lambda-powertools-logger'
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js'
import { APIGatewayProxyEventV2 } from 'aws-lambda'
import ApiResponse from '../modules/ApiResponse'
import httpResponseBuilder from '../modules/HttpResponseBuilder'

interface AuthData {
  Username: string
  Password: string
  Email: string
}

export default class SignUp {
  public async handler(event: APIGatewayProxyEventV2): Promise<ApiResponse> {
    Log.debug(`USER_POOL_ID => ${process.env.USER_POOL_ID ?? 'undefined'}`)
    Log.debug(`CLIENT_ID => ${process.env.CLIENT_ID ?? 'undefined'}`)

    if (!event.body) throw new Error('event.body is empty')
    const data: AuthData = JSON.parse(event.body)
    const attributeList: Array<AmazonCognitoIdentity.CognitoUserAttribute> = []

    const userPool = new AmazonCognitoIdentity.CognitoUserPool({
      UserPoolId: process.env.USER_POOL_ID ?? 'undefined',
      ClientId: process.env.CLIENT_ID ?? 'undefined',
    })
    const attributeEmail = new AmazonCognitoIdentity.CognitoUserAttribute({
      Name: 'email',
      Value: data.Email,
    })
    attributeList.push(attributeEmail)

    await new Promise((resolve, reject) =>
      userPool.signUp(data.Username, data.Password, attributeList, [], function (error, result) {
        if (error) {
          reject(new Error(error.message))
        } else {
          const userName = result ? result.user.getUsername() : 'undefined'
          Log.debug('user name is ' + userName)
          resolve(result)
        }
      }),
    )

    return await httpResponseBuilder(200, {
      message: 'SignUp OK.',
    })
  }
}
