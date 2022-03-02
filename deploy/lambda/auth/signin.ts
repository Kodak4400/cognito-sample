import Log from '@dazn/lambda-powertools-logger'
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js'
import { APIGatewayProxyEventV2 } from 'aws-lambda'
import ApiResponse from '../modules/ApiResponse'
import httpResponseBuilder from '../modules/HttpResponseBuilder'

interface AuthData {
  Username: string
  Password: string
}

export default class SignIn {
  public async handler(event: APIGatewayProxyEventV2): Promise<ApiResponse> {
    if (!event.body) throw new Error('event.body is empty')
    const data: AuthData = JSON.parse(event.body)

    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username: data.Username,
      Password: data.Password,
    })

    const userPool = new AmazonCognitoIdentity.CognitoUserPool({
      UserPoolId: process.env.USER_POOL_ID ?? '',
      ClientId: process.env.CLIENT_ID ?? '',
    })

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: data.Username,
      Pool: userPool,
    })

    const cognitoUserAuth: AmazonCognitoIdentity.CognitoUserSession = await new Promise((resolve, reject) =>
      cognitoUser.authenticateUser(authenticationDetails, {
        // 認証成功
        onSuccess: result => {
          Log.debug('onSuccess')
          resolve(result)
        },

        // 認証失敗
        onFailure: (error: unknown) => {
          if (error instanceof Error) {
            reject(new Error(error.message))
          }
        },

        // 仮パスワードでユーザがログイン
        newPasswordRequired: (userAttributes, requiredAttributes) => {
          cognitoUser.completeNewPasswordChallenge(data.Password, userAttributes, {
            // 認証成功
            onSuccess: result => {
              Log.debug('newPasswordRequired/onSuccess')
              resolve(result)
            },

            // 認証失敗
            onFailure: error => {
              if (error instanceof Error) {
                reject(new Error(error.message))
              }
            },
          })
        },
      }),
    )

    const idToken = cognitoUserAuth.getIdToken().getJwtToken() // IDトークン
    const accessToken = cognitoUserAuth.getAccessToken().getJwtToken() // アクセストークン
    const refreshToken = cognitoUserAuth.getRefreshToken().getToken() // 更新トークン

    Log.debug(`{ "idToken": "${idToken}", "accessToken":" ${accessToken}", "refreshToken": "${refreshToken}" }`)

    return await httpResponseBuilder(200, {
      message: `{ "idToken": "${idToken}", "accessToken":" ${accessToken}", "refreshToken": "${refreshToken}" }`,
    })
  }
}
