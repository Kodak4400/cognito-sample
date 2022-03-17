import Log from '@dazn/lambda-powertools-logger'
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js'
import { APIGatewayProxyEventV2 } from 'aws-lambda'
import crypto from 'crypto'
import * as fs from 'fs'
import { resolve } from 'path'
import ApiResponse from '../modules/ApiResponse'
import httpResponseBuilder from '../modules/HttpResponseBuilder'

interface AuthData {
  Username: string
  Password: string
}

interface Cookies {
  "CloudFront-Policy": string
  "CloudFront-Signature": string
  "CloudFront-Key-Pair-Id": string
}

interface Policy {
  Statement: Array<{
    Resource: string
    Condition: {
      DateLessThan: {
        'AWS:EpochTime': number,
      },
    },
  }>,
}

export default class CreateSignedCookies {
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

    await new Promise((resolve, reject) =>
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
      }),
    )

    const cfUrl = process.env.CF_BEHAVIOR_URL ?? 'undefined'
    const privateKey = process.env.PRIVATE_KEY ?? 'undefined'

    const signedCookies = this.getSignedCookies(cfUrl, privateKey)

    return await httpResponseBuilder(200, {
      message: signedCookies,
    })
  }

  private getSignedCookies(cfUrl: string, keypairId: string): Cookies {
    const privateKey = this._getPrivateKey() // 秘密鍵の読み込み
    const policy = this._createPolicy(cfUrl) // AWS IAMポリシー作成
    const signature = this._createPolicySignature(policy, privateKey) // CloudFront-Signatureの生成
    const policyStr = Buffer.from(JSON.stringify(policy)).toString('base64') // CloudFront-Policyの生成
    return {
      'CloudFront-Policy': this.normalizeBase64(policyStr),
      'CloudFront-Signature': this.normalizeBase64(signature),
      'CloudFront-Key-Pair-Id': keypairId,
    }
  }

  private normalizeBase64(str: string): string {
    return str.replace(/\+/g, '-').replace(/=/g, '_').replace(/\//g, '~')
  }

  private _createPolicySignature(policy: Policy, privateKey: string): string {
    const sign = crypto.createSign('RSA-SHA1')
    sign.update(JSON.stringify(policy))

    return sign.sign(privateKey, 'base64')
  }

  private _createPolicy(cfUrl: string): Policy {
    const halfTime = 1000 * 60 * 30 * 1
    const expireTime = Math.round((new Date().getTime() + halfTime) / 1000)
    const policy = {
      Statement: [
        {
          Resource: `${cfUrl}*`,
          Condition: {
            DateLessThan: {
              'AWS:EpochTime': expireTime,
            },
          },
        },
      ],
    }
    return policy
  }

  private _getPrivateKey(): string {
    return fs.readFileSync(resolve(__dirname, 'cookie.pem'), 'utf-8')
  }
}
