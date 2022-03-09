import { APIGatewayProxyEventV2 } from 'aws-lambda'
import context from 'aws-lambda-mock-context'
import * as dotenv from 'dotenv'
import { describe, expect, it } from 'vitest'
import { handler } from '../../../deploy/lambda/auth'

const result = dotenv.config()
if (result.error) {
  throw result.error
}

describe('lambda/auth/signin.ts', () => {
  const event: APIGatewayProxyEventV2 = {
    version: '2.0',
    routeKey: 'POST /api/signin',
    rawPath: '/xxxx',
    rawQueryString: 'worsds=aab&size=5&from=10&g=v',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'accept-encoding': 'gzip, deflate, br',
      'accept-language': 'ja,en-US;q=0.9,en;q=0.8',
      'content-length': '0',
      host: 'x6y19k7sdg.execute-api.us-east-1.amazonaws.com',
      'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
      'sec-ch-ua-mobile': '?0',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'none',
      'sec-fetch-user': '?1',
      'upgrade-insecure-requests': '1',
      'user-agent': 'Mozilla/5.0 (Macintosh;',
      'x-amzn-trace-id': 'Root=1-60548aae-3ee6b758461f9da675fc8f8b',
      'x-forwarded-for': '210.139.73.131',
      'x-forwarded-port': '443',
      'x-forwarded-proto': 'https',
    },
    requestContext: {
      accountId: '825880940331',
      apiId: 'x6y19k7sdg',
      domainName: 'x6y19k7sdg.execute-api.us-east-1.amazonaws.com',
      domainPrefix: 'x6y19k7sdg',
      http: {
        method: 'GET',
        path: '/xxxx',
        protocol: 'HTTP/1.1',
        sourceIp: '210.139.73.131',
        userAgent: 'Mozilla/5.0 (Macintosh;',
      },
      requestId: 'RandomId',
      routeKey: 'POST /api/singnin',
      stage: '$default',
      time: '19/Mar/2021:11:27:42 +0000',
      timeEpoch: 1616153262547,
    },
    body: '{ "Username": "admin", "Password": "Zaq1@wsxcd" }',
    isBase64Encoded: false,
  }

  it('handler', async () => {
    expect(await handler(event, context({ timeout: 30000 }), () => {})).toEqual({
      isBase64Encoded: false,
      statusCode: 200,
      body: JSON.stringify('SignUp OK.'),
      headers: {
        'content-type': 'application/json',
      },
    })
  })
})
