import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as cloudfrontOrigins,
  aws_lambda as lambda,
  aws_s3 as s3,
  Stack,
  StackProps
} from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { CdkJsonParams, Stage } from './@types/resource'
import { runCode } from './utils'

interface extendProps extends StackProps {
  stage: Stage
}

export class CloudFrontStack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

    const jwtVerifyEdgeFunction = new cloudfront.experimental.EdgeFunction(this, 'Create-Jwt-Verify-Edge-Function', {
      code: lambda.Code.fromAsset('cdk-dist/edge'),
      handler: 'index.handler',
      runtime: lambda.Runtime.NODEJS_14_X,
      environment: {},
    })

    const s3Bucket = s3.Bucket.fromBucketName(this, 'Get-S3Bucket-Origin', params.STATIC_STATIC_WEBSITE_HOSTING_BUCKET)
    const bucketNameUrl = s3Bucket.bucketWebsiteUrl.replace('http://', '')
    const s3Origin = new cloudfrontOrigins.HttpOrigin(bucketNameUrl, {
      httpPort: 80,
      customHeaders: {
        Referer: runCode(`return process.env.${params.CLOUDFRONT_REFERER}`),
      },
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
    })

    // HTTPレスポンスヘッダー付与するCloud Functions
    // const cfFunction = new cloudfront.Function(this, `Create-CF-Function`, {
    //   code: cloudfront.FunctionCode.fromInline(
    //     "function handler(event) {\
    //       var response = event.response;\
    //       var headers = response.headers;\
    //       headers['strict-transport-security'] = { value: 'max-age=63072000; includeSubdomains; preload'};\
    //       headers['x-content-type-options'] = { value: 'nosniff'};\
    //       headers['x-frame-options'] = { value: 'DENY'};\
    //       headers['x-xss-protection'] = {value: '1; mode=block'};\
    //       return response;}",
    //   ),
    // })

    // Cognitoの認証情報を検証するCloud Functions
    // const cfFunction = new cloudfront.Function(this, `Create-CF-Function`, {
    //   code: cloudfront.FunctionCode.fromFile({
    //     filePath: 'deploy/verify-jwt.js',
    //   }),
    // })

    const s3BehaviorAtDetailsProps: cloudfront.BehaviorOptions = {
      origin: s3Origin,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
      compress: true,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      edgeLambdas: [
        {
          functionVersion: jwtVerifyEdgeFunction.currentVersion,
          eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
        },
      ],
      // functionAssociations: [
      //   {
      //     function: cfFunction,
      //     eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE,
      //   },
      // ],
    }
    const behaviors: Record<string, cloudfront.BehaviorOptions> = {
      '/private/*': s3BehaviorAtDetailsProps,
    }

    const loggingBucket = new s3.Bucket(this, `Create-CloudFront-Log-Bucket`, {
      bucketName: params.CLOUDFRONT_LOG_BUCKET,
    })

    const cfDistribution = new cloudfront.Distribution(this, 'Create-CloudFront', {
      defaultBehavior: {
        origin: s3Origin,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      additionalBehaviors: behaviors,
      // certificate: this.acmCertificate,
      httpVersion: cloudfront.HttpVersion.HTTP2,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_200,
      // domainNames: aliases,
      // webAclId: this.wafId,
      logBucket: loggingBucket,
    })
  }
}
