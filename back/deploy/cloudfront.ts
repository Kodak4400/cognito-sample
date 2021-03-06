import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as cloudfrontOrigins,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_s3 as s3, Stack,
  StackProps
} from 'aws-cdk-lib'
import { Construct } from 'constructs'
import * as fs from 'fs'
import { resolve } from 'path'
import { CdkJsonParams, Stage } from './@types/resource'
import { runCode } from './utils'


interface extendProps extends StackProps {
  stage: Stage
}

export class CloudFrontStack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

    const lambdaEdgePolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'lambda:GetFunction',
        'lambda:EnableReplication*',
        'iam:CreateServiceLinkedRole',
        'cloudfront:UpdateDistribution',
        'cloudfront:CreateDistribution*',
      ],
      resources: ['*'],
    })

    // const lambdaEdgeRole = new iam.Role(this, 'Create-LambdaEdge-Role', {
    //   assumedBy: new iam.CompositePrincipal(
    //     new iam.ServicePrincipal('lambda.amazonaws.com'),
    //     new iam.ServicePrincipal('edgelambda.amazonaws.com'),
    //   ),
    //   managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
    //   path: '/lambda/',
    // })

    const jwtVerifyEdgeFunction = new cloudfront.experimental.EdgeFunction(this, 'Create-Jwt-Verify-Edge-Function', {
      code: lambda.Code.fromAsset('dist/edge'),
      handler: 'index.handler',
      runtime: lambda.Runtime.NODEJS_14_X,
      environment: {},
      // role: lambdaEdgeRole,
    })
    jwtVerifyEdgeFunction.addToRolePolicy(lambdaEdgePolicy)

    const s3Bucket = s3.Bucket.fromBucketName(this, 'Get-S3Bucket-Origin', params.STATIC_STATIC_WEBSITE_HOSTING_BUCKET)
    const bucketNameUrl = s3Bucket.bucketWebsiteUrl.replace('http://', '')
    const s3Origin = new cloudfrontOrigins.HttpOrigin(bucketNameUrl, {
      httpPort: 80,
      customHeaders: {
        Referer: runCode(`return process.env.${params.CLOUDFRONT_REFERER}`),
      },
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
    })

    // HTTP???????????????????????????????????????Cloud Functions
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

    // Cognito??????????????????????????????Cloud Functions
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

    const pubKey = new cloudfront.PublicKey(this, 'MyPubKey', {
      encodedKey: fs.readFileSync(resolve(__dirname, 'cookie.pub'), 'utf-8'),
    })
    const keyGroup = new cloudfront.KeyGroup(this, 'MyKeyGroup', {
      items: [pubKey],
    })

    const s3BehaviorAtCookieProps: cloudfront.BehaviorOptions = {
      origin: s3Origin,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
      compress: true,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      trustedKeyGroups: [keyGroup],
      // edgeLambdas: [
      //   {
      //     functionVersion: jwtVerifyEdgeFunction.currentVersion,
      //     eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
      //   },
      // ],
      // functionAssociations: [
      //   {
      //     function: cfFunction,
      //     eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE,
      //   },
      // ],
    }
    const behaviors: Record<string, cloudfront.BehaviorOptions> = {
      '/scratch*': s3BehaviorAtDetailsProps,
      '/cookie*': s3BehaviorAtCookieProps,
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
