import { aws_iam as iam, aws_s3 as s3, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { CdkJsonParams, Stage } from './@types/resource'
import { runCode } from './utils'

interface extendProps extends StackProps {
  stage: Stage
}

export class S3Stack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

    const webBucket = new s3.Bucket(this, `Create-StaticWebsiteHosting-Bucket`, {
      bucketName: params.STATIC_STATIC_WEBSITE_HOSTING_BUCKET,
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: '404.html',
      publicReadAccess: false,
      removalPolicy: RemovalPolicy.DESTROY,
    })

    const webBucketPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject', 's3:GetObjectVersion'],
      resources: [webBucket.bucketArn + '/*'],
      principals: [new iam.AnyPrincipal()],
      conditions: {
        StringEquals: {
          'aws:referer': [runCode(`return process.env.${params.CLOUDFRONT_REFERER}`)],
        },
      },
    })
    webBucket.addToResourcePolicy(webBucketPolicy)
  }
}
