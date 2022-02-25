import { Stack, StackProps, RemovalPolicy } from 'aws-cdk-lib'
import { aws_s3 as s3 } from 'aws-cdk-lib';
import { aws_iam as iam } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { S3BucketName } from './utils';

export class S3Stack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const webBucket = new s3.Bucket(this, `Create-Web-Bucket`, {
      bucketName: S3BucketName,
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
          'aws:referer': ['Amazon CloudFront'],
        },
      },
    })
    webBucket.addToResourcePolicy(webBucketPolicy)
  }
}