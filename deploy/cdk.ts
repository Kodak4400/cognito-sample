import { App } from 'aws-cdk-lib';
// import { LambdaEdgeStack } from './edge'
import * as dotenv from "dotenv";
// import { CloudFrontStack } from './cloudfront';
// import { CognitoStack } from './cognito';
import { S3Stack } from './s3';

dotenv.config({ path: __dirname + "/.env" });

const app = new App()
// new LambdaEdgeStack(app, 'LambdaEdge-Stack', { env: { region: 'us-east-1' } })

new S3Stack(app, 'Create-S3-Stack', { env: { region: 'ap-northeast-1' } })
// new CloudFrontStack(app, 'Create-CloudFront-Stack', { env: { region: 'ap-northeast-1' } })
// new CognitoStack(app, 'Create-Cognito-Stack', { env: { region: 'ap-northeast-1' } })
