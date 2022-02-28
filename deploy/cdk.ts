import { App } from "aws-cdk-lib";
import * as dotenv from "dotenv";
import { Stage } from './@types/resource';
// import { CloudFrontStack } from './cloudfront';
import { CognitoStack } from './cognito';

const result = dotenv.config();
if (result.error) {
  throw result.error;
}

const app = new App();

const stage: Stage = app.node.tryGetContext("env") || process.env.NODE_ENV;
if (!stage) {
  throw new Error("エラー: -c env=env名");
}

export const stackEnv = {
  env: {
    region: "ap-northeast-1",
  },
  stage
};

// Lambda@EdgeをNodejsFunctionをつかって実装するのは手間なので、コメントアウト
// new LambdaEdgeStack(app, "LambdaEdge-Stack", stackEnv);

new CognitoStack(app, 'Create-Cognito-Stack-Test', stackEnv)

// new S3Stack(app, "Create-S3-Stack", stackEnv);
// new CloudFrontStack(app, 'Create-CloudFront-Stack', stackEnv)
