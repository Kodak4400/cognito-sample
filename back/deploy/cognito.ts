import { aws_cognito as cognito, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CdkJsonParams, Stage } from './@types/resource';
import { runCode } from './utils';

interface extendProps extends StackProps {
  stage: Stage
}

export class CognitoStack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

    const userPool = new cognito.UserPool(this, 'Create-Cognito-UserPool', {
      userPoolName: runCode(`return process.env.${params.USER_POOL_NAME}`),
      removalPolicy: RemovalPolicy.DESTROY,
    })
    userPool.addClient('Create-Cognito-UserPool-Client', {
      userPoolClientName: runCode(`return process.env.${params.USER_POOL_CLIENT_NAME}`),
    })

    console.log(runCode(`return process.env.${params.USER_POOL_CLIENT_NAME}`))
  }
}
