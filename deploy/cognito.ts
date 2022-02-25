import { Stack, StackProps, RemovalPolicy } from 'aws-cdk-lib'
import { aws_cognito as cognito } from 'aws-cdk-lib'
import { Construct } from 'constructs';

export class CognitoStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const userPool = new cognito.UserPool(this, 'Create-Cognito-UserPool', {
      userPoolName: 'SampleUserPool',
      removalPolicy: RemovalPolicy.DESTROY,
    })
    userPool.addClient('Create-Cognito-UserPool-Client', {
      userPoolClientName: 'SampleUserPoolClient',
    })
  }
}