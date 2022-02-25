import { Stack, StackProps, Duration, RemovalPolicy } from 'aws-cdk-lib'
import { aws_lambda_nodejs as lambda_nodejs } from 'aws-cdk-lib'
import { aws_lambda as lambda } from 'aws-cdk-lib'
import { aws_logs as logs } from 'aws-cdk-lib'
import { aws_iam as iam } from 'aws-cdk-lib'
import { aws_ssm as ssm } from 'aws-cdk-lib'
import { Construct } from 'constructs'

export class LambdaEdgeStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props)

    // Lambda@Edge
    const lambdaRole = new iam.Role(this, 'lambdaRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
      path: '/lambda/',
    })

    const jwtVerifyFunction = new lambda_nodejs.NodejsFunction(this, 'Jwt-Verify-Function', {
      runtime: lambda.Runtime.NODEJS_14_X,
      entry: 'edge/auth/index.ts',
      handler: 'handler',
      role: lambdaRole,
      awsSdkConnectionReuse: false,
      environment: {},
    })
    const uniqueVersionId = `${new Date().getTime()}`
    const jwtVerifyFunctionVersion = new lambda.Version(this, `Jwt-Verify-FunctionVersion-${uniqueVersionId}`, {
      lambda: jwtVerifyFunction,
    })
    const jwtVerifyFunctionAlias = new lambda.Alias(this, 'Jwt-Verify-FunctionAlias', {
      aliasName: 'dev',
      version: jwtVerifyFunctionVersion,
    })

    new logs.LogGroup(this, 'Jwt-Verify-Function-LogGroup', {
      logGroupName: '/aws/lambda/' + jwtVerifyFunction.functionName,
      retention: logs.RetentionDays.ONE_DAY,
      removalPolicy: RemovalPolicy.DESTROY,
    })

    // Parameter storeに書き込む
    // new ssm.StringParameter(this, 'SSM-Jwt-Verify-FunctionArn', {
    //   stringValue: jwtVerifyFunction.functionArn,
    //   parameterName: `/lambda/jwt-verify-function-arn`,
    // })
  }
}
