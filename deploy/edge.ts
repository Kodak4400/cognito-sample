import {
  aws_iam as iam,
  aws_lambda as lambda,
  aws_lambda_nodejs as lambda_nodejs,
  aws_logs as logs,
  RemovalPolicy,
  Stack,
  StackProps
} from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { CdkJsonParams, Stage } from './@types/resource'
import { runCode } from './utils'

interface extendProps extends StackProps {
  stage: Stage
}

export class LambdaEdgeStack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

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
      environment: {
        USER_POOL_ID: runCode(`return process.env.${params.USER_POOL_ID}`),
        TOKEN_USE: runCode(`return process.env.${params.TOKEN_USE}`),
        CLIENT_ID: runCode(`return process.env.${params.CLIENT_ID}`),
      },
    })
    const uniqueVersionId = `${new Date().getTime()}`
    const jwtVerifyFunctionVersion = new lambda.Version(this, `Jwt-Verify-FunctionVersion-${uniqueVersionId}`, {
      lambda: jwtVerifyFunction,
    })
    new lambda.Alias(this, 'Jwt-Verify-FunctionAlias', {
      aliasName: props.stage,
      version: jwtVerifyFunctionVersion,
    })

    new logs.LogGroup(this, 'Jwt-Verify-Function-LogGroup', {
      logGroupName: '/aws/lambda/' + jwtVerifyFunction.functionName,
      retention: logs.RetentionDays.ONE_DAY,
      removalPolicy: RemovalPolicy.DESTROY,
    })
  }
}
