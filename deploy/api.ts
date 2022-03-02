import * as apigwv2 from '@aws-cdk/aws-apigatewayv2-alpha'
import { HttpLambdaIntegration } from '@aws-cdk/aws-apigatewayv2-integrations-alpha'
import {
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs, Duration, RemovalPolicy, Stack,
  StackProps
} from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { CdkJsonParams, Stage } from './@types/resource'
import { runCode } from './utils'

interface extendProps extends StackProps {
  stage: Stage
}

export class ApiStack extends Stack {
  constructor(scope: Construct, id: string, props: extendProps) {
    super(scope, id, props)

    const params: CdkJsonParams[Stage] = this.node.tryGetContext(props.stage)

    const lambdaRole = new iam.Role(this, `Create-LambdaRole`, {
      roleName: 'LambdaBasicRole',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
    })

    const authLambda = new lambda.Function(this, 'Create-AuthLambda', {
      code: lambda.Code.fromAsset('cdk-dist/auth'),
      handler: 'index.handler',
      runtime: lambda.Runtime.NODEJS_14_X,
      environment: {
        USER_POOL_ID: runCode(`return process.env.${params.USER_POOL_ID}`),
        CLIENT_ID: runCode(`return process.env.${params.CLIENT_ID}`),
      },
      role: lambdaRole,
      timeout: Duration.seconds(30),
      functionName: 'Cognito-Sample-AuthLambda',
    })

    const authLambdaAlias = new lambda.Alias(this, `CreateAuthLambda-alias`, {
      aliasName: props.stage,
      version: authLambda.currentVersion,
    })

    new logs.LogGroup(this, 'AuthLambda-Function-LogGroup', {
      logGroupName: '/aws/lambda/' + authLambdaAlias.functionName,
      retention: logs.RetentionDays.ONE_DAY,
      removalPolicy: RemovalPolicy.DESTROY,
    })

    const authIntegration = new HttpLambdaIntegration('AuthIntegration', authLambdaAlias)

    const httpApi = new apigwv2.HttpApi(this, 'Create-HttpProxyApi', {
      corsPreflight: {
        allowHeaders: ['Authorization', 'Content-Type', 'x-apigateway-header', 'x-amz-date'],
        allowMethods: [apigwv2.CorsHttpMethod.GET, apigwv2.CorsHttpMethod.POST, apigwv2.CorsHttpMethod.OPTIONS],
        allowOrigins: ['https://d28a55f3780vki.cloudfront.net'],
      },
    })

    httpApi.addRoutes({
      path: '/api/signin',
      methods: [apigwv2.HttpMethod.POST],
      integration: authIntegration,
    })
    httpApi.addRoutes({
      path: '/api/signup',
      methods: [apigwv2.HttpMethod.POST],
      integration: authIntegration,
    })
  }
}
