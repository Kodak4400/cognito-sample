# AWS Cognito + Lambda@Edge + S3（Static website hosting）

サーバーレスでプライベートなページが実現可能かを試す。

## 使用ツール

 - CDK（v2）
  - Cognito
  - S3
  - Lambda@Edge
  - API Gateway + Lambda
 - Vite(Plugin SSG) + Vue3 + TypeScript

## 構想

<img src="./cognito-lambda_edge.png">

## 使い方

npx cdk deploy -c env=env
