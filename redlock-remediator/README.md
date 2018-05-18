# ⚡️ RedLock Auto-remediation solution based on SQS Worker with Serverless

[![license](https://img.shields.io/github/license/sbstjn/lawos.svg)](https://github.com/sbstjn/sqs-worker-serverless/blob/master/LICENSE.md)
[![CircleCI](https://img.shields.io/circleci/project/github/sbstjn/sqs-worker-serverless/master.svg)](https://circleci.com/gh/sbstjn/sqs-worker-serverless)

Experiment for an Amazon SQS worker with AWS Lambda using [lawos](https://github.com/sbstjn/lawos) and [serverless](https://serverless.com).

More details: [Serverless Amazon SQS Worker with AWS Lambda](https://sbstjn.com/serverless-sqs-worker-with-aws-lambda.html)

## Setup

- SQS Queue with your messages
- CloudWatch Schedule as cron replacement
- Two (`worker`, `process`) AWS Lambda functions

## Workflow

- CloudWatch Schedule invokes `worker` every `x` minute(s)
- Function `worker` evaluates available message size in the SQS queue and decides how many `process` invokations are needed
- Function `worker` invokes `process` function(s)
- Function `process` receives from SQS, parse alert auto-remediate-cli, and then executes corresponding AWS api

## RedLock Developer Deploy

AWS DEV account is required to develop and maintain this tool. See [serverless](https://serverless.com/framework/docs/providers/aws/guide/credentials/) for how to set up AWS account with serverless framework. Configure proper AWS profile and then use `export AWS_PROFILE="your-dev-profile"` would be quick to start.


```bash
$ > yarn install
$ > yarn deploy
```
To update the deployed stacks
```bash
$ > serverless deploy
```

## Customer Deployent

CloudFormation file can be sent to customer for easy deployment.

## Add noise to SQS

You should have some data in your queue to test this setup. Use [wrk](https://github.com/wg/wrk) to send messages to SQS, but make sure to enable [anonymous access to sendMessage](http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/acp-overview.html#anonQueues) for your queue first!

```
$ > wrk -c35 -d60 -t35 \
    -s helpers/wrk.lua \
    https://sqs.REGION.amazonaws.com/ACCOUNT-ID/YourQueueName
```
