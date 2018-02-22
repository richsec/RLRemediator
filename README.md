# Summary: SQS and Lambda

This repo contains code which is integrating SQS and Lambda to perform a consumer / worker function to remediate ingested "alerts" from SQS

## Deployment Guide

Use the following command to deploy the example. Replace `<NEW_BUCKET_NAME>` with your nickname.

```
aws s3 mb s3://sqs-lambda-<NEW_BUCKET_NAME>

aws cloudformation package --template-file cloudformation.json --s3-bucket sqs-lambda-<YOUR_NICKNAME> --output-template-file output.json && aws cloudformation deploy --template-file output.json --stack-name sqs-lambda-remediator --capabilities CAPABILITY_IAM
```
