'use strict';

var AWS = require("aws-sdk");

var TASK_QUEUE_URL = process.env.TASK_QUEUE_URL;
var AWS_REGION = process.env.AWS_REGION;

var sqs = new AWS.SQS({region: AWS_REGION});
var s3 = new AWS.S3({region: AWS_REGION});

function deleteMessage(receiptHandle, cb) {
  sqs.deleteMessage({
    ReceiptHandle: receiptHandle,
    QueueUrl: TASK_QUEUE_URL
  }, cb);
}

function work(task, cb) {
  console.log(task);
  sqs.receiveMessage({
     QueueUrl: TASK_QUEUE_URL,
     MaxNumberOfMessages: 1, // One Message Max
     VisibilityTimeout: 60, // Job Run Max
     WaitTimeSeconds: 3 // Message Wait Max
   }, function(err, data) {
     // If any Messages are present
     if (data.Messages) {
        // Retrieve the first available message
        var message = data.Messages[0],
            body = JSON.parse(message.Body);
        // Present message body in JSON to be used as reference
        UseMessageBody(body, message);  // TODO Check Body for public IP and compare to whitelist
     }
   });
  cb();
}

exports.handler = function(event, context, callback) {
  work(event.Body, function(err) {
    if (err) {
      callback(err);
    } else {
      deleteMessage(event.ReceiptHandle, callback);
    }
  });
};
