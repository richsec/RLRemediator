'use strict';

const AWS = require('aws-sdk');
const LAMBDA = new AWS.Lambda({apiVersion: '2015-03-31'});
const SQS = new AWS.SQS({apiVersion: '2012-11-05'});

module.exports.handler = function handler(event, context, callback) {
  // determine SQL URL from region and env variable
  const queueUrl = 'https://sqs.' + process.env.AWS_REGION + '.amazonaws.com/' + require('alai').parse(context) + '/' + process.env.sqs;
  
  // get the ApproximateNumberOfMessages
  var sqsAvail = SQS.getQueueAttributes({
    QueueUrl: queueUrl,
    AttributeNames: ['ApproximateNumberOfMessages',]
  }).promise();
  sqsAvail.then(data => {
    // scale number of processors based on number of avaialbe messages
    var n = data['ApproximateNumberOfMessages'];
    if (n > 1000) {
      return 5;
    }
    if (n > 100) {
      return 2;
    }
    return 1;
  }).catch(callback).then(
    // invoke processors
    count => Array.apply(null, Array(count)).map((_, index) => LAMBDA.invoke({
    FunctionName: process.env.process,
    InvocationType: 'Event',
    LogType: 'None'
  },(error, data)=>{if (error) console.log(error);})).length).then(count => ({ count })).then(console.log).then(callback);
};