'use strict';

const parseArgs = require('minimist');
const camelCase = require('camelcase');
const AWS = require('aws-sdk');
const SQS = new AWS.SQS({apiVersion: '2012-11-05'});
const Lawos = require("../lib/lawos.js");
const supportedServices = {
  ec2: {apiVersion: '2016-11-15'},
  s3api: {apiVersion: '2006-03-01'},
  rds: {apiVersion: '2014-10-31'},
  iam: {apiVersion: '2010-05-08'},
  cloudtrail: {apiVersion: '2013-11-01'}
};

module.exports.handler = function handler(event, context, callback) {
  const queueUrl = 'https://sqs.' + process.env.AWS_REGION + '.amazonaws.com/' + require('alai').parse(context) + '/';
  const Q = new Lawos(queueUrl + process.env.sqs, SQS);
  
  Q.item(async (item) => {
    // parse alert message with remediation cli
    var alert = JSON.parse(item.Body);
    if (undefined == alert.alertRemediationCli || undefined == alert.alertRemediationCli.cliScript) { // no remediation available
      return new Promise(done => {
        done();
      });
    }
    
    // convert aws cli to api
    var awsapi = {
      params : {}
    };
    var awscli = parseArgs(alert.alertRemediationCli.cliScript.split(' '));
    awsapi.service = awscli._[1];
    awsapi.method = camelCase(awscli._[2]);
    Object.keys(awscli).forEach(function(key) {
      switch (key) {
        case "_":
          break;
        case "region":
          awsapi.region = awscli[key].replace(/"/g, "");
          break;
        case "acl":
          awsapi.params.ACL = awscli[key].replace(/"/g, "");
          break;
        case "cidr":
          awsapi.params.CidrIp = awscli[key].replace(/"/g, "");
          break;
        default:
          awsapi.params[camelCase(key, {pascalCase: true})] = awscli[key].replace(/"/g, "");
          break;
      }
    });
    
    // double check redediation api availability
    if (undefined == awsapi.service || ! (awsapi.service in supportedServices)) { 
      return new Promise(done => {
        done();
      });
    }

    console.log(awsapi);
    
    return new Promise(async (resolve, reject) => {
      // create aws service api
      var option = JSON.parse(JSON.stringify(supportedServices[awsapi.service]));
      if (awsapi.region !== undefined) {
        option.region = awsapi.region;
      }
      var api;
      switch (awsapi.service) {
        case "ec2":
          api = new AWS.EC2(option);
          break;
        case "s3api":
          api = new AWS.S3(option);
          break;
        case "rds":
          api = new AWS.RDS(option);
          break;
        case "iam":
          api = new AWS.IAM(option);
          break;
        case "cloudtrail":
          api = new AWS.CloudTrail(option);
          break;
      }
      
      try {
        await api[awsapi.method](awsapi.params).promise();
        resolve();
      } catch (error) {
        console.log(error);
        reject(error);
      }
     });
  });
  Q.work(() => Promise.resolve(context.getRemainingTimeInMillis() < 1000)).then(console.log).then(callback);
}
