#!/usr/bin/env node

import 'dotenv/config'
import cdk from 'aws-cdk-lib';
import ServerlessCertbotStack from '../lib/serverless-certbot-stack.js';

const app = new cdk.App();
new ServerlessCertbotStack(app, 'ServerlessCertbotStack', {
   env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});
