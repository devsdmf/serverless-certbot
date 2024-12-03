import path from 'path';

import cdk from 'aws-cdk-lib';
import s3 from 'aws-cdk-lib/aws-s3';
import lambda from 'aws-cdk-lib/aws-lambda';
import iam from 'aws-cdk-lib/aws-iam';

export default class ServerlessCertbotStack extends cdk.Stack {
  /**
   *
   * @param {Construct} scope
   * @param {string} id
   * @param {StackProps=} props
   */
  constructor(scope, id, props) {
    super(scope, id, props);

    // s3 bucket for solution files
    const bucket = new s3.Bucket(this, 'ServerlessCertbotBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true
    });

    // lambda layer
    const layerZippedPackage = path.normalize(import.meta.dirname + '/../src/layers/python-layer/layer_content.zip');
    const commonsLayer = new lambda.LayerVersion(this, 'CommonsLayer', {
      code: lambda.Code.fromAsset(layerZippedPackage),
      compatibleArchitectures: [lambda.Architecture.X86_64],
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_13],
      removalPolicy: cdk.RemovalPolicy.DESTROY
    });

    // provision-cert lambda function
    const provisionCertFunctionCode = path.normalize(import.meta.dirname + '/../src/functions/provision-certificate/package.zip');
    const provisionCertificateFunction = new lambda.Function(this, 'ProvisionCertFunc', {
      code: lambda.Code.fromAsset(provisionCertFunctionCode),
      handler: 'main.handler',
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.X86_64,
      timeout: cdk.Duration.minutes(2),
      environment: {
        ACCOUNT_EMAIL: process.env.CERTBOT_ACCOUNT_EMAIL,
        DIRECTORY_URL: process.env.CERTBOT_DIRECTORY_URL,
        USER_AGENT: process.env.CERTBOT_USERAGENT,
        DEBUG: '0',
        S3_BUCKET_NAME: bucket.bucketName
      }
    });

    // adding route53 permissions to lambda function
    provisionCertificateFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'route53:GetHostedZone',
        'route53:ListHostedZones',
        'route53:ChangeResourceRecordSets',
        'route53:ListResourceRecordSets',
        'route53:GetChange'
      ],
      resources: ['*']
    }));

    // grant read and write permissions to lambda function
    bucket.grantReadWrite(provisionCertificateFunction);
  }
};
