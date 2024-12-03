import os
import re
import time

from dotenv import load_dotenv, dotenv_values

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import josepy as jose

from OpenSSL import crypto

from acme import client
from acme import messages
from acme import crypto_util
from acme import challenges
from acme import errors

import boto3
import botocore

import logging

import validators

# defaults
DEFAULT_USER_AGENT = 'serverless-certbot-client'
DEFAULT_LOCAL_CERTS_PATH = '/tmp/acme/certs'
DEFAULT_LOCAL_ACCOUNTS_PATH = '/tmp/acme/accounts'

DEFAULT_S3_CERTS_PREFIX = 'acme/certs'
DEFAULT_S3_ACCOUNTS_PREFIX = 'acme/accounts'

ACCOUNT_REGR_FILENAME = 'regr.json'
ACCOUNT_PKEY_FILENAME = 'private_key.pem'

CERT_PKEY_FILENAME = 'private_key.pem'
CERT_CSR_FILENAME = 'cert_csr.pem'
CERT_SERVER_CERT_FILENAME = 'cert.pem'
CERT_FULLCHAIN_FILENAME = 'fullchain.pem'

DEFAULT_TMP_DIR = '/tmp/acme'
DEFAULT_TMP_ACCOUNTS_DIR = f'{DEFAULT_TMP_DIR}/accounts'
DEFAULT_ACCOUNT_REGR_FILENAME = 'regr.json'
DEFAULT_ACCOUNT_PKEY_FILENAME = 'private_key.pem'

# account key size
ACC_KEY_BITS = 2048

# certificate private key size
CERT_PRIVATE_KEY_SIZE = 2048

# finds one CERTIFICATE stricttextualmsg according to rfc7468#section-3.
# does not validate the base64text - use crypto.load_certificate.
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL # DOTALL (/s) because the base64text may include newlines
)

# initializing aws clients
route53_client = boto3.client('route53')
s3_client = boto3.client('s3')

def generate_account_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=ACC_KEY_BITS, backend=default_backend())

def create_account(client, account_email):
    try:
        return client.new_account(messages.NewRegistration.from_data(
            email=account_email, terms_of_service_agreed=True))
    except errors.ConflictError as err:
        raise Exception('An error occurred at trying to create new account, account already exists. ' + \
                        'Please restore the original registration and private key files to the accounts directory.')
    except Exception as err:
        raise Exception(f'A unexpected error has occurred: {err}')

def update_account(client, regr, email):
    try:
        return client.update_registration(regr, update=messages.UpdateRegistration.from_data(
            email=email, terms_of_service_agreed=True))
    except Exception as err:
        raise Exception(f'An error has occurred at trying to update registration, error: {err}')

def load_account_regr_from_s3(s3_client, bucket_name, account_email):
    account_files_prefix = f'{DEFAULT_S3_ACCOUNTS_PREFIX}/{account_email}'
    try:
        obj_list = s3_client.list_objects_v2(
            Bucket=bucket_name,
            MaxKeys=3,
            Prefix=account_files_prefix)

        obj_count = int(obj_list['KeyCount'])
        # 0 - there are no account files
        # 1 - missing files
        # 2 - probably have the necessary files, will be checked on next section
        if obj_count == 0:
            return None, None
        elif obj_count == 1:
            raise Exception('One or more account files are missing, please check the account directory in S3 and make sure it contains both registration and private key files')

    except s3_client.exceptions.NoSuchBucket:
        raise Exception('The specified S3 bucket does not exists or the function does not have the right access permissions, please check your environment')

    try:
        account_regr_s3_key = f'{account_files_prefix}/{DEFAULT_ACCOUNT_REGR_FILENAME}'
        account_pkey_s3_key = f'{account_files_prefix}/{account_email}/{DEFAULT_ACCOUNT_PKEY_FILENAME}'

        account_regr_obj = s3_client.get_object(Bucket=bucket_name, Key=account_regr_s3_key)
        account_regr = messages.RegistrationResource.json_loads(account_regr_obj.read())

        account_pkey_obj = s3_client.get_object(Bucket=bucket_name, Key=account_pkey_s3_key)
        account_private_key = serialization.load_pem_private_key(
            account_pkey_obj.read(), password=None)

        return account_regr, account_private_key
    except s3_client.exceptions.NoSuchKey as err:
        raise Exception(f'An error occurred at trying to load one of account files, file is missing, error: {err}')
    except botocore.exceptions.ClientError as err:
        raise Exception(f'An error occurred at trying to load files from S3 bucket, error: {err}')

def save_account_regr_to_s3(s3_client, bucket_name, account_email, account_regr, account_private_key):
    account_files_prefix = f'{DEFAULT_S3_ACCOUNTS_PREFIX}/{account_email}'
    account_regr_key = f'{account_files_prefix}/{DEFAULT_ACCOUNT_REGR_FILENAME}'
    account_pkey_key = f'{account_files_prefix}/{DEFAULT_ACCOUNT_PKEY_FILENAME}'

    try:
        account_regr_res = s3_client.put_object(Bucket=bucket_name,
                             Key=account_regr_key,
                             Body=account_regr.json_dumps())

        account_pkey_res = s3_client.put_object(Bucket=bucket_name,
                             Key=account_pkey_key,
                             Body=account_private_key.private_bytes(
                                 encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                                 encryption_algorithm=serialization.NoEncryption()))
        return account_regr_res, account_pkey_res
    except s3_client.exceptions.InvalidRequest as err:
        raise Exception(f'An error has occurred when trying to save files to S3, error: {err}')

def check_if_certificate_already_exists(s3_client, bucket_name, domain):
    cert_files_prefix = f'{DEFAULT_S3_CERTS_PREFIX}/{domain}'
    try:
        obj_list = s3_client.list_objects_v2(
            Bucket=bucket_name,
            MaxKeys=3,
            Prefix=cert_files_prefix)
        obj_count = int(obj_list['KeyCount'])
        # 0 - there are no cert files
        # 1+ - there are certificate files
        if obj_count == 0:
            return False
        return True
    except s3_client.exceptions.NoSuchBucket:
        raise Exception('The specified S3 bucket does not exists or the function does not have the right access permissions, please check your environment')
    except Exception as err:
        raise Exception(f'An unexpected error has occurred, error: {err}')

def save_certificate_files_to_s3(s3_client, bucket_name, domain, private_key, csr, server, fullchain):
    cert_files_prefix = f'{DEFAULT_S3_CERTS_PREFIX}/{domain}'
    try:
        cert_pkey_res = s3_client.put_object(Bucket=bucket_name,
                                             Key=f'{cert_files_prefix}/{CERT_PKEY_FILENAME}',
                                             Body=private_key)
        cert_csr_res = s3_client.put_object(Bucket=bucket_name,
                                            Key=f'{cert_files_prefix}/{CERT_CSR_FILENAME}',
                                            Body=csr)
        cert_server_res = s3_client.put_object(Bucket=bucket_name,
                                               Key=f'{cert_files_prefix}/{CERT_SERVER_CERT_FILENAME}',
                                               Body=server)
        cert_fullchain_res = s3_client.put_object(Bucket=bucket_name,
                                                  Key=f'{cert_files_prefix}/{CERT_FULLCHAIN_FILENAME}',
                                                  Body=fullchain)
        return cert_pkey_res, cert_csr_res, cert_server_res, cert_fullchain_res
    except s3_client.exceptions.InvalidRequest as err:
        raise Exception(f'An error has occurred when trying to save files to S3, error: {err}')

def update_hosted_zone_with_validation_entry(r53_client, hosted_zone_id, validation_domain, value, delete = False, waiter = True):
    try:
        updated_record_set = r53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Comment': 'Adding TXT record for SSL certificate challenge validation',
                'Changes': [
                    {
                        'Action': 'DELETE' if delete else 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': validation_domain,
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': f'"{value}"'
                                }
                            ]
                        }
                    }
                ]
            }
        )

        r53_waiter = r53_client.get_waiter('resource_record_sets_changed')
        r53_waiter.wait(Id=updated_record_set['ChangeInfo']['Id'])
        return
    except botocore.exceptions.ClientError as err:
        errCode = err.response['Error']['Code']
        raise Exception(f'An error [{errCode}] has occurred when trying to update DNS records: {err}')
    except Exception as err:
        raise Exception(f'An unexpected error has occurred when updating DNS records, error: {err}')

def get_challenge(order, challenge_type):
    authz_list = order.authorizations

    for authz in authz_list:
        for i in authz.body.challenges:
            if isinstance(i.chall, challenge_type):
                return i

    raise Exception('{} challenge was not offered by the CA server'.format(challenge_type))

def get_cert_from_fullchain(fullchain_pem):
    certs = CERT_PEM_REGEX.findall(fullchain_pem.encode())
    if len(certs) < 2:
        raise Exception('Failed to parse fullchain into server cert, less than 2 certificates in chain')

    certs_normalized = [crypto.dump_certificate(crypto.FILETYPE_PEM,
                            crypto.load_certificate(crypto.FILETYPE_PEM, cert)).decode() for cert in certs]

    return certs_normalized[0]

def handler(ev, ctx):
    # getting debug flag
    is_debug = True if 'DEBUG' in os.environ and int(os.environ['DEBUG']) == 1 else False

    # setting up logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if is_debug else logging.INFO)
    ch = logging.StreamHandler()
    logger.addHandler(ch)

    logger.info('provision-certificate function is running!')
    logger.debug('event received => %s', ev)
    logger.debug('context => %s', ctx)

    # setting up aws clients
    route53_client = boto3.client('route53')
    s3_client = boto3.client('s3')

    # validating user-agent
    user_agent = os.environ['USER_AGENT'] if 'USER_AGENT' in os.environ else DEFAULT_USER_AGENT
    if not isinstance(user_agent, str) or len(user_agent) == 0:
        logger.error('The specified USER_AGENT environment variable is not valid, please provide a valid string')
        return
    logger.debug(f'user-agent {user_agent} is gonna be used for the certificate generation')

    # validating directory URL
    directory_url = os.environ['DIRECTORY_URL'] if 'DIRECTORY_URL' in os.environ else None
    if directory_url == None or not isinstance(directory_url, str) or len(directory_url) == 0:
        logger.error('The specified DIRECTORY_URL environment variable is not valid, please provide a valid URL')
        return
    if not validators.url(directory_url):
        logger.error('The specified DIRECTORY_URL is not a valid URL, please provide a valid URL')
        return

    # validating account e-mail
    account_email = os.environ['ACCOUNT_EMAIL'] if 'ACCOUNT_EMAIL' in os.environ else None
    if account_email == None or not isinstance(account_email, str) or len(account_email) == 0:
        logger.error('The specified ACCOUNT_EMAIL environment variable is not valid, please provide a valid string')
        return

    if not validators.email(account_email):
        logger.error('The specified ACCOUNT_EMAIL environment variable is not valid, please provide a valid e-mail address')
        return
    logger.debug(f'account_email {account_email} is gonna be used for certificate generation')

    # validating s3 bucket
    bucket_name = os.environ['S3_BUCKET_NAME'] if 'S3_BUCKET_NAME' in os.environ else None
    if bucket_name == None or not isinstance(bucket_name, str) or len(bucket_name) == 0:
        logger.error('The specified S3_BUCKET_NAME environment variable is not valid, please provide a valid S3 bucket name')
        return None
    logger.debug(f's3 bucket {bucket_name} is gonna be used for certificate generation')


    # validating domain
    domain = ev['Domain'] if 'Domain' in ev else None
    if domain == None or not isinstance(domain, str) or len(domain) == 0:
        logger.error('The specified value Domain is not valid, please provide a valid domain name')
        return

    if not validators.domain(domain):
        logger.error('The specified value Domain is not valid, please provide a valid domain name')
        return
    logger.info(f'Generating certificates for {domain}, please wait...')

    # validating hosted zone ID
    hosted_zone_id = ev['HostedZoneId'] if 'HostedZoneId' in ev else None
    if hosted_zone_id == None or not isinstance(hosted_zone_id, str) or len(hosted_zone_id) == 0:
        logger.error(f'The specified value for HostedZoneId [{hosted_zone_id}]is not valid, please provide a valid one')
        return
    logger.debug(f'HostedZoneId {hosted_zone_id} is gonna be used for certificate generation')


    # attempting to load account info from s3
    logger.info('checking for account files in S3 bucket.,,')
    account_exists = False
    account_regr = None
    account_pkey = None
    try:
        account_regr, account_pkey = load_account_regr_from_s3(s3_client, bucket_name, account_email)
    except Exception as err:
        logger.error(f'An error occurred at trying to fetch accounts from S3, error: {err}')

    if account_regr is not None and account_pkey is not None:
        logger.debug('account exists and information has been loaded from S3 files')
        account_exists = True
    else:
        logger.debug('account does not exists, provisioning private key')
        account_pkey = generate_account_rsa_key()

    account_key = jose.JWKRSA(key=account_pkey)

    logger.debug('initializing connection with CA server')
    inet = client.ClientNetwork(account_key, user_agent=user_agent)
    directory = client.ClientV2.get_directory(directory_url, inet)
    client_acme = client.ClientV2(directory, net=inet)

    if account_exists:
        logger.info('updating account in CA server')
        try:
            updated_account_regr = update_account(client_acme, account_regr, account_email)
        except Exception as err:
            logger.error(f'An error has occurred at trying to update registration, error: {err}')
            return None
    else:
        logger.info('creating new user account on CA server')
        try:
            account_regr = create_account(client_acme, account_email)
            logger.debug(f'successfullt registered new account on CA server => {account_regr}')

            logger.debug('saving account files to S3 bucket')
            _, _ = save_account_regr_to_s3(s3_client, bucket_name, account_email, account_regr, account_pkey)
        except Exception as err:
            logger.error(f'An error has occurred at trying to create account: {err}')
            return None


    # validating hosted zone before proceeding with certificate provisioning
    try:
        hosted_zone_res = route53_client.get_hosted_zone(Id=hosted_zone_id)
    except botocore.exceptions.ClientError as err:
        errCode = err.response['Error']['Code']
        if errCode == 'NoSuchHostedZone':
            logger.error('The specified HostedZoneId is not a valid HostedZone or could not be found')
        elif errCode == 'InvalidInput':
            logger.error('The specified HostedZoneId is not a valid ID')
        else:
            logger.error(f'An error occurred at trying to request HostedZone, error: {err}')
        return
    logger.debug(f'proceeding with HostedZone: {hosted_zone_res}')

    # validating if certificate has already been generated
    try:
        cert_files_exists = check_if_certificate_already_exists(s3_client, bucket_name, domain)
        if cert_files_exists:
            logger.error('A certificate for the specified domain already exists, if you want to renew it, refer to the correct function')
            return None
    except Exception as err:
        logger.error(f'An error has occurred when trying to check for previous certificate files, error: {err}')
        return None

    # create certificate private key and csr
    logger.info('generating private key for certificate...')
    cert_private_key = crypto.PKey()
    cert_private_key.generate_key(crypto.TYPE_RSA, CERT_PRIVATE_KEY_SIZE)
    cert_private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_private_key)
    logger.debug('successfully generated private key => %s', cert_private_key_pem)

    logger.info('generating certificate singning request...')
    cert_csr_pem = crypto_util.make_csr(cert_private_key_pem, [domain])
    logger.debug('successfully generated CSR file => %s', cert_csr_pem)

    # issue certificate order
    logger.info('placing certificate order request...')
    cert_order = client_acme.new_order(cert_csr_pem)
    logger.debug('successfully placed order => %s', cert_order)

    # getting challenge
    challb = get_challenge(cert_order, challenges.DNS01)
    validation_domain = challb.validation_domain_name(domain)
    validation_value = challb.validation(account_key)
    logger.info('successfully obtained DNS challenge from CA server => %s', challb)
    logger.info('domain name entry for DNS challenge: %s', validation_domain)
    logger.info('TXT value for DNS challenge: %s', validation_value)

    # updating DNS resource records
    logger.info('updating route53 record set to provide challenge validation, this may take a while...')
    try:
        _ = update_hosted_zone_with_validation_entry(route53_client, hosted_zone_id, validation_domain, validation_value)
        logger.debug('successfully updated hosted zone with challenge entries')
    except Exception as err:
        logger.error(f'An error has occurred at trying to update dns records, error: {err}')
        return None

    logger.info('requesting challenge validation from CA server...')
    challr, challv = challb.response_and_validation(account_key)

    # validating DNS record
    client_acme.answer_challenge(challb, challr)
    fulfilled_order = client_acme.poll_and_finalize(cert_order)

    logger.info('successfully fulfilled certificate validation request!')
    logger.debug('fullfilled order => %s', fulfilled_order)

    logger.info('generating server certificate...')
    fullchain_pem = fulfilled_order.fullchain_pem
    cert_pem = get_cert_from_fullchain(fullchain_pem)

    logger.info('uploading certificate files to S3')
    try:
        save_certificate_files_to_s3(s3_client, bucket_name, domain,
                                     cert_private_key_pem, cert_csr_pem, cert_pem, fullchain_pem)
        logger.debug('successfully saved files to S3')
    except Exception as err:
        logger.error(f'An error has occurred when trying to save files to S3, error: {err}')
        return None

    # todo: upload to acm

    # cleaning up
    logger.info('removing route53 record set...')
    try:
        _ = update_hosted_zone_with_validation_entry(route53_client, hosted_zone_id, validation_domain, validation_value, delete=True, waiter=False)
        logger.debug('successfully updated hosted zone')
    except Exception as err:
        logger.error(f'An error has occurred at trying to update dns records, error: {err}')
        return None

    return {
        'message': 'Success!',
    }

# main function for direct script execution
if __name__ == '__main__':
    load_dotenv()
    handler({
        'Domain': 'realm.333oclock.com',
        'HostedZoneId': 'Z03632269X136HVCJ49T'
    }, None)
