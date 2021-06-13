#!/usr/bin/env python3

import sys
import os
import time
from pprint import pprint

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import routeros_api
from routeros_api import exceptions


# Script expects its parameters as environment variables exported from getssl.cfg

# Hostname of the RouterOS device. Required.
hostname = os.getenv('ROUTEROS_SSL_HOSTNAME')

# Username, must be in a group with 'api', 'read', 'write' and 'ftp' (to write files) privileges. Required.
username = os.getenv('ROUTEROS_SSL_USERNAME')

# Password. Required.
password = os.getenv('ROUTEROS_SSL_PASSWORD')

# Name to use for the installed chain certificate. May create multiple (suffixed _number)
# if there is more than one certificate in the chain. Optional. Default: LE_Chain
chain_name = os.getenv('ROUTEROS_SSL_CHAIN_NAME', default='LE_Chain')

# Prefix of the certificate to create. Should not match any existing trustpoints as this
# script will remove them. Will be suffixed with the certificate serial. Optional. Default: LE_Cert
cert_prefix = os.getenv('ROUTEROS_SSL_CERT_PREFIX', default='LE_')

# File containing the certificate to deploy. Required.
cert_file = os.getenv('ROUTEROS_SSL_CERT')

# File containing the chain up to and including the root, but NOT including our certificate. Required.
chain_file = os.getenv('ROUTEROS_SSL_CHAIN')

# File containing the private key. Required.
key_file = os.getenv('ROUTEROS_SSL_KEY')

# Whether to enable debugging output. Usually exported from getssl so getssl can be run with -d.
# Optional. Default: 0
debug = int(os.getenv('_USE_DEBUG', 0)) == 1

# Which services to apply the certificate to (/ip service set <x> certificate=newcert). Comma-separated.
# Optional. Default: www-ssl,api-ssl. Can be blank.
services = os.getenv('ROUTEROS_SSL_SERVICES', default='www-ssl,api-ssl').split(',')

# Method to connect to API:
# plain - unencrypted (api). Note this will send passwords in plaintext in recent RouterOS!
# ssl - encrypted (api-ssl).
# ssl-insecure - encrypted (api_ssl) but ignore self-signed or invalid common name. Needed to bootstrap
# or if using staging certificates
apitype = os.getenv('ROUTEROS_SSL_APITYPE', default='ssl')

# End of environment variable parameters


def error_exit(code, message, detail=None):
    global debug

    print(message, file=sys.stderr)
    if debug:
        print(detail, file=sys.stderr)

    sys.exit(code)


def load_file(file):
    with open(file, 'r') as f:
        return f.read()


# There appears to be no way via the API to get a file onto the system, so we run a ridiculous sequence
# of commands to set the file's contents (obviously only works for text files)
# Filename should be without .txt. File will be created with .txt appended (new filename is returned)
def upload_file(filename, contents):
    if debug:
        print('Uploading %s' % (filename))
    api_root.call('file/print', { 'file': filename.encode() })

    # Astoundingly the file will not show up if we query for its ID immediately
    time.sleep(1)

    full_filename = '%s.txt' % (filename)

    file_id = get_file_id(full_filename)

    api.get_resource('file').set(id=file_id, contents=contents)

    return full_filename


def get_file_id(filename):
    our_file = api.get_resource('file').get(name=filename)
    if len(our_file) != 1:
        raise Exception("Unable to find file %s" % (filename))
    return our_file[0]['id']


def delete_file(filename):
    file_id = get_file_id(filename)
    api.get_resource('file').remove(id=file_id)


# 1. Connect to API

try:
    if apitype == 'plain':
        connection = routeros_api.RouterOsApiPool(hostname, username=username, password=password,
                                                  plaintext_login=True) #, debug=debug)
    elif apitype == 'ssl':
        connection = routeros_api.RouterOsApiPool(hostname, username=username, password=password,
                                                  plaintext_login=True, use_ssl=True) #, debug=debug)
    elif apitype == 'ssl-insecure':
        connection = routeros_api.RouterOsApiPool(hostname, username=username, password=password,
                                                  plaintext_login=True, use_ssl=True,
                                                  ssl_verify=False, ssl_verify_hostname=False) #, debug=debug)
    else:
        error_exit(1, 'Unknown api type %s' % (apitype))

    api = connection.get_api()

except routeros_api.exceptions.RouterOsApiConnectionError as e:
    error_exit(1, 'Connection error: %s' % (str(e)))
except routeros_api.exceptions.RouterOsApiCommunicationError as e:
    # although we have str(e) as detail available, do not output it as it may contain
    # an unencrypted password in the command string
    error_exit(1, 'Communication error: %s' % (e.original_message.decode()))

api_root = api.get_binary_resource('/');


# 2. Load certificate in PEM format

cert = load_file(cert_file)
chain = load_file(chain_file)
key = load_file(key_file)

# Load the certificate into cryptography to get its serial number
cert_x509 = x509.load_pem_x509_certificate(cert.encode(), default_backend())

# Create certificate name based on prefix and serial number in hex
serial_hex = hex(cert_x509.serial_number).split('x')[-1]

cert_name = cert_prefix + serial_hex
if debug:
    print("Certificate name is %s" % (cert_name))


# 2. Upload the certificate if it doesn't exist

find_our_cert = api.get_resource('certificate').get(name=cert_name)
if len(find_our_cert) == 0:
    if debug:
        print('Uploading certificate %s' % (cert_name))

    temp_cert_file = upload_file('tmp_crt_%s' % (cert_name), cert)
    api_root.call('certificate/import', { 'name': cert_name.encode(), 'file-name': temp_cert_file.encode(), 'passphrase': ''.encode() })
    delete_file(temp_cert_file)

    temp_key_file = upload_file('tmp_key_%s' % (cert_name), key)
    api_root.call('certificate/import', { 'name': cert_name.encode(), 'file-name': temp_key_file.encode(), 'passphrase': ''.encode() })
    delete_file(temp_key_file)

    temp_chain_file = upload_file('tmp_chain_%s' % (cert_name), chain)
    api_root.call('certificate/import', { 'name': chain_name.encode(), 'file-name': temp_chain_file.encode(), 'passphrase': ''.encode() })
    delete_file(temp_chain_file)
else:
    if debug:
        print('Certificate %s already exists on router' % (cert_name))


# 3. Assign the certificate to the requested services

for service in services:
    the_service = api.get_resource('ip/service').get(name=service)
    if len(the_service) != 1:
        error_exit(1, "Couldn't find IP service %s" % (service))

    service_id = the_service[0]['id']

    if debug:
        print('Assigning %s to %s service' % (cert_name, service))
    api.get_resource('ip/service').set(id=service_id, certificate=cert_name)


# 4. remove any old certificates created by this script:
# - that were installed by this script (so begin with cert_prefix)
# - aren't our new certificate
# - that don't begin with chain_name (in case cert_prefix also matches chain_name, e.g. cert_prefix is LE_ and chain_name is LE_Chain)
# NB. A unique prefix is required if the device has more than one LE certificate, or this script will remove the others!

existing_certificates = api.get_resource('certificate').get()

for old_certificate in existing_certificates:
    old_cert_name = old_certificate['name']
    old_cert_id = old_certificate['id']
    if old_cert_name.startswith(cert_prefix) and old_cert_name != cert_name and not old_cert_name.startswith(chain_name):
        print('Removing old certificate: %s' % (old_cert_name))
        api.get_resource('certificate').remove(id=old_cert_id)
