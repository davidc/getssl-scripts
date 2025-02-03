#!/usr/bin/env python3

import sys
import os
import requests
import requests.exceptions
import logging
import json
import base64
import re
from pprint import pprint

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend


# Script expects its parameters as environment variables exported from getssl.cfg

# Hostname of the ASA. Required.
hostname = os.getenv('ASA_SSL_HOSTNAME')

# Username, requires privilege 15. Required.
username = os.getenv('ASA_SSL_USERNAME')

# Password. Required.
password = os.getenv('ASA_SSL_PASSWORD')

# Prefix of the trustpoints to create. Should not match any existing trustpoints as this
# script will remove them. Optional. Default: TrustPoint_LE_L
trustpoint_prefix = os.getenv('ASA_SSL_TRUSTPOINT_PREFIX', default='TrustPoint_LE_')

# File containing the certificate to deploy. Required.
cert_file = os.getenv('ASA_SSL_CERT')

# File containing the chain up to and including the root, but NOT including our certificate. Required.
chain_file = os.getenv('ASA_SSL_CHAIN')

# File containing the private key. Required.
key_file = os.getenv('ASA_SSL_KEY')

# Whether to disable SSL validation for the API calls. Needed if deploying for the first time
# or using staging certificates. Not recommended otherwise. Optional. Default: 0.
insecure = int(os.getenv('ASA_SSL_INSECURE', 0))

# Whether to enable debugging output. Usually exported from getssl so getssl can be run with -d.
# Optional. Default: 0
debug = int(os.getenv('_USE_DEBUG', 0)) == 1

# Which interfaces to apply the trustpoint (ssl trustpoint <tp> <interface>). Comma-separated.
# Optional. Default: outside. Can be blank.
interfaces = os.getenv('ASA_SSL_INTERFACES', default='outside').split(',')

# Whether to also set the ikev2 remote-access trustpoint for IKEv2. Set to 'only' this the only
# trustpoint (normal case), set it to 'add' to just add it to the existing list, set it to a number
# to insert it at that line (usually 1), leave it empty to not set it at all.
# Optional. Default: empty
ikev2 = os.getenv('ASA_SSL_IKEV2', default='')


# End of environment variable parameters


# Enable full HTTP debugging
HTTP_DEBUG = False


api_base_url = 'https://' + hostname + '/api'

ssl_verify = True if insecure == 0 else False

# Passphrase used to encrypt the pkcs12 file while it is delivered to the ASA.
pass_phrase = 'cisco123'


# HTTP debugging

if HTTP_DEBUG:
    import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def load_certificate(cert_file):
    with open(cert_file, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


# The chain file can contain multiple certificates and cryptography has no way
# to load the all. Separate them and load them into an array.
def load_chain(chain_file):
    chain_certs = []

    with open(chain_file, 'r') as f:
        accum = ''
        state = 0 # // 1 = in cert

        for line in f.readlines():
            if state == 0 and line.strip() == '-----BEGIN CERTIFICATE-----':
                accum = line
                state = 1
            elif state == 1:
                accum += line
                if line.strip() == '-----END CERTIFICATE-----':
                    state = 0
                    chain_cert = x509.load_pem_x509_certificate(accum.encode('UTF-8'), default_backend())
                    chain_certs.append(chain_cert)
    return chain_certs


def load_private_key(key_file):
    with open(key_file, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), None, default_backend())


def api_call(url, http_method, data):
    headers = { 'Content-Type': 'application/json', 'User-Agent': 'REST API Agent' }

    response = requests.request(http_method, url, data=json.dumps(data), auth=(username, password), headers=headers, verify=ssl_verify)

    if response.status_code > 299:
        try:
            json_error = json.loads(response.text)
            if json_error and 'messages' in json_error:
                code = json_error['messages'][0]['code']
                details = json_error['messages'][0]['details']
                raise requests.exceptions.HTTPError(code + ': ' + details)
            elif json_error and 'response' in json_error:
                # cli errors are just in the response message
                raise requests.exceptions.HTTPError(' '.join(json_error['response']))
        except ValueError:
            pass

        response.raise_for_status()

    return response


def list_trustpoints():
    trustpoints = []

    response = json.loads(api_call(api_base_url + '/certificate/identity', 'GET', {} ).text)

    for item in response['items']:
        trustpoints.append(item['name'])

    return trustpoints


def delete_trustpoint(trustpoint):
    api_call(api_base_url + '/certificate/identity/' + trustpoint, 'DELETE', {} )


def exec(cmds):
    if not isinstance(cmds, list):
        cmds = [ cmds ]

    if debug:
        pprint(cmds)
    return json.loads(api_call(api_base_url + '/cli', 'POST', { 'commands': cmds } ).text)


def get_ikev2_trustpoints():
    trustpoints = []
    output = exec('sh run crypto ikev2 | begin crypto ikev2 remote-access trustpoint')
    lines = output['response'][0].strip().split("\n")

    for line in lines:
        match = re.match(r"^\s*crypto ikev2 remote-access trustpoint ([^ ]+)$", line.strip())
        if match:
            trustpoints.append(match.group(1))

    return trustpoints


# 1. Load certificate and convert to pkcs12 format

cert = load_certificate(cert_file)
chain_certs = load_chain(chain_file)
key = load_private_key(key_file)

# Convert to pkcs12
p12 = pkcs12.serialize_key_and_certificates('mycert'.encode('UTF-8'), key, cert, chain_certs,
                                            serialization.BestAvailableEncryption(pass_phrase.encode('UTF-8')))

# Conert to cisco-format base64
p12_base64 = "-----BEGIN PKCS12-----\n" + base64.encodebytes(p12).decode('utf-8') + "-----END PKCS12-----\n"

# Create trustpoint name based on prefix and serial number in hex
serial_hex = hex(cert.serial_number).split('x')[-1]
trustpoint = trustpoint_prefix + serial_hex
if debug:
    print("Trustpoint name is %s" % (trustpoint))


# 2. Upload the certificate to a new trustpoint if it doesn't exist

existing_trustpoints = list_trustpoints()

if trustpoint not in existing_trustpoints:
    if debug:
        print("Trustpoint does not exist, adding")
    data = {
        'kind': 'object#IdentityCertificate',
        'name': trustpoint,
        'certText': p12_base64.splitlines(),
        'certPass': pass_phrase,
    }

    url = api_base_url + '/certificate/identity'

    response = api_call(url, 'POST', data)
    if debug:
        print("Added trustpoint")
else:
    if debug:
        print("Trustpoint already exists")


# 3. Assign the trustpoint to the requested interfaces

cmds = []

for interface in interfaces:
    cmds.append('ssl trust-point %s %s' % (trustpoint, interface))

if len(cmds) > 0:
    if debug:
        print("Assigning cert to interfaces")
    exec(cmds)


# TODO: Add the ability to assign certificates to SNI hostnames instead, using
# ssl trust-point <trustpoint> domain <sni-hostname>


# 4. Assign the trustpoint to IKEv2

if ikev2 != '':
    if debug:
        print("Assigning ikev2 remote-access trustpoint")

    ikev2_trustpoints = get_ikev2_trustpoints()
    cmds = []

    if trustpoint not in ikev2_trustpoints:
        # add it
        if (ikev2 == 'only' or ikev2 == 'add') :
            cmds.append('crypto ikev2 remote-access trustpoint %s' % (trustpoint))
        elif ikev2.isdigit():
            cmds.append('crypto ikev2 remote-access trustpoint %s line %s' % (trustpoint, ikev2))

    if ikev2 == 'only':
        # remove anything apart from ourselves
        for old_trustpoint in ikev2_trustpoints:
            if old_trustpoint != trustpoint:
                cmds.append('no crypto ikev2 remote-access trustpoint %s' % (old_trustpoint))

    if len(cmds) > 0:
        exec(cmds)


# 5. remove any old certificates created by this script:
# - that were installed by this script (so begin with trustpoint_prefix)
# - that don't begin with trustpoint_prefix + current_serial (because multiple can be installed for the CA, e.g. TP_MYSERIAL and TP_MYSERIAL-1
# NB. A unique prefix is required if the device has more than one LE certificate, or this script will remove the others!

for old_trustpoint in existing_trustpoints:
    if old_trustpoint.startswith(trustpoint_prefix) and not old_trustpoint.startswith(trustpoint):
        if debug:
            print('Removing old trustpoint: %s' % (old_trustpoint))
        delete_trustpoint(old_trustpoint)
