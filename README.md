# Getssl scripts for DNS validation and device installation

## General

These scripts aid in installing Let's Encrypt certificates to devices that can't run an ACME client directly.
They are intended for use with [getssl](https://github.com/srvrco/getssl) although could potentially be
adapted for other ACME clients.

getssl should run on an independent host, using DNS challenge responses. Scripts are included for
[acme-dns](https://github.com/joohoi/acme-dns) although another DNS update mechanism could be used.
After receiving the certificate, it uploads the device to a Cisco ASA or Mikrotik device using their API.

If you export _USE_DEBUG from getssl.cfg, these scripts will produce additional debugging output
when you run `getssl` with the `-d` flag.


## Acme-DNS

`dns_add_acme_dns` adds the challenge record to an [acme-dns](https://github.com/joohoi/acme-dns) server
via the simple REST API.

`dns_del_acme_dns` does nothing; acme-dns does not have a remove method (although it does only keep
the last two records added).

You will need to follow the acme-dns instructions to register an account and subdomain.

Briefly,
1. `curl -X POST http://acme-challenge-responder.mydomain.com:5443/register`
2. Add CNAME to DNS (e.g. `_acme-challenge.vpn.mydomain.com CNAME 12345-67890.acme-challenge-responder.mydomain.com`)

Example additions to `getssl.cfg`:

```
VALIDATE_VIA_DNS=true
export ACME_DNS_API_URL=https://acme-challenge-responder.mydomain.com:5443
export ACME_DNS_USERNAME=<username from register>
export ACME_DNS_PASSWORD=<password from register>
export ACME_DNS_SUBDOMAIN=<subdomain from register>
DNS_ADD_COMMAND=<dir>/dns_add_acme_dns
DNS_DEL_COMMAND=<dir>/dns_del_acme_dns
DNS_EXTRA_WAIT=0
export _USE_DEBUG
```

When using acme-dns, there is no need to wait for DNS to propagate since it is instant, hence `DNS_EXTRA_WAIT` is
set to 0 to avoid unnecessary delays.


## Installation scripts

These scripts install the new certificate on various types of device.

### Cisco ASA

In order to deliver the certificate to a Cisco ASA, you will need the REST API installed.

Reference: https://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html

Briefly,
1. Download asa-restapi-7141-lfbff-k8.SPA
2. Copy it to the ASA
3. Ensure the HTTPS server is running and available to the client (in particular, this is considered
management, so you will need a `http <network> <mask> <interface>` line permitting access from the
host running getssl).
4. Configure the image and enable the agent:

```
vpn(config)# rest-api image disk0:/asa-restapi-7141-lfbff-k8.SPA
vpn(config)# rest-api agent
```

5. Create a user with privilege 15 for the script to use
```
vpn(config)# username svc-sslinstall password drowssap1 privilege 15
```

You need cryptography version 3.0 or later, use `pip3 install -r requirements.txt`

**Note that this script only supports one LE certificate with the same trustpoint prefix;
it will assume other trustpoints with the same prefix are old certificates that this script
has installed and remove them. If you need more than one certificate, e.g. certificates with
different names, you must use a different trustpoint prefix for each.**

Example additions to `getssl.cfg`:

```
export ASA_SSL_HOSTNAME=vpn.mydomain.com
export ASA_SSL_USERNAME=<asa username>
export ASA_SSL_PASSWORD=<asa password>
export ASA_SSL_TRUSTPOINT_PREFIX=TrustPoint_LE_
export ASA_SSL_INTERFACES=outside
export ASA_SSL_IKEV2=only

# Ideally we would verify the certificate when connecting to the API, but if this is the first
# run and you don't have an existing certificate, or if you are using a staging certificate, we
# must ignore certificate warnings - set ASA_SSL_INSECURE to 1 to do this.
export ASA_SSL_INSECURE=1

# Copy these three lines verbatim to set the files automatically to what getssl created:
export ASA_SSL_CERT=${CERT_FILE}
export ASA_SSL_KEY=${DOMAIN_DIR}/${DOMAIN}.key
export ASA_SSL_CHAIN=${CA_CERT}

# Pass through getssl's -d debug flag
export _USE_DEBUG

RELOAD_CMD="<dir>/install_to_asa.py"

```

Parameters are currently documented at the top of install_to_asa.py

Note that if the device doesn't have a valid certificate, you will need to set ASA_SSL_INSECURE
to 1 to disable certificate validation. This may be needed the first time you run, before you have
a valid certificate, or if you are using the staging servers. For normal use, it is strongly
recommended to not use this option (unset it or set it to 0).


### RouterOS

The certificate is delivered to a Mikrotik RouterOS device using the API.

You will need the API (or preferably API-SSL) service enabled under `/ip service` and permitting this
host to call it.

You will also need a user that is in a group that has at least ftp,read,write,test,api privileges.

The script requires cryptography version 3.0 or later and [routeros-api](https://github.com/socialwifi/RouterOS-api),
use `pip3 install -r requirements.txt` to install.

**Note that this script only supports one LE certificate with the same trustpoint prefix;
it will assume other trustpoints with the same prefix are old certificates that this script
has installed and remove them. If you need more than one certificate, e.g. certificates with
different names, you must use a different trustpoint prefix for each.**

Example additions to `getssl.cfg`:

```
export ROUTEROS_SSL_HOSTNAME=router.mydomain.com
export ROUTEROS_SSL_USERNAME=<routeros username>
export ROUTEROS_SSL_PASSWORD=<routeros username>
export ROUTEROS_SSL_CHAIN_NAME=LE_Chain
export ROUTEROS_SSL_CERT_PREFIX=LE_
export ROUTEROS_SSL_SERVICES=api-ssl,www-ssl

# API type to use (plain, ssl or ssl-insecure)
export ROUTEROS_SSL_APITYPE=ssl

# Copy these three lines verbatim to set the files automatically to what getssl created:
export ROUTEROS_SSL_CERT=$CERT_FILE
export ROUTEROS_SSL_KEY=$DOMAIN_DIR/${DOMAIN}.key
export ROUTEROS_SSL_CHAIN=$CA_CERT

# Pass through getssl's -d debug flag
export _USE_DEBUG

RELOAD_CMD="<dir>/install_to_routeros.py"
```

These parameters are currently documented in more detail at the top of install_to_routeros.py

Note that if the device doesn't have a valid certificate, you must use either 'plain' or
'ssl-insecure' api methods. The former is unencrypted, the latter uses SSL but does not
verify the certificate. This may be needed the first time you run, before you have
a valid certificate, or if you are using the staging servers. For normal use, it is strongly
recommended to use 'ssl'.

Note in particular that 'plain' sends the API username and password as well as the
private key in plaintext!
