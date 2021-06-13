# Getssl scripts for DNS validation and device installation

## General

If you export _USE_DEBUG from getssl.cfg, these scripts will produce additional debugging output
when you run `getssl` with the `-d` flag.

## Acme-DNS

dns_add_acme_dns adds the challenge record to an [acme-dns](https://github.com/joohoi/acme-dns) server
via the simple REST API.

dns_del_acme_dns does nothing; acme-dns does not have a remove method (although it does only keep
the last two records added).

You will need to follow the acme-dns instructions to

Briefly,
1. curl -X POST http://acme-challenge-responder.mydomain.com:5443/register
2. Add CNAME to DNS (e.g. _acme-challenge.vpn.mydomain.com CNAME 12345-67890.acme-challenge-responder.mydomain.com

Example additions to getssl.cfg:

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

When using acme-dns, there is no need to wait for DNS to propagate since it is instant, hence DNS_EXTRA_WAIT is
set to 0 to avoid unnecessary delay.s


## Cisco ASA

In order to deliver the certificate to a Cisco ASA, you will need the REST API installed.

Reference: https://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html

Briefly,
1. Download asa-restapi-7141-lfbff-k8.SPA
2. Copy it to the ASA
3. Ensure the HTTPS server is running and available to the client.
4. Configure the image and enable the agent:

vpn(config)# rest-api image disk0:/asa-restapi-7141-lfbff-k8.SPA
vpn(config)# rest-api agent

5. Create a user with privilege 15 for the script to use
vpn(config)# username svc-sslinstall password drowssap1 privilege 15

You need cryptography version 3.0 or later, use `pip3 install -r requirements.txt`

Example getssl.cfg:

```
export ASA_SSL_HOSTNAME=vpn.mydomain
export ASA_SSL_USERNAME=<asa username>
export ASA_SSL_PASSWORD=<asa password>
export ASA_SSL_TRUSTPOINT_PREFIX=TrustPoint_LE_
export ASA_SSL_INTERFACES=outside
export ASA_SSL_IKEV2=only

# Copy these three lines verbatim to set the files automatically to what getssl created:
export ASA_SSL_CERT=${CERT_FILE}
export ASA_SSL_KEY=${DOMAIN_DIR}/${DOMAIN}.key
export ASA_SSL_CHAIN=${CA_CERT}

# Ideally we will verify the certificate when connecting to the API, but if this is the first
# run and you don't have an existing certificate, or if you are using a staging certificate, we
# must ignore certificate warnings - set ASA_SSL_INSECURE to 1 to do this.
export ASA_SSL_INSECURE=1

export _USE_DEBUG

RELOAD_CMD="<dir>/install_to_asa.py"

```

Parameters are currently documented at the top of install_to_asa.py
