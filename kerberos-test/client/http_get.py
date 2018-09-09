#!/usr/bin/env python

import time
import socket
import argparse
import sys
import urlparse
import base64
import httplib
import gssapi

parser = argparse.ArgumentParser()
parser.add_argument('url',
    help='url to connect to (including http/https://)')
args = parser.parse_args()

# verify url
url = urlparse.urlparse(args.url)
if url.scheme == 'http':
    conn_factory = httplib.HTTPConnection
elif url.scheme == 'https':
    conn_factory = httplib.HTTPSConnection
else:
    print('Invalid scheme "%s". Should be http or https.' % url.scheme)
    sys.exit(1)



service_principal = gssapi.Name('HTTP@%s' % url.hostname, name_type=gssapi.NameType.hostbased_service)

ctx = gssapi.SecurityContext(name=service_principal, usage='initiate')

conn = conn_factory(url.netloc)

# First request: Expected response:
#     "HTTP/1.1 401 Unauthorized" with "WWW-Authenticate: Negotiate" header
try:
    conn.request("GET", url.path)
except socket.error as e:
    print('Error connecting to %s: %s' % (args.url, e))
    sys.exit(1)

response = conn.getresponse()
response.read()
if response.getheader("www-authenticate") != 'Negotiate':
    print('no Negotiate')
    sys.exit(1)


in_token = None
counter = 0
while not ctx.complete and counter < 20:
    out_token = ctx.step(in_token)
    if out_token:
        out_token_b64 = base64.b64encode(out_token)
        conn.request("GET", url.path,
            headers={"Authorization": "Negotiate %s" % out_token_b64})

        response = conn.getresponse()
        data = response.read()
        if response.getheader("www-authenticate") != None:
            in_token_b64 = response.getheader("www-authenticate")[10:]
            in_token = base64.b64decode(in_token_b64)
        else:
            break
    counter += 1

print data


