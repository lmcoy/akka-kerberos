#!/bin/bash

KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM
SUPPORTED_ENCRYPTION_TYPES=aes256-cts-hmac-sha1-96:normal

echo "REALM: $REALM"
echo "KADMIN_PRINCIPAL_FULL: $KADMIN_PRINCIPAL_FULL"
echo "KADMIN_PASSWORD: $KADMIN_PASSWORD"
echo ""


KDC_KADMIN_SERVER=$(hostname -f)
tee /etc/krb5.conf <<EOF
[libdefaults]
	default_realm = $REALM
	dns_lookup_realm = false

[realms]
	$REALM = {
		kdc_ports = 88,750
		kadmind_port = 749
		kdc = $KDC_KADMIN_SERVER
		admin_server = $KDC_KADMIN_SERVER
	}
EOF

tee /etc/krb5kdc/kdc.conf <<EOF
[realms]
	$REALM = {
		acl_file = /etc/krb5kdc/kadm5.acl
		max_renewable_life = 7d 0h 0m 0s
		supported_enctypes = $SUPPORTED_ENCRYPTION_TYPES
		default_principal_flags = +preauth
	}
EOF
echo ""

tee /etc/krb5kdc/kadm5.acl <<EOF
$KADMIN_PRINCIPAL_FULL *
noPermissions@$REALM X
EOF
echo ""

MASTER_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w20 | head -n1)
krb5_newrealm <<EOF
$MASTER_PASSWORD
$MASTER_PASSWORD
EOF

kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"

krb5kdc
kadmind -nofork