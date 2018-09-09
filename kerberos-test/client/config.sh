#!/bin/bash

KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM

function kadminCommand {
    kadmin -p $KADMIN_PRINCIPAL_FULL -w $KADMIN_PASSWORD -q "$1"
}

sed -i "s/{{{REALM}}}/$REALM/g" /etc/krb5.conf

until kadminCommand "list_principals $KADMIN_PRINCIPAL_FULL"; do
  >&2 echo "KDC is unavailable - sleeping 1 sec"
  sleep 1
done
