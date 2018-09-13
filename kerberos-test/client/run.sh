#!/bin/bash

source `dirname $0`/config.sh

KEYTAB="/tmp/http.keytab"
JAAS_FILE="/tmp/jaas.conf"
HOST=$(hostname)
HTTP_PRINCIPAL="HTTP/$HOST"

# add service principal
kadminCommand "addprinc -randkey $HTTP_PRINCIPAL"

# create keytab for service principal
kadminCommand "ktadd -k $KEYTAB $HTTP_PRINCIPAL"

# use admin account
kinit $KADMIN_PRINCIPAL <<EOF
$KADMIN_PASSWORD
EOF

# use : instead of /
sed -i "s:{{{KEYTAB}}}:$KEYTAB:g" $JAAS_FILE
sed -i "s:{{{HTTP_PRINCIPAL}}}:$HTTP_PRINCIPAL:g" $JAAS_FILE

java -Djava.security.auth.login.config=$JAAS_FILE -jar /tmp/akka-kerberos-assembly-0.1.jar "$HTTP_PRINCIPAL" &

# wait until server is up
sleep 5

ANSWER=`python /tmp/http_get.py http://$(hostname):8090/hello`

EXPECTED="Hello $KADMIN_PRINCIPAL@$REALM"
if [ "$ANSWER" = "$EXPECTED" ]; then
	echo "test passed"
else
	echo "test failed:"
	echo "got: $ANSWER"
	echo "expected: $EXPECTED"
	exit 1
fi

# just wait a bit in case one wants to login to do further testing
sleep 1000000


