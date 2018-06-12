#!/bin/bash

CURVE=prime256v1
PASS=test
HOSTNAME=blackhole.rh.com
RSAPORT=50044
ECCPORT=50045

## root ca
mkdir -p /tmp/test/ca/{certs,crl,newcerts,private}
cd /tmp/test/ca
touch index.{rsa,ecc}.txt
echo 1000 > serial

#create root ca keys
openssl genrsa -aes256 -passout pass:$PASS -out private/ca.rsa.key.pem 4096 
openssl ecparam -name $CURVE -genkey | openssl ec -aes256 -passout pass:$PASS -out private/ca.ecc.key.pem

#copy root ca configs
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/openssl.rsa.cnf -O openssl.rsa.cnf
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/openssl.ecc.cnf -O openssl.ecc.cnf

#sign root ca certs
openssl req -config openssl.rsa.cnf -key private/ca.rsa.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.rsa.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com"
openssl req -config openssl.ecc.cnf -key private/ca.ecc.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.ecc.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com" 


## intermediate ca

mkdir -p /tmp/test/ca/intermediate/{certs,crl,csr,newcerts,private}
cd /tmp/test/ca/intermediate
touch index.{rsa,ecc}.txt
echo 1000 > serial
echo 1000 > crlnumber
cd /tmp/test/ca/

#create intermediate ca keys
openssl genrsa -aes256 -passout pass:$PASS -out intermediate/private/intermediate.rsa.key.pem 4096
openssl ecparam -name $CURVE -genkey  | openssl ec -aes256 -passout pass:$PASS -out intermediate/private/intermediate.ecc.key.pem

#copy intermediate ca configs
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/i_openssl.rsa.cnf -O intermediate/openssl.rsa.cnf
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/i_openssl.ecc.cnf -O intermediate/openssl.ecc.cnf

#sign intermediate ca certs
openssl req -config intermediate/openssl.rsa.cnf -new -sha256 -key intermediate/private/intermediate.rsa.key.pem -out intermediate/csr/intermediate.rsa.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com" 
openssl req -config intermediate/openssl.ecc.cnf -new -sha256 -key intermediate/private/intermediate.ecc.key.pem -out intermediate/csr/intermediate.ecc.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com" 

openssl ca -config openssl.rsa.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.rsa.csr.pem -out intermediate/certs/intermediate.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
openssl ca -config openssl.ecc.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.ecc.csr.pem -out intermediate/certs/intermediate.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch


# server cert

# create server key
cd /tmp/test/ca/intermediate/
openssl genrsa -out private/blackhole.rh.com.rsa.key.pem 2048
openssl ecparam -name $CURVE -genkey -out private/blackhole.rh.com.ecc.key.pem 

#create csr
openssl req -config openssl.rsa.cnf -key private/$HOSTNAME.rsa.key.pem -new -sha256 -out csr/$HOSTNAME.rsa.csr.pem -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com" 
openssl req -config openssl.ecc.cnf -key private/$HOSTNAME.ecc.key.pem -new -sha256 -out csr/$HOSTNAME.ecc.csr.pem -subj "/C=US/ST=CA/L=CM/O=log/CN=blackhole.rh.com"

#sign csr
openssl ca -config openssl.rsa.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in csr/$HOSTNAME.rsa.csr.pem -out certs/$HOSTNAME.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
openssl ca -config openssl.ecc.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in csr/$HOSTNAME.ecc.csr.pem -out certs/$HOSTNAME.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch

# check

# chain root / intermediate
cat certs/intermediate.rsa.cert.pem ../certs/ca.rsa.cert.pem > certs/ca-chain.rsa.cert.pem
cat certs/intermediate.ecc.cert.pem ../certs/ca.ecc.cert.pem > certs/ca-chain.ecc.cert.pem

openssl verify -CAfile certs/ca-chain.rsa.cert.pem  certs/$HOSTNAME.rsa.cert.pem
if [ $? -ne 0 ]
then
    echo "certificates not verifiable"
    exit 1
fi
openssl verify -CAfile certs/ca-chain.ecc.cert.pem  certs/$HOSTNAME.ecc.cert.pem
if [ $? -ne 0 ]
then
    echo "certificates not verifiable"
    exit 1
fi

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private/$HOSTNAME.rsa.key.pem -out private/$HOSTNAME.rsa.pkcs8.key
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private/$HOSTNAME.ecc.key.pem -out private/$HOSTNAME.ecc.pkcs8.key


#copy logstash config
cd /tmp/test
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/ls.conf -O ls.conf

#start logstash
LS_JAVA_OPTS="-Djavax.net.debug=all" /usr/share/logstash/bin/logstash --config.debug --log.level=debug -f /tmp/test/ls.conf -l /tmp/test/ &> /tmp/test/ls.out &
LS_PID=$!

#wait for logstash to be ready
until ss -nptl | grep -qE "\:5004[45]"
do 
    sleep 1
    echo "waiting for logstash to be ready"
done

#connect to logstash via rsa certificate
echo | openssl s_client -CAfile /tmp/test/ca/intermediate/certs/ca-chain.rsa.cert.pem  -cert /tmp/test/ca/intermediate/certs/$HOSTNAME.rsa.cert.pem -key /tmp/test/ca/intermediate/private/$HOSTNAME.rsa.pkcs8.key  -servername $HOSTNAME -state -tls1_2 -connect $HOSTNAME:$RSAPORT 2>&1 | tee /tmp/test/rsa.client.log

#connect to logstash via ecc certificate
echo | openssl s_client -CAfile /tmp/test/ca/intermediate/certs/ca-chain.ecc.cert.pem  -cert /tmp/test/ca/intermediate/certs/$HOSTNAME.ecc.cert.pem -key /tmp/test/ca/intermediate/private/$HOSTNAME.ecc.pkcs8.key  -servername $HOSTNAME -state -tls1_2 -connect $HOSTNAME:$ECCPORT 2>&1 | tee /tmp/test/ecc.client.log

#kill logstash and tcpdump
kill $LS_PID 
kill -2 $TD_PID
