#!/bin/bash

CURVE=prime256v1
PASS=test

## root ca
mkdir -p ~/test/ca/{certs,crl,newcerts,private}
cd ~/test/ca
touch index.{rsa,ecc}.txt
echo 1000 > serial

#create root ca keys
openssl genrsa -aes256 -passout pass:$PASS -out private/ca.rsa.key.pem 4096 
openssl ecparam -name $CURVE -genkey | openssl ec -aes256 -passout pass:$PASS -out private/ca.ecc.key.pem

#copy root ca configs
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/openssl.rsa.cnf -O openssl.rsa.cnf
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/openssl.ecc.cnf -O openssl.ecc.cnf

#sign root ca certs
openssl req -config openssl.rsa.cnf -key private/ca.rsa.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.rsa.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=root ca rsa"
openssl req -config openssl.ecc.cnf -key private/ca.ecc.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.ecc.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=root ca ecc"


## intermediate ca

mkdir -p ~/test/ca/intermediate/{certs,crl,csr,newcerts,private}
cd ~/test/ca/intermediate
touch index.{rsa,ecc}.txt
echo 1000 > serial
echo 1000 > crlnumber
cd ~/test/ca/

#create intermediate ca keys
openssl genrsa -aes256 -passout pass:$PASS -out intermediate/private/intermediate.rsa.key.pem 4096
openssl ecparam -name $CURVE -genkey  | openssl ec -aes256 -passout pass:$PASS -out intermediate/private/intermediate.ecc.key.pem

#copy intermediate ca configs
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/i_openssl.rsa.cnf -O intermediate/openssl.rsa.cnf
wget https://raw.githubusercontent.com/cloudsriseup/cryptoCA_test/master/i_openssl.ecc.cnf -O intermediate/openssl.ecc.cnf

#sign intermediate ca certs
openssl req -config intermediate/openssl.rsa.cnf -new -sha256 -key intermediate/private/intermediate.rsa.key.pem -out intermediate/csr/intermediate.rsa.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=intermediate ca rsa"
openssl req -config intermediate/openssl.ecc.cnf -new -sha256 -key intermediate/private/intermediate.ecc.key.pem -out intermediate/csr/intermediate.ecc.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=intermediate ca ecc"

openssl ca -config openssl.rsa.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.rsa.csr.pem -out intermediate/certs/intermediate.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
openssl ca -config openssl.ecc.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.ecc.csr.pem -out intermediate/certs/intermediate.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch


# server cert

# create server key
cd ~/test/ca/intermediate/
openssl genrsa -out private/localhost.rsa.key.pem 2048
openssl ecparam -name $CURVE -genkey -out private/localhost.ecc.key.pem 

#create csr
openssl req -config openssl.rsa.cnf -key private/localhost.rsa.key.pem -new -sha256 -out csr/localhost.rsa.csr.pem -subj "/C=US/ST=test/L=test/O=test/CN=localhost"
openssl req -config openssl.ecc.cnf -key private/localhost.ecc.key.pem -new -sha256 -out csr/localhost.ecc.csr.pem -subj "/C=US/ST=test/L=test/O=test/CN=localhost"

#sign csr
openssl ca -config openssl.rsa.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in csr/localhost.rsa.csr.pem -out certs/localhost.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
openssl ca -config openssl.ecc.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in csr/localhost.ecc.csr.pem -out certs/localhost.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch

# check

# chain root / intermediate
cat certs/intermediate.rsa.cert.pem ../certs/ca.rsa.cert.pem > certs/ca-chain.rsa.cert.pem
cat certs/intermediate.ecc.cert.pem ../certs/ca.ecc.cert.pem > certs/ca-chain.ecc.cert.pem

openssl verify -CAfile certs/ca-chain.rsa.cert.pem  certs/localhost.rsa.cert.pem
if [ $? -ne 0 ]
then
    echo "certificates not verifiable"
    exit 1
fi
openssl verify -CAfile certs/ca-chain.ecc.cert.pem  certs/localhost.ecc.cert.pem
if [ $? -ne 0 ]
then
    echo "certificates not verifiable"
    exit 1
fi

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private/localhost.rsa.key.pem -out private/localhost.rsa.pkcs8.key
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private/localhost.ecc.key.pem -out private/localhost.ecc.pkcs8.key

