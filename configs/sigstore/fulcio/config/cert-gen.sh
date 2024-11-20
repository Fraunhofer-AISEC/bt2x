#!/usr/bin/env bash
echo "Generating key..."
openssl ecparam -genkey \
  -name prime256v1 \
  -noout \
  -out fulcio_key_unencrypted.pem
echo "Completed."
echo "Generating encrypted private key..."
openssl ec \
  -in fulcio_key_unencrypted.pem \
  -out fulcio_key.pem -aes256
echo "Generating CA Certificate..."
openssl req -x509 \
        -key fulcio_key_unencrypted.pem \
        -out fulcio.pem -sha256 \
        -days 365 \
        -subj "/C=DE/ST=Bayern/L=Garching bei Muenchen/O=bt2x/CN=fulcio"  \
        -addext basicConstraints=critical,CA:TRUE,pathlen:1  \
        -addext keyUsage=critical,keyCertSign,cRLSign
chmod o+r fulcio_key.pem
echo "Completed."
