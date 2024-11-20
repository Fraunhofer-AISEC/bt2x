#!/usr/bin/env bash
echo "Generating EC key for P256..."
openssl ecparam -genkey \
           -name prime256v1 \
           -out rekor_key.pem -noout
echo "Completed... (rekor_key.pem)"

echo "Extracting pubkey..."
openssl ec -in=rekor_key.pem -pubout > rekor_pub_key.pem
echo "Completed... (rekor_pub_key.pem)"