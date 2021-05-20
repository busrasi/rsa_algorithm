#/usr/bin/bash
# ssh-keygen -t rsa -b 4096 -o -a 100 -f id_rsa -m PEM < /dev/null
#Generate RSA Private Key
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_keygen_pubexp:65537 | \
  openssl pkcs8 -topk8 -nocrypt -outform pem > rsa.private
#Generate RSA Public Key
openssl rsa -inform pem -in rsa.private -out rsa.public -pubout -outform pem

echo "RSA Key Pair Has been Generated!"
