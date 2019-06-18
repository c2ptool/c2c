openssl genrsa -aes256 -out ca.key.pem 2048
chmod 400 ca.key.pem
openssl req -new -x509 -subj "/CN=lykhnyca" -extensions v3_ca -days 3650 -key ca.key.pem -sha256 -out ca.pem -config lykhny-localhost.cnf
#openssl x509 -in ca-localhost.pem -text -noout