openssl genrsa -out localhost.key.pem 2048
openssl req -subj "/CN=localhost" -extensions v3_req -sha256 -new -key localhost.key.pem -out localhost.csr
openssl x509 -req -extensions v3_req -days 3650 -sha256 -in localhost.csr -CA ca.pem -CAkey ca.key.pem -CAcreateserial -out localhost.crt -extfile localhost.cnf