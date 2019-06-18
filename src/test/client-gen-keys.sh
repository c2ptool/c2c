# openssl dhparam -out dh.pem 2048
openssl req -newkey rsa:2048 -nodes -keyout client.key -x509 -days 10000 -out client.crt -subj '//C=RU\ST=CA\L=MO\O=Tunneff\CN=127.0.0.1'
