# openssl dhparam -out dh.pem 2048
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 10000 -out server.crt -subj '//C=RU\ST=CA\L=MO\O=Tunneff\CN=localhost'
