# ttunnel
Client/Server TLS Tunnel for FTP Shell

Certificate Generation:
    ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout rootkey.pem -out rootreq.pem
        openssl x509 -req -in rootreq.pem -sha256 -extfile openssl.cnf -extensions v3_ca -signkey rootkey.pem -out rootcert.pem
        cat rootcert.pem rootkey.pem > root.pem
        openssl x509 -subject -issuer -noout -in root.pem

    SERVER CA SIGNED BY ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout serverCAkey.pem -out serverCAreq.pem
        openssl x509 -req -in serverCAreq.pem -sha256 -extfile openssl.cnf -extensions v3_ca -CA root.pem -CAkey root.pem -CAcreateserial -out serverCAcert.pem
        cat serverCAcert.pem serverCAkey.pem rootcert.pem > serverCA.pem
        openssl x509 -subject -issuer -noout -in serverCA.pem

    SERVER CERT SIGNED BY SERVER CA:
        openssl req -newkey rsa:2408 -sha256 -keyout serverkey.pem -out serverreq.pem
        openssl x509 -req -in serverreq.pem -sha256 -extfile openssl.cnf -extensions server_cert -CA serverCA.pem -CAkey serverCA.pem -CAcreateserial -out servercert.pem
        cat servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem
        openssl x509 -subject -issuer -noout -in server.pem

    CLIENT CERT SIGNED BY ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout clientkey.pem -out clientreq.pem
        openssl x509 -req -in clientreq.pem -sha256 -extfile openssl.cnf -extensions usr_cert -CA root.pem -CAkey root.pem -CAcreateserial -out clientcert.pem
        cat clientcert.pem clientkey.pem rootcert.pem > client.pem
        openssl x509 -subject -issuer -noout -in client.pem


